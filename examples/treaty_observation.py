#!/usr/bin/env python3
"""Read treaty audit logs from NeonDB and submit observation traces to Daconic.

Usage: python3 examples/treaty_observation.py

Environment:
  DACONIC_API_TOKEN - token for Daconic API (required)

NeonDB connection string is embedded per task requirements.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict

import httpx
import psycopg2

NEON_CONN = (
    "postgresql://neondb_owner:npg_Ygo9arzu3NjM@ep-young-sunset-a568cnk5-pooler.us-east-2.aws.neon.tech/"
    "neondb?sslmode=require&channel_binding=require"
)
DACONIC_URL = "http://127.0.0.1:8080/observations"

LOG = logging.getLogger("treaty_observation")


def to_ns(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def build_trace(
    audit_id: str,
    email_id: str | None,
    sender_email: str | None,
    created_at: datetime,
    critical_findings: int,
    email_sent: bool,
    payload_action: str,
    scenario: str,
) -> Dict[str, Any]:
    observed_ns = to_ns(created_at)

    def stage_payload(mask_sender: bool) -> Dict[str, Any]:
        return {
            "audit_id": audit_id,
            "critical_findings": int(critical_findings),
            "email_sent": bool(email_sent),
            "sender_email": "[REMOVED]" if mask_sender else (sender_email or ""),
            "action": payload_action,
        }

    trace = {
        "schema_version": "1",
        "interaction_id": str(audit_id),
        "correlation_id": email_id,
        "agent_id": "treaty-comparison-agent",
        "action": "llm_send",
        "scenario": scenario,
        "policy": {"id": "llm-data-policy", "version": "v1"},
        "context": {
            "principal": "agent-1",
            "delegated_user": None,
            "resource": str(audit_id),
            "destination": "approved-model",
        },
        "stages": {
            "input": {
                "availability": "present",
                "source": "treaty-agent-host",
                "observed_at_ns": observed_ns,
                "representation": "canonical-json-v1",
                "payload": stage_payload(mask_sender=False),
            },
            "transformed": {
                "availability": "present",
                "source": "treaty-agent-host",
                "observed_at_ns": observed_ns,
                "representation": "canonical-json-v1",
                "payload": stage_payload(mask_sender=True),
            },
            "outbound": {
                "availability": "present",
                "source": "treaty-agent-host",
                "observed_at_ns": observed_ns,
                "representation": "canonical-json-v1",
                "payload": stage_payload(mask_sender=True),
            },
        },
    }

    return trace


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    token = os.getenv("DACONIC_API_TOKEN")
    if not token:
        LOG.error("DACONIC_API_TOKEN environment variable is not set")
        return 2

    try:
        conn = psycopg2.connect(NEON_CONN)
    except Exception as exc:  # pragma: no cover - runtime error handling
        LOG.exception("Failed to connect to NeonDB: %s", exc)
        return 1

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT audit_id, email_id, sender_email, event_data, created_at "
                    "FROM treaty_audit_logs WHERE compliance_checked_at IS NULL"
                )
                rows = cur.fetchall()

                if not rows:
                    LOG.info("No un-checked treaty_audit_logs found")
                    return 0

                client = httpx.Client(timeout=15.0)

                for audit_id, email_id, sender_email, event_data, created_at in rows:
                    try:
                        if isinstance(event_data, str):
                            ed = json.loads(event_data)
                        else:
                            ed = event_data or {}

                        # Extract values with safe defaults
                        critical = int(ed.get("critical_findings", 0))
                        email_sent = bool(ed.get("email_sent", ed.get("email_sent", False)))

                        # Determine scenario and payload action
                        if critical > 0:
                            if email_sent:
                                scenario = "with_processing"
                                compliance_result = "COMPLIANT"
                            else:
                                scenario = "without_processing"
                                compliance_result = "VIOLATION"
                            payload_action = "REVIEW_EMAIL_SENT"
                        else:
                            scenario = "with_processing"
                            compliance_result = "NOT_APPLICABLE"
                            payload_action = "no_review_needed"

                        # Ensure integer counts
                        critical = int(critical)

                        trace = build_trace(
                            audit_id=str(audit_id),
                            email_id=email_id,
                            sender_email=sender_email,
                            created_at=created_at,
                            critical_findings=critical,
                            email_sent=email_sent,
                            payload_action=payload_action,
                            scenario=scenario,
                        )

                        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

                        resp = client.post(DACONIC_URL, json=trace, headers=headers)

                        if 200 <= resp.status_code < 300:
                            # Mark as checked
                            with conn.cursor() as update_cur:
                                update_cur.execute(
                                    "UPDATE treaty_audit_logs SET compliance_checked_at = NOW() WHERE audit_id = %s",
                                    (audit_id,),
                                )
                            LOG.info(
                                "Submitted audit_id=%s -> %s (severity=%d)", audit_id, compliance_result, critical
                            )
                            print(f"{audit_id}\t{compliance_result}\t{critical}")
                        else:
                            LOG.error(
                                "Failed to POST trace for audit_id=%s: status=%s body=%s",
                                audit_id,
                                resp.status_code,
                                resp.text,
                            )
                            print(f"{audit_id}\tERROR_POST\t{critical}")

                    except Exception as row_exc:  # per-row error handling
                        LOG.exception("Error processing audit_id=%s: %s", audit_id, row_exc)
                        print(f"{audit_id}\tERROR\t0")

    finally:
        try:
            conn.close()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
