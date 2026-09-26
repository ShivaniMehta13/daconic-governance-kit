import sys
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from daconic_governance import Governance
from treaty_adapter import TreatyAdapter

NEON_DSN = (
    "postgresql://neondb_owner:npg_Ygo9arzu3NjM@"
    "ep-young-sunset-a568cnk5-pooler.us-east-2.aws.neon.tech/neondb"
    "?sslmode=require&channel_binding=require"
)


def treaty_policy():
    return {
        "agent_id": "treaty-agent",
        "version": "v1",
        "capabilities": {
            "refund": {
                "kind": "refund",
                "restricted_response_paths": [],
                "corroborate_paths": ["/record_id", "/case_id", "/status"],
            }
        },
        "rules": [
            "scope",
            "reference",
            "amount_integrity",
            "hard_ceiling",
            "approval",
            "restricted_data",
        ],
        "params": {
            "autonomous_minor": 0,
            "ceiling_minor": 100000,
            "concurrency": 2,
            "approval_seconds": 600,
            "facts_max_age_seconds": 86400,
        },
        "routes": [{"priority": 10, "match": {"action": "refund"}}],
    }


def fetch_pending_rows(limit=3):
    with psycopg2.connect(NEON_DSN) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT comparison_id, session_id, critical_findings
                FROM treaty_comparisons
                WHERE review_completed = false
                ORDER BY comparison_id
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()


def main():
    state_dir = Path("./treaty-broker-state")
    state_dir.mkdir(parents=True, exist_ok=True)

    adapter = TreatyAdapter(NEON_DSN)
    with Governance(state_dir, adapter) as app:
        app.policies.install(treaty_policy())

        rows = fetch_pending_rows(limit=3)
        if not rows:
            print("No open treaty comparisons found.")
            return

        for row in rows:
            comparison_id = str(row["comparison_id"])
            session_id = str(row["session_id"])
            amount_minor = int(row["critical_findings"]) * 10000
            txn_id = f"tx-{comparison_id[:8]}"
            run = None
            try:
                run = app.broker.start_run("treaty-agent", session_id)
                result = app.broker.execute(
                    run,
                    "refund",
                    {"record_id": comparison_id, "amount_minor": amount_minor},
                    txn_id,
                )
                print(f"{comparison_id} / {session_id}: effect={result['decision']['effect']}")

                if result["decision"]["effect"] == "step_up":
                    approval = app.broker.issue_approval(
                        agent_id="treaty-agent",
                        case_id=session_id,
                        transaction_id=txn_id,
                        record_id=comparison_id,
                        max_amount_minor=amount_minor,
                        approver_id="reviewer",
                        expires_seconds=600,
                    )
                    approved = app.broker.execute(
                        run,
                        "refund",
                        {"record_id": comparison_id, "amount_minor": amount_minor},
                        txn_id,
                        approval_token=approval,
                    )
                    print(f"{comparison_id} / {session_id}: approved={approved}")
            except Exception as exc:
                print(f"{comparison_id} / {session_id}: error={exc}")
            finally:
                if run is not None:
                    try:
                        app.broker.end_run(run)
                    except Exception:
                        pass


if __name__ == "__main__":
    main()
