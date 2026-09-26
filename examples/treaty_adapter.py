import os
import time

import psycopg2
from psycopg2.extras import RealDictCursor


NEON_DSN = (
    "postgresql://neondb_owner:npg_Ygo9arzu3NjM@"
    "ep-young-sunset-a568cnk5-pooler.us-east-2.aws.neon.tech/neondb"
    "?sslmode=require&channel_binding=require"
)


class TreatyAdapter:
    def __init__(self, dsn=None):
        self.dsn = dsn or os.environ.get("NEON_DSN", NEON_DSN)

    def _connect(self):
        return psycopg2.connect(self.dsn)

    def read(self, case_id, record_id, tenant):
        with self._connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT comparison_id, session_id, critical_findings, review_completed
                    FROM treaty_comparisons
                    WHERE comparison_id = %s AND session_id = %s
                    LIMIT 1
                    """,
                    (record_id, case_id),
                )
                row = cur.fetchone()

        if row is None:
            return {}

        amount_minor = int(row["critical_findings"]) * 10000
        status = "open" if not row["review_completed"] else "closed"
        return {
            "record_id": row["comparison_id"],
            "case_id": row["session_id"],
            "tenant": tenant,
            "status": status,
            "amount_minor": amount_minor,
            "balance_minor": amount_minor,
            "version": 1,
            "observed_at": int(time.time()),
        }

    def apply(self, action, facts, idempotency_key):
        comparison_id = facts["record_id"]
        case_id = facts["case_id"]

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS treaty_broker_idempotency (
                        idempotency_key TEXT PRIMARY KEY,
                        comparison_id TEXT,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                    """
                )
                cur.execute(
                    "SELECT 1 FROM treaty_broker_idempotency WHERE idempotency_key = %s",
                    (idempotency_key,),
                )
                if cur.fetchone() is not None:
                    conn.commit()
                    return {
                        "record_id": comparison_id,
                        "case_id": case_id,
                        "status": "approved",
                        "idempotent": True,
                    }

                cur.execute(
                    "INSERT INTO treaty_broker_idempotency (idempotency_key, comparison_id) VALUES (%s, %s)",
                    (idempotency_key, comparison_id),
                )
                cur.execute(
                    "UPDATE treaty_comparisons SET status = %s, review_completed = true WHERE comparison_id = %s",
                    ("APPROVED", comparison_id),
                )
                conn.commit()

        return {
            "record_id": comparison_id,
            "case_id": case_id,
            "status": "approved",
            "idempotent": False,
        }

    def read_after(self, case_id, record_id, tenant):
        return self.read(case_id, record_id, tenant)
