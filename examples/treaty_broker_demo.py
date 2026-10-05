"""Treaty broker live demo: prints every policy check, shows STOP / APPROVE / DENY,
and proves it by printing the DB row before and after each step.

Usage:
    export NEON_DATABASE_URL='postgresql://...'
    python3 examples/treaty_broker_demo.py            # runs with seeded dummy scenarios
    python3 examples/treaty_broker_demo.py --pause    # waits for Enter between steps (for live narration)
    python3 examples/treaty_broker_demo.py --no-seed  # use rows as they are in the DB

Scenarios (seeded on the first 3 rows with review_completed = false):
    1. critical_findings = 0   -> amount 0        -> ALLOW directly (within autonomous limit)
    2. critical_findings = 2   -> amount 20000    -> STEP_UP (agent stopped) -> human approval -> ALLOW
    3. critical_findings = 15  -> amount 150000   -> DENY (above hard ceiling 100000, approval cannot override)
"""
import argparse
import os
import sys
import time
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from daconic_governance import Governance  # noqa: E402
from treaty_adapter import TreatyAdapter  # noqa: E402
from treaty_broker_test import treaty_policy  # noqa: E402

from treaty_adapter import NEON_DSN as DSN

SCENARIOS = [
    (0, "Low risk: no critical findings"),
    (2, "Medium risk: critical findings need human review"),
    (15, "High risk: exceeds hard ceiling"),
]

RULE_LABELS = {
    "scope": "Is this action within the agent's allowed scope?",
    "reference": "Does the record exist and match the case?",
    "amount_integrity": "Does the amount match what the DB says?",
    "hard_ceiling": "Is the amount under the hard ceiling (100000)?",
    "approval": "Is amount within autonomous limit, or is there a valid human approval?",
    "restricted_data": "Is restricted data kept out of the response?",
}


def line(ch="-", n=78):
    print(ch * n)


def pause(args, msg="Press Enter to continue..."):
    if args.pause:
        input(f"\n   [{msg}]")


def db_row(comparison_id):
    with psycopg2.connect(DSN) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT comparison_id, session_id, critical_findings, status, review_completed "
                "FROM treaty_comparisons WHERE comparison_id = %s",
                (comparison_id,),
            )
            return cur.fetchone()


def show_db(label, comparison_id):
    r = db_row(comparison_id)
    print(f"   DB {label:<7}: status={r['status']!s:<15} review_completed={r['review_completed']}")


def seed_rows():
    with psycopg2.connect(DSN) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT comparison_id, session_id FROM treaty_comparisons "
                "ORDER BY comparison_id LIMIT %s",
                (len(SCENARIOS),),
            )
            rows = cur.fetchall()
            if len(rows) < len(SCENARIOS):
                raise SystemExit(
                    f"Need {len(SCENARIOS)} rows with review_completed=false, found {len(rows)}. "
                    "Run reset (see docs) or use --no-seed."
                )
            for row, (findings, _) in zip(rows, SCENARIOS):
                cur.execute(
                    "UPDATE treaty_comparisons SET critical_findings = %s, "
                    "status = 'PENDING_REVIEW', review_completed = false WHERE comparison_id = %s",
                    (findings, row["comparison_id"]),
                )
        conn.commit()
    return [str(r["comparison_id"]) for r in rows]


def open_rows(limit=3):
    with psycopg2.connect(DSN) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT comparison_id FROM treaty_comparisons WHERE review_completed = false "
                "ORDER BY comparison_id LIMIT %s",
                (limit,),
            )
            return [str(r["comparison_id"]) for r in cur.fetchall()]


def print_decision(decision):
    effect = decision["effect"].upper()
    violated = decision.get("violations") or []
    violated_text = " ".join(str(v) for v in violated).lower()
    triggered = decision.get("rule")
    print("   Policy checks (treaty-agent v1):")
    for rule in decision.get("evaluated_rules", []):
        hit = (rule in violated_text) or (effect != "ALLOW" and rule == triggered)
        mark = "FAIL" if hit else "PASS"
        print(f"     [{mark}] {rule:<17} {RULE_LABELS.get(rule, '')}")
    if effect != "ALLOW":
        print(f"   Triggered rule : {triggered}")
    if decision.get("reasons"):
        print(f"   Reasons        : {decision['reasons']}")
    if violated:
        print(f"   Violations     : {violated}")


def banner(effect):
    return {
        "ALLOW": ">>> ALLOW: action permitted",
        "STEP_UP": ">>> STEP_UP: AGENT STOPPED, waiting for human approval",
        "DENY": ">>> DENY: action BLOCKED, approval cannot override",
        "DEFER": ">>> DEFER: action deferred",
    }.get(effect, f">>> {effect}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pause", action="store_true", help="wait for Enter between steps")
    ap.add_argument("--no-seed", action="store_true", help="do not modify DB rows")
    args = ap.parse_args()

    ids = open_rows(len(SCENARIOS)) if args.no_seed else seed_rows()
    if not ids:
        raise SystemExit("No open treaty comparisons found.")

    state_dir = Path(f"./treaty-demo-state-{int(time.time())}")
    state_dir.mkdir(parents=True, exist_ok=True)
    adapter = TreatyAdapter(DSN)

    line("=")
    print("TREATY AGENT + DACONIC BROKER LIVE DEMO")
    print("Policy: treaty-agent v1 | autonomous limit 0 | hard ceiling 100000 | amount = critical_findings x 10000")
    print(f"Evidence ledger: {state_dir}")
    line("=")

    with Governance(state_dir, adapter) as app:
        app.policies.install(treaty_policy())

        for n, cid in enumerate(ids, 1):
            r = db_row(cid)
            session_id = str(r["session_id"])
            findings = int(r["critical_findings"])
            amount = findings * 10000
            txn = f"tx-{cid[:8]}-{int(time.time())}"
            label = SCENARIOS[n - 1][1] if not args.no_seed and n <= len(SCENARIOS) else ""

            print(f"\nCASE {n}: {label}")
            line()
            print(f"   comparison_id={cid}")
            print(f"   critical_findings={findings} -> requested amount_minor={amount}")
            print("   Agent wants to: mark treaty comparison APPROVED / close review")
            show_db("before", cid)
            pause(args, "Press Enter to send the agent action to the broker")

            run = None
            try:
                run = app.broker.start_run("treaty-agent", session_id)
                payload = {"record_id": cid, "amount_minor": amount}
                res = app.broker.execute(run, "refund", payload, txn)
                d = res["decision"]
                print_decision(d)
                print(f"   {banner(d['effect'].upper())}")
                show_db("after", cid)

                if d["effect"] == "allow":
                    print(f"   Result: {res.get('result')}")
                elif d["effect"] == "step_up":
                    print("   (DB unchanged: the agent did NOT get to write anything)")
                    pause(args, "Press Enter for the human reviewer to approve")
                    print("   Human reviewer 'reviewer' approves (max amount %s, valid 600s)..." % amount)
                    token = app.broker.issue_approval(
                        agent_id="treaty-agent",
                        case_id=session_id,
                        transaction_id=txn,
                        record_id=cid,
                        max_amount_minor=amount,
                        approver_id="reviewer",
                        expires_seconds=600,
                    )
                    res2 = app.broker.execute(run, "refund", payload, txn, approval_token=token)
                    d2 = res2["decision"]
                    print_decision(d2)
                    print(f"   {banner(d2['effect'].upper())}")
                    print(f"   Result: {res2.get('result')}")
                    show_db("after", cid)
                else:
                    print("   (DB unchanged: action never reached the database)")
            except Exception as exc:
                print(f"   ERROR: {exc}")
            finally:
                if run is not None:
                    try:
                        app.broker.end_run(run)
                    except Exception:
                        pass
            pause(args, "next case")

    line("=")
    print("DONE. Every decision above is signed into the evidence ledger:", state_dir)
    line("=")


if __name__ == "__main__":
    main()
