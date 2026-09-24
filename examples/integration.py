"""Run from project root after installing. All enterprise effects here are synthetic."""
import tempfile
from daconic_governance import Governance
from daconic_governance.fixtures import FixtureAdapter, profile


def main():
    with tempfile.TemporaryDirectory(prefix="daconic-example-") as directory:
        with Governance(directory, FixtureAdapter()) as gov:
            gov.policies.install(profile())
            run = gov.broker.start_run("refund-agent", "case-1")
            # Register only this wrapper in the existing runtime's tool registry.
            def refund(record_id: str, amount_minor: int, transaction_id: str):
                result = gov.broker.execute(run, "refund", {"record_id":record_id,"amount_minor":amount_minor},transaction_id)
                return result
            print(refund("record-1",5000,"tx-1"))
            gov.broker.end_run(run)


if __name__ == "__main__": main()
