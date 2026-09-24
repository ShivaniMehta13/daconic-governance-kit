from .storage import Store
from .evidence import Ledger
from .policy import PolicyStore
from .broker import Broker
from .runtime import Queue, Router, Workers


class Governance:
    def __init__(self, directory, adapter, policy_directory=None, tenant="poc", checkpoint_records=100, checkpoint_seconds=30):
        self.store = Store(directory)
        try:
            self.ledger = Ledger(self.store, checkpoint_records, checkpoint_seconds)
            self.policies = PolicyStore(self.store, policy_directory)
            self.broker = Broker(self.policies, self.ledger, adapter, tenant)
            self.queue = Queue(self.store)
            self.router = Router(self.policies)
            self.workers = Workers(self.queue, self.broker)
        except Exception:
            self.store.close()
            raise

    def close(self):
        if not self.store.closed:
            self.workers.close()
            try:
                self.ledger.checkpoint(force=True)
            finally:
                self.queue.close()
                self.store.close()

    def __enter__(self): return self
    def __exit__(self, *exc): self.close()
