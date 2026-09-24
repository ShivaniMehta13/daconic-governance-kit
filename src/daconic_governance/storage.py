"""Single-process SQLite coordinator. All ledger/approval/action writes share a transaction."""
import contextlib
import os
import sqlite3
import threading
import time
from pathlib import Path


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Fail rather than silently permit multiple coordinators or key races.
        self._lease = open(self.directory / "process.lock", "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self._lease.write(b"0")
                self._lease.flush()
                self._lease.seek(0)
                msvcrt.locking(self._lease.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lease.close()
            raise RuntimeError("A coordinator already owns this deployment")
        self.lock = threading.RLock()
        self.closed = False
        self.commit_ns = 0
        self.transaction_count = 0
        self.db = sqlite3.connect(self.directory / "state.sqlite3", check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS ledger (seq INTEGER PRIMARY KEY, envelope TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS ledger_hash ON ledger(json_extract(envelope,'$.hash'));
        CREATE TABLE IF NOT EXISTS policies (hash TEXT PRIMARY KEY, document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS profiles (agent TEXT PRIMARY KEY, hash TEXT NOT NULL REFERENCES policies(hash));
        CREATE TABLE IF NOT EXISTS approvals (token_hash TEXT PRIMARY KEY, data TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, state TEXT NOT NULL, result TEXT, intent_hash TEXT);
        CREATE TABLE IF NOT EXISTS queue (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, payload TEXT NOT NULL,
          agent TEXT, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, available REAL NOT NULL,
          lease_until REAL, lease_token TEXT, error TEXT);
        CREATE INDEX IF NOT EXISTS queue_ready ON queue(agent,state,available);
        ''')

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            if self.closed:
                raise RuntimeError("Store is closed")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                started_commit = time.perf_counter_ns()
                self.db.execute("COMMIT")
                self.commit_ns += time.perf_counter_ns() - started_commit
                self.transaction_count += 1
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self):
        with self.lock:
            if not self.closed:
                self.db.close()
                self._lease.close()
                self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def atomic_write(path, content):
    """Fsync bytes, atomic rename, and directory fsync on POSIX."""
    import tempfile
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
