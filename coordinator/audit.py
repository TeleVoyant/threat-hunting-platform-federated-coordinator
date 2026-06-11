# observability/audit.py
"""
Immutable audit trail for security-relevant platform actions.
Stored in append-only SQLite database.
"""

import sqlite3
import time
import json
import hashlib
from pathlib import Path
from coordinator.logging import get_logger

logger = get_logger("observability.audit")


class AuditTrail:

    def __init__(self, db_path: str = "/data/audit/audit.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False because FastAPI handlers may run on
        # different threads (sync handlers via run_in_threadpool, TestClient).
        # The hash-chain mutation is guarded by self._lock below.
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        from threading import Lock
        self._lock = Lock()
        self._create_table()
        self._prev_hash = self._get_last_hash()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT,
                details TEXT,
                chain_hash TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def log(self, action: str, actor: str, target: str = "", details: dict = None):
        """
        Log an audit event with hash chain integrity.
        Each entry's hash includes the previous entry's hash,
        creating a tamper-evident chain (like a mini blockchain).
        """
        timestamp = time.time()
        details_json = json.dumps(details or {})

        # Hash-chain mutation must be atomic: read prev_hash, compute, write,
        # update prev_hash. Lock prevents two concurrent calls from
        # producing entries with the same prev_hash.
        with self._lock:
            chain_input = (
                f"{self._prev_hash}{timestamp}{action}{actor}{target}{details_json}"
            )
            chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

            self.conn.execute(
                "INSERT INTO audit_log (timestamp, action, actor, target, details, chain_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (timestamp, action, actor, target, details_json, chain_hash),
            )
            self.conn.commit()
            self._prev_hash = chain_hash

        logger.info(
            "AUDIT",
            action=action,
            actor=actor,
            target=target,
            chain_hash=chain_hash[:16],
        )

    def verify_integrity(self) -> tuple[bool, int]:
        """Verify the entire audit chain hasn't been tampered with."""
        rows = self.conn.execute(
            "SELECT timestamp, action, actor, target, details, chain_hash "
            "FROM audit_log ORDER BY id"
        ).fetchall()

        prev_hash = "genesis"
        for i, (ts, action, actor, target, details, stored_hash) in enumerate(rows):
            chain_input = f"{prev_hash}{ts}{action}{actor}{target}{details}"
            expected_hash = hashlib.sha256(chain_input.encode()).hexdigest()
            if expected_hash != stored_hash:
                logger.critical(
                    "AUDIT CHAIN BROKEN",
                    row=i,
                    expected=expected_hash[:16],
                    stored=stored_hash[:16],
                )
                return False, i
            prev_hash = stored_hash

        return True, len(rows)

    def _get_last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "genesis"

    def query(
        self, action: str = None, actor: str = None, limit: int = 100
    ) -> list[dict]:
        """Query audit log with filters."""
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if action:
            query += " AND action = ?"
            params.append(action)
        if actor:
            query += " AND actor = ?"
            params.append(actor)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "action": r[2],
                "actor": r[3],
                "target": r[4],
                "details": json.loads(r[5]),
                "chain_hash": r[6],
            }
            for r in rows
        ]
