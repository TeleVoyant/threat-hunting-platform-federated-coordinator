# federated/coordinator_store.py
"""
SQLite-backed registries for the FL coordinator: participating
organizations + round history.

Lives ONLY on the FL coordinator host — the org platform never reads
this DB.

Tables
------
  orgs    — enrolled organizations, API keys, trust scores, status
  rounds  — every FL round started, its params, and its outcome
"""

import json
import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    org_id           TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL,
    api_key_hash     TEXT NOT NULL,                    -- bootstrap-only after mTLS
    public_key_pem   TEXT,                             -- Ed25519 SPKI PEM (added Sprint C+)
    cert_pem         TEXT,                             -- client cert signed by federation CA
    cert_serial      TEXT,                             -- decimal string of cert serial
    enrolled_at      REAL NOT NULL,
    enrolled_by      TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    trust_score      REAL NOT NULL DEFAULT 1.0,
    last_seen_at     REAL,
    last_accuracy    REAL,                             -- last validation accuracy (poisoning sudden-drop baseline; persisted so it survives restarts)
    notes            TEXT,
    leave_requested_at  REAL,                          -- mutual-ack removal: when the org requested to leave
    leave_attestation   BLOB,                          -- org-signed fl.leave_request.v1 (non-repudiation)
    leave_signature     TEXT,                          -- hex Ed25519 sig over leave_attestation
    removal_attestation BLOB,                          -- coordinator-signed fl.removal_confirm.v1
    removal_signature   TEXT                           -- hex sig over removal_attestation
);

CREATE TABLE IF NOT EXISTS rounds (
    round_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at            REAL NOT NULL,
    started_by            TEXT NOT NULL,
    completed_at          REAL,
    status                TEXT NOT NULL DEFAULT 'running',
    params_json           TEXT NOT NULL,
    num_clients_invited   INTEGER NOT NULL DEFAULT 0,
    num_clients_responded INTEGER NOT NULL DEFAULT 0,
    num_clients_accepted  INTEGER NOT NULL DEFAULT 0,
    num_clients_rejected  INTEGER NOT NULL DEFAULT 0,
    global_model_hash     TEXT,
    eval_metrics_json     TEXT,
    announce_attestation  BLOB,                         -- coordinator-signed round announcement (canonical-JSON bytes)
    announce_signature    TEXT                          -- hex Ed25519 signature over announce_attestation
);

-- One-shot challenge tokens issued per (org, round). Bound and consumed
-- atomically when a contribution is verified — prevents replay both
-- across and within rounds.
CREATE TABLE IF NOT EXISTS challenges (
    challenge       TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    round_id        INTEGER NOT NULL,
    issued_at       REAL NOT NULL,
    expires_at      REAL NOT NULL,
    consumed        INTEGER NOT NULL DEFAULT 0,
    consumed_at     REAL,
    FOREIGN KEY(org_id) REFERENCES orgs(org_id)
);

-- Permanent record of every accepted+verified contribution.
-- The signed_attestation column is the BYTES that were signed — this is
-- the non-repudiable artefact. Anyone with the org's public key can
-- re-verify the signature against it years later.
CREATE TABLE IF NOT EXISTS contributions (
    contribution_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    round_id             INTEGER NOT NULL,
    org_id               TEXT NOT NULL,
    received_at          REAL NOT NULL,
    model_sha256         TEXT NOT NULL,
    num_examples         INTEGER NOT NULL,
    model_path           TEXT,                             -- on-disk path to the persisted XGBoost JSON (accepted contributions only)
    signed_attestation   BLOB NOT NULL,
    signature_hex        TEXT NOT NULL,
    challenge            TEXT NOT NULL,
    accepted             INTEGER NOT NULL DEFAULT 0,
    rejection_reason     TEXT,
    FOREIGN KEY(round_id) REFERENCES rounds(round_id),
    FOREIGN KEY(org_id)   REFERENCES orgs(org_id)
);

-- Versioned global models. Aggregation produces a 'staged' version that soaks
-- under observation; the operator promotes it to 'active' (the published model
-- served to orgs) after the soak window, archiving the previously-active one.
-- Rollback re-activates an archived version. One 'active' row at a time.
CREATE TABLE IF NOT EXISTS global_models (
    version_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    round_id          INTEGER NOT NULL,
    created_at        REAL NOT NULL,
    staged_until      REAL NOT NULL,                  -- soak end; publish allowed after this
    status            TEXT NOT NULL DEFAULT 'staged', -- staged | active | archived
    model_hash        TEXT NOT NULL,
    model_path        TEXT NOT NULL,
    promoted_at       REAL,
    promoted_by       TEXT,
    eval_metrics_json TEXT,
    FOREIGN KEY(round_id) REFERENCES rounds(round_id)
);

CREATE INDEX IF NOT EXISTS ix_orgs_status        ON orgs(status);
CREATE INDEX IF NOT EXISTS ix_rounds_started_at  ON rounds(started_at DESC);
CREATE INDEX IF NOT EXISTS ix_challenges_org_rnd ON challenges(org_id, round_id);
CREATE INDEX IF NOT EXISTS ix_contrib_round      ON contributions(round_id, org_id);
CREATE INDEX IF NOT EXISTS ix_gm_status          ON global_models(status);
CREATE INDEX IF NOT EXISTS ix_gm_round           ON global_models(round_id);
"""


class CoordinatorStore:

    def __init__(self, db_path: str = "data/fl_coordinator/coordinator.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        # Defensive migrations: add columns to tables created by an older schema.
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(contributions)")}
        if "model_path" not in cols:
            self.conn.execute("ALTER TABLE contributions ADD COLUMN model_path TEXT")
        ocols = {r[1] for r in self.conn.execute("PRAGMA table_info(orgs)")}
        if "last_accuracy" not in ocols:
            self.conn.execute("ALTER TABLE orgs ADD COLUMN last_accuracy REAL")
        rcols = {r[1] for r in self.conn.execute("PRAGMA table_info(rounds)")}
        if "announce_attestation" not in rcols:
            self.conn.execute("ALTER TABLE rounds ADD COLUMN announce_attestation BLOB")
        if "announce_signature" not in rcols:
            self.conn.execute("ALTER TABLE rounds ADD COLUMN announce_signature TEXT")
        # Mutual-ack org removal columns (added later than the original orgs table).
        for _col, _type in (
            ("leave_requested_at", "REAL"), ("leave_attestation", "BLOB"),
            ("leave_signature", "TEXT"), ("removal_attestation", "BLOB"),
            ("removal_signature", "TEXT"),
        ):
            if _col not in ocols:
                self.conn.execute(f"ALTER TABLE orgs ADD COLUMN {_col} {_type}")
        self.conn.commit()
        self._lock = Lock()

    # ── Orgs ────────────────────────────────────────────────────────────────

    def enroll_org(
        self,
        org_id: str,
        display_name: str,
        api_key_hash: str,
        enrolled_by: str,
        *,
        public_key_pem: Optional[str] = None,
        cert_pem: Optional[str] = None,
        cert_serial: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> dict:
        """
        Insert a new org. If status is 'revoked', re-enroll (rotates everything).
        Otherwise rejects duplicate org_id with 'active'/'blocked' status —
        admin must explicitly revoke first.

        public_key_pem + cert_pem + cert_serial are populated when the org
        provides a public key (which the coordinator wraps in a CA-signed cert).
        """
        with self._lock:
            existing = self.conn.execute(
                "SELECT status FROM orgs WHERE org_id = ?", (org_id,),
            ).fetchone()
            if existing and existing["status"] != "revoked":
                raise ValueError(
                    f"org_id already enrolled (status={existing['status']}): "
                    f"{org_id}"
                )
            self.conn.execute(
                "INSERT OR REPLACE INTO orgs(org_id, display_name, "
                "api_key_hash, public_key_pem, cert_pem, cert_serial, "
                "enrolled_at, enrolled_by, status, trust_score, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 1.0, ?)",
                (org_id, display_name, api_key_hash, public_key_pem,
                 cert_pem, cert_serial, time.time(), enrolled_by, notes),
            )
            self.conn.commit()
        return self.get_org(org_id)

    def get_org_public_key(self, org_id: str) -> Optional[str]:
        """PEM-encoded Ed25519 public key for the org (None if not registered)."""
        row = self.conn.execute(
            "SELECT public_key_pem FROM orgs WHERE org_id = ? AND status = 'active'",
            (org_id,),
        ).fetchone()
        return row["public_key_pem"] if row and row["public_key_pem"] else None

    def list_revoked_serials(self) -> list[int]:
        """All revoked-status orgs' cert serials, for CRL regeneration."""
        rows = self.conn.execute(
            "SELECT cert_serial FROM orgs "
            "WHERE status = 'revoked' AND cert_serial IS NOT NULL"
        ).fetchall()
        return [int(r["cert_serial"]) for r in rows]

    # ── Challenges (one-shot nonces for replay protection) ──────────────────

    def issue_challenge(
        self,
        org_id: str,
        round_id: int,
        challenge: str,
        ttl_seconds: int = 600,
    ) -> dict:
        """Persist a freshly-generated challenge bound to (org, round)."""
        now = time.time()
        with self._lock:
            self.conn.execute(
                "INSERT INTO challenges(challenge, org_id, round_id, "
                "issued_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (challenge, org_id, round_id, now, now + ttl_seconds),
            )
            self.conn.commit()
        return {
            "challenge":   challenge,
            "expires_at":  now + ttl_seconds,
            "issued_at":   now,
        }

    def consume_challenge(
        self,
        challenge: str,
        org_id: str,
        round_id: int,
    ) -> Optional[str]:
        """
        Atomically validate + consume a challenge. Returns None on success,
        a string error reason on failure. The single UPDATE prevents two
        concurrent contributions from both consuming the same challenge.
        """
        now = time.time()
        with self._lock:
            cur = self.conn.execute(
                "UPDATE challenges SET consumed = 1, consumed_at = ? "
                "WHERE challenge = ? AND org_id = ? AND round_id = ? "
                "  AND consumed = 0 AND expires_at > ?",
                (now, challenge, org_id, round_id, now),
            )
            self.conn.commit()
            if cur.rowcount > 0:
                return None
            # Diagnose why it failed for a clearer error message
            row = self.conn.execute(
                "SELECT org_id, round_id, consumed, expires_at "
                "FROM challenges WHERE challenge = ?",
                (challenge,),
            ).fetchone()
            if not row:
                return "Unknown challenge"
            if row["org_id"] != org_id:
                return "Challenge belongs to a different org"
            if row["round_id"] != round_id:
                return "Challenge belongs to a different round"
            if row["consumed"]:
                return "Challenge already consumed"
            if row["expires_at"] <= now:
                return "Challenge expired"
            return "Challenge consumption failed"

    # ── Contributions ──────────────────────────────────────────────────────

    def record_contribution(
        self,
        *,
        round_id: int,
        org_id: str,
        model_sha256: str,
        num_examples: int,
        signed_attestation: bytes,
        signature_hex: str,
        challenge: str,
        accepted: bool,
        model_path: Optional[str] = None,
        rejection_reason: Optional[str] = None,
    ) -> int:
        """
        Permanently record a contribution. The signed_attestation bytes
        + signature_hex form the non-repudiable proof: any third party
        with the org's public key can re-verify them later.

        `model_path` points at the persisted XGBoost JSON on disk (set for
        accepted contributions so the aggregation step can reload the bytes).
        """
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO contributions(round_id, org_id, received_at, "
                "model_sha256, num_examples, model_path, signed_attestation, "
                "signature_hex, challenge, accepted, rejection_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (round_id, org_id, time.time(), model_sha256, num_examples,
                 model_path, signed_attestation, signature_hex, challenge,
                 1 if accepted else 0, rejection_reason),
            )
            self.conn.commit()
        return cur.lastrowid

    def has_accepted_contribution(self, round_id: int, org_id: str) -> bool:
        """True if this org already has an accepted contribution for the round.
        Enforces one-accepted-submission-per-(org, round) at the API layer."""
        row = self.conn.execute(
            "SELECT 1 FROM contributions WHERE round_id = ? AND org_id = ? "
            "AND accepted = 1 LIMIT 1",
            (round_id, org_id),
        ).fetchone()
        return row is not None

    def get_accepted_models(self, round_id: int) -> list[dict]:
        """
        Accepted contributions for a round joined with the org's current trust
        score, for the aggregation step. Returns org_id, num_examples,
        model_path, model_sha256, trust_score (one row per accepted org).
        """
        rows = self.conn.execute(
            "SELECT c.org_id, c.num_examples, c.model_path, c.model_sha256, "
            "       COALESCE(o.trust_score, 0.5) AS trust_score "
            "FROM contributions c LEFT JOIN orgs o ON o.org_id = c.org_id "
            "WHERE c.round_id = ? AND c.accepted = 1 AND c.model_path IS NOT NULL "
            "ORDER BY c.received_at",
            (round_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_contributions(self, round_id: Optional[int] = None,
                            org_id: Optional[str] = None) -> list[dict]:
        sql = ("SELECT contribution_id, round_id, org_id, received_at, "
                "model_sha256, num_examples, accepted, rejection_reason "
                "FROM contributions WHERE 1=1")
        params: list = []
        if round_id is not None:
            sql += " AND round_id = ?"; params.append(round_id)
        if org_id is not None:
            sql += " AND org_id = ?"; params.append(org_id)
        sql += " ORDER BY received_at DESC"
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def get_org(self, org_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM orgs WHERE org_id = ?", (org_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_orgs(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM orgs ORDER BY enrolled_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def authenticate_org(self, org_id: str, api_key_hash: str) -> Optional[dict]:
        """Return the org row if api_key_hash matches AND status == 'active'."""
        row = self.conn.execute(
            "SELECT * FROM orgs WHERE org_id = ? AND status = 'active'",
            (org_id,),
        ).fetchone()
        if row is None:
            return None
        # Constant-time compare
        import hmac as _hmac
        if not _hmac.compare_digest(row["api_key_hash"], api_key_hash):
            return None
        return dict(row)

    def set_org_status(self, org_id: str, status: str) -> None:
        if status not in {"active", "blocked", "revoked", "leave_pending"}:
            raise ValueError(f"Invalid status: {status}")
        with self._lock:
            self.conn.execute(
                "UPDATE orgs SET status = ? WHERE org_id = ?",
                (status, org_id),
            )
            self.conn.commit()

    def set_leave_request(self, org_id: str, attestation: bytes, signature_hex: str) -> None:
        """Org requested to leave: store the org-signed fl.leave_request.v1
        (non-repudiation) and move the org to 'leave_pending' so it stops being
        invited to rounds while the operator decides. Half of the mutual ack."""
        with self._lock:
            self.conn.execute(
                "UPDATE orgs SET status = 'leave_pending', leave_requested_at = ?, "
                "leave_attestation = ?, leave_signature = ? WHERE org_id = ?",
                (time.time(), attestation, signature_hex, org_id),
            )
            self.conn.commit()

    def set_removal_confirm(self, org_id: str, attestation: bytes, signature_hex: str) -> None:
        """Operator approved removal: store the coordinator-signed
        fl.removal_confirm.v1 so the org can fetch + verify it (via
        GET /orgs/{id}/removal-status) before wiping its local credentials."""
        with self._lock:
            self.conn.execute(
                "UPDATE orgs SET removal_attestation = ?, removal_signature = ? "
                "WHERE org_id = ?",
                (attestation, signature_hex, org_id),
            )
            self.conn.commit()

    def update_org_trust(self, org_id: str, trust_score: float) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE orgs SET trust_score = ?, last_seen_at = ? "
                "WHERE org_id = ?",
                (max(0.0, min(1.0, trust_score)), time.time(), org_id),
            )
            self.conn.commit()

    def get_org_last_accuracy(self, org_id: str) -> Optional[float]:
        """Persisted last-round validation accuracy for the sudden-drop
        poisoning heuristic. None when the org has not been scored yet."""
        row = self.conn.execute(
            "SELECT last_accuracy FROM orgs WHERE org_id = ?", (org_id,),
        ).fetchone()
        return row["last_accuracy"] if row and row["last_accuracy"] is not None else None

    def set_org_last_accuracy(self, org_id: str, accuracy: float) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE orgs SET last_accuracy = ? WHERE org_id = ?",
                (float(accuracy), org_id),
            )
            self.conn.commit()

    # ── Rounds ─────────────────────────────────────────────────────────────

    def start_round(
        self,
        started_by: str,
        params: dict,
        invited_count: int,
    ) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO rounds(started_at, started_by, status, params_json, "
                "num_clients_invited) VALUES (?, ?, 'running', ?, ?)",
                (time.time(), started_by, json.dumps(params), invited_count),
            )
            self.conn.commit()
        return cur.lastrowid

    def set_round_announcement(
        self, round_id: int, attestation: bytes, signature_hex: str,
    ) -> None:
        """Persist the coordinator-signed announcement for a round so invited
        orgs can fetch + verify it (GET /rounds/{id}/announcement)."""
        with self._lock:
            self.conn.execute(
                "UPDATE rounds SET announce_attestation = ?, "
                "announce_signature = ? WHERE round_id = ?",
                (attestation, signature_hex, round_id),
            )
            self.conn.commit()

    def complete_round(
        self,
        round_id: int,
        *,
        status: str,
        responded: int,
        accepted: int,
        rejected: int,
        global_model_hash: Optional[str] = None,
        eval_metrics: Optional[dict] = None,
    ) -> None:
        # completed_at is only meaningful once the round is actually completed
        # (published). For the intermediate 'aggregated' state it stays NULL and
        # is stamped later by set_round_status('completed').
        completed_at = time.time() if status == "completed" else None
        with self._lock:
            self.conn.execute(
                "UPDATE rounds SET completed_at = ?, status = ?, "
                "num_clients_responded = ?, num_clients_accepted = ?, "
                "num_clients_rejected = ?, global_model_hash = ?, "
                "eval_metrics_json = ? WHERE round_id = ?",
                (completed_at, status, responded, accepted, rejected,
                 global_model_hash,
                 json.dumps(eval_metrics) if eval_metrics else None,
                 round_id),
            )
            self.conn.commit()

    def get_round(self, round_id: int) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM rounds WHERE round_id = ?", (round_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["params"] = json.loads(d.pop("params_json") or "{}")
        if d.get("eval_metrics_json"):
            d["eval_metrics"] = json.loads(d.pop("eval_metrics_json"))
        else:
            d.pop("eval_metrics_json", None)
        # Surface the signed announcement as a JSON-safe sub-object; never leak
        # the raw BLOB column (would break JSON serialisation of GET /rounds/{id}).
        ann = d.pop("announce_attestation", None)
        sig = d.pop("announce_signature", None)
        if ann is not None:
            d["round_announcement"] = {
                "signed_attestation": ann.decode("utf-8") if isinstance(ann, (bytes, bytearray)) else ann,
                "signature_hex": sig,
            }
        return d

    def list_rounds(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT round_id, started_at, started_by, completed_at, status, "
            "num_clients_invited, num_clients_responded, num_clients_accepted, "
            "num_clients_rejected, global_model_hash "
            "FROM rounds ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_rounds_by_status(self, status: str) -> list[dict]:
        """Full round dicts (incl. params) for every round in a given status —
        used by org-facing round discovery."""
        rows = self.conn.execute(
            "SELECT round_id FROM rounds WHERE status = ? ORDER BY started_at DESC",
            (status,),
        ).fetchall()
        return [self.get_round(r["round_id"]) for r in rows]

    def set_round_status(self, round_id: int, status: str) -> None:
        # Stamp completed_at when (and only when) the round reaches 'completed'
        # (i.e. its global model is published).
        with self._lock:
            if status == "completed":
                self.conn.execute(
                    "UPDATE rounds SET status = ?, completed_at = ? WHERE round_id = ?",
                    (status, time.time(), round_id),
                )
            else:
                self.conn.execute(
                    "UPDATE rounds SET status = ? WHERE round_id = ?", (status, round_id),
                )
            self.conn.commit()

    # ── Versioned global models (staged -> active -> archived + rollback) ────

    def _gm_row(self, row) -> Optional[dict]:
        if not row:
            return None
        d = dict(row)
        if d.get("eval_metrics_json"):
            d["eval_metrics"] = json.loads(d.pop("eval_metrics_json"))
        else:
            d.pop("eval_metrics_json", None)
        return d

    def stage_global_model(
        self, round_id: int, *, model_hash: str, model_path: str,
        staged_until: float, eval_metrics: Optional[dict] = None,
    ) -> int:
        """Record a freshly-merged global model as a 'staged' version that soaks
        under observation until `staged_until`. Returns its version_id."""
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO global_models(round_id, created_at, staged_until, "
                "status, model_hash, model_path, eval_metrics_json) "
                "VALUES (?, ?, ?, 'staged', ?, ?, ?)",
                (round_id, time.time(), staged_until, model_hash, model_path,
                 json.dumps(eval_metrics) if eval_metrics else None),
            )
            self.conn.commit()
        return cur.lastrowid

    def get_global_model(self, version_id: int) -> Optional[dict]:
        return self._gm_row(self.conn.execute(
            "SELECT * FROM global_models WHERE version_id = ?", (version_id,),
        ).fetchone())

    def get_staged_model_for_round(self, round_id: int) -> Optional[dict]:
        return self._gm_row(self.conn.execute(
            "SELECT * FROM global_models WHERE round_id = ? AND status = 'staged' "
            "ORDER BY created_at DESC LIMIT 1", (round_id,),
        ).fetchone())

    def get_active_global_model(self) -> Optional[dict]:
        return self._gm_row(self.conn.execute(
            "SELECT * FROM global_models WHERE status = 'active' "
            "ORDER BY promoted_at DESC LIMIT 1",
        ).fetchone())

    def promote_global_model(self, version_id: int, promoted_by: str) -> Optional[dict]:
        """Make `version_id` the active (published) global model, archiving the
        previously-active one. Serves both first-publish and rollback. Returns
        the promoted row, or None if the version doesn't exist."""
        with self._lock:
            exists = self.conn.execute(
                "SELECT 1 FROM global_models WHERE version_id = ?", (version_id,),
            ).fetchone()
            if not exists:
                return None
            self.conn.execute(
                "UPDATE global_models SET status = 'archived' WHERE status = 'active'")
            self.conn.execute(
                "UPDATE global_models SET status = 'active', promoted_at = ?, "
                "promoted_by = ? WHERE version_id = ?",
                (time.time(), promoted_by, version_id),
            )
            self.conn.commit()
        return self.get_global_model(version_id)

    def list_global_models(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT version_id, round_id, created_at, staged_until, status, "
            "model_hash, promoted_at, promoted_by FROM global_models "
            "ORDER BY version_id DESC LIMIT ?", (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
