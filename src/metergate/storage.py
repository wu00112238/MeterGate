"""
MeterGate — SQLite Persistent Storage & Local Data Integrity Audit Trail
Implements:
  - M-01 / M-10: Zero commercial paywall, zero license issuance/signing; HMAC-SHA256 is strictly used
    for local SQLite data integrity (tamper-evident audit chain & backup manifest verification).
  - M-02: Single-instance zero-config design (no multi-tenant isolation overhead).
  - M-08: Cost Ledger persistence (`usage_ledger`) with immediate Today & Cumulative spend calculation.
  - M-09 / R8: Daily Agent Behavior Digest & Report Center queries (date history, event filter, pagination).
  - R1: O(1) fast audit chain head/tail status (`get_audit_chain_status_fast`) decoupled from O(N) full scan (`verify_audit_chain`).
  - R2: Batch write transaction context (`batch_write_transaction`) & multi-event batch audit insert (`append_audit_events_batch`).
  - R3: Persistent false-positive allowlist management (`list_allowlist_entries`, `add_allowlist_entry`, `remove_allowlist_entry`).
  - ARC-2: Server-authoritative time source (`_clock`); caller-supplied dates are never accepted for quota calculations.
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import hmac
import io
import json
import math
import os
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from . import __version__

CURRENT_SCHEMA_VERSION = __version__


def resolve_default_state_dir() -> Path:
    env_dir = os.environ.get("METERGATE_STATE_DIR")
    if env_dir:
        base = Path(env_dir).expanduser().resolve()
    else:
        candidate = (Path.home() / ".metergate").resolve()
        candidate.mkdir(parents=True, exist_ok=True)
        probe_db = candidate / ".sqlite_lock_probe.db"
        try:
            conn = sqlite3.connect(str(probe_db), timeout=1.0)
            conn.execute("CREATE TABLE IF NOT EXISTS _p (id INT);")
            conn.close()
            if probe_db.exists():
                probe_db.unlink()
            base = candidate
        except sqlite3.OperationalError:
            import tempfile
            base = (Path(tempfile.gettempdir()) / "metergate_state").resolve()
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def load_or_create_integrity_key(key_path: Path, env_var: str) -> bytes:
    """
    M-10: Generates or loads a local-only random HMAC key strictly for SQLite data integrity
    (tamper-evident audit chain and backup verification). Carries zero authorization/licensing semantics.
    """
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        return env_val.encode("utf-8")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(key_path.parent, 0o700)
    except OSError:
        pass
    if key_path.exists():
        raw = key_path.read_text(encoding="utf-8").strip()
        if len(raw) >= 32:
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
            return raw.encode("utf-8")
    generated = secrets.token_hex(32)
    key_path.write_text(generated + "\n", encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return generated.encode("utf-8")


DEFAULT_STATE_DIR = resolve_default_state_dir()
DEFAULT_DB_PATH = DEFAULT_STATE_DIR / "metergate_state.db"


class MeterGateStorage:
    """Thread-safe, single-instance SQLite persistence layer with HMAC-SHA256 tamper-evident audit trail."""

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        integrity_secret: Optional[str | bytes] = None,
        server_clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if db_path is not None:
            resolved_db = Path(db_path).expanduser().resolve()
            resolved_db.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(resolved_db.parent, 0o700)
            except OSError:
                pass
        else:
            env_db = os.environ.get("METERGATE_DB_PATH", "").strip()
            if env_db:
                resolved_db = Path(env_db).expanduser().resolve()
                resolved_db.parent.mkdir(parents=True, exist_ok=True)
            else:
                resolved_db = resolve_default_state_dir() / "metergate_state.db"

        self.db_path = str(resolved_db)
        self._lock = threading.RLock()
        self._clock: Callable[[], float] = server_clock or time.time
        self._batch_depth = 0
        self._commit_count = 0
        self._audit_head_cache: Optional[Dict[str, Any]] = None

        if integrity_secret is not None:
            self._integrity_key = (
                integrity_secret.encode("utf-8")
                if isinstance(integrity_secret, str)
                else bytes(integrity_secret)
            )
        else:
            key_file = resolved_db.parent / f".{resolved_db.stem}_integrity_hmac.key"
            self._integrity_key = load_or_create_integrity_key(
                key_file, "METERGATE_INTEGRITY_HMAC_SECRET"
            )

        self.integrity_key_path = (
            resolved_db.parent / f".{resolved_db.stem}_integrity_hmac.key"
        )

        self._conn = sqlite3.connect(
            self.db_path, check_same_thread=False, timeout=15.0
        )
        self._conn.row_factory = sqlite3.Row
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass
        self._init_schema()

    def _commit_if_needed(self) -> None:
        """R2: Commits immediately unless inside an active `batch_write_transaction()`."""
        if self._batch_depth <= 0:
            self._conn.commit()
            self._commit_count += 1

    @contextlib.contextmanager
    def batch_write_transaction(self) -> Iterator[None]:
        """
        R2: Re-entrant batch transaction context manager.
        Groups multiple audit events, ledger writes, and structured logs within a single Agent turn
        into one atomic SQLite commit, eliminating redundant fsync/transaction overhead.
        """
        with self._lock:
            self._batch_depth += 1
            try:
                yield
            except Exception:
                if self._batch_depth == 1:
                    self._conn.rollback()
                    self._audit_head_cache = None
                raise
            finally:
                self._batch_depth -= 1
                if self._batch_depth == 0:
                    self._conn.commit()
                    self._commit_count += 1

    def get_commit_count(self) -> int:
        with self._lock:
            return self._commit_count

    def now_epoch(self) -> float:
        """ARC-2: Returns server-authoritative epoch timestamp."""
        return float(self._clock())

    def now_iso(self) -> str:
        """ARC-2: Returns server-authoritative ISO-8601 UTC timestamp."""
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now_epoch()))

    def now_utc_date(self) -> str:
        """ARC-2: Returns server-authoritative UTC natural date (`YYYY-MM-DD`)."""
        return time.strftime("%Y-%m-%d", time.gmtime(self.now_epoch()))

    def _init_schema(self) -> None:
        """Single authoritative schema definition with high-frequency indexes."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("PRAGMA journal_mode=WAL;")
            except sqlite3.OperationalError:
                cur.execute("PRAGMA journal_mode=DELETE;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA busy_timeout=5000;")
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    schema_version TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    description TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    utc_date TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL DEFAULT 'local_agent',
                    mode TEXT NOT NULL,
                    decision_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_log_utc_date_seq
                    ON audit_log(utc_date, seq DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_log_event_type_date
                    ON audit_log(event_type, utc_date, seq DESC);

                CREATE TABLE IF NOT EXISTS usage_ledger (
                    request_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL DEFAULT 'local_agent',
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    utc_date TEXT NOT NULL,
                    selected_model TEXT NOT NULL,
                    baseline_model TEXT NOT NULL,
                    ab_bucket TEXT NOT NULL,
                    estimated_prompt_tokens INTEGER NOT NULL,
                    estimated_completion_tokens INTEGER NOT NULL,
                    estimated_cost_usd REAL NOT NULL,
                    estimated_baseline_cost_usd REAL NOT NULL DEFAULT 0.0,
                    actual_prompt_tokens INTEGER,
                    actual_completion_tokens INTEGER,
                    actual_cached_tokens INTEGER,
                    actual_cost_usd REAL,
                    baseline_actual_cost_usd REAL,
                    reconciled_savings_usd REAL,
                    detection_cost_usd REAL NOT NULL DEFAULT 0.0,
                    latency_ms REAL,
                    gateway_overhead_ms REAL NOT NULL DEFAULT 0.0,
                    task_summary TEXT NOT NULL DEFAULT '',
                    reconciled INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_usage_ledger_utc_date
                    ON usage_ledger(utc_date);
                CREATE INDEX IF NOT EXISTS idx_usage_ledger_session_id
                    ON usage_ledger(session_id);

                CREATE TABLE IF NOT EXISTS model_feedback (
                    model_id TEXT PRIMARY KEY,
                    ema_latency_ms REAL NOT NULL,
                    ema_failure_rate REAL NOT NULL,
                    ema_quality_score REAL NOT NULL,
                    sample_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ephemeral_tokens (
                    token_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL DEFAULT 'local_agent',
                    session_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    status TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    approved_by TEXT,
                    consumed_at REAL
                );

                CREATE TABLE IF NOT EXISTS real_traffic_samples (
                    sample_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL DEFAULT 'local_agent',
                    timestamp TEXT NOT NULL,
                    utc_date TEXT NOT NULL,
                    source_connector TEXT NOT NULL,
                    target_resources_json TEXT NOT NULL,
                    outbound_sinks_json TEXT NOT NULL,
                    sanitized_payload TEXT NOT NULL,
                    observed_risk_level TEXT NOT NULL,
                    observed_confidence REAL NOT NULL,
                    observed_action TEXT NOT NULL,
                    observed_threats_json TEXT NOT NULL,
                    detection_latency_ms REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS structured_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    level TEXT NOT NULL,
                    event TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                """
            )
            ts = self.now_iso()
            schema_hash = hashlib.sha256(
                f"metergate_schema:{CURRENT_SCHEMA_VERSION}".encode("utf-8")
            ).hexdigest()
            cur.execute(
                """
                INSERT OR IGNORE INTO schema_migrations (schema_version, applied_at, checksum, description)
                VALUES (?, ?, ?, ?)
                """,
                (
                    CURRENT_SCHEMA_VERSION,
                    ts,
                    schema_hash,
                    f"MeterGate v{CURRENT_SCHEMA_VERSION} Open-Source Single-Instance Indexed Schema",
                ),
            )
            self._conn.commit()

    def get_schema_version(self) -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT schema_version FROM schema_migrations ORDER BY applied_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
            return str(row["schema_version"]) if row else CURRENT_SCHEMA_VERSION

    def get_system_state(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM system_state WHERE key = ?", (key,)
            ).fetchone()
            return str(row["value"]) if row else default

    def set_system_state(self, key: str, value: str) -> None:
        ts = self.now_iso()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO system_state (key, value, updated_at)
                VALUES (?, ?, ?)
                """,
                (key, value, ts),
            )
            self._commit_if_needed()

    # R3: Persistent False-Positive Allowlist Management
    def list_allowlist_entries(self) -> List[Dict[str, Any]]:
        raw = self.get_system_state("firewall_allowlist_json", default="[]")
        try:
            items = json.loads(raw or "[]")
            return items if isinstance(items, list) else []
        except Exception:
            return []

    def add_allowlist_entry(
        self,
        entry_type: str,
        value: str,
        note: str = "",
    ) -> Dict[str, Any]:
        norm_type = str(entry_type).strip().lower()
        if norm_type not in ("pattern", "payload_sha256", "connector"):
            raise ValueError(
                f"Unsupported allowlist entry_type '{entry_type}'. Must be 'pattern', 'payload_sha256', or 'connector'."
            )
        clean_val = str(value).strip()
        if not clean_val:
            raise ValueError("Allowlist value cannot be empty.")
        with self._lock:
            entries = self.list_allowlist_entries()
            for existing in entries:
                if (
                    existing.get("entry_type") == norm_type
                    and existing.get("value") == clean_val
                ):
                    return existing
            new_item = {
                "entry_id": f"alw_{uuid.uuid4().hex[:10]}",
                "entry_type": norm_type,
                "value": clean_val,
                "note": str(note or "").strip()[:200],
                "created_at": self.now_iso(),
            }
            entries.append(new_item)
            self.set_system_state(
                "firewall_allowlist_json",
                json.dumps(entries, ensure_ascii=False),
            )
            return new_item

    def remove_allowlist_entry(self, entry_id: str) -> bool:
        target_id = str(entry_id).strip()
        with self._lock:
            entries = self.list_allowlist_entries()
            filtered = [e for e in entries if e.get("entry_id") != target_id]
            if len(filtered) == len(entries):
                return False
            self.set_system_state(
                "firewall_allowlist_json",
                json.dumps(filtered, ensure_ascii=False),
            )
            return True

    def consume_first_launch_flag(self) -> bool:
        """
        M-14: Checks if this is the first time MeterGate has been launched on this storage instance.
        Returns True only once and marks `first_launch_completed = true` so the tip/donation prompt
        never bothers the user again.
        """
        with self._lock:
            already = self.get_system_state("first_launch_completed")
            if already == "true":
                return False
            self.set_system_state("first_launch_completed", "true")
            return True

    def get_mode(self, default: str = "enforce") -> str:
        val = self.get_system_state("gateway_mode", default=default)
        return val if val in ("observe", "shadow", "enforce") else default

    def set_mode(self, mode: str) -> str:
        norm = mode.strip().lower()
        if norm not in ("observe", "shadow", "enforce"):
            raise ValueError(f"Unsupported mode '{mode}'")
        self.set_system_state("gateway_mode", norm)
        return norm

    def _compute_entry_hmac(
        self,
        prev_hash: str,
        timestamp: str,
        event_type: str,
        session_id: str,
        agent_id: str,
        mode: str,
        decision_json: str,
    ) -> str:
        canonical = (
            f"{prev_hash}|{timestamp}|{event_type}|{session_id}|{agent_id}|{mode}|{decision_json}"
        )
        return hmac.new(
            self._integrity_key, canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def compute_integrity_digest(self, canonical_str: str) -> str:
        """
        M-10: Computes a local HMAC-SHA256 digest strictly for data tamper-evidence
        (audit evidence exports & backup manifests). Does not represent any license or authorization.
        """
        return hmac.new(
            self._integrity_key, canonical_str.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def append_audit_events_batch(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        R2: Appends multiple audit events to the HMAC-SHA256 hash-chained audit trail
        within a single lock acquisition and a single SQLite commit.
        """
        if not events:
            return []
        with self._lock:
            cur = self._conn.cursor()
            if self._audit_head_cache is not None:
                prev_hash = str(self._audit_head_cache["head_hash"])
                current_total = int(self._audit_head_cache["checked_entries"])
            else:
                row = cur.execute(
                    "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_hash = str(row["entry_hash"]) if row else "0" * 64
                cnt_row = cur.execute("SELECT COUNT(*) AS cnt FROM audit_log").fetchone()
                current_total = int(cnt_row["cnt"]) if cnt_row else 0

            ts_default = self.now_iso()
            day_default = self.now_utc_date()
            results: List[Dict[str, Any]] = []

            for ev in events:
                ts = str(ev.get("timestamp") or ts_default)
                day_str = str(ev.get("utc_date") or day_default)
                event_type = str(ev["event_type"])
                session_id = str(ev.get("session_id", "sess_default"))
                agent_id = str(ev.get("agent_id", "local_agent"))
                mode = str(ev.get("mode", "enforce"))
                decision_payload = ev.get("decision_payload", {})
                decision_json = json.dumps(
                    decision_payload, ensure_ascii=False, sort_keys=True
                )
                entry_hash = self._compute_entry_hmac(
                    prev_hash,
                    ts,
                    event_type,
                    session_id,
                    agent_id,
                    mode,
                    decision_json,
                )
                cur.execute(
                    """
                    INSERT INTO audit_log (timestamp, utc_date, event_type, session_id, agent_id, mode, decision_json, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts,
                        day_str,
                        event_type,
                        session_id,
                        agent_id,
                        mode,
                        decision_json,
                        prev_hash,
                        entry_hash,
                    ),
                )
                seq_val = int(cur.lastrowid or (current_total + 1))
                current_total += 1
                results.append(
                    {
                        "seq": seq_val,
                        "timestamp": ts,
                        "utc_date": day_str,
                        "event_type": event_type,
                        "session_id": session_id,
                        "agent_id": agent_id,
                        "mode": mode,
                        "prev_hash": prev_hash,
                        "entry_hash": entry_hash,
                    }
                )
                prev_hash = entry_hash

            self._commit_if_needed()
            self._audit_head_cache = {
                "valid": True,
                "checked_entries": current_total,
                "head_seq": results[-1]["seq"],
                "head_hash": prev_hash,
                "hmac_protected": True,
                "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                "integrity_purpose": "local_tamper_evident_audit_log",
            }
            return results

    def append_audit_event(
        self,
        event_type: str,
        session_id: str,
        mode: str,
        decision_payload: Dict[str, Any],
        agent_id: str = "local_agent",
    ) -> Dict[str, Any]:
        """Appends an immutable event to the HMAC-SHA256 hash-chained local audit trail."""
        batch_res = self.append_audit_events_batch(
            [
                {
                    "event_type": event_type,
                    "session_id": session_id,
                    "mode": mode,
                    "decision_payload": decision_payload,
                    "agent_id": agent_id,
                }
            ]
        )
        return batch_res[0]

    def get_audit_chain_status_fast(self, tail_limit: int = 2) -> Dict[str, Any]:
        """
        R1: High-frequency O(1) audit chain status check for `/api/v1/status`, `/api/v1/ledger`, and `/healthz`.
        Verifies only the latest `tail_limit` entries and sequence continuity against the head row via primary key index,
        guaranteeing constant O(1) latency even when `audit_log` contains 100,000+ entries.
        Full O(N) chain verification remains in `verify_audit_chain()` for `audit-verify`, `backup`, `restore`, and `evidence`.
        """
        with self._lock:
            tail_rows = self._conn.execute(
                "SELECT seq, timestamp, event_type, session_id, agent_id, mode, decision_json, prev_hash, entry_hash "
                "FROM audit_log ORDER BY seq DESC LIMIT ?",
                (max(1, int(tail_limit)),),
            ).fetchall()
            if not tail_rows:
                return {
                    "valid": True,
                    "checked_entries": 0,
                    "tail_verified_entries": 0,
                    "head_hash": "0" * 64,
                    "hmac_protected": True,
                    "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                    "integrity_purpose": "local_tamper_evident_audit_log",
                }

            head_seq = int(tail_rows[0]["seq"])
            head_hash = str(tail_rows[0]["entry_hash"])
            chronological_tail = list(reversed(tail_rows))

            for idx, r in enumerate(chronological_tail):
                if int(r["seq"]) == 1 and str(r["prev_hash"]) != "0" * 64:
                    return {
                        "valid": False,
                        "checked_entries": head_seq,
                        "broken_at_seq": 1,
                        "reason": "Genesis prev_hash mismatch",
                        "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                    }
                if idx > 0:
                    prev_row = chronological_tail[idx - 1]
                    if int(r["seq"]) != int(prev_row["seq"]) + 1:
                        return {
                            "valid": False,
                            "checked_entries": head_seq,
                            "broken_at_seq": int(r["seq"]),
                            "reason": f"Sequence gap detected in tail (expected {int(prev_row['seq']) + 1}, got {r['seq']})",
                            "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                        }
                    if not hmac.compare_digest(
                        str(r["prev_hash"]), str(prev_row["entry_hash"])
                    ):
                        return {
                            "valid": False,
                            "checked_entries": head_seq,
                            "broken_at_seq": int(r["seq"]),
                            "reason": "prev_hash mismatch in tail window",
                            "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                        }
                recalc = self._compute_entry_hmac(
                    r["prev_hash"],
                    r["timestamp"],
                    r["event_type"],
                    r["session_id"],
                    r["agent_id"],
                    r["mode"],
                    r["decision_json"],
                )
                if not hmac.compare_digest(recalc, str(r["entry_hash"])):
                    return {
                        "valid": False,
                        "checked_entries": head_seq,
                        "broken_at_seq": int(r["seq"]),
                        "reason": "HMAC entry_hash tampering detected in tail window",
                        "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                    }

            status = {
                "valid": True,
                "checked_entries": head_seq,
                "tail_verified_entries": len(chronological_tail),
                "head_seq": head_seq,
                "head_hash": head_hash,
                "hmac_protected": True,
                "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                "integrity_purpose": "local_tamper_evident_audit_log",
            }
            self._audit_head_cache = status
            return status

    def verify_audit_chain(self, expected_min_entries: int = 0) -> Dict[str, Any]:
        """Verifies cryptographic HMAC-SHA256 data integrity of the entire audit log chain (O(N) full scan)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, timestamp, event_type, session_id, agent_id, mode, decision_json, prev_hash, entry_hash FROM audit_log ORDER BY seq ASC"
            ).fetchall()
            if len(rows) < expected_min_entries:
                return {
                    "valid": False,
                    "checked_entries": len(rows),
                    "broken_at_seq": len(rows) + 1,
                    "reason": f"Audit log truncation detected: found {len(rows)} entries, expected >= {expected_min_entries}",
                }
            expected_prev = "0" * 64
            expected_seq = 1
            for r in rows:
                if r["seq"] != expected_seq:
                    return {
                        "valid": False,
                        "checked_entries": len(rows),
                        "broken_at_seq": r["seq"],
                        "reason": f"Sequence gap detected (expected seq {expected_seq}, got {r['seq']})",
                    }
                if not hmac.compare_digest(str(r["prev_hash"]), expected_prev):
                    return {
                        "valid": False,
                        "checked_entries": len(rows),
                        "broken_at_seq": r["seq"],
                        "reason": "prev_hash mismatch",
                    }
                recalc = self._compute_entry_hmac(
                    r["prev_hash"],
                    r["timestamp"],
                    r["event_type"],
                    r["session_id"],
                    r["agent_id"],
                    r["mode"],
                    r["decision_json"],
                )
                if not hmac.compare_digest(recalc, str(r["entry_hash"])):
                    return {
                        "valid": False,
                        "checked_entries": len(rows),
                        "broken_at_seq": r["seq"],
                        "reason": "HMAC entry_hash tampering or forged chain recalculation detected",
                    }
                expected_prev = r["entry_hash"]
                expected_seq += 1

            res = {
                "valid": True,
                "checked_entries": len(rows),
                "head_hash": expected_prev,
                "hmac_protected": True,
                "verification_mode": "FULL_CHAIN_SCAN",
                "integrity_purpose": "local_tamper_evident_audit_log",
            }
            self._audit_head_cache = {
                "valid": True,
                "checked_entries": len(rows),
                "head_seq": len(rows),
                "head_hash": expected_prev,
                "hmac_protected": True,
                "verification_mode": "O1_HEAD_AND_TAIL_SNAPSHOT",
                "integrity_purpose": "local_tamper_evident_audit_log",
            }
            return res

    def list_audit_events(
        self, limit: int = 100, utc_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._lock:
            if utc_date:
                rows = self._conn.execute(
                    "SELECT seq, timestamp, utc_date, event_type, session_id, agent_id, mode, decision_json, prev_hash, entry_hash FROM audit_log WHERE utc_date = ? ORDER BY seq DESC LIMIT ?",
                    (utc_date, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT seq, timestamp, utc_date, event_type, session_id, agent_id, mode, decision_json, prev_hash, entry_hash FROM audit_log ORDER BY seq DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            out = []
            for r in rows:
                out.append(
                    {
                        "seq": r["seq"],
                        "timestamp": r["timestamp"],
                        "utc_date": r["utc_date"],
                        "event_type": r["event_type"],
                        "session_id": r["session_id"],
                        "agent_id": r["agent_id"],
                        "mode": r["mode"],
                        "decision": json.loads(r["decision_json"]),
                        "prev_hash": r["prev_hash"],
                        "entry_hash": r["entry_hash"],
                    }
                )
            return out

    # R8: Report Center Date History, Event Type Filtering, and Pagination
    def list_available_report_dates(self) -> List[Dict[str, Any]]:
        """
        R8: Lists all UTC dates present in `audit_log` or `usage_ledger` (plus today),
        ordered newest first, with per-day turn counts and spend summaries for independent historical lookup.
        """
        today_str = self.now_utc_date()
        with self._lock:
            audit_rows = self._conn.execute(
                "SELECT utc_date, COUNT(*) AS total_events, "
                "SUM(CASE WHEN event_type = 'GATEWAY_TURN_DECISION' THEN 1 ELSE 0 END) AS turn_events "
                "FROM audit_log GROUP BY utc_date ORDER BY utc_date DESC"
            ).fetchall()
            ledger_rows = self._conn.execute(
                "SELECT utc_date, COUNT(*) AS requests, "
                "SUM(CASE WHEN reconciled = 1 AND actual_cost_usd IS NOT NULL THEN actual_cost_usd ELSE estimated_cost_usd END) AS spent_usd "
                "FROM usage_ledger GROUP BY utc_date ORDER BY utc_date DESC"
            ).fetchall()

        date_map: Dict[str, Dict[str, Any]] = {
            today_str: {
                "utc_date": today_str,
                "total_audit_events": 0,
                "turn_events": 0,
                "ledger_requests": 0,
                "spent_usd": 0.0,
            }
        }
        for r in audit_rows:
            d = str(r["utc_date"])
            if d not in date_map:
                date_map[d] = {
                    "utc_date": d,
                    "total_audit_events": 0,
                    "turn_events": 0,
                    "ledger_requests": 0,
                    "spent_usd": 0.0,
                }
            date_map[d]["total_audit_events"] = int(r["total_events"] or 0)
            date_map[d]["turn_events"] = int(r["turn_events"] or 0)

        for r in ledger_rows:
            d = str(r["utc_date"])
            if d not in date_map:
                date_map[d] = {
                    "utc_date": d,
                    "total_audit_events": 0,
                    "turn_events": 0,
                    "ledger_requests": 0,
                    "spent_usd": 0.0,
                }
            date_map[d]["ledger_requests"] = int(r["requests"] or 0)
            date_map[d]["spent_usd"] = round(float(r["spent_usd"] or 0.0), 6)

        return sorted(date_map.values(), key=lambda x: x["utc_date"], reverse=True)

    @staticmethod
    def _matches_report_filter(event: Dict[str, Any], event_filter: str) -> bool:
        flt = (event_filter or "all").strip().lower()
        if flt in ("", "all", "*"):
            return True
        ev_type = str(event.get("event_type", "")).upper()
        dec = event.get("decision", {}) if isinstance(event.get("decision"), dict) else {}
        allowed = bool(dec.get("allowed", True))
        action = str(dec.get("action_taken", "ALLOW")).upper()
        redacted = int(dec.get("redacted_secrets", 0))
        trifecta = bool(dec.get("trifecta_triggered", False))

        if flt == "blocked":
            return (
                ev_type in ("GATEWAY_TURN_DECISION", "BUDGET_HARD_CAP_BLOCKED")
                and (not allowed or action != "ALLOW" or ev_type == "BUDGET_HARD_CAP_BLOCKED")
            )
        if flt == "allowed":
            return ev_type == "GATEWAY_TURN_DECISION" and allowed and action.startswith("ALLOW")
        if flt == "redacted":
            return redacted > 0
        if flt == "trifecta":
            return trifecta
        return ev_type == flt.upper()

    def query_report_events(
        self,
        utc_date: Optional[str] = None,
        event_filter: str = "all",
        page: int = 1,
        page_size: int = 10,
    ) -> Dict[str, Any]:
        """
        R8: Queries historical or current-day audit events with filtering and pagination.
        """
        clean_page = max(1, int(page))
        clean_size = max(1, min(200, int(page_size)))
        with self._lock:
            if utc_date and utc_date.strip() and utc_date.strip().lower() != "all":
                rows = self._conn.execute(
                    "SELECT seq, timestamp, utc_date, event_type, session_id, agent_id, mode, decision_json, prev_hash, entry_hash "
                    "FROM audit_log WHERE utc_date = ? ORDER BY seq DESC",
                    (utc_date.strip(),),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT seq, timestamp, utc_date, event_type, session_id, agent_id, mode, decision_json, prev_hash, entry_hash "
                    "FROM audit_log ORDER BY seq DESC"
                ).fetchall()

        all_events: List[Dict[str, Any]] = []
        for r in rows:
            ev = {
                "seq": r["seq"],
                "timestamp": r["timestamp"],
                "utc_date": r["utc_date"],
                "event_type": r["event_type"],
                "session_id": r["session_id"],
                "agent_id": r["agent_id"],
                "mode": r["mode"],
                "decision": json.loads(r["decision_json"]),
                "prev_hash": r["prev_hash"],
                "entry_hash": r["entry_hash"],
            }
            if self._matches_report_filter(ev, event_filter):
                all_events.append(ev)

        total_count = len(all_events)
        total_pages = max(1, math.ceil(total_count / clean_size)) if total_count > 0 else 1
        effective_page = min(clean_page, total_pages)
        start_idx = (effective_page - 1) * clean_size
        end_idx = start_idx + clean_size
        paged_items = all_events[start_idx:end_idx]

        return {
            "utc_date": utc_date or "all",
            "event_filter": event_filter or "all",
            "page": effective_page,
            "page_size": clean_size,
            "total_count": total_count,
            "total_pages": total_pages,
            "has_prev": effective_page > 1,
            "has_next": effective_page < total_pages,
            "items": paged_items,
            "all_matching_events": all_events,
        }

    def export_audit_csv(self) -> str:
        rows = self.list_audit_events(limit=500)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "seq",
                "timestamp",
                "utc_date",
                "event_type",
                "session_id",
                "agent_id",
                "mode",
                "prev_hash",
                "entry_hash",
                "decision_json",
            ]
        )
        for r in reversed(rows):
            writer.writerow(
                [
                    r["seq"],
                    r["timestamp"],
                    r["utc_date"],
                    r["event_type"],
                    r["session_id"],
                    r["agent_id"],
                    r["mode"],
                    r["prev_hash"],
                    r["entry_hash"],
                    json.dumps(r["decision"], ensure_ascii=False),
                ]
            )
        return buf.getvalue()

    def record_estimated_usage(
        self,
        request_id: str,
        session_id: str,
        selected_model: str,
        baseline_model: str,
        ab_bucket: str,
        estimated_prompt_tokens: int,
        estimated_completion_tokens: int,
        estimated_cost_usd: float,
        detection_cost_usd: float,
        agent_id: str = "local_agent",
        estimated_baseline_cost_usd: float = 0.0,
        gateway_overhead_ms: float = 0.0,
        task_summary: str = "",
    ) -> None:
        """
        ARC-2 & M-08: Records estimated usage using server-authoritative clock (`now_iso` / `now_utc_date`).
        """
        ts = self.now_iso()
        day_str = self.now_utc_date()
        clean_agent = str(agent_id or "local_agent").strip() or "local_agent"
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO usage_ledger (
                    request_id, agent_id, session_id, timestamp, utc_date,
                    selected_model, baseline_model, ab_bucket,
                    estimated_prompt_tokens, estimated_completion_tokens,
                    estimated_cost_usd, estimated_baseline_cost_usd,
                    detection_cost_usd, gateway_overhead_ms, task_summary, reconciled
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    request_id,
                    clean_agent,
                    str(session_id),
                    ts,
                    day_str,
                    selected_model,
                    baseline_model,
                    ab_bucket,
                    estimated_prompt_tokens,
                    estimated_completion_tokens,
                    estimated_cost_usd,
                    estimated_baseline_cost_usd,
                    detection_cost_usd,
                    gateway_overhead_ms,
                    str(task_summary or "")[:200],
                ),
            )
            self._commit_if_needed()

    def backfill_actual_usage(
        self,
        request_id: str,
        actual_prompt_tokens: int,
        actual_completion_tokens: int,
        actual_cached_tokens: int,
        actual_cost_usd: float,
        baseline_actual_cost_usd: float,
        latency_ms: float,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM usage_ledger WHERE request_id = ?", (request_id,)
            ).fetchone()
            if not row:
                return None
            reconciled_savings = round(
                max(0.0, baseline_actual_cost_usd - actual_cost_usd), 6
            )
            self._conn.execute(
                """
                UPDATE usage_ledger
                SET actual_prompt_tokens = ?,
                    actual_completion_tokens = ?,
                    actual_cached_tokens = ?,
                    actual_cost_usd = ?,
                    baseline_actual_cost_usd = ?,
                    reconciled_savings_usd = ?,
                    latency_ms = ?,
                    reconciled = 1
                WHERE request_id = ?
                """,
                (
                    actual_prompt_tokens,
                    actual_completion_tokens,
                    actual_cached_tokens,
                    actual_cost_usd,
                    baseline_actual_cost_usd,
                    reconciled_savings,
                    latency_ms,
                    request_id,
                ),
            )
            self._commit_if_needed()
            updated = self._conn.execute(
                "SELECT * FROM usage_ledger WHERE request_id = ?", (request_id,)
            ).fetchone()
            return dict(updated) if updated else None

    def get_daily_quota_usage(
        self,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        ARC-2 & M-08: Calculates natural UTC day (`YYYY-MM-DD`) spend strictly using
        the server's authoritative clock (`self.now_utc_date()`). Never accepts caller `utc_date`.
        """
        day_str = self.now_utc_date()
        with self._lock:
            if agent_id:
                rows = self._conn.execute(
                    "SELECT * FROM usage_ledger WHERE agent_id = ? AND utc_date = ?",
                    (agent_id, day_str),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM usage_ledger WHERE utc_date = ?",
                    (day_str,),
                ).fetchall()

        spent_usd = 0.0
        tokens_today = 0
        prompt_tokens_today = 0
        completion_tokens_today = 0
        cached_tokens_today = 0
        for r in rows:
            if r["reconciled"] == 1 and r["actual_cost_usd"] is not None:
                spent_usd += float(r["actual_cost_usd"])
                p = int(r["actual_prompt_tokens"] or 0)
                c = int(r["actual_completion_tokens"] or 0)
                ca = int(r["actual_cached_tokens"] or 0)
                prompt_tokens_today += p
                completion_tokens_today += c
                cached_tokens_today += ca
                tokens_today += p + c
            else:
                spent_usd += float(r["estimated_cost_usd"] or 0.0)
                p = int(r["estimated_prompt_tokens"] or 0)
                c = int(r["estimated_completion_tokens"] or 0)
                prompt_tokens_today += p
                completion_tokens_today += c
                tokens_today += p + c

        return {
            "agent_id": agent_id,
            "utc_date": day_str,
            "requests_today": len(rows),
            "tokens_today": tokens_today,
            "prompt_tokens_today": prompt_tokens_today,
            "completion_tokens_today": completion_tokens_today,
            "cached_tokens_today": cached_tokens_today,
            "daily_spent_usd": round(spent_usd, 6),
        }

    def get_session_spend_usd(self, session_id: str) -> Dict[str, Any]:
        """ARC-4: Computes cumulative spend for a specific session_id."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM usage_ledger WHERE session_id = ?",
                (session_id,),
            ).fetchall()
        spent = 0.0
        for r in rows:
            if r["reconciled"] == 1 and r["actual_cost_usd"] is not None:
                spent += float(r["actual_cost_usd"])
            else:
                spent += float(r["estimated_cost_usd"] or 0.0)
        return {
            "session_id": session_id,
            "turns_count": len(rows),
            "session_spent_usd": round(spent, 6),
        }

    def get_usage_summary(
        self,
        agent_id: Optional[str] = None,
        target_utc_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        M-08 & R8: One-screen Cost Ledger summary returning target/Today's spend, Total cumulative spend,
        per-model cost breakdown, and recent ledger entries.
        """
        day_str = (
            target_utc_date.strip()
            if (target_utc_date and target_utc_date.strip())
            else self.now_utc_date()
        )
        with self._lock:
            if agent_id:
                rows = self._conn.execute(
                    "SELECT * FROM usage_ledger WHERE agent_id = ? ORDER BY timestamp DESC, rowid DESC",
                    (agent_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM usage_ledger ORDER BY timestamp DESC, rowid DESC"
                ).fetchall()

        total_requests = len(rows)
        reconciled_rows = [r for r in rows if r["reconciled"] == 1]
        reconciled_count = len(reconciled_rows)
        unreconciled_count = total_requests - reconciled_count
        total_estimated_usd = round(
            sum(r["estimated_cost_usd"] or 0.0 for r in rows), 6
        )
        total_estimated_baseline_usd = round(
            sum(r["estimated_baseline_cost_usd"] or 0.0 for r in rows), 6
        )
        total_actual_usd = round(
            sum((r["actual_cost_usd"] or 0.0) for r in reconciled_rows), 6
        )
        total_baseline_usd = round(
            sum((r["baseline_actual_cost_usd"] or 0.0) for r in reconciled_rows), 6
        )
        total_reconciled_savings_usd = round(
            sum((r["reconciled_savings_usd"] or 0.0) for r in reconciled_rows), 6
        )

        today_cost_usd = 0.0
        today_actual_reconciled_usd = 0.0
        today_estimated_unreconciled_usd = 0.0
        today_reconciled_requests = 0
        today_estimated_requests = 0
        today_baseline_usd = 0.0
        today_requests = 0
        today_tokens = 0
        today_prompt_tokens = 0
        today_completion_tokens = 0
        today_cached_tokens = 0
        total_tokens = 0
        total_prompt_tokens = 0
        total_completion_tokens = 0
        total_cached_tokens = 0
        total_estimated_unreconciled_usd = 0.0
        model_breakdown: Dict[str, Dict[str, Any]] = {}
        day_model_breakdown: Dict[str, Dict[str, Any]] = {}

        for r in rows:
            is_rec = bool(r["reconciled"] == 1 and r["actual_cost_usd"] is not None)
            eff_cost = (
                float(r["actual_cost_usd"])
                if is_rec
                else float(r["estimated_cost_usd"] or 0.0)
            )
            if not is_rec:
                total_estimated_unreconciled_usd += eff_cost
            eff_base = (
                float(r["baseline_actual_cost_usd"])
                if r["reconciled"] == 1 and r["baseline_actual_cost_usd"] is not None
                else float(r["estimated_baseline_cost_usd"] or 0.0)
            )
            p_tok = (
                int(r["actual_prompt_tokens"])
                if r["reconciled"] == 1 and r["actual_prompt_tokens"] is not None
                else int(r["estimated_prompt_tokens"] or 0)
            )
            c_tok = (
                int(r["actual_completion_tokens"])
                if r["reconciled"] == 1 and r["actual_completion_tokens"] is not None
                else int(r["estimated_completion_tokens"] or 0)
            )
            cached_tok = (
                int(r["actual_cached_tokens"])
                if r["reconciled"] == 1 and r["actual_cached_tokens"] is not None
                else 0
            )
            row_tokens = p_tok + c_tok
            total_tokens += row_tokens
            total_prompt_tokens += p_tok
            total_completion_tokens += c_tok
            total_cached_tokens += cached_tok

            m_id = str(r["selected_model"])
            if m_id not in model_breakdown:
                model_breakdown[m_id] = {
                    "model_id": m_id,
                    "calls": 0,
                    "reconciled_calls": 0,
                    "estimated_calls": 0,
                    "tokens": 0,
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "cached_tokens": 0,
                    "reconciled_prompt_tokens": 0,
                    "reconciled_completion_tokens": 0,
                    "reconciled_cached_tokens": 0,
                    "estimated_prompt_tokens": 0,
                    "estimated_completion_tokens": 0,
                    "cost_usd": 0.0,
                    "actual_reconciled_usd": 0.0,
                    "estimated_unreconciled_usd": 0.0,
                }
            model_breakdown[m_id]["calls"] += 1
            model_breakdown[m_id]["tokens"] += row_tokens
            model_breakdown[m_id]["prompt_tokens"] += p_tok
            model_breakdown[m_id]["completion_tokens"] += c_tok
            model_breakdown[m_id]["cached_tokens"] += cached_tok
            model_breakdown[m_id]["cost_usd"] = round(
                model_breakdown[m_id]["cost_usd"] + eff_cost, 6
            )
            if is_rec:
                model_breakdown[m_id]["reconciled_calls"] += 1
                model_breakdown[m_id]["reconciled_prompt_tokens"] += p_tok
                model_breakdown[m_id]["reconciled_completion_tokens"] += c_tok
                model_breakdown[m_id]["reconciled_cached_tokens"] += cached_tok
                model_breakdown[m_id]["actual_reconciled_usd"] = round(
                    model_breakdown[m_id]["actual_reconciled_usd"] + eff_cost, 6
                )
            else:
                model_breakdown[m_id]["estimated_calls"] += 1
                model_breakdown[m_id]["estimated_prompt_tokens"] += p_tok
                model_breakdown[m_id]["estimated_completion_tokens"] += c_tok
                model_breakdown[m_id]["estimated_unreconciled_usd"] = round(
                    model_breakdown[m_id]["estimated_unreconciled_usd"] + eff_cost, 6
                )

            if r["utc_date"] == day_str:
                today_cost_usd += eff_cost
                if is_rec:
                    today_actual_reconciled_usd += eff_cost
                    today_reconciled_requests += 1
                else:
                    today_estimated_unreconciled_usd += eff_cost
                    today_estimated_requests += 1
                today_baseline_usd += eff_base
                today_requests += 1
                today_tokens += row_tokens
                today_prompt_tokens += p_tok
                today_completion_tokens += c_tok
                today_cached_tokens += cached_tok
                if m_id not in day_model_breakdown:
                    day_model_breakdown[m_id] = {
                        "model_id": m_id,
                        "calls": 0,
                        "reconciled_calls": 0,
                        "estimated_calls": 0,
                        "tokens": 0,
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "cached_tokens": 0,
                        "reconciled_prompt_tokens": 0,
                        "reconciled_completion_tokens": 0,
                        "reconciled_cached_tokens": 0,
                        "estimated_prompt_tokens": 0,
                        "estimated_completion_tokens": 0,
                        "cost_usd": 0.0,
                        "actual_reconciled_usd": 0.0,
                        "estimated_unreconciled_usd": 0.0,
                    }
                day_model_breakdown[m_id]["calls"] += 1
                day_model_breakdown[m_id]["tokens"] += row_tokens
                day_model_breakdown[m_id]["prompt_tokens"] += p_tok
                day_model_breakdown[m_id]["completion_tokens"] += c_tok
                day_model_breakdown[m_id]["cached_tokens"] += cached_tok
                day_model_breakdown[m_id]["cost_usd"] = round(
                    day_model_breakdown[m_id]["cost_usd"] + eff_cost, 6
                )
                if is_rec:
                    day_model_breakdown[m_id]["reconciled_calls"] += 1
                    day_model_breakdown[m_id]["reconciled_prompt_tokens"] += p_tok
                    day_model_breakdown[m_id]["reconciled_completion_tokens"] += c_tok
                    day_model_breakdown[m_id]["reconciled_cached_tokens"] += cached_tok
                    day_model_breakdown[m_id]["actual_reconciled_usd"] = round(
                        day_model_breakdown[m_id]["actual_reconciled_usd"] + eff_cost, 6
                    )
                else:
                    day_model_breakdown[m_id]["estimated_calls"] += 1
                    day_model_breakdown[m_id]["estimated_prompt_tokens"] += p_tok
                    day_model_breakdown[m_id]["estimated_completion_tokens"] += c_tok
                    day_model_breakdown[m_id]["estimated_unreconciled_usd"] = round(
                        day_model_breakdown[m_id]["estimated_unreconciled_usd"] + eff_cost, 6
                    )

        effective_cost_usd = round(
            sum(
                (
                    float(r["actual_cost_usd"])
                    if r["reconciled"] == 1 and r["actual_cost_usd"] is not None
                    else float(r["estimated_cost_usd"] or 0.0)
                )
                for r in rows
            ),
            6,
        )
        effective_baseline_cost_usd = round(
            sum(
                (
                    float(r["baseline_actual_cost_usd"])
                    if r["reconciled"] == 1 and r["baseline_actual_cost_usd"] is not None
                    else float(r["estimated_baseline_cost_usd"] or 0.0)
                )
                for r in rows
            ),
            6,
        )
        effective_savings_usd = round(
            max(0.0, effective_baseline_cost_usd - effective_cost_usd), 6
        )
        effective_savings_pct = (
            round((effective_savings_usd / effective_baseline_cost_usd) * 100.0, 2)
            if effective_baseline_cost_usd > 0
            else 0.0
        )
        today_savings_usd = round(max(0.0, today_baseline_usd - today_cost_usd), 6)

        total_detection_cost_usd = round(
            sum(r["detection_cost_usd"] or 0.0 for r in rows), 6
        )

        recent_list = []
        for r in rows[:20]:
            d = dict(r)
            is_r = bool(d.get("reconciled") == 1 and d.get("actual_cost_usd") is not None)
            d["cost_source"] = "ACTUAL_BILLABLE" if is_r else "ESTIMATED_ONLY"
            d["cost_label_zh"] = "真实对账金额 (Actual)" if is_r else "预估金额 [估算/Estimated]"
            d["effective_row_cost_usd"] = round(
                float(d["actual_cost_usd"]) if is_r else float(d.get("estimated_cost_usd") or 0.0),
                6,
            )
            p_tok_r = (
                int(d.get("actual_prompt_tokens"))
                if is_r and d.get("actual_prompt_tokens") is not None
                else int(d.get("estimated_prompt_tokens") or 0)
            )
            c_tok_r = (
                int(d.get("actual_completion_tokens"))
                if is_r and d.get("actual_completion_tokens") is not None
                else int(d.get("estimated_completion_tokens") or 0)
            )
            cached_tok_r = (
                int(d.get("actual_cached_tokens") or 0)
                if is_r
                else 0
            )
            d["prompt_tokens"] = p_tok_r
            d["completion_tokens"] = c_tok_r
            d["cached_tokens"] = cached_tok_r
            d["total_tokens"] = p_tok_r + c_tok_r
            recent_list.append(d)

        return {
            "utc_date": day_str,
            "today_requests": today_requests,
            "today_reconciled_requests": today_reconciled_requests,
            "today_estimated_requests": today_estimated_requests,
            "today_tokens": today_tokens,
            "today_prompt_tokens": today_prompt_tokens,
            "today_completion_tokens": today_completion_tokens,
            "today_cached_tokens": today_cached_tokens,
            "today_cost_usd": round(today_cost_usd, 6),
            "today_actual_reconciled_cost_usd": round(today_actual_reconciled_usd, 6),
            "today_estimated_unreconciled_cost_usd": round(today_estimated_unreconciled_usd, 6),
            "total_actual_reconciled_cost_usd": total_actual_usd,
            "total_estimated_unreconciled_cost_usd": round(total_estimated_unreconciled_usd, 6),
            "today_baseline_cost_usd": round(today_baseline_usd, 6),
            "today_savings_usd": today_savings_usd,
            "total_requests": total_requests,
            "total_tokens": total_tokens,
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "total_cached_tokens": total_cached_tokens,
            "reconciled_requests": reconciled_count,
            "pending_reconciliation_requests": unreconciled_count,
            "total_estimated_cost_usd": total_estimated_usd,
            "total_estimated_baseline_cost_usd": total_estimated_baseline_usd,
            "total_actual_cost_usd": total_actual_usd,
            "total_baseline_cost_usd": total_baseline_usd,
            "total_reconciled_savings_usd": total_reconciled_savings_usd,
            "effective_cost_usd": effective_cost_usd,
            "effective_baseline_cost_usd": effective_baseline_cost_usd,
            "effective_savings_usd": effective_savings_usd,
            "effective_savings_pct": effective_savings_pct,
            "total_detection_cost_usd": total_detection_cost_usd,
            "model_breakdown": list(model_breakdown.values()),
            "day_model_breakdown": list(day_model_breakdown.values()),
            "recent_ledger": recent_list,
        }

    def update_model_feedback(
        self,
        model_id: str,
        latency_ms: float,
        failed: bool,
        quality_score: float,
        default_latency: float = 150.0,
        default_quality: float = 0.92,
    ) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM model_feedback WHERE model_id = ?", (model_id,)
            ).fetchone()
            alpha = 0.3
            fail_val = 1.0 if failed else 0.0
            if not row:
                ema_lat = latency_ms if latency_ms > 0 else default_latency
                ema_fail = fail_val
                ema_qual = quality_score
                count = 1
            else:
                ema_lat = round(
                    (1 - alpha) * row["ema_latency_ms"] + alpha * latency_ms, 2
                )
                ema_fail = round(
                    (1 - alpha) * row["ema_failure_rate"] + alpha * fail_val, 4
                )
                ema_qual = round(
                    (1 - alpha) * row["ema_quality_score"] + alpha * quality_score, 4
                )
                count = row["sample_count"] + 1
            ts = self.now_iso()
            self._conn.execute(
                """
                INSERT OR REPLACE INTO model_feedback
                (model_id, ema_latency_ms, ema_failure_rate, ema_quality_score, sample_count, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (model_id, ema_lat, ema_fail, ema_qual, count, ts),
            )
            self._commit_if_needed()
            return {
                "model_id": model_id,
                "ema_latency_ms": ema_lat,
                "ema_failure_rate": ema_fail,
                "ema_quality_score": ema_qual,
                "sample_count": count,
            }

    def get_model_feedback(self, model_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM model_feedback WHERE model_id = ?", (model_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_model_feedback(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM model_feedback ORDER BY model_id ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def save_ephemeral_token(
        self,
        token_id: str,
        session_id: str,
        scope: str,
        status: str,
        signature: str,
        created_at: float,
        expires_at: float,
        agent_id: str = "local_agent",
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO ephemeral_tokens
                (token_id, agent_id, session_id, scope, status, signature, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    agent_id,
                    session_id,
                    scope,
                    status,
                    signature,
                    created_at,
                    expires_at,
                ),
            )
            self._commit_if_needed()

    def get_ephemeral_token(self, token_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ephemeral_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_ephemeral_token_status(
        self,
        token_id: str,
        status: str,
        approved_by: Optional[str] = None,
        consumed_at: Optional[float] = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE ephemeral_tokens
                SET status = ?,
                    approved_by = COALESCE(?, approved_by),
                    consumed_at = COALESCE(?, consumed_at)
                WHERE token_id = ?
                """,
                (
                    status,
                    approved_by,
                    consumed_at,
                    token_id,
                ),
            )
            self._commit_if_needed()

    def record_real_traffic_sample(
        self,
        sample_id: str,
        agent_id: str,
        source_connector: str,
        target_resources: List[str],
        outbound_sinks: List[str],
        sanitized_payload: str,
        observed_risk_level: str,
        observed_confidence: float,
        observed_action: str,
        observed_threats: List[str],
        detection_latency_ms: float,
        max_retained: int = 500,
    ) -> Dict[str, Any]:
        ts = self.now_iso()
        day_str = self.now_utc_date()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO real_traffic_samples (
                    sample_id, agent_id, timestamp, utc_date, source_connector,
                    target_resources_json, outbound_sinks_json, sanitized_payload,
                    observed_risk_level, observed_confidence, observed_action,
                    observed_threats_json, detection_latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample_id,
                    agent_id,
                    ts,
                    day_str,
                    source_connector,
                    json.dumps(target_resources, ensure_ascii=False),
                    json.dumps(outbound_sinks, ensure_ascii=False),
                    sanitized_payload,
                    observed_risk_level,
                    observed_confidence,
                    observed_action,
                    json.dumps(observed_threats, ensure_ascii=False),
                    detection_latency_ms,
                ),
            )
            if max_retained > 0:
                self._conn.execute(
                    """
                    DELETE FROM real_traffic_samples
                    WHERE rowid NOT IN (
                        SELECT rowid FROM real_traffic_samples
                        ORDER BY rowid DESC
                        LIMIT ?
                    )
                    """,
                    (max_retained,),
                )
            self._commit_if_needed()
        return {
            "sample_id": sample_id,
            "agent_id": agent_id,
            "timestamp": ts,
            "utc_date": day_str,
            "source_connector": source_connector,
            "target_resources": target_resources,
            "outbound_sinks": outbound_sinks,
            "sanitized_payload": sanitized_payload,
            "observed_risk_level": observed_risk_level,
            "observed_confidence": observed_confidence,
            "observed_action": observed_action,
            "observed_threats": observed_threats,
            "detection_latency_ms": detection_latency_ms,
        }

    def list_real_traffic_samples(
        self, limit: int = 500, utc_date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._lock:
            if utc_date:
                rows = self._conn.execute(
                    "SELECT * FROM real_traffic_samples WHERE utc_date = ? ORDER BY rowid ASC LIMIT ?",
                    (utc_date, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM real_traffic_samples ORDER BY rowid ASC LIMIT ?",
                    (limit,),
                ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["target_resources"] = json.loads(d.pop("target_resources_json", "[]"))
            d["outbound_sinks"] = json.loads(d.pop("outbound_sinks_json", "[]"))
            d["observed_threats"] = json.loads(d.pop("observed_threats_json", "[]"))
            out.append(d)
        return out

    def append_structured_log(
        self,
        request_id: str,
        level: str,
        event: str,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        ts = self.now_iso()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO structured_logs (timestamp, request_id, level, event, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    request_id,
                    level.upper(),
                    event,
                    json.dumps(details, ensure_ascii=False, sort_keys=True),
                ),
            )
            self._commit_if_needed()
            return {
                "log_id": cur.lastrowid,
                "timestamp": ts,
                "request_id": request_id,
                "level": level.upper(),
                "event": event,
                "details": details,
            }

    def list_structured_logs(
        self,
        request_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            if request_id:
                rows = self._conn.execute(
                    "SELECT * FROM structured_logs WHERE request_id = ? ORDER BY log_id DESC LIMIT ?",
                    (request_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM structured_logs ORDER BY log_id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json", "{}"))
            out.append(d)
        return out

    def create_backup(self, backup_path: Path | str) -> Dict[str, Any]:
        target = Path(backup_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            chain_check = self.verify_audit_chain()
            if not chain_check["valid"]:
                raise RuntimeError(
                    f"Refused to backup corrupted audit chain: {chain_check.get('reason')}"
                )
            bck_conn = sqlite3.connect(str(target))
            try:
                self._conn.backup(bck_conn)
            finally:
                bck_conn.close()
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass

        bck_bytes = target.read_bytes()
        file_sha256 = hashlib.sha256(bck_bytes).hexdigest()
        manifest_body = {
            "backup_version": CURRENT_SCHEMA_VERSION,
            "created_at": self.now_iso(),
            "backup_file": target.name,
            "file_size_bytes": len(bck_bytes),
            "file_sha256": file_sha256,
            "audit_chain_entries": chain_check["checked_entries"],
            "audit_head_hash": chain_check["head_hash"],
            "schema_version": self.get_schema_version(),
        }
        canonical_manifest = json.dumps(
            manifest_body, ensure_ascii=False, sort_keys=True
        )
        seal_hmac = self.compute_integrity_digest(canonical_manifest)
        manifest = {
            "manifest": manifest_body,
            "integrity_seal_hmac": seal_hmac,
        }
        manifest_path = Path(f"{target}.manifest.json")
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return {
            "status": "BACKUP_CREATED",
            "backup_path": str(target),
            "manifest_path": str(manifest_path),
            "file_sha256": file_sha256,
            "audit_chain_entries": chain_check["checked_entries"],
            "audit_head_hash": chain_check["head_hash"],
            "integrity_seal_hmac": seal_hmac,
        }

    def verify_backup(self, backup_path: Path | str) -> Dict[str, Any]:
        target = Path(backup_path).expanduser().resolve()
        if not target.exists():
            return {"valid": False, "reason": f"Backup file not found: {target}"}
        manifest_path = Path(f"{target}.manifest.json")
        file_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()

        if manifest_path.exists():
            try:
                m_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
                m_body = m_obj.get("manifest", {})
                expected_seal = self.compute_integrity_digest(
                    json.dumps(m_body, ensure_ascii=False, sort_keys=True)
                )
                if not hmac.compare_digest(
                    str(m_obj.get("integrity_seal_hmac", "")), expected_seal
                ):
                    return {
                        "valid": False,
                        "reason": "Backup manifest integrity HMAC mismatch",
                    }
                if m_body.get("file_sha256") != file_sha256:
                    return {
                        "valid": False,
                        "reason": "Backup file SHA-256 digest does not match manifest",
                    }
            except Exception as exc:
                return {"valid": False, "reason": f"Invalid backup manifest: {exc}"}

        temp_storage = MeterGateStorage(
            db_path=target,
            integrity_secret=self._integrity_key,
            server_clock=self._clock,
        )
        chain_check = temp_storage.verify_audit_chain()
        temp_storage._conn.close()
        if not chain_check["valid"]:
            return {
                "valid": False,
                "reason": f"Backup internal audit chain invalid: {chain_check.get('reason')}",
            }
        return {
            "valid": True,
            "backup_path": str(target),
            "file_sha256": file_sha256,
            "checked_entries": chain_check["checked_entries"],
            "head_hash": chain_check["head_hash"],
        }

    def restore_backup(self, backup_path: Path | str) -> Dict[str, Any]:
        verif = self.verify_backup(backup_path)
        if not verif["valid"]:
            raise ValueError(
                f"Refused to restore invalid or tampered backup: {verif.get('reason')}"
            )
        target = Path(backup_path).expanduser().resolve()
        with self._lock:
            src_conn = sqlite3.connect(str(target))
            try:
                src_conn.backup(self._conn)
            finally:
                src_conn.close()
            self._audit_head_cache = None
            post_check = self.verify_audit_chain()
            if not post_check["valid"]:
                raise RuntimeError(
                    f"Post-restore audit verification failed: {post_check.get('reason')}"
                )
        return {
            "status": "BACKUP_RESTORED",
            "restored_from": str(target),
            "checked_entries": post_check["checked_entries"],
            "head_hash": post_check["head_hash"],
            "valid": True,
        }

    def clean_all_local_state(self) -> Dict[str, Any]:
        """
        B6: Zero-residue cleanup helper. Closes SQLite connection and removes local DB,
        WAL/SHM journals, and integrity HMAC key files so uninstall/reset leaves zero footprint.
        """
        removed_files: List[str] = []
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
            db_p = Path(self.db_path)
            candidates = [
                db_p,
                Path(f"{self.db_path}-wal"),
                Path(f"{self.db_path}-shm"),
                self.integrity_key_path,
            ]
            for fp in candidates:
                if fp.exists():
                    try:
                        fp.unlink()
                        removed_files.append(str(fp))
                    except OSError:
                        pass
            self._audit_head_cache = None
        return {
            "status": "CLEANED_ZERO_RESIDUE",
            "removed_files": removed_files,
        }
