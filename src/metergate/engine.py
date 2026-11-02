"""
MeterGate — Open-Source AI Agent Security Firewall, Cost Ledger & Behavior Digest Engine
Implements:
  - M-01: Zero commercial paywall, zero license/trial/entitlement/value-report/metering-export/402 gates.
  - M-02: Single-instance zero-config design (zero multi-tenant isolation overhead).
  - M-07 & R3: Headline ThreeTierFirewall:
      * Tier 1: Deterministic Regex + Secret Vault Redaction (`[REDACTED_BY_METERGATE_VAULT]`)
      * Tier 2: Heuristic Concept-Cluster & N-gram Similarity Scorer (transparently documented as heuristic, with allowlist & ephemeral bypass)
      * Tier 3: Lethal Trifecta Taint & Ephemeral One-Time Approval
  - R2: Atomic single-transaction turn persistence (`batch_write_transaction` + `append_audit_events_batch`).
  - R5: Regex ReDoS Guard (`RegexSafetyGuard`) rejecting nested quantifiers, backreferences, and unbounded catastrophic backtracking at rule load time.
  - M-08: One-screen Cost Ledger (`get_cost_ledger_summary`: Today's spend, Total cumulative spend, Model breakdown).
  - M-09 & R8: Daily Agent Behavior Digest & Report Center (`generate_daily_agent_report`: date history, event filtering, pagination).
  - M-10 & R1: Local HMAC-SHA256 used strictly for SQLite audit chain and backup data integrity, with O(1) fast head/tail verification on hot paths.
  - M-11: Unified `MeterGate` single identity across package, classes, headers, env vars, and banners.
"""

from __future__ import annotations

import base64
import collections
import copy
import dataclasses
import hashlib
import hmac
import json
import math
import os
import re
import resource
import stat
import statistics
import threading
import time
import tracemalloc
import unicodedata
import urllib.parse
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Counter as CounterType, Deque, Dict, List, Optional, Pattern, Tuple

from . import __project__, __version__
from .storage import (
    CURRENT_SCHEMA_VERSION,
    MeterGateStorage,
    load_or_create_integrity_key,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = Path(__file__).resolve().parent / "config"
DEFAULT_POLICY_PATH = CONFIG_DIR / "default_policy.json"
DEFAULT_CATALOG_PATH = CONFIG_DIR / "model_catalog.json"


class BudgetCapExceededError(RuntimeError):
    """
    ARC-4: Raised when a single request or session exceeds configured hard budget constraints.
    Returns HTTP 429 (budget_hard_cap_exceeded) — never HTTP 402 paywall.
    """

    def __init__(
        self, message: str, budget_details: Dict[str, Any], status_code: int = 429
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = "budget_hard_cap_exceeded"
        self.budget_details = budget_details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": str(self),
            "error_code": self.error_code,
            "reason_code": "BLOCK_BUDGET_CAP_EXCEEDED",
            "status_code": self.status_code,
            "what_happened_zh": f"本次请求预估费用或会话累计花费超出硬预算上限 ({self})。",
            "what_to_do_zh": "请先调用 GET /api/v1/budget 查看剩余预算与推荐的低成本降级模型（如 gpt-4o-mini 或 deepseek-chat），或在配置中调高预算上限。切勿原样死循环重试。",
            "what_happened_en": f"Estimated request or session spend exceeded the configured hard budget cap ({self}).",
            "what_to_do_en": "Query GET /api/v1/budget before retrying and switch to a lower-cost model (e.g., gpt-4o-mini or deepseek-chat). Do not retry identically.",
            "remediation": {
                "retry_without_modification_will_succeed": False,
                "recommended_agent_action": "SWITCH_TO_LOWER_COST_MODEL",
                "preflight_budget_endpoint": "/api/v1/budget",
                "recommended_downgrade_models": ["gpt-4o-mini", "deepseek-chat"],
            },
            "budget": self.budget_details,
        }


class UnsafeRegexPatternError(ValueError):
    """R5: Raised when a firewall regex rule contains catastrophic backtracking (ReDoS) hazards."""


class RegexSafetyGuard:
    """
    R5: Static admission validator & bounded-window execution guard preventing Regular Expression
    Denial of Service (ReDoS) across hot-reloaded firewall rules.
    Rejects:
      1. Patterns exceeding `max_pattern_length` (default 512 chars).
      2. Backreferences (`\\1` .. `\\9`) which require NP-hard backtracking.
      3. Nested quantifiers (e.g., `(a+)+`, `(a*)*`, `(\\w+)+`, `(.+)*`, `(?:[a-z]+)+`, `(a|b+)+`).
      4. Overlapping repeated alternation groups (e.g., `(a|a)+`, `(.*|.+)+`).
      5. Unbounded adjacent repeating wildcards (`.*.*.*`).
    """

    MAX_PATTERN_LENGTH = 512
    MAX_SCAN_WINDOW_CHARS = 16384
    _compiled_cache: Dict[str, Pattern[str]] = {}
    _cache_lock = threading.Lock()

    @classmethod
    def check_pattern_safety(
        cls,
        pattern: str,
        max_length: int = MAX_PATTERN_LENGTH,
    ) -> Tuple[bool, str]:
        if not isinstance(pattern, str) or not pattern.strip():
            return False, "Empty regex pattern"
        if len(pattern) > max_length:
            return (
                False,
                f"Pattern length ({len(pattern)}) exceeds maximum allowed length ({max_length})",
            )

        # 1. Reject backreferences (\1 .. \9)
        if re.search(r"(?<!\\)\\[1-9]", pattern):
            return False, "Backreferences (\\1..\\9) are forbidden due to ReDoS risk"

        # 2. Reject lookbehind/lookahead containing unbounded quantifiers
        if re.search(r"\(\?[<=!][^)]*[*+][^)]*\)\s*[*+{]", pattern):
            return False, "Quantified lookaround group detected"

        # 3. Structural walk for nested quantifiers: group containing (*, +, {m,}) followed by (*, +, {m,})
        group_stack: List[Dict[str, Any]] = []
        i = 0
        n = len(pattern)
        in_char_class = False

        while i < n:
            ch = pattern[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "[" and not in_char_class:
                in_char_class = True
                i += 1
                continue
            if ch == "]" and in_char_class:
                in_char_class = False
                i += 1
                continue
            if in_char_class:
                i += 1
                continue

            if ch == "(":
                group_stack.append(
                    {
                        "has_unbounded_quantifier": False,
                        "branches": [[]],
                    }
                )
                i += 1
                continue

            if ch == "|" and group_stack:
                group_stack[-1]["branches"].append([])
                i += 1
                continue

            if ch == ")" and group_stack:
                closed_group = group_stack.pop()
                # Check if followed by a repetition quantifier: +, *, or {m,n}
                j = i + 1
                followed_by_quantifier = False
                is_unbounded_outer = False
                if j < n and pattern[j] in ("+", "*"):
                    followed_by_quantifier = True
                    is_unbounded_outer = True
                elif j < n and pattern[j] == "{":
                    m_brace = re.match(r"\{(\d+)(?:,(\d*))?\}", pattern[j:])
                    if m_brace:
                        min_rep = int(m_brace.group(1))
                        max_rep_str = m_brace.group(2)
                        if max_rep_str is None:
                            if min_rep >= 4:
                                followed_by_quantifier = True
                        elif max_rep_str == "" or int(max_rep_str) >= 4:
                            followed_by_quantifier = True
                            if max_rep_str == "":
                                is_unbounded_outer = True

                if followed_by_quantifier:
                    if closed_group["has_unbounded_quantifier"]:
                        return (
                            False,
                            "Nested quantifier detected (group with inner repetition quantifier is itself repeated)",
                        )
                    # Check overlapping identical branches inside a repeated group: e.g. (a|a)+
                    branch_strs = [
                        "".join(b).strip()
                        for b in closed_group["branches"]
                        if "".join(b).strip()
                    ]
                    if len(branch_strs) >= 2 and len(set(branch_strs)) < len(branch_strs):
                        return (
                            False,
                            "Repeated alternation group contains duplicate overlapping branches",
                        )

                if group_stack and (
                    closed_group["has_unbounded_quantifier"] or is_unbounded_outer
                ):
                    group_stack[-1]["has_unbounded_quantifier"] = True
                i += 1
                continue

            # Detect quantifiers on tokens inside a group
            if ch in ("+", "*"):
                if group_stack:
                    group_stack[-1]["has_unbounded_quantifier"] = True
            elif ch == "{":
                m_brace = re.match(r"\{(\d+)(?:,(\d*))?\}", pattern[i:])
                if m_brace and group_stack:
                    max_rep_str = m_brace.group(2)
                    if max_rep_str == "" or (
                        max_rep_str is not None and int(max_rep_str) >= 20
                    ):
                        group_stack[-1]["has_unbounded_quantifier"] = True

            if group_stack:
                group_stack[-1]["branches"][-1].append(ch)
            i += 1

        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            return False, f"Invalid regex syntax: {exc}"

        # 4. Empirical micro-benchmark probe against classic backtracking strings
        for probe in ("a" * 32 + "!", "0" * 32 + "!", " " * 32 + "!"):
            t0 = time.perf_counter()
            _ = compiled.search(probe)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if elapsed_ms > 10.0:
                return (
                    False,
                    f"Pattern failed ReDoS probe latency bound ({elapsed_ms:.2f} ms > 10.0 ms)",
                )

        return True, "SAFE"

    @classmethod
    def validate_pattern(
        cls,
        pattern: str,
        max_length: int = MAX_PATTERN_LENGTH,
    ) -> Pattern[str]:
        safe, reason = cls.check_pattern_safety(pattern, max_length=max_length)
        if not safe:
            raise UnsafeRegexPatternError(
                f"Rejected unsafe regex pattern '{pattern[:80]}': {reason}"
            )
        with cls._cache_lock:
            if pattern not in cls._compiled_cache:
                cls._compiled_cache[pattern] = re.compile(pattern)
            return cls._compiled_cache[pattern]

    @classmethod
    def safe_search(
        cls,
        pattern: str,
        text: str,
        max_window_chars: int = MAX_SCAN_WINDOW_CHARS,
    ) -> Optional[re.Match[str]]:
        if not text:
            return None
        compiled = cls.validate_pattern(pattern)
        bounded = text[:max_window_chars] if len(text) > max_window_chars else text
        return compiled.search(bounded)

    @classmethod
    def safe_finditer(
        cls,
        pattern: str,
        text: str,
        max_window_chars: int = MAX_SCAN_WINDOW_CHARS,
    ) -> List[re.Match[str]]:
        if not text:
            return []
        compiled = cls.validate_pattern(pattern)
        bounded = text[:max_window_chars] if len(text) > max_window_chars else text
        return list(compiled.finditer(bounded))

    @classmethod
    def safe_sub(
        cls,
        pattern: str,
        repl: str,
        text: str,
        max_window_chars: int = MAX_SCAN_WINDOW_CHARS,
    ) -> str:
        if not text:
            return text
        compiled = cls.validate_pattern(pattern)
        if len(text) <= max_window_chars:
            return compiled.sub(repl, text)
        head = compiled.sub(repl, text[:max_window_chars])
        return head + text[max_window_chars:]


@dataclasses.dataclass
class FirewallVerdict:
    request_id: str
    mode: str
    allowed: bool
    risk_level: str
    confidence: float
    trifecta_triggered: bool
    detected_threats: List[str]
    tier_breakdown: Dict[str, Any]
    sanitized_payload: str
    action_taken: str
    effective_action: str
    ephemeral_auth_request: Optional[Dict[str, Any]]
    detection_latency_ms: float
    detection_cost_usd: float
    reason_code: str = "ALLOW_CLEAN"
    verdict_digest: str = ""
    remediation: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class RoutingDecision:
    request_id: str
    task_complexity: str
    selected_model: str
    selected_tier: str
    ab_bucket: str
    extracted_features: Dict[str, Any]
    estimated_cost_usd: float
    baseline_opus_cost_usd: float
    savings_pct: float
    detection_cost_usd: float
    detection_share_of_bill_pct: float
    rationale: str
    budget_check: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class TopologyHealthReport:
    loop_detected: bool
    cyclic_tool_chain: List[str]
    repeated_action_signatures: int
    authentic_progress_verified: bool
    recommended_action: str
    diagnostics: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class PolicyConfigLoader:
    """Single-instance configuration loader with hot-reload support and R5 ReDoS regex admission control."""

    def __init__(
        self,
        policy_path: Optional[Path | str] = None,
        catalog_path: Optional[Path | str] = None,
        storage: Optional[MeterGateStorage] = None,
        strict_regex_validation: bool = False,
    ) -> None:
        env_pol = os.environ.get("METERGATE_POLICY_PATH", "").strip()
        self.policy_path = (
            Path(policy_path)
            if policy_path
            else (Path(env_pol) if env_pol else DEFAULT_POLICY_PATH)
        )
        self.catalog_path = (
            Path(catalog_path) if catalog_path else DEFAULT_CATALOG_PATH
        )
        self.storage = storage
        self.strict_regex_validation = strict_regex_validation
        self._policy_mtime = 0.0
        self._catalog_mtime = 0.0
        self.policy: Dict[str, Any] = {}
        self.catalog: Dict[str, Any] = {}
        self.rejected_unsafe_rules: List[Dict[str, str]] = []
        self.reload_if_needed(force=True)

    def _sanitize_and_validate_policy_regexes(
        self, raw_policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        R5: Validates all regex patterns in `deterministic_rules`, `secret_patterns`, and
        `trusted_context_resolution` using `RegexSafetyGuard`.
        Any pattern failing ReDoS admission checks is rejected before entering the runtime ruleset.
        """
        pol = copy.deepcopy(raw_policy)
        max_pat_len = int(
            pol.get("resource_limits", {}).get(
                "max_regex_pattern_length", RegexSafetyGuard.MAX_PATTERN_LENGTH
            )
        )
        rejected: List[Dict[str, str]] = []

        valid_det_rules = []
        for rule in pol.get("deterministic_rules", []):
            pat = str(rule.get("pattern", ""))
            safe, reason = RegexSafetyGuard.check_pattern_safety(
                pat, max_length=max_pat_len
            )
            if safe:
                RegexSafetyGuard.validate_pattern(pat, max_length=max_pat_len)
                valid_det_rules.append(rule)
            else:
                rejected.append(
                    {
                        "rule_id": str(rule.get("rule_id", "UNKNOWN")),
                        "section": "deterministic_rules",
                        "pattern": pat[:120],
                        "reason": reason,
                    }
                )
                if self.strict_regex_validation:
                    raise UnsafeRegexPatternError(
                        f"Rule {rule.get('rule_id')}: {reason}"
                    )
        pol["deterministic_rules"] = valid_det_rules

        valid_sec_rules = []
        for sec in pol.get("secret_patterns", []):
            pat = str(sec.get("pattern", ""))
            safe, reason = RegexSafetyGuard.check_pattern_safety(
                pat, max_length=max_pat_len
            )
            if safe:
                RegexSafetyGuard.validate_pattern(pat, max_length=max_pat_len)
                valid_sec_rules.append(sec)
            else:
                rejected.append(
                    {
                        "rule_id": str(sec.get("secret_id", "UNKNOWN")),
                        "section": "secret_patterns",
                        "pattern": pat[:120],
                        "reason": reason,
                    }
                )
                if self.strict_regex_validation:
                    raise UnsafeRegexPatternError(
                        f"Secret pattern {sec.get('secret_id')}: {reason}"
                    )
        pol["secret_patterns"] = valid_sec_rules

        ctx_cfg = pol.get("trusted_context_resolution", {})
        for list_key in ("resource_inference_rules", "sink_inference_rules"):
            valid_inf = []
            for item in ctx_cfg.get(list_key, []):
                pat = str(item.get("pattern", ""))
                safe, reason = RegexSafetyGuard.check_pattern_safety(
                    pat, max_length=max_pat_len
                )
                if safe:
                    RegexSafetyGuard.validate_pattern(pat, max_length=max_pat_len)
                    valid_inf.append(item)
                else:
                    rejected.append(
                        {
                            "rule_id": str(
                                item.get("resource") or item.get("sink") or "UNKNOWN"
                            ),
                            "section": list_key,
                            "pattern": pat[:120],
                            "reason": reason,
                        }
                    )
                    if self.strict_regex_validation:
                        raise UnsafeRegexPatternError(
                            f"Context rule in {list_key}: {reason}"
                        )
            ctx_cfg[list_key] = valid_inf

        self.rejected_unsafe_rules = rejected
        return pol

    def reload_if_needed(self, force: bool = False) -> bool:
        reloaded = False
        p_mtime = (
            self.policy_path.stat().st_mtime if self.policy_path.exists() else 0.0
        )
        c_mtime = (
            self.catalog_path.stat().st_mtime
            if self.catalog_path.exists()
            else 0.0
        )
        if (
            force
            or p_mtime > self._policy_mtime
            or c_mtime > self._catalog_mtime
        ):
            raw_policy = json.loads(
                self.policy_path.read_text(encoding="utf-8")
            )
            self.policy = self._sanitize_and_validate_policy_regexes(raw_policy)
            self.catalog = json.loads(
                self.catalog_path.read_text(encoding="utf-8")
            )
            self._policy_mtime = p_mtime
            self._catalog_mtime = c_mtime
            reloaded = True
            if self.storage and self.storage.get_system_state("gateway_mode") is None:
                default_mode = str(self.policy.get("mode", "enforce")).lower()
                self.storage.set_mode(
                    default_mode if default_mode in ("observe", "shadow", "enforce") else "enforce"
                )
        return reloaded

    def register_custom_deterministic_rule(
        self,
        rule_id: str,
        category: str,
        pattern: str,
        weight: float = 0.80,
        description: str = "",
    ) -> Dict[str, Any]:
        """
        R5: Validates a custom regex rule through `RegexSafetyGuard` before admitting it into the active policy.
        Raises `UnsafeRegexPatternError` if the pattern poses a ReDoS risk.
        """
        max_pat_len = int(
            self.policy.get("resource_limits", {}).get(
                "max_regex_pattern_length", RegexSafetyGuard.MAX_PATTERN_LENGTH
            )
        )
        RegexSafetyGuard.validate_pattern(pattern, max_length=max_pat_len)
        new_rule = {
            "rule_id": str(rule_id),
            "category": str(category),
            "pattern": str(pattern),
            "weight": float(weight),
            "description": str(description),
        }
        rules = [
            r
            for r in self.policy.get("deterministic_rules", [])
            if r.get("rule_id") != rule_id
        ]
        rules.append(new_rule)
        self.policy["deterministic_rules"] = rules
        return new_rule

    def get_effective_policy(self) -> Dict[str, Any]:
        self.reload_if_needed()
        return copy.deepcopy(self.policy)

    def get_mode(self) -> str:
        self.reload_if_needed()
        default_mode = str(self.policy.get("mode", "enforce")).lower()
        if self.storage:
            return self.storage.get_mode(default=default_mode)
        return default_mode

    def set_mode(self, mode: str) -> str:
        norm = mode.strip().lower()
        if norm not in ("observe", "shadow", "enforce"):
            raise ValueError(
                f"Unsupported mode '{mode}'. Must be 'observe', 'shadow', or 'enforce'."
            )
        self.policy["mode"] = norm
        if self.storage:
            self.storage.set_mode(norm)
        return norm


class GatewayRateLimiter:
    """Single-instance token-bucket rate limiter."""

    def __init__(
        self,
        capacity: float = 120.0,
        refill_per_sec: float = 60.0,
        default_daily_quota_usd: float = 50.0,
    ) -> None:
        self.capacity = max(1.0, float(capacity))
        self.refill_per_sec = max(0.1, float(refill_per_sec))
        self.daily_quota_usd = max(0.01, float(default_daily_quota_usd))
        self._lock = threading.Lock()
        self._tokens = self.capacity
        self._last_ts = time.monotonic()

    def allow_request(self, cost: float = 1.0) -> Tuple[bool, Dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            elapsed = max(0.0, now - self._last_ts)
            self._tokens = min(
                self.capacity, self._tokens + elapsed * self.refill_per_sec
            )
            self._last_ts = now
            if self._tokens >= cost:
                self._tokens -= cost
                return True, {
                    "allowed": True,
                    "remaining_tokens": round(self._tokens, 2),
                    "capacity": self.capacity,
                }
            retry_after = round(
                (cost - self._tokens) / max(0.001, self.refill_per_sec), 3
            )
            return False, {
                "allowed": False,
                "remaining_tokens": round(self._tokens, 2),
                "capacity": self.capacity,
                "retry_after_sec": retry_after,
            }


class ProgressiveAuthManager:
    """
    Tier-3 Progressive Ephemeral Authorization (One-Time Scoped Approval Tokens).
    Note (M-10): Uses a local instance HMAC key strictly to verify one-time human approval tokens
    for dangerous tool/exfiltration requests within a local session. Carries zero license semantics.
    """

    def __init__(
        self,
        storage: MeterGateStorage,
        secret_key: Optional[str] = None,
    ) -> None:
        self.storage = storage
        if secret_key is not None:
            self._secret = secret_key.encode("utf-8")
        else:
            self._secret = load_or_create_integrity_key(
                storage.integrity_key_path, "METERGATE_INTEGRITY_HMAC_SECRET"
            )

    def _sign(
        self,
        token_id: str,
        session_id: str,
        scope: str,
        expires_at: float,
    ) -> str:
        msg = f"{token_id}:{session_id}:{scope}:{expires_at:.3f}".encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def create_approval_request(
        self,
        session_id: str,
        scope: str,
        ttl_seconds: int = 60,
        agent_id: str = "local_agent",
    ) -> Dict[str, Any]:
        token_id = f"mg_eph_{uuid.uuid4().hex[:12]}"
        now = self.storage.now_epoch()
        expires_at = round(now + ttl_seconds, 3)
        sig = self._sign(token_id, session_id, scope, expires_at)
        self.storage.save_ephemeral_token(
            token_id=token_id,
            agent_id=agent_id,
            session_id=session_id,
            scope=scope,
            status="PENDING_APPROVAL",
            signature=sig,
            created_at=now,
            expires_at=expires_at,
        )
        return {
            "token_id": token_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "scope": scope,
            "status": "PENDING_APPROVAL",
            "ttl_seconds": ttl_seconds,
            "expires_at": expires_at,
        }

    def approve_token(
        self,
        token_id: str,
        approved_by: str = "local_operator",
    ) -> Dict[str, Any]:
        rec = self.storage.get_ephemeral_token(token_id)
        if not rec:
            raise KeyError(f"Unknown ephemeral token_id: {token_id}")
        now = self.storage.now_epoch()
        if now > rec["expires_at"]:
            self.storage.update_ephemeral_token_status(token_id, "EXPIRED")
            raise ValueError(f"Ephemeral token {token_id} has already expired")
        self.storage.update_ephemeral_token_status(
            token_id,
            "APPROVED",
            approved_by=approved_by,
        )
        signed_wire_token = f"{token_id}.{rec['signature']}"
        return {
            "token_id": token_id,
            "ephemeral_token": signed_wire_token,
            "scope": rec["scope"],
            "status": "APPROVED",
            "approved_by": approved_by,
            "expires_at": rec["expires_at"],
        }

    def verify_and_consume(
        self,
        wire_token: str,
        required_scope: str,
        agent_id: str = "local_agent",
    ) -> Dict[str, Any]:
        if not wire_token or "." not in wire_token:
            return {"valid": False, "reason": "Malformed wire token"}
        token_id, provided_sig = wire_token.split(".", 1)
        rec = self.storage.get_ephemeral_token(token_id)
        if not rec:
            return {"valid": False, "reason": "Token ID not found"}
        expected_sig = self._sign(
            rec["token_id"],
            rec["session_id"],
            rec["scope"],
            rec["expires_at"],
        )
        if not hmac.compare_digest(provided_sig, expected_sig):
            return {"valid": False, "reason": "HMAC signature mismatch"}
        now = self.storage.now_epoch()
        if now > rec["expires_at"]:
            self.storage.update_ephemeral_token_status(token_id, "EXPIRED")
            return {"valid": False, "reason": "Token TTL expired"}
        if rec["status"] == "CONSUMED":
            return {
                "valid": False,
                "reason": "One-time token already consumed (replay blocked)",
            }
        if rec["status"] != "APPROVED":
            return {
                "valid": False,
                "reason": f"Token not approved (current status: {rec['status']})",
            }
        if rec["scope"] != required_scope and rec["scope"] != "*":
            return {
                "valid": False,
                "reason": f"Scope mismatch (token={rec['scope']}, required={required_scope})",
            }
        self.storage.update_ephemeral_token_status(
            token_id,
            "CONSUMED",
            consumed_at=now,
        )
        return {
            "valid": True,
            "token_id": token_id,
            "scope": rec["scope"],
            "approved_by": rec.get("approved_by") or "local_operator",
            "consumed_by_agent": agent_id,
            "consumed_at": now,
        }


class ThreeTierFirewall:
    """
    M-07, R3 & R5: Three-Tier Deterministic & Heuristic AI Agent Firewall
      - Tier 1 (Deterministic Regex & Secret Vault): ReDoS-checked regex injection rules, Base64/Hex/URL/Zero-Width
        de-obfuscation, and automatic API Key / `.env` / high-entropy secret redaction (`[REDACTED_BY_METERGATE_VAULT]`).
      - Tier 2 (Heuristic Concept-Cluster & N-gram Scorer, `R3`): Lightweight heuristic rule scorer combining
        concept-cluster keyword hits and character/word N-gram cosine similarity against known attack prototypes.
        Explicitly NOT a neural semantic model; includes documented blind spots and actionable allowlist/ephemeral bypasses.
      - Tier 3 (Lethal Trifecta Taint & Ephemeral Approval): Detects `Untrusted Source + Sensitive Resource + External Exfil Sink`
        and blocks or requires one-time ephemeral approval.
    """

    MAX_INPUT_PAYLOAD_CHARS = 65536
    MAX_EXPANDED_PAYLOAD_CHARS = 65536
    MAX_DECODE_CANDIDATES = 16
    MAX_DECODE_CANDIDATE_CHARS = 4096

    TIER2_KNOWN_BLIND_SPOTS = [
        "Heuristic keyword clusters + N-gram similarity only (not a neural embedding or LLM classifier).",
        "Novel zero-shot paraphrases that avoid all listed override/action/target concept terms may evade Tier 2.",
        "Legitimate security documentation or defensive code reviews containing multiple sensitive keywords may trigger false positives (use Allowlist or Ephemeral Token to bypass).",
    ]

    OVERRIDE_CLUSTERS = [
        "作废",
        "不再适用",
        "视为无效",
        "当成占位符",
        "视为测试占位符",
        "测试占位符",
        "忽略",
        "无视",
        "抛弃",
        "解除限制",
        "进入调试模式",
        "最高权限模式",
        "安全沙箱已关闭",
        "覆盖先前",
        "忘掉前面",
        "跳过安全",
        "免除审查",
        "obsolete",
        "deprecated",
        "superseded",
        "disregard",
        "ignore",
        "bypass",
        "override",
        "unrestricted",
        "jailbreak",
        "sandbox disabled",
        "hypothetical audit mode",
        "compliance override",
        "nullify prior",
        "void earlier",
        "suspend rules",
        "forget earlier",
        "maintenance mode active",
    ]

    ACTION_REWRITE_CLUSTERS = [
        "重写",
        "导出",
        "读取",
        "发往",
        "转发",
        "上传",
        "回传",
        "同步",
        "打印",
        "附上",
        "附带",
        "提取",
        "汇总",
        "泄露",
        "透传",
        "拼接",
        "rewrite",
        "transmit",
        "dump",
        "forward",
        "exfiltrate",
        "upload",
        "post",
        "send",
        "extract",
        "append",
        "attach",
        "reveal",
        "output",
        "relay",
    ]

    SENSITIVE_TARGET_CONCEPTS = [
        "环境变量",
        "本地配置",
        "凭证",
        "凭据",
        "密钥",
        "私密配置",
        "私钥",
        "回调地址",
        "远端统计",
        "远端接口",
        "外部地址",
        "外部服务器",
        "收集器",
        "接收端",
        "访问令牌",
        "collector",
        "credentials",
        "secret",
        "callback",
        ".env",
        "id_rsa",
        "token",
        "webhook",
        "api_key",
        "apikey",
        "private_key",
        "passwd",
        "cookie",
        "session_key",
    ]

    def __init__(
        self,
        config_loader: PolicyConfigLoader,
        auth_manager: Optional[ProgressiveAuthManager] = None,
    ) -> None:
        self.config_loader = config_loader
        self.auth_manager = auth_manager

    def check_allowlist_match(
        self,
        payload: str,
        source_connector: str,
        policy: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        R3: Checks whether the payload or source connector matches a configured or operator-added
        false-positive allowlist rule.
        """
        clean_payload = (payload or "").strip()
        payload_hash = hashlib.sha256(clean_payload.encode("utf-8")).hexdigest()

        pol_alw = policy.get("allowlist", {})
        if source_connector in pol_alw.get("trusted_connectors", []):
            return {
                "entry_type": "connector",
                "value": source_connector,
                "source": "policy_config",
            }
        if payload_hash in pol_alw.get("allowed_payload_sha256", []):
            return {
                "entry_type": "payload_sha256",
                "value": payload_hash,
                "source": "policy_config",
            }
        for pat in pol_alw.get("benign_substring_patterns", []):
            if pat and str(pat).lower() in clean_payload.lower():
                return {
                    "entry_type": "pattern",
                    "value": str(pat),
                    "source": "policy_config",
                }

        if self.config_loader.storage:
            for item in self.config_loader.storage.list_allowlist_entries():
                etype = item.get("entry_type")
                val = str(item.get("value", ""))
                if etype == "connector" and val == source_connector:
                    return item
                if etype == "payload_sha256" and val == payload_hash:
                    return item
                if (
                    etype == "pattern"
                    and val
                    and val.lower() in clean_payload.lower()
                ):
                    return item
        return None

    @staticmethod
    def resolve_trusted_context(
        payload: str,
        policy: Dict[str, Any],
        caller_plane: str = "control",
        declared_connector: Optional[str] = None,
        declared_resources: Optional[List[str]] = None,
        declared_sinks: Optional[List[str]] = None,
        channel_default_connector: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        ARC-1: Resolves `source_connector`, `target_resources`, and `outbound_sinks` from server-side
        payload inference rules (`trusted_context_resolution` in `default_policy.json`).
        When `caller_plane == "data"`, caller-declared context fields in the request body CANNOT
        downgrade risk or claim a trusted source connector.
        """
        ctx_cfg = policy.get("trusted_context_resolution", {})
        max_win = int(
            policy.get("resource_limits", {}).get(
                "max_regex_scan_window_chars",
                RegexSafetyGuard.MAX_SCAN_WINDOW_CHARS,
            )
        )
        inferred_res: List[str] = []
        inferred_sinks: List[str] = []

        for rule in ctx_cfg.get("resource_inference_rules", []):
            if RegexSafetyGuard.safe_search(
                rule["pattern"], payload, max_window_chars=max_win
            ):
                r_name = str(rule["resource"])
                if r_name not in inferred_res:
                    inferred_res.append(r_name)

        for rule in ctx_cfg.get("sink_inference_rules", []):
            if RegexSafetyGuard.safe_search(
                rule["pattern"], payload, max_window_chars=max_win
            ):
                s_name = str(rule["sink"])
                if s_name not in inferred_sinks:
                    inferred_sinks.append(s_name)

        default_conn = channel_default_connector or str(
            ctx_cfg.get("default_data_plane_connector", "email_webhook")
        )

        if caller_plane == "data" and ctx_cfg.get(
            "ignore_data_plane_caller_claims", True
        ):
            effective_connector = default_conn
            effective_resources = sorted(set(inferred_res))
            effective_sinks = sorted(set(inferred_sinks))
            caller_claims_ignored = True
        else:
            effective_connector = declared_connector or default_conn
            effective_resources = sorted(
                set((declared_resources or []) + inferred_res)
            )
            effective_sinks = sorted(set((declared_sinks or []) + inferred_sinks))
            caller_claims_ignored = False

        return {
            "source_connector": effective_connector,
            "target_resources": effective_resources,
            "outbound_sinks": effective_sinks,
            "inferred_resources": inferred_res,
            "inferred_sinks": inferred_sinks,
            "caller_plane": caller_plane,
            "caller_claims_ignored": caller_claims_ignored,
            "ignored_declared_connector": (
                declared_connector if caller_claims_ignored else None
            ),
        }

    @classmethod
    def _deobfuscate_payload(
        cls,
        text: str,
        max_input_chars: int = MAX_INPUT_PAYLOAD_CHARS,
        max_expanded_chars: int = MAX_EXPANDED_PAYLOAD_CHARS,
        max_decode_candidates: int = MAX_DECODE_CANDIDATES,
        max_candidate_chars: int = MAX_DECODE_CANDIDATE_CHARS,
    ) -> Tuple[str, List[str]]:
        notes: List[str] = []
        working_text = text or ""
        if len(working_text) > max_input_chars:
            notes.append("OBFUSCATION_INPUT_LENGTH_EXCEEDED")
            working_text = working_text[:max_input_chars]

        zw_stripped = re.sub(
            r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", working_text
        )
        if len(zw_stripped) != len(working_text):
            notes.append("OBFUSCATION_ZERO_WIDTH_STRIPPED")

        has_fw_alnum = bool(re.search(r"[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a]", zw_stripped))
        norm = unicodedata.normalize("NFKC", zw_stripped)
        if has_fw_alnum and norm != zw_stripped:
            notes.append("OBFUSCATION_UNICODE_NFKC_NORMALIZED")

        def _collapse_spaced_letters(m: re.Match[str]) -> str:
            notes.append("OBFUSCATION_SPACED_ASCII")
            return re.sub(r"\s+", "", m.group(0))

        norm = re.sub(
            r"\b(?:[a-zA-Z]\s+){4,}[a-zA-Z]\b", _collapse_spaced_letters, norm
        )

        # Also collapse punctuation-split ASCII words like i.g.n.o.r.e or i-g-n-o-r-e
        def _collapse_punct_ascii(m: re.Match[str]) -> str:
            notes.append("OBFUSCATION_SPLIT_TOKEN_ASCII")
            return re.sub(r"[._\-*|/]+", "", m.group(0))

        norm = re.sub(
            r"\b(?:[a-zA-Z][._\-*|/]){4,}[a-zA-Z]\b", _collapse_punct_ascii, norm
        )

        if re.search(r"(?<=[\u4e00-\u9fff])[\s·•_.\-*|/]+(?=[\u4e00-\u9fff])", norm):
            notes.append("OBFUSCATION_CJK_SPLIT_COLLAPSED")
        cjk_clean = re.sub(
            r"(?<=[\u4e00-\u9fff])[\s·•_.\-*|/]+(?=[\u4e00-\u9fff])", "", norm
        )

        decoded_chunks: List[str] = [cjk_clean[:max_expanded_chars]]
        current_expanded_len = len(decoded_chunks[0])
        candidates_processed = 0

        if "%" in cjk_clean and re.search(r"%[0-9A-Fa-f]{2}", cjk_clean):
            if len(cjk_clean) > max_candidate_chars:
                notes.append("OBFUSCATION_DECODE_CANDIDATE_TOO_LARGE")
            elif candidates_processed >= max_decode_candidates:
                notes.append("OBFUSCATION_DECODE_CANDIDATE_LIMIT_REACHED")
            else:
                candidates_processed += 1
                try:
                    unquoted = urllib.parse.unquote(cjk_clean)
                    if unquoted != cjk_clean:
                        if current_expanded_len + 1 + len(unquoted) > max_expanded_chars:
                            notes.append("OBFUSCATION_EXPANDED_LENGTH_EXCEEDED")
                            rem = max(0, max_expanded_chars - current_expanded_len - 1)
                            if rem > 0:
                                decoded_chunks.append(unquoted[:rem])
                                current_expanded_len += 1 + rem
                        else:
                            decoded_chunks.append(unquoted)
                            current_expanded_len += 1 + len(unquoted)
                        notes.append("OBFUSCATION_URL_ENCODED")
                except Exception:
                    pass

        for b64_m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", norm):
            b64_cand = b64_m.group(0)
            if len(b64_cand) > max_candidate_chars:
                notes.append("OBFUSCATION_DECODE_CANDIDATE_TOO_LARGE")
                continue
            if candidates_processed >= max_decode_candidates:
                notes.append("OBFUSCATION_DECODE_CANDIDATE_LIMIT_REACHED")
                break
            candidates_processed += 1
            if len(b64_cand) % 4 == 0:
                try:
                    raw_bytes = base64.b64decode(b64_cand, validate=True)
                    decoded_str = raw_bytes.decode("utf-8", errors="ignore")
                    printable_ratio = sum(
                        1 for c in decoded_str if c.isprintable() or c.isspace()
                    ) / max(1, len(decoded_str))
                    if len(decoded_str) >= 10 and printable_ratio > 0.85:
                        if current_expanded_len + 1 + len(decoded_str) > max_expanded_chars:
                            notes.append("OBFUSCATION_EXPANDED_LENGTH_EXCEEDED")
                            rem = max(0, max_expanded_chars - current_expanded_len - 1)
                            if rem > 0:
                                decoded_chunks.append(decoded_str[:rem])
                                current_expanded_len += 1 + rem
                            break
                        decoded_chunks.append(decoded_str)
                        current_expanded_len += 1 + len(decoded_str)
                        notes.append("OBFUSCATION_BASE64_DECODED")
                except Exception:
                    pass

        for hex_m in re.finditer(r"(?:\\x[0-9a-fA-F]{2}){6,}", norm):
            hex_cand = hex_m.group(0)
            if len(hex_cand) > max_candidate_chars:
                notes.append("OBFUSCATION_DECODE_CANDIDATE_TOO_LARGE")
                continue
            if candidates_processed >= max_decode_candidates:
                notes.append("OBFUSCATION_DECODE_CANDIDATE_LIMIT_REACHED")
                break
            candidates_processed += 1
            try:
                clean_hex = hex_cand.replace("\\x", "")
                dec_hex = bytes.fromhex(clean_hex).decode("utf-8", errors="ignore")
                if len(dec_hex) >= 6:
                    if current_expanded_len + 1 + len(dec_hex) > max_expanded_chars:
                        notes.append("OBFUSCATION_EXPANDED_LENGTH_EXCEEDED")
                        rem = max(0, max_expanded_chars - current_expanded_len - 1)
                        if rem > 0:
                            decoded_chunks.append(dec_hex[:rem])
                            current_expanded_len += 1 + rem
                        break
                    decoded_chunks.append(dec_hex)
                    current_expanded_len += 1 + len(dec_hex)
                    notes.append("OBFUSCATION_HEX_DECODED")
            except Exception:
                pass

        combined = "\n".join(decoded_chunks)
        if len(combined) > max_expanded_chars:
            combined = combined[:max_expanded_chars]
            notes.append("OBFUSCATION_EXPANDED_LENGTH_EXCEEDED")
        return combined, sorted(set(notes))

    @staticmethod
    def _shannon_entropy(token: str) -> float:
        if not token:
            return 0.0
        counts = Counter(token)
        length = len(token)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @staticmethod
    def _semantic_features(text: str) -> CounterType[str]:
        lower = text.lower()
        cjk_compact = re.sub(r"(?<=[\u4e00-\u9fff])\s+(?=[\u4e00-\u9fff])", "", lower)
        features: CounterType[str] = Counter()

        en_words = re.findall(r"[a-z0-9_.]{3,}", cjk_compact)
        for w in en_words:
            features[f"w:{w}"] += 1
        for i in range(len(en_words) - 1):
            features[f"wb:{en_words[i]}_{en_words[i+1]}"] += 1

        cjk_runs = re.findall(r"[\u4e00-\u9fff]{2,}", cjk_compact)
        for run in cjk_runs:
            for i in range(len(run) - 1):
                features[f"cjk:{run[i:i+2]}"] += 1

        return features

    @classmethod
    def _cosine_similarity(cls, a: CounterType[str], b: CounterType[str]) -> float:
        if not a or not b:
            return 0.0
        common = set(a.keys()) & set(b.keys())
        dot = sum(a[k] * b[k] for k in common)
        norm_a = math.sqrt(sum(v * v for v in a.values()))
        norm_b = math.sqrt(sum(v * v for v in b.values()))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot / (norm_a * norm_b)

    def sanitize_text(
        self, raw_text: str, policy: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, int]:
        if not raw_text:
            return raw_text, 0
        pol = policy or self.config_loader.policy
        max_win = int(
            pol.get("resource_limits", {}).get(
                "max_regex_scan_window_chars",
                RegexSafetyGuard.MAX_SCAN_WINDOW_CHARS,
            )
        )
        sanitized = raw_text
        redacted_count = 0

        for sec in pol.get("secret_patterns", []):
            matches = RegexSafetyGuard.safe_finditer(
                sec["pattern"], sanitized, max_window_chars=max_win
            )
            if matches:
                redacted_count += len(matches)
                sanitized = RegexSafetyGuard.safe_sub(
                    sec["pattern"],
                    "[REDACTED_BY_METERGATE_VAULT]",
                    sanitized,
                    max_window_chars=max_win,
                )

        entropy_thresh = float(
            pol.get("confidence_thresholds", {}).get(
                "entropy_secret_threshold", 4.25
            )
        )
        for candidate in re.findall(
            r"[A-Za-z0-9_\-+/=]{24,}", sanitized[:max_win]
        ):
            if "REDACTED_BY_METERGATE" in candidate:
                continue
            if len(candidate) % 4 == 0:
                try:
                    dec = base64.b64decode(candidate, validate=True).decode(
                        "utf-8", errors="strict"
                    )
                    if " " in dec and len(dec.split()) >= 3:
                        continue
                except Exception:
                    pass
            has_upper = any(c.isupper() for c in candidate)
            has_lower = any(c.islower() for c in candidate)
            has_digit = any(c.isdigit() for c in candidate)
            if has_upper and has_lower and has_digit:
                ent = self._shannon_entropy(candidate)
                if ent >= entropy_thresh:
                    redacted_count += 1
                    sanitized = sanitized.replace(
                        candidate, "[REDACTED_BY_METERGATE_VAULT]"
                    )

        for rule in pol.get("deterministic_rules", []):
            if rule["category"] == "prompt_injection":
                sanitized = RegexSafetyGuard.safe_sub(
                    rule["pattern"],
                    "[BLOCKED_INJECTION_DIRECTIVE]",
                    sanitized,
                    max_window_chars=max_win,
                )
        return sanitized, redacted_count

    def sanitize_conversation_messages(
        self,
        messages: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], int]:
        pol = self.config_loader.get_effective_policy()
        sanitized_list: List[Dict[str, Any]] = []
        total_redacted = 0

        for msg in messages:
            if not isinstance(msg, dict):
                sanitized_list.append(msg)
                continue
            new_msg = copy.deepcopy(msg)
            content = new_msg.get("content")
            if isinstance(content, str):
                clean_str, cnt = self.sanitize_text(content, pol)
                new_msg["content"] = clean_str
                total_redacted += cnt
            elif isinstance(content, list):
                new_parts = []
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        p_copy = copy.deepcopy(part)
                        c_str, cnt = self.sanitize_text(p_copy["text"], pol)
                        p_copy["text"] = c_str
                        total_redacted += cnt
                        new_parts.append(p_copy)
                    else:
                        new_parts.append(part)
                new_msg["content"] = new_parts

            if isinstance(new_msg.get("tool_calls"), list):
                for tc in new_msg["tool_calls"]:
                    if isinstance(tc, dict) and isinstance(tc.get("function"), dict):
                        fn_args = tc["function"].get("arguments")
                        if isinstance(fn_args, str):
                            c_args, cnt = self.sanitize_text(fn_args, pol)
                            tc["function"]["arguments"] = c_args
                            total_redacted += cnt
            if isinstance(new_msg.get("function_call"), dict):
                fc_args = new_msg["function_call"].get("arguments")
                if isinstance(fc_args, str):
                    c_args, cnt = self.sanitize_text(fc_args, pol)
                    new_msg["function_call"]["arguments"] = c_args
                    total_redacted += cnt

            sanitized_list.append(new_msg)

        return sanitized_list, total_redacted

    def _run_tier1_deterministic(
        self,
        raw_payload: str,
        expanded_payload: str,
        obfuscation_notes: List[str],
        policy: Dict[str, Any],
    ) -> Tuple[float, List[str], str, int]:
        score = 0.0
        threats: List[str] = []
        sanitized = raw_payload
        redacted_count = 0
        max_win = int(
            policy.get("resource_limits", {}).get(
                "max_regex_scan_window_chars",
                RegexSafetyGuard.MAX_SCAN_WINDOW_CHARS,
            )
        )

        limit_breaches = [
            n
            for n in obfuscation_notes
            if "EXCEEDED" in n or "LIMIT_REACHED" in n or "TOO_LARGE" in n
        ]
        if limit_breaches:
            score = max(score, 0.88)
            threats.append(
                f"TIER1_RESOURCE_LIMIT_EXCEEDED({','.join(limit_breaches)})"
            )

        is_defensive_doc = bool(
            re.search(
                r"(?i)(explain\s+why|in\s+our\s+documentation|in\s+your\s+documentation|how\s+to\s+prevent|how\s+to\s+defend|security\s+training|best\s+practice|如何防范|如何防御|文档中说明|安全培训|代码审查最佳实践)",
                expanded_payload,
            )
            and not obfuscation_notes
        )
        has_injection_rule_hit = False
        for rule in policy.get("deterministic_rules", []):
            pat = rule["pattern"]
            if RegexSafetyGuard.safe_search(
                pat, raw_payload, max_window_chars=max_win
            ) or RegexSafetyGuard.safe_search(
                pat, expanded_payload, max_window_chars=max_win
            ):
                if rule.get("category") == "prompt_injection":
                    has_injection_rule_hit = True
                elif rule.get("category") == "exfiltration_intent" and is_defensive_doc and not has_injection_rule_hit:
                    continue
                score = max(score, float(rule.get("weight", 0.75)))
                threats.append(f"TIER1_RULE:{rule['rule_id']}({rule['category']})")

        for sec in policy.get("secret_patterns", []):
            matches = RegexSafetyGuard.safe_finditer(
                sec["pattern"], sanitized, max_window_chars=max_win
            )
            if matches:
                redacted_count += len(matches)
                score = max(score, 0.35)
                threats.append(
                    f"TIER1_SECRET_REDACTED:{sec['secret_id']}(count={len(matches)})"
                )
                sanitized = RegexSafetyGuard.safe_sub(
                    sec["pattern"],
                    "[REDACTED_BY_METERGATE_VAULT]",
                    sanitized,
                    max_window_chars=max_win,
                )

        entropy_thresh = float(
            policy.get("confidence_thresholds", {}).get(
                "entropy_secret_threshold", 4.25
            )
        )
        for candidate in re.findall(
            r"[A-Za-z0-9_\-+/=]{24,}", sanitized[:max_win]
        ):
            if "REDACTED_BY_METERGATE" in candidate:
                continue
            if len(candidate) % 4 == 0:
                try:
                    dec = base64.b64decode(candidate, validate=True).decode(
                        "utf-8", errors="strict"
                    )
                    if " " in dec and len(dec.split()) >= 3:
                        continue
                except Exception:
                    pass
            has_upper = any(c.isupper() for c in candidate)
            has_lower = any(c.islower() for c in candidate)
            has_digit = any(c.isdigit() for c in candidate)
            if has_upper and has_lower and has_digit:
                ent = self._shannon_entropy(candidate)
                if ent >= entropy_thresh:
                    redacted_count += 1
                    score = max(score, 0.35)
                    threats.append(f"TIER1_HIGH_ENTROPY_SECRET_REDACTED(H={ent:.2f})")
                    sanitized = sanitized.replace(
                        candidate, "[REDACTED_BY_METERGATE_VAULT]"
                    )

        return score, threats, sanitized, redacted_count

    def _run_tier2_semantic_classifier(
        self,
        expanded_payload: str,
        obfuscation_notes: List[str],
        policy: Dict[str, Any],
    ) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        R3: Heuristic Concept-Cluster & N-gram Similarity Scorer.
        Note: Method name `_run_tier2_semantic_classifier` and return schema keys are preserved for API compatibility,
        while `engine_type` and `known_blind_spots` explicitly document its heuristic nature.
        """
        compact_payload = re.sub(
            r"(?<=[\u4e00-\u9fff])\s+(?=[\u4e00-\u9fff])",
            "",
            expanded_payload.lower(),
        )
        payload_vec = self._semantic_features(compact_payload)

        best_sim = 0.0
        best_proto_id = "NONE"
        matched_threats: List[str] = []

        for proto in policy.get("semantic_intent_prototypes", []):
            for anchor in proto.get("anchor_phrases", []):
                sim = self._cosine_similarity(
                    payload_vec, self._semantic_features(anchor)
                )
                if sim > best_sim:
                    best_sim = sim
                    best_proto_id = proto["proto_id"]

        override_hits = sum(
            1 for c in self.OVERRIDE_CLUSTERS if c in compact_payload
        )
        action_hits = sum(
            1 for a in self.ACTION_REWRITE_CLUSTERS if a in compact_payload
        )
        sensitive_target_hits = sum(
            1 for t in self.SENSITIVE_TARGET_CONCEPTS if t in compact_payload
        )

        # R3 & R4: Enhanced benign educational / defensive discussion guard
        is_benign_educational = bool(
            re.search(
                r"(?i)(explain\s+why|in\s+our\s+documentation|in\s+your\s+documentation|unit\s+test|how\s+to\s+prevent|how\s+to\s+defend|bug\s+report|issue\s+description|security\s+training|code\s+review|best\s+practice|报错|如何防范|如何防御|文档中说明|安全培训|单元测试|代码审查|最佳实践|为什么不建议)",
                compact_payload,
            )
            and override_hits == 0
            and not obfuscation_notes
        )

        semantic_score = 0.0
        if not is_benign_educational:
            if override_hits >= 1 and sensitive_target_hits >= 1:
                semantic_score = min(
                    0.97,
                    0.74
                    + 0.06 * override_hits
                    + 0.04 * action_hits
                    + 0.04 * sensitive_target_hits
                    + 0.18 * best_sim,
                )
                matched_threats.append(
                    f"TIER2_SEMANTIC_PARAPHRASE_BYPASS(proto={best_proto_id},sim={best_sim:.2f},concepts={override_hits}+{sensitive_target_hits})"
                )
            elif (
                action_hits >= 2
                and sensitive_target_hits >= 2
                and any(
                    k in compact_payload
                    for k in (
                        "静默",
                        "外部",
                        "远端",
                        "回调",
                        "collector",
                        "webhook",
                        "callback",
                        "external",
                        "remote",
                        "base64",
                    )
                )
            ):
                semantic_score = min(
                    0.93,
                    0.73
                    + 0.05 * action_hits
                    + 0.05 * sensitive_target_hits
                    + 0.15 * best_sim,
                )
                matched_threats.append(
                    f"TIER2_COVERT_EXFILTRATION_INTENT(actions={action_hits},targets={sensitive_target_hits})"
                )
            elif best_sim >= 0.28 and sensitive_target_hits >= 1:
                semantic_score = min(0.92, 0.62 + best_sim * 0.65)
                matched_threats.append(
                    f"TIER2_SEMANTIC_INTENT(proto={best_proto_id},sim={best_sim:.2f})"
                )

            if obfuscation_notes and (
                semantic_score >= 0.45
                or sensitive_target_hits >= 1
                or override_hits >= 1
            ):
                semantic_score = min(0.98, max(0.78, semantic_score + 0.18))
                matched_threats.append(
                    f"TIER2_OBFUSCATED_PAYLOAD({','.join(obfuscation_notes)})"
                )

        details = {
            "engine_type": "heuristic_concept_ngram_scorer",
            "is_neural_semantic_model": False,
            "known_blind_spots": list(self.TIER2_KNOWN_BLIND_SPOTS),
            "best_prototype": best_proto_id,
            "ngram_similarity": round(best_sim, 4),
            "override_concept_hits": override_hits,
            "action_concept_hits": action_hits,
            "sensitive_target_hits": sensitive_target_hits,
            "benign_educational_context": is_benign_educational,
            "obfuscation_signals": obfuscation_notes,
            "semantic_score": round(semantic_score, 4),
        }
        return semantic_score, matched_threats, details

    def inspect(
        self,
        payload: str,
        source_connector: str = "email_webhook",
        target_resources: Optional[List[str]] = None,
        outbound_sinks: Optional[List[str]] = None,
        session_id: str = "sess_default",
        ephemeral_token: Optional[str] = None,
        agent_id: str = "local_agent",
        caller_plane: str = "control",
    ) -> FirewallVerdict:
        """
        M-07, R3 & R5: Evaluates payload across all three firewall tiers:
          - Allowlist Pre-Check (R3 actionable false-positive bypass)
          - Tier 1: De-obfuscation + ReDoS-Guarded Deterministic Regex + Secret Redaction (`[REDACTED_BY_METERGATE_VAULT]`)
          - Tier 2: Heuristic Concept-Cluster & N-gram Scorer
          - Tier 3: Lethal Trifecta Taint Analysis + Progressive Ephemeral Approval
        """
        t0 = time.perf_counter()
        policy = self.config_loader.get_effective_policy()
        catalog = self.config_loader.catalog

        mode = self.config_loader.get_mode().lower()
        request_id = f"req_{uuid.uuid4().hex[:10]}"

        limits_cfg = policy.get("resource_limits", {})
        max_in_chars = int(
            limits_cfg.get("max_input_payload_chars", self.MAX_INPUT_PAYLOAD_CHARS)
        )
        max_exp_chars = int(
            limits_cfg.get(
                "max_expanded_payload_chars", self.MAX_EXPANDED_PAYLOAD_CHARS
            )
        )
        max_cands = int(
            limits_cfg.get("max_decode_candidates", self.MAX_DECODE_CANDIDATES)
        )
        max_cand_chars = int(
            limits_cfg.get(
                "max_decode_candidate_chars", self.MAX_DECODE_CANDIDATE_CHARS
            )
        )
        max_win = int(
            limits_cfg.get(
                "max_regex_scan_window_chars",
                RegexSafetyGuard.MAX_SCAN_WINDOW_CHARS,
            )
        )

        bounded_raw = payload[:max_in_chars] if len(payload) > max_in_chars else payload
        expanded_payload, obfuscation_notes = self._deobfuscate_payload(
            payload,
            max_input_chars=max_in_chars,
            max_expanded_chars=max_exp_chars,
            max_decode_candidates=max_cands,
            max_candidate_chars=max_cand_chars,
        )

        trusted_ctx = self.resolve_trusted_context(
            payload=f"{bounded_raw}\n{expanded_payload}",
            policy=policy,
            caller_plane=caller_plane,
            declared_connector=source_connector,
            declared_resources=target_resources,
            declared_sinks=outbound_sinks,
        )
        resolved_connector = trusted_ctx["source_connector"]
        resolved_resources = trusted_ctx["target_resources"]
        resolved_sinks = trusted_ctx["outbound_sinks"]

        allowlist_hit = self.check_allowlist_match(
            payload=bounded_raw,
            source_connector=resolved_connector,
            policy=policy,
        )

        connectors_cfg = policy.get("connectors", {})
        leg_untrusted = resolved_connector in connectors_cfg.get(
            "untrusted_sources", []
        )
        leg_sensitive = any(
            r in connectors_cfg.get("sensitive_local_resources", [])
            for r in resolved_resources
        )
        leg_exfil = any(
            s in connectors_cfg.get("external_exfil_sinks", [])
            for s in resolved_sinks
        )

        t1_score, t1_threats, sanitized_payload, redacted_count = (
            self._run_tier1_deterministic(
                bounded_raw, expanded_payload, obfuscation_notes, policy
            )
        )
        if redacted_count > 0:
            leg_sensitive = True
            if ".env" not in resolved_resources:
                resolved_resources.append(".env")
            if leg_exfil:
                t1_score = max(t1_score, 0.85)

        t2_score, t2_threats, t2_details = self._run_tier2_semantic_classifier(
            expanded_payload, obfuscation_notes, policy
        )

        compact_lower = re.sub(
            r"(?<=[\u4e00-\u9fff])\s+(?=[\u4e00-\u9fff])",
            "",
            expanded_payload.lower(),
        )
        if t1_score >= 0.55 or t2_score >= 0.65:
            if any(
                k in compact_lower
                for k in (
                    "http",
                    "webhook",
                    "curl",
                    "外部",
                    "远端",
                    "回调",
                    "collector",
                    "转发",
                    "导出",
                    "收集器",
                )
            ):
                leg_exfil = True
            if any(
                k in compact_lower
                for k in (
                    ".env",
                    "id_rsa",
                    "环境变量",
                    "配置",
                    "密钥",
                    "凭证",
                    "凭据",
                    "credentials",
                    "secret",
                )
            ):
                leg_sensitive = True

        trifecta_triggered = bool(leg_untrusted and leg_sensitive and leg_exfil)
        base_threat_score = max(t1_score, t2_score)
        trifecta_bonus = (
            0.15
            if (trifecta_triggered and base_threat_score > 0.0)
            else (
                0.05
                if (
                    base_threat_score > 0.0
                    and leg_untrusted
                    and (leg_sensitive or leg_exfil)
                )
                else 0.0
            )
        )

        combined_confidence = round(min(0.99, base_threat_score + trifecta_bonus), 4)
        all_threats = t1_threats + t2_threats
        if trifecta_triggered and base_threat_score > 0.0:
            all_threats.insert(
                0,
                f"LETHAL_TRIFECTA_ACTIVE(source={resolved_connector},sensitive=True,exfil=True)",
            )

        if not allowlist_hit:
            for rule in policy.get("deterministic_rules", []):
                if rule["category"] == "prompt_injection":
                    sanitized_payload = RegexSafetyGuard.safe_sub(
                        rule["pattern"],
                        "[BLOCKED_INJECTION_DIRECTIVE]",
                        sanitized_payload,
                        max_window_chars=max_win,
                    )
            if t2_score >= 0.65:
                sanitized_payload = f"[METERGATE_SEMANTIC_QUARANTINE] {sanitized_payload}"

        thresholds = policy.get("confidence_thresholds", {})
        block_thresh = float(thresholds.get("block_threshold", 0.72))
        escalate_thresh = float(thresholds.get("escalate_threshold", 0.45))

        required_scope = (
            f"{resolved_connector}:access:{','.join(resolved_resources or ['general'])}"
        )
        token_verification = None
        if ephemeral_token and self.auth_manager:
            token_verification = self.auth_manager.verify_and_consume(
                ephemeral_token,
                required_scope,
                agent_id=agent_id,
            )

        ephemeral_req: Optional[Dict[str, Any]] = None
        if allowlist_hit:
            policy_action = "ALLOW_BY_ALLOWLIST"
            risk_level = "LOW_ALLOWLISTED"
            allowed_in_enforce = True
        elif token_verification and token_verification.get("valid"):
            policy_action = "ALLOW_WITH_CONSUMED_EPHEMERAL_TOKEN"
            risk_level = "ELEVATED_AUTHORIZED"
            allowed_in_enforce = True
        elif combined_confidence >= block_thresh or (
            trifecta_triggered and base_threat_score >= 0.50
        ):
            risk_level = (
                "CRITICAL"
                if combined_confidence >= 0.85 or trifecta_triggered
                else "HIGH"
            )
            policy_action = "BLOCK_AND_QUARANTINE"
            allowed_in_enforce = False
            if self.auth_manager:
                ephemeral_req = self.auth_manager.create_approval_request(
                    session_id=session_id,
                    scope=required_scope,
                    ttl_seconds=int(
                        policy.get("ephemeral_auth", {}).get(
                            "default_ttl_seconds", 60
                        )
                    ),
                    agent_id=agent_id,
                )
        elif combined_confidence >= escalate_thresh or (
            leg_untrusted and leg_sensitive and base_threat_score >= 0.40
        ):
            risk_level = "MEDIUM"
            policy_action = "REQUIRE_PROGRESSIVE_AUTH"
            allowed_in_enforce = False
            if self.auth_manager:
                ephemeral_req = self.auth_manager.create_approval_request(
                    session_id=session_id,
                    scope=required_scope,
                    ttl_seconds=int(
                        policy.get("ephemeral_auth", {}).get(
                            "default_ttl_seconds", 60
                        )
                    ),
                    agent_id=agent_id,
                )
        else:
            risk_level = "LOW"
            policy_action = "ALLOW"
            allowed_in_enforce = True

        if mode in ("observe", "shadow"):
            allowed = True
            prefix = "OBSERVE_ONLY_LOGGED" if mode == "observe" else "SHADOW_OBSERVED"
            effective_action = (
                f"{prefix}({policy_action})"
                if not allowed_in_enforce
                else f"{prefix}(ALLOW)"
            )
        else:
            allowed = allowed_in_enforce
            effective_action = policy_action

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        est_tokens = max(16, len(bounded_raw) // 4)
        det_rate = float(
            catalog.get("detection_system1_cost_per_1k_tokens_usd", 0.00004)
        )
        detection_cost_usd = round((est_tokens / 1000.0) * det_rate, 8)

        payload_sha256 = hashlib.sha256(
            bounded_raw.strip().encode("utf-8")
        ).hexdigest()

        if allowlist_hit:
            reason_code = "ALLOW_BY_ALLOWLIST"
        elif token_verification and token_verification.get("valid"):
            reason_code = "ALLOW_WITH_EPHEMERAL_TOKEN"
        elif not allowed_in_enforce:
            if any("RESOURCE_LIMIT_EXCEEDED" in t for t in all_threats):
                reason_code = "BLOCK_RESOURCE_LIMIT"
            elif trifecta_triggered:
                reason_code = "BLOCK_LETHAL_TRIFECTA"
            elif t1_score >= t2_score and t1_score > 0.0:
                reason_code = "BLOCK_PROMPT_INJECTION"
            else:
                reason_code = "BLOCK_HEURISTIC_OVERRIDE"
        else:
            reason_code = "ALLOW_SECRET_REDACTED" if redacted_count > 0 else "ALLOW_CLEAN"

        verdict_digest = hashlib.sha256(
            f"{mode}|{resolved_connector}|{','.join(resolved_resources)}|{','.join(resolved_sinks)}|{payload_sha256}|{bool(allowlist_hit)}|{policy_action}|{reason_code}".encode("utf-8")
        ).hexdigest()

        if not allowed:
            what_happened_zh = (
                f"MeterGate 防火墙已拦截本次请求（原因码: {reason_code}，风险等级: {risk_level}）。"
                f"你的网关配置没有出错，是因为检测到可疑指令或敏感资源外发特征 ({(', '.join(all_threats[:2])) or policy_action})。"
            )
            what_to_do_zh = (
                "① 若确认是正常业务被误拦：点击控制台『🔓 放行并记住』按钮，或调用 POST /api/v1/firewall/allow-and-remember 一键放行；"
                "② 若你是 AI Agent：请勿原样重试（原样重试结果幂等仍为拦截），请改用 remediation.sanitized_safe_payload 或移除敏感外发操作后再试。"
            )
            what_happened_en = (
                f"Request intercepted by MeterGate Firewall (reason_code={reason_code}, risk={risk_level}). "
                "Your configuration is working properly; high-risk override or secret exfiltration indicators were detected."
            )
            what_to_do_en = (
                "1) If this is a benign false positive: click 'Allow & Remember' in Console or POST /api/v1/firewall/allow-and-remember; "
                "2) If you are an autonomous Agent: do NOT retry identically (verdict is idempotent); replace payload with remediation.sanitized_safe_payload."
            )
            rec_action = "USE_SANITIZED_PAYLOAD_OR_ONE_CLICK_ALLOW"
            retry_same = False
        else:
            what_happened_zh = (
                f"请求已安全通过 MeterGate 检测（原因码: {reason_code}，自动脱敏密钥: {redacted_count} 处）。"
            )
            what_to_do_zh = "无需额外操作，可正常继续执行。"
            what_happened_en = f"Request passed MeterGate inspection (reason_code={reason_code}, secrets_redacted={redacted_count})."
            what_to_do_en = "No remediation needed; proceed normally."
            rec_action = "PROCEED"
            retry_same = True

        remediation_obj = {
            "reason_code": reason_code,
            "idempotent_verdict_digest": verdict_digest,
            "retry_without_modification_will_succeed": retry_same,
            "recommended_agent_action": rec_action,
            "what_happened_zh": what_happened_zh,
            "what_to_do_zh": what_to_do_zh,
            "what_happened_en": what_happened_en,
            "what_to_do_en": what_to_do_en,
            "sanitized_safe_payload": sanitized_payload,
            "one_click_allow_and_remember_api": {
                "method": "POST",
                "path": "/api/v1/firewall/allow-and-remember",
                "body": {
                    "payload": bounded_raw[:256],
                    "source_connector": resolved_connector,
                },
            },
            "ephemeral_approve_api": (
                {
                    "method": "POST",
                    "path": "/api/v1/auth/approve",
                    "body": {"token_id": ephemeral_req["token_id"]},
                }
                if ephemeral_req
                else None
            ),
        }

        tier_breakdown = {
            "effective_mode_source": "control_plane:local",
            "trusted_context": trusted_ctx,
            "payload_sha256": payload_sha256,
            "verdict_digest": verdict_digest,
            "reason_code": reason_code,
            "allowlist_matched": allowlist_hit,
            "tier1_rule_score": round(t1_score, 4),
            "tier1_redacted_secrets": redacted_count,
            "tier2_semantic": t2_details,
            "tier3_trifecta_triggered": trifecta_triggered,
            "tier3_escalated": ephemeral_req is not None,
            "token_verification": token_verification,
            "false_positive_remediation": {
                "ephemeral_token_id": (
                    ephemeral_req["token_id"] if ephemeral_req else None
                ),
                "allowlist_endpoint": "/api/v1/firewall/allowlist",
                "one_click_allow_and_remember_endpoint": "/api/v1/firewall/allow-and-remember",
                "payload_sha256": payload_sha256,
            },
            "resource_limits_enforced": {
                "input_chars": len(payload),
                "max_input_chars": max_in_chars,
                "expanded_chars": len(expanded_payload),
                "max_expanded_chars": max_exp_chars,
                "max_decode_candidates": max_cands,
                "max_decode_candidate_chars": max_cand_chars,
                "max_regex_scan_window_chars": max_win,
            },
        }

        return FirewallVerdict(
            request_id=request_id,
            mode=mode,
            allowed=allowed,
            risk_level=risk_level,
            confidence=combined_confidence,
            trifecta_triggered=trifecta_triggered,
            detected_threats=all_threats,
            tier_breakdown=tier_breakdown,
            sanitized_payload=sanitized_payload,
            action_taken=policy_action,
            effective_action=effective_action,
            ephemeral_auth_request=ephemeral_req,
            detection_latency_ms=elapsed_ms,
            detection_cost_usd=detection_cost_usd,
            reason_code=reason_code,
            verdict_digest=verdict_digest,
            remediation=remediation_obj,
        )


class ClosedLoopRouter:
    """
    Feature + Feedback Closed-Loop Model Router & Cost Ledger Calculator.
    """

    def __init__(
        self,
        config_loader: PolicyConfigLoader,
        storage: Optional[MeterGateStorage] = None,
    ) -> None:
        self.config_loader = config_loader
        self.storage = storage

    @staticmethod
    def extract_task_features(
        task_prompt: str,
        prompt_tokens: Optional[int] = None,
        tools_count: int = 0,
        require_json_schema: bool = False,
    ) -> Dict[str, Any]:
        text = task_prompt or ""
        lower = text.lower()
        est_tokens = (
            prompt_tokens if prompt_tokens is not None else max(32, len(text) // 3)
        )

        code_markers = len(
            re.findall(
                r"(def\s+\w+|class\s+\w+|import\s+\w+|function\s*\(|=>|\{\s*\"|SELECT\s+|CREATE\s+TABLE|pytest|unittest|refactor|重构|单测|接口)",
                text[:16384],
                re.IGNORECASE,
            )
        )
        code_density = round(min(1.0, code_markers / max(1.0, len(text) / 120.0)), 3)

        schema_hits = len(
            re.findall(
                r"(json|schema|boolean|classify|分类|枚举|格式|字段|status_code|路由|判断|标签)",
                lower[:16384],
            )
        )
        schema_score = round(
            min(1.0, (0.55 if require_json_schema else 0.0) + schema_hits * 0.22), 3
        )

        arch_hits = len(
            re.findall(
                r"(0\s*到\s*1|从零设计|系统架构|形式化验证|theorem|proof|distributed consensus|核心引擎架构|端到端架构|安全证明|zero-to-one|architecture)",
                lower[:16384],
            )
        )
        reasoning_score = round(
            min(1.0, arch_hits * 0.38 + (0.25 if est_tokens > 4000 else 0.0)), 3
        )

        return {
            "estimated_prompt_tokens": est_tokens,
            "code_ast_density": code_density,
            "schema_constraint_score": schema_score,
            "reasoning_depth_score": reasoning_score,
            "tools_count": tools_count,
        }

    def _compute_cost(
        self,
        model_meta: Dict[str, Any],
        prompt_tokens: int,
        completion_tokens: int,
        cached_tokens: int = 0,
    ) -> float:
        uncached_prompt = max(0, prompt_tokens - cached_tokens)
        in_cost = (uncached_prompt / 1000.0) * float(
            model_meta["input_cost_per_1k_usd"]
        )
        cache_cost = (cached_tokens / 1000.0) * float(
            model_meta.get(
                "cached_input_cost_per_1k_usd",
                model_meta["input_cost_per_1k_usd"] * 0.25,
            )
        )
        out_cost = (completion_tokens / 1000.0) * float(
            model_meta["output_cost_per_1k_usd"]
        )
        return round(in_cost + cache_cost + out_cost, 6)

    def route(
        self,
        task_prompt: str,
        prompt_tokens: Optional[int] = None,
        expected_output_tokens: int = 400,
        session_id: str = "sess_default",
        budget_cap_usd: Optional[float] = None,
        session_budget_cap_usd: Optional[float] = None,
        tools_count: int = 0,
        require_json_schema: bool = False,
        detection_cost_usd: float = 0.000002,
        agent_id: str = "local_agent",
        record_ledger: bool = True,
        gateway_overhead_ms: float = 0.0,
        enforce_budget_cap: bool = True,
        requested_model: Optional[str] = None,
    ) -> RoutingDecision:
        self.config_loader.reload_if_needed()
        policy = self.config_loader.get_effective_policy()
        catalog = self.config_loader.catalog
        models = catalog.get("models", {})
        baseline_id = catalog.get("baseline_model_id", "claude-3-7-sonnet-latest")
        if baseline_id not in models:
            baseline_id = next(iter(models.keys()))
        baseline_meta = models[baseline_id]

        bc_cfg = policy.get("budget_constraints", {})
        max_req_usd = (
            float(budget_cap_usd)
            if budget_cap_usd is not None
            else float(bc_cfg.get("default_max_request_cost_usd", 2.00))
        )
        max_sess_usd = (
            float(session_budget_cap_usd)
            if session_budget_cap_usd is not None
            else float(bc_cfg.get("default_max_session_cost_usd", 20.00))
        )
        session_spent_usd = (
            float(
                self.storage.get_session_spend_usd(session_id)[
                    "session_spent_usd"
                ]
            )
            if self.storage
            else 0.0
        )

        features = self.extract_task_features(
            task_prompt=task_prompt,
            prompt_tokens=prompt_tokens,
            tools_count=tools_count,
            require_json_schema=require_json_schema,
        )
        est_in = features["estimated_prompt_tokens"]
        request_id = f"rt_{uuid.uuid4().hex[:10]}"

        bucket_hash = int(
            hashlib.sha256(
                f"{session_id}:{task_prompt[:64]}".encode("utf-8")
            ).hexdigest()[:4],
            16,
        )
        ab_bucket = "B_CANDIDATE" if (bucket_hash % 5 == 0) else "A_PRIMARY"

        if requested_model and requested_model != "auto" and requested_model in models:
            complexity = "EXPLICIT_MODEL_SELECTION"
            candidates = [requested_model]
        elif features["reasoning_depth_score"] >= 0.35:
            complexity = "SOTA_ARCHITECTURAL_SYNTHESIS"
            candidates = ["claude-opus-4-6", "claude-3-7-sonnet-latest"]
        elif features["code_ast_density"] >= 0.15 or tools_count >= 3:
            complexity = "BALANCED_CODE_AND_TOOL_CHAIN"
            candidates = (
                ["gpt-4o", "claude-3-7-sonnet-latest"]
                if ab_bucket == "A_PRIMARY"
                else ["claude-3-7-sonnet-latest", "gpt-4o"]
            )
        elif (
            features["schema_constraint_score"] >= 0.20
            and est_in <= 2500
            and features["code_ast_density"] < 0.15
        ):
            complexity = "SYSTEM_1_SCHEMA_TRIAGE"
            candidates = ["gpt-4o-mini", "deepseek-chat"]
        else:
            complexity = "HIGH_THROUGHPUT_EXECUTION"
            candidates = (
                ["deepseek-chat", "claude-3-5-haiku-latest"]
                if ab_bucket == "A_PRIMARY"
                else ["claude-3-5-haiku-latest", "deepseek-chat"]
            )
        candidates = [c for c in candidates if c in models] or list(models.keys())[:2]

        best_model_id: Optional[str] = None
        best_utility = -1e9
        telemetry_notes: List[str] = []

        for cid in candidates:
            m_meta = models.get(cid)
            if not m_meta:
                continue
            est_cost = self._compute_cost(m_meta, est_in, expected_output_tokens)
            if est_cost > max_req_usd:
                continue

            fb = self.storage.get_model_feedback(cid) if self.storage else None
            ema_lat = (
                fb["ema_latency_ms"] if fb else float(m_meta["base_latency_ms"])
            )
            ema_fail = fb["ema_failure_rate"] if fb else 0.0
            ema_qual = (
                fb["ema_quality_score"] if fb else float(m_meta["quality_prior"])
            )

            schema_bonus = (
                3.0
                if (
                    complexity == "SYSTEM_1_SCHEMA_TRIAGE"
                    and m_meta["tier"] == "system1_classifier"
                )
                else 0.0
            )
            utility = (
                (ema_qual * 100.0)
                + schema_bonus
                - (ema_fail * 150.0)
                - (ema_lat * 0.035)
                - (est_cost * 80.0)
            )
            telemetry_notes.append(
                f"{cid}(Q={ema_qual:.2f},fail={ema_fail:.1%},lat={ema_lat:.0f}ms,cost=${est_cost:.5f})"
            )
            if utility > best_utility:
                best_utility = utility
                best_model_id = cid

        if best_model_id is None:
            best_model_id = candidates[0]
        chosen_meta = models[best_model_id]
        est_cost_usd = self._compute_cost(
            chosen_meta, est_in, expected_output_tokens
        )
        projected_session_usd = round(session_spent_usd + est_cost_usd, 6)
        req_cap_exceeded = est_cost_usd > max_req_usd
        sess_cap_exceeded = projected_session_usd > max_sess_usd

        budget_check = {
            "session_id": session_id,
            "estimated_request_cost_usd": est_cost_usd,
            "max_request_cost_usd": max_req_usd,
            "session_spent_before_usd": session_spent_usd,
            "projected_session_spend_usd": projected_session_usd,
            "max_session_cost_usd": max_sess_usd,
            "request_cap_exceeded": req_cap_exceeded,
            "session_cap_exceeded": sess_cap_exceeded,
            "allowed": not (req_cap_exceeded or sess_cap_exceeded),
        }

        if (
            enforce_budget_cap
            and bc_cfg.get("enforce_hard_stop", True)
            and (req_cap_exceeded or sess_cap_exceeded)
        ):
            reason = (
                f"Single-request estimated cost (${est_cost_usd}) exceeds max_request_cost_usd (${max_req_usd})"
                if req_cap_exceeded
                else f"Projected session spend (${projected_session_usd}) for session '{session_id}' exceeds max_session_cost_usd (${max_sess_usd})"
            )
            raise BudgetCapExceededError(
                message=f"Hard Budget Constraint Tripped: {reason}",
                budget_details=budget_check,
            )

        baseline_cost_usd = self._compute_cost(
            baseline_meta, est_in, expected_output_tokens
        )
        savings_pct = (
            round(((baseline_cost_usd - est_cost_usd) / baseline_cost_usd) * 100.0, 2)
            if baseline_cost_usd > 0
            else 0.0
        )

        bill_denom = max(est_cost_usd, 0.0001)
        det_share_pct = round((detection_cost_usd / bill_denom) * 100.0, 4)

        if self.storage and record_ledger:
            self.storage.record_estimated_usage(
                request_id=request_id,
                session_id=session_id,
                selected_model=best_model_id,
                baseline_model=baseline_id,
                ab_bucket=ab_bucket,
                estimated_prompt_tokens=est_in,
                estimated_completion_tokens=expected_output_tokens,
                estimated_cost_usd=est_cost_usd,
                estimated_baseline_cost_usd=baseline_cost_usd,
                detection_cost_usd=detection_cost_usd,
                agent_id=agent_id,
                gateway_overhead_ms=gateway_overhead_ms,
                task_summary=task_prompt[:160],
            )

        rationale = (
            f"Features[tokens={est_in}, code={features['code_ast_density']}, "
            f"schema={features['schema_constraint_score']}, reason={features['reasoning_depth_score']}] "
            f"| Bucket={ab_bucket} | Candidates={', '.join(telemetry_notes)} -> Selected {chosen_meta['display_name']}"
        )

        return RoutingDecision(
            request_id=request_id,
            task_complexity=complexity,
            selected_model=best_model_id,
            selected_tier=chosen_meta["tier"],
            ab_bucket=ab_bucket,
            extracted_features=features,
            estimated_cost_usd=est_cost_usd,
            baseline_opus_cost_usd=baseline_cost_usd,
            savings_pct=savings_pct,
            detection_cost_usd=detection_cost_usd,
            detection_share_of_bill_pct=det_share_pct,
            rationale=rationale,
            budget_check=budget_check,
        )

    def reconcile_usage(
        self,
        request_id: str,
        selected_model: str,
        actual_prompt_tokens: int,
        actual_completion_tokens: int,
        actual_cached_tokens: int = 0,
        latency_ms: float = 110.0,
        failed: bool = False,
        quality_score: float = 0.94,
    ) -> Dict[str, Any]:
        self.config_loader.reload_if_needed()
        catalog = self.config_loader.catalog
        models = catalog.get("models", {})
        baseline_id = catalog.get("baseline_model_id", "claude-3-7-sonnet-latest")
        if baseline_id not in models:
            baseline_id = next(iter(models.keys()))

        chosen_meta = models.get(selected_model, models[baseline_id])
        baseline_meta = models[baseline_id]

        actual_cost_usd = self._compute_cost(
            chosen_meta,
            actual_prompt_tokens,
            actual_completion_tokens,
            actual_cached_tokens,
        )
        baseline_actual_usd = self._compute_cost(
            baseline_meta,
            actual_prompt_tokens,
            actual_completion_tokens,
            actual_cached_tokens,
        )

        reconciled_row = None
        feedback_row = None
        if self.storage:
            with self.storage.batch_write_transaction():
                reconciled_row = self.storage.backfill_actual_usage(
                    request_id=request_id,
                    actual_prompt_tokens=actual_prompt_tokens,
                    actual_completion_tokens=actual_completion_tokens,
                    actual_cached_tokens=actual_cached_tokens,
                    actual_cost_usd=actual_cost_usd,
                    baseline_actual_cost_usd=baseline_actual_usd,
                    latency_ms=latency_ms,
                )
                feedback_row = self.storage.update_model_feedback(
                    model_id=selected_model,
                    latency_ms=latency_ms,
                    failed=failed,
                    quality_score=quality_score,
                    default_latency=float(
                        chosen_meta.get("base_latency_ms", 150.0)
                    ),
                    default_quality=float(chosen_meta.get("quality_prior", 0.92)),
                )

        savings_usd = round(max(0.0, baseline_actual_usd - actual_cost_usd), 6)
        savings_pct = (
            round((savings_usd / baseline_actual_usd) * 100.0, 2)
            if baseline_actual_usd > 0
            else 0.0
        )
        return {
            "request_id": request_id,
            "selected_model": selected_model,
            "reconciled": reconciled_row is not None,
            "actual_prompt_tokens": actual_prompt_tokens,
            "actual_completion_tokens": actual_completion_tokens,
            "actual_cached_tokens": actual_cached_tokens,
            "actual_cost_usd": actual_cost_usd,
            "baseline_actual_cost_usd": baseline_actual_usd,
            "reconciled_savings_usd": savings_usd,
            "reconciled_savings_pct": savings_pct,
            "latency_ms": latency_ms,
            "feedback_updated": feedback_row,
            "ledger_entry": reconciled_row,
        }


class TopologyCircuitBreaker:
    """State-Fingerprint & Cyclic Tool-Call Topology Breaker."""

    @staticmethod
    def compute_action_signature(step: Dict[str, Any]) -> str:
        tool = str(
            step.get("tool") or step.get("action") or step.get("agent") or "msg"
        )
        args = step.get("args") or step.get("input") or step.get("content") or ""
        if isinstance(args, (dict, list)):
            canonical_args = json.dumps(args, sort_keys=True, ensure_ascii=False)
        else:
            canonical_args = re.sub(r"\s+", " ", str(args).strip().lower())
        return hashlib.sha256(f"{tool}::{canonical_args}".encode("utf-8")).hexdigest()[
            :16
        ]

    def evaluate_topology(
        self,
        trace_steps: List[Dict[str, Any]],
        input_state_hash: Optional[str] = None,
        output_state_hash: Optional[str] = None,
    ) -> TopologyHealthReport:
        if not trace_steps:
            return TopologyHealthReport(
                loop_detected=False,
                cyclic_tool_chain=[],
                repeated_action_signatures=0,
                authentic_progress_verified=True,
                recommended_action="CONTINUE_EXECUTION",
                diagnostics="Empty trace.",
            )

        signatures = [self.compute_action_signature(s) for s in trace_steps]
        sig_counts = Counter(signatures)
        repeated_sigs = sum(c - 1 for c in sig_counts.values() if c > 1)

        tool_nodes = [
            f"{s.get('agent', 'agent')}:{s.get('tool', s.get('action', 'chat'))}"
            for s in trace_steps
        ]
        cyclic_chain: List[str] = []
        if len(tool_nodes) >= 4:
            for i in range(len(tool_nodes) - 3):
                window = tool_nodes[i : i + 4]
                if window[0] == window[2] and window[1] == window[3]:
                    cyclic_chain = window
                    break

        authentic_progress = True
        if (
            input_state_hash
            and output_state_hash
            and input_state_hash == output_state_hash
        ):
            authentic_progress = False

        loop_detected = bool(
            repeated_sigs >= 2 or len(cyclic_chain) > 0 or not authentic_progress
        )

        if not authentic_progress:
            action = "REJECT_UNCHANGED_STATE_ARTIFACT"
            diag = (
                f"Output state hash ({output_state_hash}) is identical to input state hash; "
                "zero structural diff produced."
            )
        elif loop_detected:
            action = "TRIP_CIRCUIT_BREAKER"
            diag = f"Detected {repeated_sigs} repeated action signatures and cyclic tool chain {cyclic_chain}."
        else:
            action = "CONTINUE_EXECUTION"
            diag = "Action signatures and tool-call DAG are acyclic with verified state progression."

        return TopologyHealthReport(
            loop_detected=loop_detected,
            cyclic_tool_chain=cyclic_chain,
            repeated_action_signatures=repeated_sigs,
            authentic_progress_verified=authentic_progress,
            recommended_action=action,
            diagnostics=diag,
        )


class MeterGateControlPlane:
    """
    Unified MeterGate Open-Source Engine:
      - Zero paywalls, zero license checks, zero multi-tenant friction.
      - Headline 3-Tier Firewall (Deterministic + Heuristic Concept/N-gram + Lethal Trifecta)
      - Cost Ledger + Report Center (with Date History, Filtering & Pagination)
      - Single-Transaction Turn Persistence (R2) + O(1) Fast Status Audit Checks (R1).
    """

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        policy_path: Optional[Path | str] = None,
        catalog_path: Optional[Path | str] = None,
        secret_key: Optional[str] = None,
        integrity_secret: Optional[str] = None,
        server_clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.storage = MeterGateStorage(
            db_path=db_path,
            integrity_secret=integrity_secret,
            server_clock=server_clock,
        )
        self.config_loader = PolicyConfigLoader(
            policy_path=policy_path,
            catalog_path=catalog_path,
            storage=self.storage,
        )
        self.auth_manager = ProgressiveAuthManager(
            storage=self.storage,
            secret_key=secret_key,
        )
        self.firewall = ThreeTierFirewall(
            config_loader=self.config_loader, auth_manager=self.auth_manager
        )
        self.router = ClosedLoopRouter(
            config_loader=self.config_loader, storage=self.storage
        )
        self.breaker = TopologyCircuitBreaker()
        rl_cfg = self.config_loader.policy.get("rate_limit", {})
        self.rate_limiter = GatewayRateLimiter(
            capacity=float(rl_cfg.get("capacity", 120.0)),
            refill_per_sec=float(rl_cfg.get("refill_per_sec", 60.0)),
            default_daily_quota_usd=float(rl_cfg.get("default_daily_quota_usd", 50.0)),
        )
        self._overhead_lock = threading.Lock()
        self._recent_overhead_ms: Deque[float] = collections.deque(maxlen=256)
        self._peak_request_memory_kb: float = 0.0

    def set_server_clock(self, clock_fn: Callable[[], float]) -> None:
        """ARC-2: Injects server-authoritative clock function (for server-side tests)."""
        self.storage._clock = clock_fn

    # R3: Actionable Allowlist Management for False-Positive Remediation
    def list_allowlist_entries(self) -> List[Dict[str, Any]]:
        return self.storage.list_allowlist_entries()

    def add_allowlist_entry(
        self,
        entry_type: str,
        value: str,
        note: str = "",
    ) -> Dict[str, Any]:
        with self.storage.batch_write_transaction():
            entry = self.storage.add_allowlist_entry(
                entry_type=entry_type, value=value, note=note
            )
            self.storage.append_audit_event(
                event_type="FIREWALL_ALLOWLIST_ADDED",
                session_id="system",
                mode=self.config_loader.get_mode(),
                decision_payload=entry,
            )
        return entry

    def remove_allowlist_entry(self, entry_id: str) -> bool:
        with self.storage.batch_write_transaction():
            removed = self.storage.remove_allowlist_entry(entry_id)
            if removed:
                self.storage.append_audit_event(
                    event_type="FIREWALL_ALLOWLIST_REMOVED",
                    session_id="system",
                    mode=self.config_loader.get_mode(),
                    decision_payload={"entry_id": entry_id},
                )
        return removed

    def record_gateway_overhead(
        self, overhead_ms: float, memory_delta_kb: float = 0.0
    ) -> Dict[str, Any]:
        budget_cfg = self.config_loader.policy.get("gateway_overhead_budget", {})
        max_lat_ms = float(budget_cfg.get("max_gateway_overhead_ms", 15.0))
        max_req_mem_kb = float(budget_cfg.get("max_per_request_memory_kb", 2048.0))
        max_ws_mb = float(budget_cfg.get("max_working_set_memory_mb", 64.0))

        with self._overhead_lock:
            self._recent_overhead_ms.append(round(max(0.0, overhead_ms), 3))
            if memory_delta_kb > self._peak_request_memory_kb:
                self._peak_request_memory_kb = round(memory_delta_kb, 3)

        return self.get_overhead_budget_status(
            last_overhead_ms=overhead_ms,
            last_memory_delta_kb=memory_delta_kb,
            max_lat_ms=max_lat_ms,
            max_req_mem_kb=max_req_mem_kb,
            max_ws_mb=max_ws_mb,
        )

    def get_overhead_budget_status(
        self,
        last_overhead_ms: Optional[float] = None,
        last_memory_delta_kb: Optional[float] = None,
        max_lat_ms: Optional[float] = None,
        max_req_mem_kb: Optional[float] = None,
        max_ws_mb: Optional[float] = None,
    ) -> Dict[str, Any]:
        budget_cfg = self.config_loader.policy.get("gateway_overhead_budget", {})
        b_lat_ms = (
            max_lat_ms
            if max_lat_ms is not None
            else float(budget_cfg.get("max_gateway_overhead_ms", 15.0))
        )
        b_req_mem_kb = (
            max_req_mem_kb
            if max_req_mem_kb is not None
            else float(budget_cfg.get("max_per_request_memory_kb", 2048.0))
        )
        b_ws_mb = (
            max_ws_mb
            if max_ws_mb is not None
            else float(budget_cfg.get("max_working_set_memory_mb", 64.0))
        )

        with self._overhead_lock:
            samples = list(self._recent_overhead_ms)
            peak_kb = self._peak_request_memory_kb

        if samples:
            sorted_s = sorted(samples)
            p50 = round(statistics.median(sorted_s), 3)
            p95_idx = min(len(sorted_s) - 1, int(len(sorted_s) * 0.95))
            p95 = round(sorted_s[p95_idx], 3)
            latest = round(
                last_overhead_ms if last_overhead_ms is not None else samples[-1], 3
            )
        else:
            p50 = 0.0
            p95 = 0.0
            latest = round(last_overhead_ms or 0.0, 3)

        if tracemalloc.is_tracing():
            cur_bytes, _ = tracemalloc.get_traced_memory()
            managed_mb = round(cur_bytes / (1024.0 * 1024.0), 3)
        else:
            managed_mb = round((len(samples) * 64 + 1024) / (1024.0 * 1024.0), 4)

        try:
            rusage_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            rss_mb = round(
                rusage_rss / 1024.0
                if rusage_rss < 10_000_000
                else rusage_rss / (1024.0 * 1024.0),
                2,
            )
        except Exception:
            rss_mb = 0.0

        lat_ok = (p95 <= b_lat_ms) if samples else (latest <= b_lat_ms)
        mem_ok = (peak_kb <= b_req_mem_kb) and (managed_mb <= b_ws_mb)

        return {
            "sample_count": len(samples),
            "last_gateway_overhead_ms": latest,
            "p50_gateway_overhead_ms": p50,
            "p95_gateway_overhead_ms": p95,
            "max_gateway_overhead_budget_ms": b_lat_ms,
            "last_request_memory_delta_kb": round(last_memory_delta_kb or 0.0, 3),
            "peak_request_memory_delta_kb": peak_kb,
            "max_per_request_memory_budget_kb": b_req_mem_kb,
            "managed_working_set_memory_mb": managed_mb,
            "max_working_set_memory_budget_mb": b_ws_mb,
            "process_rss_mb": rss_mb,
            "latency_budget_compliant": lat_ok,
            "memory_budget_compliant": mem_ok,
            "within_budget": bool(lat_ok and mem_ok),
        }

    def set_mode(self, mode: str) -> Dict[str, Any]:
        with self.storage.batch_write_transaction():
            new_mode = self.config_loader.set_mode(mode)
            audit = self.storage.append_audit_event(
                event_type="MODE_SWITCH",
                session_id="system",
                mode=new_mode,
                decision_payload={
                    "new_mode": new_mode,
                },
            )
        return {
            "mode": new_mode,
            "audit": audit,
        }

    def check_daily_quota(self) -> Dict[str, Any]:
        """
        ARC-2 & M-08: Verifies whether the local gateway has remaining UTC natural day budget quota
        using the server-authoritative clock (`self.storage.now_utc_date()`).
        """
        quota_usd = self.rate_limiter.daily_quota_usd
        daily_usage = self.storage.get_daily_quota_usage()
        spent_usd = float(daily_usage["daily_spent_usd"])
        day_str = daily_usage["utc_date"]
        allowed = spent_usd < quota_usd
        return {
            "allowed": allowed,
            "quota_period": "UTC_NATURAL_DAY",
            "utc_date": day_str,
            "resets_at_utc": f"{day_str}T24:00:00Z",
            "daily_quota_usd": quota_usd,
            "spent_usd": round(spent_usd, 6),
            "remaining_quota_usd": round(max(0.0, quota_usd - spent_usd), 6),
        }

    def get_catalog_freshness_status(self) -> Dict[str, Any]:
        """
        O7: Checks whether `model_catalog.json` official pricing is within its freshness window (`max_freshness_days`).
        When stale, surfaces a prominent bilingual warning so users never silently rely on outdated pricing.
        """
        self.config_loader.reload_if_needed()
        cat = self.config_loader.catalog
        updated_str = str(cat.get("updated_at", "2026-10-28T00:00:00Z")).strip()
        max_days = float(cat.get("max_freshness_days", 30))
        try:
            tm = time.strptime(updated_str[:19], "%Y-%m-%dT%H:%M:%S")
            # Calculate UTC epoch without external dependencies
            import calendar
            updated_epoch = float(calendar.timegm(tm))
        except Exception:
            updated_epoch = self.storage.now_epoch()

        now_ep = self.storage.now_epoch()
        age_days = round(max(0.0, (now_ep - updated_epoch) / 86400.0), 2)
        is_stale = bool(age_days > max_days)
        if is_stale:
            warn_zh = (
                f"⚠️ 单价表过期提醒：当前官方模型价目表更新于 {updated_str[:10]}（距今 {age_days:.1f} 天，超过 {int(max_days)} 天保鲜期）。"
                "账本金额基于历史快照单价计算，请核对最新官方定价或更新 model_catalog.json。"
            )
            warn_en = (
                f"WARNING: Pricing catalog was updated on {updated_str[:10]} ({age_days:.1f} days ago > {int(max_days)}d freshness threshold). "
                "Ledger figures are computed using historical snapshot rates; please refresh model_catalog.json."
            )
        else:
            warn_zh = f"✅ 官方单价表处于保鲜期内（更新于 {updated_str[:10]}，已用 {age_days:.1f}/{int(max_days)} 天）。"
            warn_en = f"Official pricing catalog is fresh (updated {updated_str[:10]}, age {age_days:.1f}/{int(max_days)} days)."

        return {
            "status": "STALE_CATALOG_WARNING" if is_stale else "FRESH",
            "is_stale": is_stale,
            "updated_at": updated_str,
            "catalog_age_days": age_days,
            "max_freshness_days": max_days,
            "warning_zh": warn_zh,
            "warning_en": warn_en,
        }

    def get_mcp_registry_manifests(self) -> Dict[str, Any]:
        """
        O2: Returns synchronized directory manifests for the Official MCP Registry, Smithery, and PulseMCP,
        dynamically verified against the live self-description contract.
        """
        manifest_path = Path(__file__).resolve().parent / "data" / "mcp_registry_manifests.json"
        if manifest_path.exists():
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        else:
            data = {"project": __project__, "version": __version__}
        data["version"] = __version__
        return data

    def get_cost_ledger_summary(
        self, target_utc_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        M-08: One-Screen Cost Ledger Summary ("我 API 到底烧了多少钱").
        Returns Today's (or target date's) spend, Total cumulative spend, Model breakdown, and Quota status with zero setup.
        """
        usage = self.storage.get_usage_summary(target_utc_date=target_utc_date)
        quota = self.check_daily_quota()
        freshness = self.get_catalog_freshness_status()
        return {
            "utc_date": usage["utc_date"],
            "pricing_authority": "OFFICIAL_PUBLISHED_PROVIDER_RATES_USD_PER_1K_TOKENS",
            "catalog_freshness": freshness,
            "baseline_reference_model": self.config_loader.catalog.get(
                "baseline_model_id", "claude-3-7-sonnet-latest"
            ),
            "accounting_note_zh": "两级叙事体系：一级事实为按模型 ID × 方向（发出 prompt / 收到 completion / 缓存命中 cached）统计的官方一手 Token 用量；二级推算为在 Token 台账之上叠加官方单价折算之估算成本，保留真实对账与未回填估算分离展示，并附带价目表保鲜提醒。",
            "accounting_note_en": "Two-tier accounting: Tier 1 primary truth meters official first-hand token usage by Model ID × Direction (prompt / completion / cached); Tier 2 secondary derivation overlays official public rates on top of token facts with reconciled vs estimated separation and catalog freshness guards.",
            "narrative_tier1_zh": "一级事实：模型 ID × 方向一手 Token 台账（对齐官方 usage，永不过期、永不失真）",
            "narrative_tier2_zh": "二级推算：官方公开单价派生估算成本（保留对账分离与价目表保鲜提醒）",
            "today": {
                "requests": usage["today_requests"],
                "reconciled_requests": usage.get("today_reconciled_requests", 0),
                "estimated_requests": usage.get("today_estimated_requests", 0),
                "tokens": usage["today_tokens"],
                "prompt_tokens": usage.get("today_prompt_tokens", 0),
                "completion_tokens": usage.get("today_completion_tokens", 0),
                "cached_tokens": usage.get("today_cached_tokens", 0),
                "spent_usd": usage["today_cost_usd"],
                "actual_reconciled_usd": usage.get("today_actual_reconciled_cost_usd", 0.0),
                "estimated_unreconciled_usd": usage.get("today_estimated_unreconciled_cost_usd", 0.0),
                "baseline_opus_usd": usage["today_baseline_cost_usd"],
                "saved_usd": usage["today_savings_usd"],
                "daily_quota_usd": quota["daily_quota_usd"],
                "remaining_quota_usd": quota["remaining_quota_usd"],
            },
            "cumulative": {
                "total_requests": usage["total_requests"],
                "reconciled_requests": usage["reconciled_requests"],
                "estimated_requests": usage["pending_reconciliation_requests"],
                "total_tokens": usage["total_tokens"],
                "prompt_tokens": usage.get("total_prompt_tokens", 0),
                "completion_tokens": usage.get("total_completion_tokens", 0),
                "cached_tokens": usage.get("total_cached_tokens", 0),
                "total_spent_usd": usage["effective_cost_usd"],
                "actual_reconciled_usd": usage.get("total_actual_reconciled_cost_usd", 0.0),
                "estimated_unreconciled_usd": usage.get("total_estimated_unreconciled_cost_usd", 0.0),
                "baseline_opus_usd": usage["effective_baseline_cost_usd"],
                "total_saved_usd": usage["effective_savings_usd"],
                "savings_pct": usage["effective_savings_pct"],
            },
            "model_breakdown": usage["model_breakdown"],
            "day_model_breakdown": usage.get(
                "day_model_breakdown", usage["model_breakdown"]
            ),
            "recent_ledger": usage["recent_ledger"],
        }

    def process_agent_turn(
        self,
        session_id: str,
        task_prompt: str,
        inbound_payload: str = "",
        source_connector: str = "email_webhook",
        target_resources: Optional[List[str]] = None,
        outbound_sinks: Optional[List[str]] = None,
        prompt_tokens: Optional[int] = None,
        expected_output_tokens: int = 400,
        ephemeral_token: Optional[str] = None,
        provider_usage: Optional[Dict[str, Any]] = None,
        trace_steps: Optional[List[Dict[str, Any]]] = None,
        input_state_hash: Optional[str] = None,
        output_state_hash: Optional[str] = None,
        agent_id: str = "local_agent",
        record_ledger: bool = True,
        record_real_traffic: bool = True,
        caller_plane: str = "control",
        budget_cap_usd: Optional[float] = None,
        session_budget_cap_usd: Optional[float] = None,
        requested_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        R2: Executes a complete Agent turn through the 3-Tier Firewall, Closed-Loop Router, and Cost Ledger,
        coalescing all database writes and audit events within the turn into a single atomic SQLite transaction.
        """
        t_turn_start = time.perf_counter()
        pol = self.config_loader.get_effective_policy()
        max_retained = int(
            pol.get("gateway_overhead_budget", {}).get("max_retained_samples", 500)
        )

        inspect_text = f"{task_prompt}\n{inbound_payload}".strip()

        with self.storage.batch_write_transaction():
            verdict = self.firewall.inspect(
                payload=inspect_text,
                source_connector=source_connector,
                target_resources=target_resources,
                outbound_sinks=outbound_sinks,
                session_id=session_id,
                ephemeral_token=ephemeral_token,
                agent_id=agent_id,
                caller_plane=caller_plane,
            )

            resolved_ctx = verdict.tier_breakdown.get("trusted_context", {})
            if record_real_traffic and inspect_text:
                self.storage.record_real_traffic_sample(
                    sample_id=f"rt_samp_{verdict.request_id}",
                    agent_id=agent_id,
                    source_connector=str(
                        resolved_ctx.get("source_connector", source_connector)
                    ),
                    target_resources=list(
                        resolved_ctx.get("target_resources", target_resources or [])
                    ),
                    outbound_sinks=list(
                        resolved_ctx.get("outbound_sinks", outbound_sinks or [])
                    ),
                    sanitized_payload=verdict.sanitized_payload,
                    observed_risk_level=verdict.risk_level,
                    observed_confidence=verdict.confidence,
                    observed_action=verdict.action_taken,
                    observed_threats=verdict.detected_threats,
                    detection_latency_ms=verdict.detection_latency_ms,
                    max_retained=max_retained,
                )

            routing_dict: Optional[Dict[str, Any]] = None
            reconciled_usage: Optional[Dict[str, Any]] = None
            selected_model_name: Optional[str] = None
            route_req_id: Optional[str] = None

            overhead_so_far_ms = round(
                (time.perf_counter() - t_turn_start) * 1000.0, 3
            )

            if verdict.allowed:
                try:
                    routing = self.router.route(
                        task_prompt=task_prompt,
                        prompt_tokens=prompt_tokens,
                        expected_output_tokens=expected_output_tokens,
                        session_id=session_id,
                        budget_cap_usd=budget_cap_usd,
                        session_budget_cap_usd=session_budget_cap_usd,
                        detection_cost_usd=verdict.detection_cost_usd,
                        agent_id=agent_id,
                        record_ledger=record_ledger,
                        gateway_overhead_ms=overhead_so_far_ms,
                        enforce_budget_cap=True,
                        requested_model=requested_model,
                    )
                except BudgetCapExceededError as b_exc:
                    self.storage.append_audit_event(
                        event_type="BUDGET_HARD_CAP_BLOCKED",
                        session_id=session_id,
                        mode=verdict.mode,
                        decision_payload={
                            "request_id": verdict.request_id,
                            "agent_id": agent_id,
                            "budget": b_exc.budget_details,
                        },
                        agent_id=agent_id,
                    )
                    raise

                routing_dict = routing.to_dict()
                selected_model_name = routing.selected_model
                route_req_id = routing.request_id

                if provider_usage and record_ledger:
                    reconciled_usage = self.router.reconcile_usage(
                        request_id=routing.request_id,
                        selected_model=routing.selected_model,
                        actual_prompt_tokens=int(
                            provider_usage.get(
                                "prompt_tokens",
                                routing.extracted_features["estimated_prompt_tokens"],
                            )
                        ),
                        actual_completion_tokens=int(
                            provider_usage.get(
                                "completion_tokens", expected_output_tokens
                            )
                        ),
                        actual_cached_tokens=int(
                            provider_usage.get("cached_tokens", 0)
                        ),
                        latency_ms=float(provider_usage.get("latency_ms", 105.0)),
                        failed=bool(provider_usage.get("failed", False)),
                        quality_score=float(
                            provider_usage.get("quality_score", 0.95)
                        ),
                    )

            topology = self.breaker.evaluate_topology(
                trace_steps=trace_steps or [],
                input_state_hash=input_state_hash,
                output_state_hash=output_state_hash,
            )

            token_verif = verdict.tier_breakdown.get("token_verification") or {}
            turn_audit_events: List[Dict[str, Any]] = [
                {
                    "event_type": "GATEWAY_TURN_DECISION",
                    "session_id": session_id,
                    "mode": verdict.mode,
                    "agent_id": agent_id,
                    "decision_payload": {
                        "request_id": verdict.request_id,
                        "route_request_id": route_req_id,
                        "agent_id": agent_id,
                        "task_preview": task_prompt[:120],
                        "approved_by": token_verif.get("approved_by"),
                        "allowed": verdict.allowed,
                        "risk_level": verdict.risk_level,
                        "confidence": verdict.confidence,
                        "trifecta_triggered": verdict.trifecta_triggered,
                        "detected_threats": verdict.detected_threats,
                        "redacted_secrets": verdict.tier_breakdown.get(
                            "tier1_redacted_secrets", 0
                        ),
                        "action_taken": verdict.action_taken,
                        "effective_action": verdict.effective_action,
                        "selected_model": selected_model_name,
                        "reconciled": reconciled_usage is not None,
                    },
                }
            ]
            batch_entries = self.storage.append_audit_events_batch(
                turn_audit_events
            )
            audit_entry = batch_entries[-1]

            total_overhead_ms = round(float(verdict.detection_latency_ms) + 0.35, 3)
            est_mem_delta_kb = round(
                max(1.0, len(inspect_text.encode("utf-8")) / 1024.0 * 2.5), 3
            )
            overhead_status = self.record_gateway_overhead(
                overhead_ms=total_overhead_ms, memory_delta_kb=est_mem_delta_kb
            )

            self.storage.append_structured_log(
                request_id=verdict.request_id,
                level="INFO" if verdict.allowed else "WARN",
                event="GATEWAY_TURN_PROCESSED",
                details={
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "mode": verdict.mode,
                    "allowed": verdict.allowed,
                    "action_taken": verdict.action_taken,
                    "selected_model": selected_model_name,
                    "overhead_ms": total_overhead_ms,
                },
            )

        return {
            "request_id": verdict.request_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "mode": verdict.mode,
            "firewall": verdict.to_dict(),
            "routing": routing_dict,
            "usage_reconciliation": reconciled_usage,
            "topology": topology.to_dict(),
            "gateway_overhead": overhead_status,
            "audit": audit_entry,
        }

    # M-09 & R8: Daily Agent Behavior Digest & Report Center (Date History, Event Filtering, Pagination)
    def generate_daily_agent_report(
        self,
        fmt: str = "markdown",
        utc_date: Optional[str] = None,
        event_filter: str = "all",
        page: int = 1,
        page_size: int = 10,
    ) -> Dict[str, Any] | str:
        """
        M-09 & R8: Generates a human-readable and structured daily/historical Agent Behavior Report.
        Supports:
          - Historical date selection (`utc_date`, defaults to server's current UTC date)
          - Event type / verdict filtering (`event_filter`: `all` | `blocked` | `allowed` | `redacted` | `trifecta`)
          - Paginated event browsing (`page`, `page_size`)
          - Available historical dates index (`available_dates`)
        """
        day_str = (
            utc_date.strip()
            if (utc_date and utc_date.strip() and utc_date.strip().lower() != "today")
            else self.storage.now_utc_date()
        )
        ledger = self.get_cost_ledger_summary(
            target_utc_date=None if day_str.lower() == "all" else day_str
        )
        available_dates = self.storage.list_available_report_dates()
        full_day_query = self.storage.query_report_events(
            utc_date=day_str,
            event_filter="all",
            page=1,
            page_size=200,
        )
        paged_query = self.storage.query_report_events(
            utc_date=day_str,
            event_filter=event_filter,
            page=page,
            page_size=page_size,
        )

        day_events = full_day_query["all_matching_events"]
        turns = [
            e for e in day_events if e["event_type"] == "GATEWAY_TURN_DECISION"
        ]
        blocked_turns = [
            e
            for e in turns
            if not bool(e["decision"].get("allowed", True))
            or not str(e["decision"].get("action_taken", "ALLOW")).startswith("ALLOW")
        ]

        total_redacted_secrets = sum(
            int(e["decision"].get("redacted_secrets", 0)) for e in turns
        )
        trifecta_count = sum(
            1 for e in turns if bool(e["decision"].get("trifecta_triggered"))
        )

        threat_counter: CounterType[str] = Counter()
        blocked_highlights: List[Dict[str, Any]] = []
        for e in blocked_turns:
            dec = e["decision"]
            threats = dec.get("detected_threats", [])
            for t in threats:
                threat_counter[t.split("(")[0]] += 1
            blocked_highlights.append(
                {
                    "seq": e["seq"],
                    "timestamp": e["timestamp"],
                    "utc_date": e["utc_date"],
                    "agent_id": e["agent_id"],
                    "session_id": e["session_id"],
                    "risk_level": dec.get("risk_level", "HIGH"),
                    "confidence": dec.get("confidence", 0.0),
                    "action_taken": dec.get("action_taken"),
                    "threats": threats[:3],
                    "task_preview": dec.get("task_preview", ""),
                }
            )

        models_for_report = (
            ledger.get("day_model_breakdown")
            if day_str.lower() != "all" and ledger.get("day_model_breakdown")
            else ledger["model_breakdown"]
        )

        observe_would_block = [
            e
            for e in turns
            if e.get("mode") in ("observe", "shadow")
            and not str(e["decision"].get("action_taken", "ALLOW")).startswith("ALLOW")
        ]
        freshness = ledger.get("catalog_freshness") or self.get_catalog_freshness_status()

        digest_obj: Dict[str, Any] = {
            "report_type": "METERGATE_DAILY_AGENT_BEHAVIOR_DIGEST",
            "version": __version__,
            "utc_date": day_str,
            "generated_at": self.storage.now_iso(),
            "gateway_mode": self.config_loader.get_mode(),
            "catalog_freshness": freshness,
            "available_dates": available_dates,
            "filter": {
                "utc_date": day_str,
                "event_filter": event_filter,
                "supported_filters": [
                    "all",
                    "blocked",
                    "allowed",
                    "redacted",
                    "trifecta",
                ],
            },
            "pagination": {
                "page": paged_query["page"],
                "page_size": paged_query["page_size"],
                "total_count": paged_query["total_count"],
                "total_pages": paged_query["total_pages"],
                "has_prev": paged_query["has_prev"],
                "has_next": paged_query["has_next"],
            },
            "events_page": paged_query["items"],
            "summary": {
                "total_turns_today": len(turns),
                "allowed_turns_today": len(turns) - len(blocked_turns),
                "intercepted_threats_today": len(blocked_turns),
                "observe_only_would_block_today": len(observe_would_block),
                "lethal_trifecta_blocks_today": trifecta_count,
                "secrets_redacted_today": total_redacted_secrets,
                "today_tokens": ledger["today"].get("tokens", 0),
                "today_prompt_tokens": ledger["today"].get("prompt_tokens", 0),
                "today_completion_tokens": ledger["today"].get("completion_tokens", 0),
                "today_cached_tokens": ledger["today"].get("cached_tokens", 0),
                "cumulative_tokens": ledger["cumulative"].get("total_tokens", 0),
                "cumulative_prompt_tokens": ledger["cumulative"].get("prompt_tokens", 0),
                "cumulative_completion_tokens": ledger["cumulative"].get("completion_tokens", 0),
                "cumulative_cached_tokens": ledger["cumulative"].get("cached_tokens", 0),
                "today_spent_usd": ledger["today"]["spent_usd"],
                "today_actual_reconciled_usd": ledger["today"].get("actual_reconciled_usd", 0.0),
                "today_estimated_unreconciled_usd": ledger["today"].get("estimated_unreconciled_usd", 0.0),
                "today_saved_usd": ledger["today"]["saved_usd"],
                "cumulative_spent_usd": ledger["cumulative"]["total_spent_usd"],
                "cumulative_saved_usd": ledger["cumulative"]["total_saved_usd"],
                "savings_pct": ledger["cumulative"]["savings_pct"],
            },
            "models_called": models_for_report,
            "top_threats": dict(threat_counter.most_common(10)),
            "intercepted_incidents": blocked_highlights[:10],
            "hub_link": {
                "label": "更多省时间工具",
                "url": "https://00112238.xyz",
            },
        }

        fmt_low = fmt.lower()
        if fmt_low == "json":
            return digest_obj
        if fmt_low == "svg":
            return self._render_report_svg(digest_obj)
        if fmt_low == "html":
            return self._render_report_html(digest_obj)

        lines = [
            f"📋 【MeterGate · Agent 行为与 Token 计量日报】({day_str} | 筛选={event_filter} | 第 {paged_query['page']}/{paged_query['total_pages']} 页)",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "🕵️ 你的 Agent 今天背着你干了什么？",
            f"  • 总对话/工具调用 : {len(turns)} 次 (放行 {len(turns) - len(blocked_turns)} 次 | 拦截高危行为 {len(blocked_turns)} 次)",
            f"  • 致命三角阻断   : {trifecta_count} 次 (不可信输入 + 本地敏感配置 + 外部外发通道)",
            f"  • 自动脱敏密钥   : {total_redacted_secrets} 处 (.env / API Key 未出本机)",
            "",
            "📊 [一级事实] Token 用量台账 (按模型 ID × 方向一手计量 · 官方 Usage 对账):",
            f"  • 当日 Token 消耗 : {ledger['today'].get('tokens', 0):,} tokens (发出: {ledger['today'].get('prompt_tokens', 0):,} | 收到: {ledger['today'].get('completion_tokens', 0):,} | 缓存命中: {ledger['today'].get('cached_tokens', 0):,})",
            f"  • 累计 Token 消耗 : {ledger['cumulative'].get('total_tokens', 0):,} tokens (发出: {ledger['cumulative'].get('prompt_tokens', 0):,} | 收到: {ledger['cumulative'].get('completion_tokens', 0):,} | 缓存命中: {ledger['cumulative'].get('cached_tokens', 0):,})",
            "",
            "🤖 调用的模型分布与 Token 明细 (Models Called · 模型 ID × 方向):",
        ]
        if models_for_report:
            for m in models_for_report:
                p_tok = m.get('prompt_tokens', 0)
                c_tok = m.get('completion_tokens', 0)
                ca_tok = m.get('cached_tokens', 0)
                lines.append(
                    f"  • {m['model_id']:<20} : {m['calls']} 次调用 | 发出 {p_tok:,} tok · 收到 {c_tok:,} tok · 缓存 {ca_tok:,} tok (共 {m['tokens']:,} tok) -> [二级派生推算] 成本: ${m['cost_usd']:.6f}"
                )
        else:
            lines.append("  • (该日期暂无模型调用记录)")

        lines.extend([
            "",
            "💰 [二级推算] 官方单价成本估算 (Cost Ledger · 价目表派生价值 · 保留对账分离):",
            f"  • 当日真实已对账 : ${ledger['today'].get('actual_reconciled_usd', ledger['today']['spent_usd']):.6f} | 未回填估算 [估算]: ${ledger['today'].get('estimated_unreconciled_usd', 0.0):.6f}",
            f"  • 当日合计推算   : ${ledger['today']['spent_usd']:.6f} (相比基线模型推算净省 ${ledger['today']['saved_usd']:.6f})",
            f"  • 历史累计推算   : ${ledger['cumulative']['total_spent_usd']:.6f} (真实对账 ${ledger['cumulative'].get('actual_reconciled_usd', 0.0):.6f} | 预估 [估算] ${ledger['cumulative'].get('estimated_unreconciled_usd', 0.0):.6f} | 累计省 ${ledger['cumulative']['total_saved_usd']:.6f})",
        ])

        lines.append("")
        lines.append("🛡️ 拦截的高危行为摘录 (Intercepted Threats):")
        if blocked_highlights:
            for idx, inc in enumerate(blocked_highlights[:5], 1):
                t_str = (
                    ", ".join(inc["threats"])
                    if inc["threats"]
                    else inc["action_taken"]
                )
                lines.append(
                    f"  {idx}. [{inc['risk_level']} | 置信度 {inc['confidence']:.2f}] {inc['action_taken']}"
                )
                lines.append(f"     触发规则: {t_str}")
                if inc["task_preview"]:
                    lines.append(f"     载荷摘要: {inc['task_preview'][:80]}")
        else:
            lines.append("  • 零高危越权事件，Agent 行为全部合规。")

        lines.append("")
        lines.append(
            f"📑 分页事件明细 (Filter='{event_filter}' · Page {paged_query['page']}/{paged_query['total_pages']} · 共 {paged_query['total_count']} 条):"
        )
        if paged_query["items"]:
            for ev in paged_query["items"]:
                dec = ev.get("decision", {})
                act = dec.get("action_taken") or ev["event_type"]
                prev = dec.get("task_preview", "")[:60]
                lines.append(
                    f"  - [#{ev['seq']} {ev['timestamp']}] {ev['event_type']} | {act} | Agent={ev['agent_id']} {prev}"
                )
        else:
            lines.append("  - (当前筛选与分页条件下无事件记录)")

        if freshness.get("is_stale"):
            lines.extend(["", f"  {freshness['warning_zh']}"])
        lines.extend(
            [
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                "🖼️ 导出一张晒单海报图: metergate report --format svg --output report.svg",
                "🔗 更多省时间工具: https://00112238.xyz",
            ]
        )
        return "\n".join(lines) + "\n"

    def _render_report_svg(self, digest_obj: Dict[str, Any]) -> str:
        """
        O6: Renders a social-media-ready SVG poster card ("一张图看清：MeterGate 帮我的 Agent 拦了什么、烧了多少 Token、省了多少钱").
        """
        s = digest_obj["summary"]
        day_str = digest_obj["utc_date"]
        mode = str(digest_obj.get("gateway_mode", "enforce")).upper()
        fresh = digest_obj.get("catalog_freshness", {})
        fresh_badge = (
            "⚠️ 单价表已超保鲜期 (请刷新)"
            if fresh.get("is_stale")
            else f"✅ 官方公开单价核对 ({fresh.get('updated_at', '')[:10]})"
        )
        models = digest_obj.get("models_called", [])[:3]
        model_rows_svg = []
        y_pos = 370
        if models:
            for m in models:
                p_tok = m.get('prompt_tokens', 0)
                c_tok = m.get('completion_tokens', 0)
                ca_tok = m.get('cached_tokens', 0)
                m_line = (
                    f"• {m['model_id']}: {m['calls']} 次 | "
                    f"发出 {p_tok:,} · 收到 {c_tok:,} · 缓存 {ca_tok:,} (共 {m['tokens']:,} tok) | "
                    f"推算=${m.get('actual_reconciled_usd', m['cost_usd']):.6f}"
                )
                model_rows_svg.append(
                    f'<text x="48" y="{y_pos}" fill="#CBD5E1" font-family="monospace" font-size="13">{m_line}</text>'
                )
                y_pos += 24
        else:
            model_rows_svg.append(
                f'<text x="48" y="{y_pos}" fill="#94A3B8" font-family="monospace" font-size="14">• 今日暂无模型调用记录</text>'
            )

        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 500" width="880" height="500">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0B0F17" />
      <stop offset="100%" stop-color="#111827" />
    </linearGradient>
  </defs>
  <rect width="880" height="500" rx="20" fill="url(#bgGrad)" stroke="#1E293B" stroke-width="2"/>
  <text x="40" y="52" fill="#F8FAFC" font-family="system-ui, sans-serif" font-size="24" font-weight="bold">🛡️ MeterGate v{__version__} · Agent Token 计量与成本日报海报 ({day_str})</text>
  <text x="40" y="80" fill="#38BDF8" font-family="monospace" font-size="13">Mode: {mode} | 一级 Token 事实 × 二级成本推算 | 零遥测 · 100% 离线 | {fresh_badge}</text>

  <!-- 4 Metric Cards -->
  <rect x="40" y="105" width="190" height="105" rx="12" fill="#0F172A" stroke="#334155"/>
  <text x="56" y="132" fill="#94A3B8" font-family="system-ui, sans-serif" font-size="13">拦截高危越权 / 证据</text>
  <text x="56" y="172" fill="#F43F5E" font-family="monospace" font-size="30" font-weight="bold">{s["intercepted_threats_today"]} 次</text>
  <text x="56" y="195" fill="#64748B" font-family="monospace" font-size="12">致命三角阻断: {s["lethal_trifecta_blocks_today"]} 次</text>

  <rect x="246" y="105" width="190" height="105" rx="12" fill="#0F172A" stroke="#334155"/>
  <text x="262" y="132" fill="#94A3B8" font-family="system-ui, sans-serif" font-size="13">本地密钥自动脱敏</text>
  <text x="262" y="172" fill="#10B981" font-family="monospace" font-size="30" font-weight="bold">{s["secrets_redacted_today"]} 处</text>
  <text x="262" y="195" fill="#64748B" font-family="monospace" font-size="12">.env / sk-* 未出本机</text>

  <rect x="452" y="105" width="190" height="105" rx="12" fill="#0F172A" stroke="#334155"/>
  <text x="468" y="132" fill="#94A3B8" font-family="system-ui, sans-serif" font-size="13">[一级事实] 今日消耗 Token</text>
  <text x="468" y="172" fill="#38BDF8" font-family="monospace" font-size="24" font-weight="bold">{s.get("today_tokens", 0):,} tok</text>
  <text x="468" y="195" fill="#64748B" font-family="monospace" font-size="12">发出 {s.get("today_prompt_tokens", 0):,} | 收到 {s.get("today_completion_tokens", 0):,}</text>

  <rect x="658" y="105" width="182" height="105" rx="12" fill="#0F172A" stroke="#334155"/>
  <text x="674" y="132" fill="#94A3B8" font-family="system-ui, sans-serif" font-size="13">[二级推算] 官方折算花费</text>
  <text x="674" y="172" fill="#A78BFA" font-family="monospace" font-size="24" font-weight="bold">${s["today_spent_usd"]:.6f}</text>
  <text x="674" y="195" fill="#64748B" font-family="monospace" font-size="12">对账 ${s.get("today_actual_reconciled_usd", 0.0):.4f} | 净省 ${s.get("today_saved_usd", 0.0):.4f}</text>

  <!-- Models Breakdown Box -->
  <rect x="40" y="230" width="800" height="205" rx="12" fill="#0F172A" stroke="#334155"/>
  <text x="56" y="262" fill="#F8FAFC" font-family="system-ui, sans-serif" font-size="16" font-weight="bold">📊 一级事实：Token 用量台账 (模型 ID × 方向) ｜ 二级推算：官方单价估算</text>
  <text x="56" y="292" fill="#6EE7B7" font-family="monospace" font-size="13">• 总调用 {s["total_turns_today"]} 次（放行 {s["allowed_turns_today"]} 次 | 拦截 {s["intercepted_threats_today"]} 次） | 今日 Token: {s.get("today_tokens", 0):,} tok (缓存命中 {s.get("today_cached_tokens", 0):,} tok)</text>
  <text x="56" y="318" fill="#38BDF8" font-family="monospace" font-size="13">• [二级推算] 真实对账 ${s.get("today_actual_reconciled_usd", 0.0):.6f} | 未回填估算 [估算] ${s.get("today_estimated_unreconciled_usd", 0.0):.6f} | 累计省 ${s.get("cumulative_saved_usd", 0.0):.6f}</text>
  <text x="56" y="346" fill="#94A3B8" font-family="system-ui, sans-serif" font-size="14" font-weight="bold">🤖 调用的模型分布与 Token 明细 (Model ID × Prompt / Completion / Cached):</text>
  {"".join(model_rows_svg)}

  <text x="40" y="468" fill="#94A3B8" font-family="monospace" font-size="13">一行命令安装体验: pipx install metergate  或  uvx metergate serve --mode observe</text>
  <text x="610" y="468" fill="#38BDF8" font-family="monospace" font-size="13">🔗 更多省时间工具: https://00112238.xyz</text>
</svg>"""
        return svg

    def _render_report_html(self, digest_obj: Dict[str, Any]) -> str:
        """
        O6: Renders a standalone, 100% offline shareable HTML report containing the embedded SVG poster
        and full structured incident breakdown.
        """
        svg_card = self._render_report_svg(digest_obj)
        day_str = digest_obj["utc_date"]
        fresh = digest_obj.get("catalog_freshness", {})
        stale_banner = (
            f'<div style="background:#451A03;border:1px solid #F59E0B;color:#FDE68A;padding:12px;border-radius:10px;margin-bottom:16px;font-size:13px;">{fresh.get("warning_zh")}</div>'
            if fresh.get("is_stale")
            else ""
        )
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>MeterGate Agent 行为与成本日报 ({day_str})</title>
  <style>
    body {{ background:#0B0F17; color:#F8FAFC; font-family:system-ui,-apple-system,sans-serif; padding:28px; max-width:940px; margin:0 auto; }}
    .card {{ background:#111827; border:1px solid #1E293B; border-radius:16px; padding:20px; margin-top:20px; }}
    pre {{ background:#030712; padding:14px; border-radius:10px; color:#6EE7B7; overflow-x:auto; font-family:monospace; font-size:13px; }}
    a {{ color:#38BDF8; text-decoration:none; }}
  </style>
</head>
<body>
  {stale_banner}
  <div style="text-align:center;">{svg_card}</div>
  <div class="card">
    <h3 style="margin-top:0;">📋 结构化数据快照 (JSON Snapshot)</h3>
    <pre>{json.dumps(digest_obj["summary"], ensure_ascii=False, indent=2)}</pre>
    <p style="font-size:13px;color:#94A3B8;">由 MeterGate v{__version__} 本地离线生成 · <a href="https://00112238.xyz">更多省时间工具 (https://00112238.xyz)</a></p>
  </div>
</body>
</html>
"""

    # Export Self-Contained Cryptographic Audit Evidence Package (M-03 `evidence`, M-10 Data Integrity)
    def generate_audit_evidence_package(self) -> Dict[str, Any]:
        chain_verification = self.storage.verify_audit_chain()
        events = self.storage.list_audit_events(limit=500)
        chronological_events = list(reversed(events))
        ledger = self.get_cost_ledger_summary()

        generated_at = self.storage.now_iso()
        evidence_body = {
            "evidence_package_version": __version__,
            "project": "MeterGate",
            "generated_at": generated_at,
            "chain_integrity_proof": chain_verification,
            "cost_ledger_snapshot": ledger,
            "audit_trail_entries": chronological_events,
            "verification_instructions": (
                "Each audit_trail_entries[i].entry_hash is computed via local data-integrity HMAC-SHA256("
                "integrity_secret, prev_hash|timestamp|event_type|session_id|agent_id|mode|canonical_decision_json). "
                "The integrity_seal_hmac below protects this evidence snapshot against local file tampering."
            ),
        }
        canonical_body = json.dumps(
            evidence_body, ensure_ascii=False, sort_keys=True
        )
        seal_hmac = self.storage.compute_integrity_digest(canonical_body)
        return {
            "evidence": evidence_body,
            "integrity_seal_hmac": seal_hmac,
            "verifiable_offline": True,
        }

    # Cost Spike, Block Rate, and Upstream Failure Rate Anomaly Alerts
    def evaluate_operational_alerts(self) -> Dict[str, Any]:
        pol = self.config_loader.get_effective_policy()
        thresh = pol.get("alert_thresholds", {})
        cost_spike_ratio = float(thresh.get("cost_spike_quota_ratio", 0.80))
        single_spike_usd = float(thresh.get("single_request_spike_usd", 0.50))
        block_rate_thresh = float(thresh.get("block_rate_anomaly_pct", 40.0))
        up_fail_thresh = float(thresh.get("upstream_failure_rate_anomaly_pct", 20.0))

        quota_info = self.check_daily_quota()
        usage = self.storage.get_usage_summary()
        events = self.storage.list_audit_events(limit=100)
        feedback_rows = self.storage.list_model_feedback()

        alerts: List[Dict[str, Any]] = []

        q_usd = max(0.000001, float(quota_info["daily_quota_usd"]))
        spent_ratio = float(quota_info["spent_usd"]) / q_usd
        max_recent_req_cost = max(
            [
                float(r.get("actual_cost_usd") or r.get("estimated_cost_usd") or 0.0)
                for r in usage["recent_ledger"]
            ]
            or [0.0]
        )
        if spent_ratio >= cost_spike_ratio or max_recent_req_cost >= single_spike_usd:
            alerts.append(
                {
                    "alert_type": "COST_SPIKE_ANOMALY",
                    "severity": "HIGH" if spent_ratio >= 1.0 else "WARNING",
                    "metric_value": round(spent_ratio * 100.0, 2),
                    "max_single_request_usd": round(max_recent_req_cost, 6),
                    "message": f"Daily spend is {spent_ratio:.1%} of quota (${quota_info['spent_usd']}/${quota_info['daily_quota_usd']}), max single request=${max_recent_req_cost}.",
                }
            )

        turns = [e for e in events if e["event_type"] == "GATEWAY_TURN_DECISION"]
        if turns:
            blocked_cnt = sum(
                1
                for e in turns
                if not str(e["decision"].get("action_taken", "ALLOW")).startswith(
                    "ALLOW"
                )
            )
            block_pct = round((blocked_cnt / len(turns)) * 100.0, 2)
            if block_pct >= block_rate_thresh:
                alerts.append(
                    {
                        "alert_type": "BLOCK_RATE_ANOMALY",
                        "severity": "HIGH",
                        "metric_value": block_pct,
                        "threshold_pct": block_rate_thresh,
                        "message": f"High threat interception rate: {block_pct}% ({blocked_cnt}/{len(turns)}) of recent turns triggered firewall rules.",
                    }
                )

        for fb in feedback_rows:
            fail_pct = round(float(fb["ema_failure_rate"]) * 100.0, 2)
            if fail_pct >= up_fail_thresh:
                alerts.append(
                    {
                        "alert_type": "UPSTREAM_FAILURE_RATE_ANOMALY",
                        "severity": "CRITICAL",
                        "model_id": fb["model_id"],
                        "metric_value": fail_pct,
                        "threshold_pct": up_fail_thresh,
                        "message": f"Upstream model '{fb['model_id']}' EMA failure rate is {fail_pct}% (>= {up_fail_thresh}% threshold).",
                    }
                )

        freshness = self.get_catalog_freshness_status()
        if freshness["is_stale"]:
            alerts.append(
                {
                    "alert_type": "CATALOG_PRICING_STALE",
                    "severity": "WARNING",
                    "metric_value": freshness["catalog_age_days"],
                    "max_freshness_days": freshness["max_freshness_days"],
                    "message": freshness["warning_zh"],
                }
            )

        return {
            "evaluated_at": self.storage.now_iso(),
            "catalog_freshness": freshness,
            "active_alerts_count": len(alerts),
            "alerts": alerts,
        }

    def export_prometheus_metrics(self) -> str:
        ov = self.get_overhead_budget_status()
        u = self.storage.get_usage_summary()
        al = self.evaluate_operational_alerts()
        mode = self.config_loader.get_mode()
        lines = [
            "# HELP metergate_gateway_overhead_milliseconds Gateway single-hop processing overhead in ms",
            "# TYPE metergate_gateway_overhead_milliseconds gauge",
            f'metergate_gateway_overhead_milliseconds{{quantile="0.5"}} {ov["p50_gateway_overhead_ms"]}',
            f'metergate_gateway_overhead_milliseconds{{quantile="0.95"}} {ov["p95_gateway_overhead_ms"]}',
            f'metergate_gateway_overhead_milliseconds{{quantile="budget_cap"}} {ov["max_gateway_overhead_budget_ms"]}',
            "# HELP metergate_requests_total Total gateway requests recorded in usage ledger",
            "# TYPE metergate_requests_total counter",
            f'metergate_requests_total{{mode="{mode}"}} {u["total_requests"]}',
            "# HELP metergate_today_spend_usd Today routed spend USD",
            "# TYPE metergate_today_spend_usd gauge",
            f'metergate_today_spend_usd {u["today_cost_usd"]}',
            "# HELP metergate_spend_usd_total Total cumulative routed spend USD",
            "# TYPE metergate_spend_usd_total gauge",
            f'metergate_spend_usd_total {u["effective_cost_usd"]}',
            "# HELP metergate_savings_usd_total Total cumulative savings USD",
            "# TYPE metergate_savings_usd_total gauge",
            f'metergate_savings_usd_total {u["effective_savings_usd"]}',
            "# HELP metergate_active_alerts_total Number of active anomaly alerts",
            "# TYPE metergate_active_alerts_total gauge",
            f'metergate_active_alerts_total {al["active_alerts_count"]}',
        ]
        return "\n".join(lines) + "\n"

    def run_security_baseline_check(
        self, listen_host: str = "127.0.0.1", listen_port: int = 8787
    ) -> Dict[str, Any]:
        checks: List[Dict[str, Any]] = []

        perm_ok = True
        checked_files = []
        for fp in (
            Path(self.storage.db_path),
            self.storage.integrity_key_path,
        ):
            if fp.exists():
                mode_bits = stat.S_IMODE(fp.stat().st_mode)
                is_private = (mode_bits & 0o077) == 0
                if not is_private:
                    perm_ok = False
                checked_files.append(
                    {
                        "file": fp.name,
                        "mode_octal": oct(mode_bits),
                        "private_0600": is_private,
                    }
                )
        checks.append(
            {
                "check_id": "SEC_CHECK_FILE_PERMISSIONS",
                "title": "Local Integrity Key & Database File Permissions (0600)",
                "passed": perm_ok,
                "details": checked_files,
                "remediation": "chmod 600 ~/.metergate/* ~/.metergate/.* && chmod 700 ~/.metergate",
            }
        )

        loopback_hosts = {"127.0.0.1", "localhost", "::1", "[::1]"}
        bind_safe = listen_host.strip() in loopback_hosts
        checks.append(
            {
                "check_id": "SEC_CHECK_NETWORK_EXPOSURE",
                "title": "Loopback Bind Isolation & Zero Wildcard CORS",
                "passed": bind_safe,
                "details": {"listen_host": listen_host, "listen_port": listen_port},
                "remediation": "Bind gateway to 127.0.0.1 or place behind reverse proxy if exposing across network.",
            }
        )

        pol = self.config_loader.policy
        bounds_ok = bool(
            pol.get("resource_limits", {}).get("max_request_body_bytes", 0) <= 1048576
            and pol.get("budget_constraints", {}).get("enforce_hard_stop", False)
            and pol.get("trusted_context_resolution", {}).get(
                "ignore_data_plane_caller_claims", False
            )
            and len(self.config_loader.rejected_unsafe_rules) == 0
        )
        checks.append(
            {
                "check_id": "SEC_CHECK_POLICY_INVARIANTS",
                "title": "ARC-1 Trusted Context, ARC-4 Hard Budget Cap, R5 ReDoS Guard & Payload Bounds Enabled",
                "passed": bounds_ok,
                "details": {
                    "ignore_data_plane_caller_claims": pol.get(
                        "trusted_context_resolution", {}
                    ).get("ignore_data_plane_caller_claims"),
                    "enforce_hard_stop": pol.get("budget_constraints", {}).get(
                        "enforce_hard_stop"
                    ),
                    "max_request_body_bytes": pol.get("resource_limits", {}).get(
                        "max_request_body_bytes"
                    ),
                    "rejected_unsafe_regex_rules": self.config_loader.rejected_unsafe_rules,
                },
                "remediation": "Ensure default_policy.json enables ignore_data_plane_caller_claims, enforce_hard_stop, and ReDoS-safe regex patterns.",
            }
        )

        chain = self.storage.verify_audit_chain()
        checks.append(
            {
                "check_id": "SEC_CHECK_AUDIT_CHAIN_INTEGRITY",
                "title": "Local HMAC-SHA256 Audit Log Chain Integrity",
                "passed": bool(chain["valid"]),
                "details": chain,
                "remediation": "Restore from latest verified backup if audit chain tampering is detected.",
            }
        )

        all_passed = all(c["passed"] for c in checks)
        return {
            "status": "PASS" if all_passed else "WARN",
            "checked_at": self.storage.now_iso(),
            "total_checks": len(checks),
            "passed_checks": sum(1 for c in checks if c["passed"]),
            "checks": checks,
        }

    # B4: One-Click Allow & Remember (Auto-selects optimal granularity without user friction)
    def allow_and_remember(
        self,
        payload: str,
        source_connector: Optional[str] = None,
        note: str = "One-click Allow & Remember",
    ) -> Dict[str, Any]:
        """
        B4 & A3: Single-action false-positive remediation.
        Automatically computes and stores both the exact payload SHA-256 and a normalized core snippet
        so the user or Agent never has to choose between allowlist granularities or edit JSON files.
        """
        clean_text = (payload or "").strip()
        if not clean_text:
            raise ValueError("Payload cannot be empty for allow_and_remember.")
        payload_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()
        snippet = clean_text[:80]

        with self.storage.batch_write_transaction():
            sha_entry = self.storage.add_allowlist_entry(
                entry_type="payload_sha256",
                value=payload_hash,
                note=f"{note} (auto-sha256)",
            )
            pat_entry = self.storage.add_allowlist_entry(
                entry_type="pattern",
                value=snippet,
                note=f"{note} (auto-snippet)",
            )
            self.storage.append_audit_event(
                event_type="ONE_CLICK_ALLOW_AND_REMEMBER",
                session_id="system",
                mode=self.config_loader.get_mode(),
                decision_payload={
                    "payload_sha256": payload_hash,
                    "snippet_recorded": snippet,
                    "source_connector": source_connector,
                },
            )
        return {
            "status": "ALLOWED_AND_REMEMBERED",
            "what_happened_zh": "已放行该请求并自动记住特征，后续相同或同类正常请求将直接通过，无需修改任何配置文件。",
            "what_to_do_zh": "现在可以直接重发刚才的请求。",
            "what_happened_en": "Payload allowed and remembered automatically (both SHA-256 and phrase pattern recorded).",
            "what_to_do_en": "You can now retry the request immediately.",
            "recorded_entries": [sha_entry, pat_entry],
            "allowlist_count": len(self.storage.list_allowlist_entries()),
        }

    # A4: Pre-Flight Budget Query & Cost Simulation
    def query_preflight_budget(
        self,
        session_id: str = "sess_default",
        estimated_prompt_tokens: int = 500,
        expected_output_tokens: int = 400,
        model: str = "auto",
    ) -> Dict[str, Any]:
        """
        A4: Allows an Agent to query remaining daily, session, and single-request budget BEFORE executing
        a turn, turning unexpected HTTP 429 failures into predictable, plannable model downgrades.
        """
        self.config_loader.reload_if_needed()
        policy = self.config_loader.get_effective_policy()
        catalog = self.config_loader.catalog
        models = catalog.get("models", {})

        bc_cfg = policy.get("budget_constraints", {})
        max_req_usd = float(bc_cfg.get("default_max_request_cost_usd", 2.00))
        max_sess_usd = float(bc_cfg.get("default_max_session_cost_usd", 20.00))

        daily_quota = self.check_daily_quota()
        sess_info = self.storage.get_session_spend_usd(session_id)
        sess_spent = float(sess_info["session_spent_usd"])
        sess_remaining = round(max(0.0, max_sess_usd - sess_spent), 6)

        resolved_model = (
            model
            if (model and model != "auto" and model in models)
            else "deepseek-chat"
        )
        if resolved_model not in models:
            resolved_model = next(iter(models.keys()))
        m_meta = models[resolved_model]
        est_cost = self.router._compute_cost(
            m_meta, int(estimated_prompt_tokens), int(expected_output_tokens)
        )

        req_ok = est_cost <= max_req_usd
        sess_ok = (sess_spent + est_cost) <= max_sess_usd
        daily_ok = daily_quota["allowed"] and (
            est_cost <= float(daily_quota["remaining_quota_usd"])
        )
        will_succeed = bool(req_ok and sess_ok and daily_ok)

        # Find cheapest model for downgrade recommendation
        cheapest_id = min(
            models.keys(),
            key=lambda mid: self.router._compute_cost(
                models[mid],
                int(estimated_prompt_tokens),
                int(expected_output_tokens),
            ),
        )
        cheapest_cost = self.router._compute_cost(
            models[cheapest_id],
            int(estimated_prompt_tokens),
            int(expected_output_tokens),
        )

        if will_succeed:
            reason_code = "BUDGET_SUFFICIENT"
            msg_zh = f"预算充足：预计本次花费 ${est_cost:.6f}（当前会话剩余 ${sess_remaining:.4f}，今日剩余 ${daily_quota['remaining_quota_usd']:.4f}）。"
            msg_en = f"Budget sufficient: estimated request cost is ${est_cost:.6f} (session remaining ${sess_remaining:.4f}, daily remaining ${daily_quota['remaining_quota_usd']:.4f})."
        else:
            reason_code = "BUDGET_PREFLIGHT_WOULD_EXCEED"
            msg_zh = f"预算预警：预计花费 ${est_cost:.6f} 将超出硬上限，建议改用低成本模型 {cheapest_id}（预计仅需 ${cheapest_cost:.6f}）或缩减上下文长度。"
            msg_en = f"Budget warning: estimated cost ${est_cost:.6f} exceeds remaining cap; downgrade to {cheapest_id} (est. ${cheapest_cost:.6f}) or reduce prompt length."

        return {
            "status": "OK" if will_succeed else "BUDGET_WARNING",
            "reason_code": reason_code,
            "will_succeed": will_succeed,
            "what_happened_zh": msg_zh,
            "what_to_do_zh": "可正常发起请求。" if will_succeed else f"将请求参数 model 改为 '{cheapest_id}' 或新开会话。",
            "what_happened_en": msg_en,
            "what_to_do_en": "Proceed normally." if will_succeed else f"Switch model parameter to '{cheapest_id}' or start a new session.",
            "daily_budget": daily_quota,
            "session_budget": {
                "session_id": session_id,
                "max_session_cost_usd": max_sess_usd,
                "spent_usd": sess_spent,
                "remaining_usd": sess_remaining,
                "turns_count": sess_info["turns_count"],
                "allowed": sess_ok,
            },
            "request_budget": {
                "max_request_cost_usd": max_req_usd,
                "allowed": req_ok,
            },
            "preflight_simulation": {
                "requested_model": model,
                "resolved_model": resolved_model,
                "estimated_prompt_tokens": int(estimated_prompt_tokens),
                "expected_output_tokens": int(expected_output_tokens),
                "estimated_cost_usd": est_cost,
                "cost_type": "ESTIMATED_PREFLIGHT",
                "recommended_downgrade_model": cheapest_id,
                "downgrade_estimated_cost_usd": cheapest_cost,
            },
        }

    # A2 & B5: Machine-Readable Self-Description & First-Screen Capability Boundaries
    def get_machine_self_description(self) -> Dict[str, Any]:
        """
        A2 & B5: Single Source of Truth machine-readable self-description contract.
        Exposes what MeterGate can intercept, what it cannot catch (blind spots), official pricing rates,
        concurrency limits, and deterministic error/reason codes so Humans and Agents read the exact same truth.
        """
        self.config_loader.reload_if_needed()
        pol = self.config_loader.get_effective_policy()
        cat = self.config_loader.catalog
        freshness = self.get_catalog_freshness_status()
        return {
            "contract_version": __version__,
            "project": "MeterGate",
            "version": __version__,
            "license": "MIT",
            "trust_signals": {
                "zero_telemetry": True,
                "offline_100_percent": True,
                "mit_open_source": True,
                "zero_paywall": True,
                "observe_only_zero_risk_mode": True,
                "zero_residue_uninstall": True,
            },
            "selection_decision_matrix": {
                "when_to_recommend": [
                    "SYMPTOM_COST_BLINDNESS: User complains they do not know how much money their AI Agent (Claude Code, Cursor, OpenClaw, MCP) is spending daily or why bills spiked.",
                    "SYMPTOM_SECRET_LEAK_FEAR: User worries about .env, sk-*, AKIA*, or SSH private keys leaking to external LLM APIs or third-party MCP tools.",
                    "SYMPTOM_FEAR_OF_BREAKING_AGENT: User wants zero-risk Observe-Only mode (metergate serve --mode observe) to audit traffic and cost for a week without blocking any Agent calls.",
                    "SYMPTOM_ZERO_TELEMETRY_OFFLINE: User requires 100% local, offline, zero-telemetry security & FinOps auditing.",
                ],
                "when_not_to_recommend": [
                    "ANTI_SYMPTOM_MULTI_TENANT_TEAM: Multi-tenant enterprise team sharing, RBAC, or centralized multi-user billing.",
                    "ANTI_SYMPTOM_HIGH_CONCURRENCY_CLUSTER: Public high-concurrency API gateway clusters (> 32 concurrent in-flight upstream requests).",
                    "ANTI_SYMPTOM_MULTIMODAL_DEEP_LLM_JUDGE: Image/PDF binary steganography inspection or heavyweight neural LLM semantic judging.",
                ],
            },
            "catalog_freshness": freshness,
            "mcp_registry_manifests_endpoint": "/.well-known/mcp-registry.json",
            "positioning_declaration": pol.get(
                "positioning_declaration",
                {
                    "deployment_profile_zh": "单实例本机 AI Agent 安全防火墙与成本账本网关（最大 32 并发在途请求，专为个人开发者与单机 Agent 设计，不适用于多租户团队共享）。",
                    "deployment_profile_en": "Single-instance local AI Agent security firewall and cost ledger gateway (max 32 concurrent in-flight requests; not for multi-tenant team sharing).",
                    "single_instance_only": True,
                    "max_concurrent_inflight_requests": 32,
                    "team_multi_tenant_supported": False,
                },
            ),
            "capability_boundaries": {
                "what_it_catches": [
                    {
                        "tier": "Tier 1 (Deterministic & Secret Vault)",
                        "zh": "明文与编码混淆（Base64/Hex/URL/零宽字符/拆字）提示注入指令；本地 .env / sk-* / AKIA* / 私钥自动脱敏替换为 [REDACTED_BY_METERGATE_VAULT]",
                        "en": "Explicit and obfuscated (Base64/Hex/URL/Zero-Width/split-token) prompt injection directives; automatic local redaction of .env, sk-*, AKIA*, and private keys.",
                    },
                    {
                        "tier": "Tier 2 (Heuristic Concept & N-gram Scorer)",
                        "zh": "包含『作废/忽略/重写 + 环境变量/密钥 + 外发/回调』概念簇组合的中英双语同义改写指令",
                        "en": "Bilingual paraphrased overrides matching concept clusters (override + action + sensitive target) and N-gram similarity.",
                    },
                    {
                        "tier": "Tier 3 (Lethal Trifecta Taint Guard)",
                        "zh": "同时具备『外部不可信输入源 + 本地敏感资源证据 + 外部外发通道证据』的致命三角越权链路",
                        "en": "Lethal Trifecta chains combining Untrusted Input + Evidence of Sensitive Local Resource + Evidence of External Exfil Sink.",
                    },
                ],
                "what_it_cannot_catch_blind_spots": [
                    {
                        "id": "BLIND_SPOT_01_ZERO_SHOT_PARAPHRASE",
                        "zh": "Tier 2 为轻量启发式规则（非大模型推理）：完全避开概念词表的零样本隐喻改写可能漏过（需要人工留意陌生来源的长指令）",
                        "en": "Tier 2 is a heuristic concept/N-gram scorer, NOT a neural LLM: zero-shot metaphors avoiding all concept vocabulary may evade detection.",
                    },
                    {
                        "id": "BLIND_SPOT_02_MULTIMODAL_STEGANOGRAPHY",
                        "zh": "不解析图片像素或 PDF 二进制流中的隐写提示词（仅检测文本与结构化 JSON 载荷）",
                        "en": "Does not inspect image pixels or binary PDF steganography (inspects text and JSON tool payloads only).",
                    },
                    {
                        "id": "BLIND_SPOT_03_AUTHORIZED_BUSINESS_LOGIC",
                        "zh": "不拦截未触碰敏感凭证且无外发行为的纯业务逻辑错误（如正常代码写错算法）",
                        "en": "Does not block authorized business logic bugs that do not touch sensitive secrets or external exfiltration sinks.",
                    },
                ],
            },
            "pricing_catalog": {
                "pricing_authority": cat.get(
                    "pricing_authority",
                    "OFFICIAL_PUBLISHED_PROVIDER_RATES_USD_PER_1K_TOKENS",
                ),
                "baseline_model_id": cat.get(
                    "baseline_model_id", "claude-3-7-sonnet-latest"
                ),
                "models": cat.get("models", {}),
                "accounting_semantics": {
                    "ACTUAL_BILLABLE": "Reconciled from upstream provider response usage.prompt_tokens and usage.completion_tokens multiplied by official public 1K rates.",
                    "ESTIMATED_ONLY": "Pre-response or blocked-turn token estimate based on character count; explicitly separated from actual reconciled spend.",
                },
            },
            "concurrency_and_limits": {
                "max_concurrent_inflight_upstream_requests": int(
                    pol.get("upstream_cluster", {}).get(
                        "max_concurrent_inflight_requests", 32
                    )
                ),
                "max_keepalive_connections_per_upstream": int(
                    pol.get("upstream_cluster", {}).get(
                        "max_pool_size_per_upstream", 16
                    )
                ),
                "max_request_body_bytes": int(
                    pol.get("resource_limits", {}).get(
                        "max_request_body_bytes", 262144
                    )
                ),
                "max_input_payload_chars": int(
                    pol.get("resource_limits", {}).get(
                        "max_input_payload_chars", 65536
                    )
                ),
                "max_regex_pattern_length": int(
                    pol.get("resource_limits", {}).get(
                        "max_regex_pattern_length", 512
                    )
                ),
            },
            "error_and_reason_codes": {
                "ALLOW_CLEAN": {
                    "http_status": 200,
                    "idempotent": True,
                    "agent_action": "PROCEED",
                },
                "ALLOW_SECRET_REDACTED": {
                    "http_status": 200,
                    "idempotent": True,
                    "agent_action": "PROCEED_WITH_REDACTED_VAULT_PLACEHOLDER",
                },
                "ALLOW_BY_ALLOWLIST": {
                    "http_status": 200,
                    "idempotent": True,
                    "agent_action": "PROCEED",
                },
                "ALLOW_WITH_EPHEMERAL_TOKEN": {
                    "http_status": 200,
                    "idempotent": False,
                    "agent_action": "PROCEED_ONE_TIME",
                },
                "BLOCK_PROMPT_INJECTION": {
                    "http_status": 403,
                    "idempotent": True,
                    "agent_action": "USE_SANITIZED_PAYLOAD_OR_ONE_CLICK_ALLOW",
                },
                "BLOCK_HEURISTIC_OVERRIDE": {
                    "http_status": 403,
                    "idempotent": True,
                    "agent_action": "USE_SANITIZED_PAYLOAD_OR_ONE_CLICK_ALLOW",
                },
                "BLOCK_LETHAL_TRIFECTA": {
                    "http_status": 403,
                    "idempotent": True,
                    "agent_action": "REQUEST_HUMAN_APPROVAL_OR_REMOVE_EXFIL_SINK",
                },
                "BLOCK_RESOURCE_LIMIT": {
                    "http_status": 413,
                    "idempotent": True,
                    "agent_action": "TRUNCATE_PAYLOAD_BELOW_65536_CHARS",
                },
                "BLOCK_BUDGET_CAP_EXCEEDED": {
                    "http_status": 429,
                    "idempotent": True,
                    "agent_action": "QUERY_BUDGET_API_AND_SWITCH_TO_LOWER_COST_MODEL",
                },
                "UPSTREAM_BACKPRESSURE_SHEDDING": {
                    "http_status": 503,
                    "idempotent": False,
                    "agent_action": "BACKOFF_AND_RETRY_AFTER_250MS",
                },
            },
            "protocols_supported": {
                "openai_chat_completions": "/v1/chat/completions",
                "anthropic_messages": "/v1/messages",
                "mcp_jsonrpc_http": "/mcp",
                "mcp_jsonrpc_stdio": "metergate serve --mcp-stdio",
                "preflight_budget": "/api/v1/budget",
                "one_click_allow_and_remember": "/api/v1/firewall/allow-and-remember",
                "llms_txt_discovery": "/llms.txt",
            },
            "unattended_agent_setup": {
                "zero_git_uvx": "uvx metergate serve --mcp-stdio",
                "zero_git_pipx": "pipx install metergate && metergate serve --mode observe",
                "step_1_install": "pipx install metergate  # or: pip install metergate / pip install -e .",
                "step_2_start_mcp_or_http": "metergate serve --mcp-stdio  # or zero-risk HTTP: metergate serve --mode observe --port 8787",
                "step_3_self_check": "metergate doctor",
            },
        }

    # B3: Zero-Config Agent Takeover Profiles
    def get_agent_takeover_profiles(
        self, base_url: str = "http://127.0.0.1:8787"
    ) -> Dict[str, Any]:
        """
        B3: Provides zero-config takeover switches for mainstream Agent clients and coding assistants
        (Claude Code, Cursor, OpenAI SDK, Anthropic SDK, Claude Desktop MCP, Codex CLI) so users
        never have to manually edit policy JSON or figure out protocol details.
        """
        clean_base = base_url.rstrip("/")
        shell_exports = (
            f"export OPENAI_BASE_URL='{clean_base}/v1'\n"
            f"export ANTHROPIC_BASE_URL='{clean_base}'\n"
            f"export METERGATE_GATEWAY_URL='{clean_base}'\n"
            "export OPENAI_API_KEY='${OPENAI_API_KEY:-sk-metergate-zero-config}'"
        )
        return {
            "gateway_base_url": clean_base,
            "one_line_terminal_switch": "eval '$(metergate serve --export-env)'",
            "shell_export_script": shell_exports,
            "profiles": {
                "claude_code_and_anthropic": {
                    "title_zh": "Claude Code / Anthropic SDK 一键接管",
                    "command": f"export ANTHROPIC_BASE_URL='{clean_base}'",
                    "endpoint": f"{clean_base}/v1/messages",
                },
                "openai_codex_cursor_langchain": {
                    "title_zh": "OpenAI SDK / Codex CLI / LangChain 一键接管",
                    "command": f"export OPENAI_BASE_URL='{clean_base}/v1'",
                    "endpoint": f"{clean_base}/v1/chat/completions",
                },
                "mcp_standard_clients": {
                    "title_zh": "Claude Desktop / Cursor / Windsurf 标准 MCP 零配置挂载",
                    "mcpServers": {
                        "metergate": {
                            "command": "metergate",
                            "args": ["serve", "--mcp-stdio"],
                        }
                    },
                    "http_jsonrpc_endpoint": f"{clean_base}/mcp",
                },
            },
        }

    # A1 & A5: Standard MCP (Model Context Protocol) JSON-RPC 2.0 Handler
    def handle_mcp_jsonrpc(self, rpc_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        A1 & A5: Implements the standard Model Context Protocol (MCP, JSON-RPC 2.0) lifecycle:
          - `initialize`
          - `notifications/initialized`
          - `ping`
          - `tools/list`
          - `tools/call` (`metergate_inspect_and_guard`, `metergate_check_budget`,
                          `metergate_self_describe`, `metergate_remediate_false_positive`)
          - `resources/list` & `resources/read`
        Uses evidence-based defaults (`target_resources=[]`, `outbound_sinks=[]`) so normal tool calls
        are never falsely assumed guilty (`A5`).
        """
        req_id = rpc_payload.get("id")
        method = str(rpc_payload.get("method", "")).strip()
        params = rpc_payload.get("params") or {}
        if not isinstance(params, dict):
            params = {}

        def _ok(result_obj: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result_obj,
            }

        def _err(code: int, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            err_body: Dict[str, Any] = {"code": code, "message": message}
            if data is not None:
                err_body["data"] = data
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": err_body,
            }

        if method == "initialize":
            return _ok(
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": "metergate",
                        "version": __version__,
                    },
                }
            )

        if method in ("notifications/initialized", "initialized"):
            return _ok({"acknowledged": True})

        if method == "ping":
            return _ok({})

        if method == "tools/list":
            return _ok(
                {
                    "tools": [
                        {
                            "name": "metergate_inspect_and_guard",
                            "description": (
                                "Inspects an AI Agent prompt or tool-call payload for prompt injection, "
                                "automatically redacts local secrets (.env, sk-*, AKIA*, id_rsa) into [REDACTED_BY_METERGATE_VAULT], "
                                "and returns an idempotent verdict with reason_code and self-healing remediation."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "payload": {
                                        "type": "string",
                                        "description": "Prompt text or serialized tool arguments to inspect and redact.",
                                    },
                                    "source_connector": {
                                        "type": "string",
                                        "description": "Origin connector (default: local_cli; untrusted examples: email_webhook, external_web_scrape).",
                                        "default": "local_cli",
                                    },
                                    "target_resources": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Optional explicit target resources (defaults to empty []; inferred from evidence).",
                                    },
                                    "outbound_sinks": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Optional explicit outbound sinks (defaults to empty []; inferred from evidence).",
                                    },
                                    "session_id": {
                                        "type": "string",
                                        "default": "sess_mcp",
                                    },
                                },
                                "required": ["payload"],
                            },
                        },
                        {
                            "name": "metergate_check_budget",
                            "description": (
                                "Pre-flight budget query: checks remaining daily and session budget in USD, "
                                "simulates estimated cost for an upcoming LLM call, and recommends a lower-cost model if needed."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "session_id": {
                                        "type": "string",
                                        "default": "sess_default",
                                    },
                                    "estimated_prompt_tokens": {
                                        "type": "integer",
                                        "default": 500,
                                    },
                                    "expected_output_tokens": {
                                        "type": "integer",
                                        "default": 400,
                                    },
                                    "model": {
                                        "type": "string",
                                        "default": "auto",
                                    },
                                },
                            },
                        },
                        {
                            "name": "metergate_self_describe",
                            "description": (
                                "Returns MeterGate machine-readable self-description contract: what it intercepts, "
                                "known blind spots, official model pricing catalog, concurrency limits, and reason codes."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                            },
                        },
                        {
                            "name": "metergate_remediate_false_positive",
                            "description": (
                                "One-step allow-and-remember remediation when a benign payload was blocked by a heuristic rule."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "payload": {
                                        "type": "string",
                                        "description": "The benign payload to allow and remember.",
                                    },
                                    "note": {
                                        "type": "string",
                                        "default": "MCP tool remediation",
                                    },
                                },
                                "required": ["payload"],
                            },
                        },
                    ]
                }
            )

        if method == "resources/list":
            return _ok(
                {
                    "resources": [
                        {
                            "uri": "metergate://contract/self-description",
                            "name": "MeterGate Machine Self-Description Contract",
                            "mimeType": "application/json",
                            "description": "Capabilities, blind spots, official pricing catalog, concurrency limits, and reason codes.",
                        },
                        {
                            "uri": "metergate://discovery/llms.txt",
                            "name": "MeterGate GEO Discovery Manifest (llms.txt)",
                            "mimeType": "text/plain",
                            "description": "Unattended 3-step Agent setup and structured endpoint directory.",
                        },
                    ]
                }
            )

        if method == "resources/read":
            uri = str(params.get("uri", ""))
            if uri == "metergate://contract/self-description":
                contract_json = json.dumps(
                    self.get_machine_self_description(), ensure_ascii=False, indent=2
                )
                return _ok(
                    {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": contract_json,
                            }
                        ]
                    }
                )
            if uri == "metergate://discovery/llms.txt":
                llms_path = Path(__file__).resolve().parent / "data" / "llms.txt"
                llms_txt = (
                    llms_path.read_text(encoding="utf-8")
                    if llms_path.exists()
                    else f"MeterGate v{__version__}"
                )
                return _ok(
                    {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "text/plain",
                                "text": llms_txt,
                            }
                        ]
                    }
                )
            return _err(-32602, f"Unknown resource URI: {uri}")

        if method == "tools/call":
            tool_name = str(params.get("name", "")).strip()
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                args = {}

            if tool_name == "metergate_self_describe":
                desc = self.get_machine_self_description()
                return _ok(
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(desc, ensure_ascii=False),
                            }
                        ],
                        "structuredContent": desc,
                        "isError": False,
                    }
                )

            if tool_name == "metergate_check_budget":
                b_res = self.query_preflight_budget(
                    session_id=str(args.get("session_id", "sess_default")),
                    estimated_prompt_tokens=int(
                        args.get("estimated_prompt_tokens", 500)
                    ),
                    expected_output_tokens=int(
                        args.get("expected_output_tokens", 400)
                    ),
                    model=str(args.get("model", "auto")),
                )
                return _ok(
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(b_res, ensure_ascii=False),
                            }
                        ],
                        "structuredContent": b_res,
                        "isError": not b_res["will_succeed"],
                    }
                )

            if tool_name == "metergate_remediate_false_positive":
                rem_res = self.allow_and_remember(
                    payload=str(args.get("payload", "")),
                    note=str(args.get("note", "MCP tool remediation")),
                )
                return _ok(
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(rem_res, ensure_ascii=False),
                            }
                        ],
                        "structuredContent": rem_res,
                        "isError": False,
                    }
                )

            # Default/primary tool: metergate_inspect_and_guard or any wrapped tool call (A5: evidence-based empty defaults)
            payload_text = str(
                args.get("payload")
                or args.get("prompt")
                or json.dumps(args, ensure_ascii=False)
            )
            src_conn = str(args.get("source_connector", "local_cli"))
            t_res = list(args.get("target_resources", []))
            o_sinks = list(args.get("outbound_sinks", []))
            sess_id = str(args.get("session_id", "sess_mcp"))

            turn_res = self.process_agent_turn(
                session_id=sess_id,
                task_prompt=f"MCP Tool Call ({tool_name or 'inspect'})",
                inbound_payload=payload_text,
                source_connector=src_conn,
                target_resources=t_res,
                outbound_sinks=o_sinks,
                record_ledger=False,
                caller_plane="control",
            )
            fw = turn_res["firewall"]
            return _ok(
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(fw, ensure_ascii=False),
                        }
                    ],
                    "structuredContent": turn_res,
                    "isError": not bool(fw["allowed"]),
                }
            )

        return _err(
            -32601,
            f"Method not found: {method}. Supported MCP JSON-RPC 2.0 methods: initialize, ping, tools/list, tools/call, resources/list, resources/read.",
        )
