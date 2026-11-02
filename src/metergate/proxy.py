"""
MeterGate — Production-Hardened Zero-Config HTTP/SSE/MCP Gateway Proxy
Implements:
  - M-01..M-15: Open-Source MIT Gateway, zero paywall, zero-config local sandbox fallback, 1-screen Cost Ledger.
  - R1: O(1) fast audit chain status (`get_audit_chain_status_fast`) on `/healthz`, `/api/v1/status`, `/api/v1/ledger`
        so high-frequency console/health polling never scans the full audit table or contends with writers.
  - R3: Actionable false-positive remediation endpoints (`GET/POST/DELETE /api/v1/firewall/allowlist` & `/api/v1/auth/approve`).
  - R6: Production HTTP forwarding safeguards:
        * Thread-safe Keep-Alive `UpstreamConnectionPool` (`http.client.HTTPConnection` / `HTTPSConnection`)
        * Bounded-concurrency `UpstreamBackpressureController` with fast-fail HTTP 503 (`upstream_backpressure_shedding`)
        * Explicit declared concurrency boundary (`DECLARED_CONCURRENCY_BOUNDARY`)
  - R8: Centralized Report Center API (`GET /api/v1/report` & `GET /api/v1/reports/dates`) with date history,
        event type filtering (`all` | `blocked` | `allowed` | `redacted` | `trifecta`), and pagination (`page`, `page_size`).
"""

from __future__ import annotations

import collections
import contextlib
import copy
import http.client
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from . import __project__, __version__
from .benchmark import (
    generate_honest_benchmark_report,
    run_real_traffic_benchmark,
    run_redteam_fuzzing,
    run_security_benchmark,
)
from .engine import (
    BudgetCapExceededError,
    MeterGateControlPlane,
)

WEB_INDEX_PATH = Path(__file__).resolve().parent / "web" / "index.html"
WEB_PROMO_PATH = Path(__file__).resolve().parent / "web" / "promo.html"
WEB_PROMO_EN_PATH = Path(__file__).resolve().parent / "web" / "promo_en.html"
LLMS_TXT_PATH = Path(__file__).resolve().parent / "web" / "llms.txt" if (Path(__file__).resolve().parent / "web" / "llms.txt").exists() else Path(__file__).resolve().parent / "data" / "llms.txt"
LLMS_FULL_TXT_PATH = Path(__file__).resolve().parent / "web" / "llms-full.txt"
WELL_KNOWN_CONTRACT_PATH = Path(__file__).resolve().parent / "web" / ".well-known" / "metergate.json" 

DECLARED_CONCURRENCY_BOUNDARY = {
    "target_deployment_profile": "Single-instance local developer & small-team AI Agent security gateway",
    "max_concurrent_inflight_upstream_requests": 32,
    "max_keepalive_connections_per_upstream": 16,
    "backpressure_fast_fail_status_code": 503,
    "backpressure_acquire_timeout_sec": 0.25,
    "upstream_read_timeout_sec": 15.0,
    "out_of_scope_disclaimer": (
        "MeterGate is designed as a single-node local/edge gateway (<= 32 concurrent in-flight upstream requests). "
        "Requests exceeding the in-flight concurrency boundary fail fast with HTTP 503 to protect local gateway availability; "
        "multi-node distributed high-concurrency clustering is outside the promised scope."
    ),
}

METERGATE_ENVELOPE_FIELDS = {
    "source_connector",
    "target_resources",
    "outbound_sinks",
    "ephemeral_token",
    "mode",
    "provider_usage",
    "trace_steps",
    "input_state_hash",
    "output_state_hash",
    "session_id",
    "inbound_payload",
    "task_prompt",
    "prompt",
    "upstream_base_url",
    "utc_date",
    "max_request_cost_usd",
    "max_session_cost_usd",
    "budget_cap_usd",
    "session_budget_cap_usd",
}


class LocalMockUpstreamServer:
    """
    A local HTTP OpenAI-compatible upstream provider server supporting JSON, SSE incremental streaming,
    mid-stream interruption injection, slow-response simulation, tools/tool_choice equivalence, auth checking, and `/healthz` probes.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        chunk_delay_sec: float = 0.0,
        response_delay_sec: float = 0.0,
        require_api_key: Optional[str] = None,
        force_status_code: Optional[int] = None,
        interrupt_stream_after_chunks: Optional[int] = None,
    ) -> None:
        self.chunk_delay_sec = chunk_delay_sec
        self.response_delay_sec = response_delay_sec
        self.require_api_key = require_api_key
        self.force_status_code = force_status_code
        self.interrupt_stream_after_chunks = interrupt_stream_after_chunks
        self.received_requests: List[Dict[str, Any]] = []
        self.received_headers: List[Dict[str, str]] = []
        outer = self

        class _UpstreamHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                if self.path.endswith("/healthz"):
                    if outer.force_status_code and outer.force_status_code >= 400:
                        body = json.dumps({"status": "unhealthy"}).encode("utf-8")
                        self.send_response(outer.force_status_code)
                    else:
                        body = json.dumps({"status": "healthy"}).encode("utf-8")
                        self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    self.wfile.write(body)
                    self.wfile.flush()
                    return
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:
                t0 = time.perf_counter()
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
                try:
                    payload = json.loads(raw) if raw.strip() else {}
                except json.JSONDecodeError:
                    payload = {}

                if outer.response_delay_sec > 0:
                    time.sleep(outer.response_delay_sec)

                hdr_dict = {k.lower(): v for k, v in self.headers.items()}
                outer.received_requests.append(copy.deepcopy(payload))
                outer.received_headers.append(hdr_dict)

                if outer.require_api_key:
                    auth_hdr = hdr_dict.get("authorization", "")
                    if auth_hdr != f"Bearer {outer.require_api_key}":
                        err_bytes = json.dumps(
                            {
                                "error": {
                                    "message": "Invalid or missing upstream API key",
                                    "type": "invalid_api_key",
                                }
                            }
                        ).encode("utf-8")
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(err_bytes)))
                        self.send_header("Connection", "keep-alive")
                        self.end_headers()
                        self.wfile.write(err_bytes)
                        self.wfile.flush()
                        return

                if outer.force_status_code and outer.force_status_code >= 400:
                    err_bytes = json.dumps(
                        {
                            "error": {
                                "message": f"Simulated upstream failure HTTP {outer.force_status_code}",
                                "type": "upstream_server_error",
                            }
                        }
                    ).encode("utf-8")
                    self.send_response(outer.force_status_code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    self.wfile.write(err_bytes)
                    self.wfile.flush()
                    return

                model = str(payload.get("model", "deepseek-chat"))
                messages = payload.get("messages", [])
                prompt_text = "\n".join(
                    str(m.get("content", ""))
                    for m in messages
                    if isinstance(m, dict)
                )
                prompt_tokens = max(12, len(prompt_text) // 3)
                reply_text = f"[MeterGate Upstream ({model})] Verified & processed request ({len(prompt_text)} chars)."
                completion_tokens = max(10, len(reply_text) // 4)
                cached_tokens = int(prompt_tokens * 0.25)
                stream = bool(payload.get("stream", False))

                if stream:
                    self.send_response(200)
                    self.send_header(
                        "Content-Type", "text/event-stream; charset=utf-8"
                    )
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    words = reply_text.split(" ")
                    chunk_id = f"chatcmpl-up-{int(time.time() * 1000)}"
                    for idx, w in enumerate(words):
                        if (
                            outer.interrupt_stream_after_chunks is not None
                            and idx >= outer.interrupt_stream_after_chunks
                        ):
                            self.close_connection = True
                            return
                        token_str = w if idx == 0 else " " + w
                        chunk = {
                            "id": chunk_id,
                            "object": "chat.completion.chunk",
                            "created": int(time.time()),
                            "model": model,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": (
                                        {"role": "assistant", "content": token_str}
                                        if idx == 0
                                        else {"content": token_str}
                                    ),
                                    "finish_reason": None,
                                }
                            ],
                        }
                        self.wfile.write(
                            f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode(
                                "utf-8"
                            )
                        )
                        self.wfile.flush()
                        if outer.chunk_delay_sec > 0:
                            time.sleep(outer.chunk_delay_sec)
                    final_chunk = {
                        "id": chunk_id,
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [
                            {"index": 0, "delta": {}, "finish_reason": "stop"}
                        ],
                        "usage": {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "cached_tokens": cached_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                        },
                    }
                    self.wfile.write(
                        f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n".encode(
                            "utf-8"
                        )
                    )
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                    self.close_connection = True
                    return

                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                msg_obj: Dict[str, Any] = {
                    "role": "assistant",
                    "content": reply_text,
                }
                if "tools" in payload and payload["tools"]:
                    first_tool = payload["tools"][0]
                    fn_name = (
                        first_tool.get("function", {}).get("name", "tool_fn")
                        if isinstance(first_tool, dict)
                        else "tool_fn"
                    )
                    msg_obj["tool_calls"] = [
                        {
                            "id": "call_verified_001",
                            "type": "function",
                            "function": {
                                "name": fn_name,
                                "arguments": '{"verified": true}',
                            },
                        }
                    ]
                resp_obj = {
                    "id": f"chatcmpl-up-{int(time.time() * 1000)}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": msg_obj,
                            "finish_reason": (
                                "tool_calls" if "tool_calls" in msg_obj else "stop"
                            ),
                        }
                    ],
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "cached_tokens": cached_tokens,
                        "total_tokens": prompt_tokens + completion_tokens,
                    },
                    "upstream_latency_ms": elapsed_ms,
                }
                data = json.dumps(resp_obj, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()

        self.httpd = ThreadingHTTPServer((host, port), _UpstreamHandler)
        self.host = host
        self.port = int(self.httpd.server_address[1])
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/v1"

    def start_background(self) -> str:
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self._thread.start()
        return self.base_url

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)


class UpstreamNotConfiguredError(RuntimeError):
    """Raised when no upstream endpoint is configured and auto-sandbox is disabled."""


class UpstreamProviderError(RuntimeError):
    """Raised when the upstream endpoint is unreachable, times out, or triggers backpressure shedding."""

    def __init__(
        self,
        status_code: int,
        message: str,
        upstream_body: Any = None,
        error_code: str = "upstream_provider_error",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.upstream_body = upstream_body
        self.error_code = error_code


class UpstreamConnectionPool:
    """
    R6: Thread-safe HTTP/HTTPS Keep-Alive connection pool built on `http.client`.
    Reuses persistent TCP connections per `(scheme, host, port)` origin, enforces strict socket
    connect/read timeouts, and bounds idle connections per upstream.
    """

    def __init__(self, max_pool_size_per_origin: int = 16) -> None:
        self.max_pool_size_per_origin = max(1, int(max_pool_size_per_origin))
        self._lock = threading.Lock()
        self._pools: Dict[
            Tuple[str, str, int], Deque[http.client.HTTPConnection]
        ] = {}
        self.total_acquired = 0
        self.reused_connections = 0
        self.created_connections = 0

    @staticmethod
    def _parse_origin(endpoint_url: str) -> Tuple[str, str, int, str]:
        parsed = urlparse(endpoint_url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return scheme, host, int(port), path

    def acquire(
        self, scheme: str, host: str, port: int, timeout: float
    ) -> Tuple[http.client.HTTPConnection, bool]:
        key = (scheme, host, port)
        with self._lock:
            self.total_acquired += 1
            pool = self._pools.get(key)
            while pool:
                conn = pool.popleft()
                if getattr(conn, "sock", None) is not None:
                    try:
                        conn.sock.settimeout(timeout)
                        self.reused_connections += 1
                        return conn, True
                    except Exception:
                        try:
                            conn.close()
                        except Exception:
                            pass
            self.created_connections += 1

        if scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        return conn, False

    def release(
        self,
        scheme: str,
        host: str,
        port: int,
        conn: http.client.HTTPConnection,
    ) -> None:
        if getattr(conn, "sock", None) is None:
            try:
                conn.close()
            except Exception:
                pass
            return
        key = (scheme, host, port)
        with self._lock:
            pool = self._pools.setdefault(key, collections.deque())
            if len(pool) < self.max_pool_size_per_origin:
                pool.append(conn)
                return
        try:
            conn.close()
        except Exception:
            pass

    def close_all(self) -> None:
        with self._lock:
            for pool in self._pools.values():
                while pool:
                    c = pool.popleft()
                    try:
                        c.close()
                    except Exception:
                        pass
            self._pools.clear()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            idle_count = sum(len(p) for p in self._pools.values())
            return {
                "max_pool_size_per_origin": self.max_pool_size_per_origin,
                "active_origins": len(self._pools),
                "idle_pooled_connections": idle_count,
                "total_acquired": self.total_acquired,
                "created_connections": self.created_connections,
                "reused_connections": self.reused_connections,
            }


class UpstreamBackpressureController:
    """
    R6: Bounded concurrency & backpressure controller for upstream HTTP/SSE forwarding.
    Prevents slow or stalled upstreams from exhausting gateway worker threads and starving `/healthz` or `/console`.
    """

    def __init__(
        self,
        max_inflight: int = 32,
        acquire_timeout_sec: float = 0.25,
    ) -> None:
        self.max_inflight = max(1, int(max_inflight))
        self.acquire_timeout_sec = max(0.001, float(acquire_timeout_sec))
        self._sem = threading.BoundedSemaphore(self.max_inflight)
        self._lock = threading.Lock()
        self.current_inflight = 0
        self.peak_inflight = 0
        self.rejected_backpressure_count = 0

    @contextlib.contextmanager
    def acquire_slot(self) -> Iterator[None]:
        acquired = self._sem.acquire(timeout=self.acquire_timeout_sec)
        if not acquired:
            with self._lock:
                self.rejected_backpressure_count += 1
                cur = self.current_inflight
            raise UpstreamProviderError(
                status_code=503,
                error_code="upstream_backpressure_shedding",
                message=(
                    f"Gateway backpressure limit reached ({cur}/{self.max_inflight} concurrent upstream requests in flight). "
                    "Failing fast to preserve gateway availability."
                ),
                upstream_body={
                    "error_code": "upstream_backpressure_shedding",
                    "current_inflight": cur,
                    "max_inflight": self.max_inflight,
                    "acquire_timeout_sec": self.acquire_timeout_sec,
                },
            )
        with self._lock:
            self.current_inflight += 1
            if self.current_inflight > self.peak_inflight:
                self.peak_inflight = self.current_inflight
        try:
            yield
        finally:
            with self._lock:
                self.current_inflight = max(0, self.current_inflight - 1)
            self._sem.release()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "max_inflight": self.max_inflight,
                "acquire_timeout_sec": self.acquire_timeout_sec,
                "current_inflight": self.current_inflight,
                "peak_inflight": self.peak_inflight,
                "rejected_backpressure_count": self.rejected_backpressure_count,
            }


class UpstreamForwarder:
    """
    HTTP/SSE upstream cluster client with:
      - R6 Keep-Alive Connection Pool (`UpstreamConnectionPool`) & Backpressure Fast-Fail (`UpstreamBackpressureController`)
      - Multi-upstream cluster with health checks, cooldowns & automatic failover (`ARC-3`)
      - Zero-config local echo fallback when no upstream is specified (`M-04`)
      - Transparent request payload equivalence & incremental SSE streaming (`D2`)
    """

    def __init__(
        self,
        default_upstream_base_url: Optional[str] = None,
        cooldown_seconds: float = 30.0,
        enable_zero_config_fallback: bool = True,
        max_pool_size_per_upstream: int = 16,
        max_concurrent_inflight_requests: int = 32,
        backpressure_acquire_timeout_sec: float = 0.25,
        default_read_timeout_sec: float = 15.0,
        max_response_bytes: int = 4194304,
    ) -> None:
        raw = (
            default_upstream_base_url
            if default_upstream_base_url is not None
            else (
                os.environ.get("METERGATE_UPSTREAM_URL", "").strip()
                or os.environ.get("METERGATE_UPSTREAM_BASE_URL", "").strip()
            )
        )
        self.cooldown_seconds = float(cooldown_seconds)
        self.enable_zero_config_fallback = enable_zero_config_fallback
        self.default_read_timeout_sec = float(default_read_timeout_sec)
        self.max_response_bytes = int(max_response_bytes)
        self.pool = UpstreamConnectionPool(
            max_pool_size_per_origin=max_pool_size_per_upstream
        )
        self.backpressure = UpstreamBackpressureController(
            max_inflight=max_concurrent_inflight_requests,
            acquire_timeout_sec=backpressure_acquire_timeout_sec,
        )
        self._lock = threading.RLock()
        self._health_state: Dict[str, Dict[str, Any]] = {}
        self.upstream_urls: List[str] = []
        self.default_upstream_base_url: str = ""
        self.last_forward_meta: Dict[str, Any] = {}
        self._builtin_sandbox_upstream: Optional[LocalMockUpstreamServer] = None
        if raw:
            self.configure_upstreams(
                [u.strip() for u in raw.split(",") if u.strip()]
            )

    def _get_or_start_sandbox_upstream(self) -> str:
        with self._lock:
            if self._builtin_sandbox_upstream is None:
                self._builtin_sandbox_upstream = LocalMockUpstreamServer()
                self._builtin_sandbox_upstream.start_background()
            url = self._builtin_sandbox_upstream.base_url
            self._ensure_state(url)
            return url

    def shutdown(self) -> None:
        self.pool.close_all()
        with self._lock:
            if self._builtin_sandbox_upstream is not None:
                self._builtin_sandbox_upstream.shutdown()
                self._builtin_sandbox_upstream = None

    def _ensure_state(self, url: str) -> Dict[str, Any]:
        norm = url.strip().rstrip("/")
        if norm not in self._health_state:
            self._health_state[norm] = {
                "url": norm,
                "healthy": True,
                "consecutive_failures": 0,
                "total_failures": 0,
                "total_successes": 0,
                "cooldown_until_epoch": 0.0,
                "last_error": "",
                "last_latency_ms": 0.0,
            }
        return self._health_state[norm]

    def configure_upstreams(
        self,
        upstream_urls: List[str],
        cooldown_seconds: Optional[float] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            cleaned = [
                u.strip().rstrip("/") for u in upstream_urls if u and u.strip()
            ]
            self.upstream_urls = cleaned
            self.default_upstream_base_url = cleaned[0] if cleaned else ""
            if cooldown_seconds is not None:
                self.cooldown_seconds = max(0.0, float(cooldown_seconds))
            for u in cleaned:
                self._ensure_state(u)
            return self.get_cluster_status()

    def _mark_success(self, url: str, latency_ms: float) -> None:
        with self._lock:
            st = self._ensure_state(url)
            st["healthy"] = True
            st["consecutive_failures"] = 0
            st["total_successes"] += 1
            st["cooldown_until_epoch"] = 0.0
            st["last_latency_ms"] = round(latency_ms, 3)

    def _mark_failure(self, url: str, error_msg: str) -> None:
        with self._lock:
            st = self._ensure_state(url)
            st["healthy"] = False
            st["consecutive_failures"] += 1
            st["total_failures"] += 1
            st["last_error"] = str(error_msg)
            st["cooldown_until_epoch"] = time.time() + self.cooldown_seconds

    def get_cluster_status(self) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            items = []
            for u in self.upstream_urls:
                st = dict(self._ensure_state(u))
                st["in_cooldown"] = st["cooldown_until_epoch"] > now
                items.append(st)
            return {
                "configured": len(self.upstream_urls) > 0,
                "zero_config_sandbox_ready": self.enable_zero_config_fallback,
                "primary_upstream": self.default_upstream_base_url
                or "builtin_zero_config_sandbox",
                "upstream_count": len(self.upstream_urls),
                "cooldown_seconds": self.cooldown_seconds,
                "connection_pool": self.pool.get_stats(),
                "backpressure": self.backpressure.get_stats(),
                "declared_concurrency_boundary": DECLARED_CONCURRENCY_BOUNDARY,
                "upstreams": items,
            }

    def check_upstreams_health(self, timeout: float = 3.0) -> Dict[str, Any]:
        for u in list(self.upstream_urls):
            probe_url = f"{u}/healthz"
            req = urllib.request.Request(probe_url, method="GET")
            t0 = time.perf_counter()
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    _ = resp.read(256)
                    if 200 <= resp.status < 400:
                        self._mark_success(u, (time.perf_counter() - t0) * 1000.0)
                    else:
                        self._mark_failure(u, f"HTTP {resp.status}")
            except Exception as exc:
                self._mark_failure(u, str(exc))
        return self.get_cluster_status()

    def resolve_upstream_candidates(
        self, override_url: Optional[str] = None
    ) -> List[str]:
        if override_url and override_url.strip():
            parts = [
                u.strip().rstrip("/")
                for u in override_url.split(",")
                if u.strip()
            ]
            if parts:
                return parts
        env_url = (
            os.environ.get("METERGATE_UPSTREAM_URL", "").strip()
            or os.environ.get("METERGATE_UPSTREAM_BASE_URL", "").strip()
        )
        raw_list = list(self.upstream_urls)
        if not raw_list and self.default_upstream_base_url:
            raw_list = [
                u.strip().rstrip("/")
                for u in self.default_upstream_base_url.split(",")
                if u.strip()
            ]
        if not raw_list and env_url:
            raw_list = [
                u.strip().rstrip("/") for u in env_url.split(",") if u.strip()
            ]
        if not raw_list:
            if self.enable_zero_config_fallback:
                return [self._get_or_start_sandbox_upstream()]
            raise UpstreamNotConfiguredError(
                "No upstream LLM endpoint configured. Set METERGATE_UPSTREAM_URL or pass --upstream-url."
            )
        now = time.time()
        with self._lock:
            active: List[str] = []
            cooling: List[Tuple[float, str]] = []
            for u in raw_list:
                st = self._ensure_state(u)
                if st["cooldown_until_epoch"] <= now:
                    active.append(u)
                else:
                    cooling.append((st["cooldown_until_epoch"], u))
            cooling.sort(key=lambda item: item[0])
            return active + [u for _, u in cooling]

    def resolve_upstream_url(self, override_url: Optional[str] = None) -> str:
        candidates = self.resolve_upstream_candidates(override_url)
        return candidates[0]

    @staticmethod
    def resolve_upstream_api_key(
        headers: Optional[Dict[str, str]] = None,
        explicit_key: Optional[str] = None,
    ) -> Optional[str]:
        if explicit_key and explicit_key.strip():
            return explicit_key.strip()
        if headers:
            for k, v in headers.items():
                if k.lower() in (
                    "x-metergate-upstream-key",
                    "x-upstream-api-key",
                    "x-provider-api-key",
                ) and v.strip():
                    val = v.strip()
                    return (
                        val[7:].strip()
                        if val.lower().startswith("bearer ")
                        else val
                    )
            for k, v in headers.items():
                if k.lower() == "authorization" and v.strip():
                    val = v.strip()
                    return (
                        val[7:].strip()
                        if val.lower().startswith("bearer ")
                        else val
                    )
        for env_name in ("METERGATE_UPSTREAM_API_KEY", "OPENAI_API_KEY"):
            env_val = os.environ.get(env_name, "").strip()
            if env_val:
                return env_val
        return None

    @staticmethod
    def build_transparent_upstream_payload(
        original_body: Dict[str, Any],
        selected_model: str,
        sanitized_messages: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        upstream_payload = {
            k: copy.deepcopy(v)
            for k, v in original_body.items()
            if k not in METERGATE_ENVELOPE_FIELDS
        }
        upstream_payload["model"] = selected_model
        upstream_payload["messages"] = sanitized_messages
        return upstream_payload

    def _pooled_json_post(
        self,
        endpoint: str,
        encoded_body: bytes,
        headers: Dict[str, str],
        timeout: float,
    ) -> Tuple[int, bytes, bool]:
        """
        R6: Executes an HTTP POST using the Keep-Alive `UpstreamConnectionPool`, automatically
        retrying once on a fresh socket if a pooled idle connection was closed by the peer.
        """
        scheme, host, port, path = self.pool._parse_origin(endpoint)
        req_headers = dict(headers)
        req_headers["Connection"] = "keep-alive"
        req_headers["Content-Length"] = str(len(encoded_body))

        for attempt in range(2):
            conn, was_reused = self.pool.acquire(
                scheme, host, port, timeout=timeout
            )
            try:
                conn.request("POST", path, body=encoded_body, headers=req_headers)
                resp = conn.getresponse()
                status = int(resp.status)
                raw_bytes = resp.read(self.max_response_bytes + 1)
                if len(raw_bytes) > self.max_response_bytes:
                    conn.close()
                    raise UpstreamProviderError(
                        status_code=502,
                        error_code="upstream_response_too_large",
                        message=f"Upstream response exceeded max limit ({self.max_response_bytes} bytes)",
                    )
                conn_hdr = (resp.getheader("Connection") or "").lower()
                if conn_hdr == "close" or resp.version == 10:
                    conn.close()
                else:
                    self.pool.release(scheme, host, port, conn)
                return status, raw_bytes, was_reused
            except (
                http.client.RemoteDisconnected,
                http.client.CannotSendRequest,
                BrokenPipeError,
                ConnectionResetError,
            ):
                try:
                    conn.close()
                except Exception:
                    pass
                if was_reused and attempt == 0:
                    continue
                raise
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                raise
        raise RuntimeError("Unreachable pooled POST state")

    def forward_json_completion(
        self,
        upstream_payload: Dict[str, Any],
        upstream_url_override: Optional[str] = None,
        upstream_api_key: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[Dict[str, Any], float]:
        eff_timeout = (
            float(timeout)
            if timeout is not None
            else self.default_read_timeout_sec
        )
        with self.backpressure.acquire_slot():
            candidates = self.resolve_upstream_candidates(upstream_url_override)
            encoded = json.dumps(
                upstream_payload, ensure_ascii=False
            ).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if upstream_api_key:
                headers["Authorization"] = f"Bearer {upstream_api_key}"

            failed_attempts: List[Dict[str, Any]] = []
            last_exc: Optional[UpstreamProviderError] = None

            for idx, base in enumerate(candidates):
                endpoint = (
                    base
                    if base.endswith("/chat/completions")
                    else f"{base}/chat/completions"
                )
                t0 = time.perf_counter()
                try:
                    status, body_bytes, was_reused = self._pooled_json_post(
                        endpoint=endpoint,
                        encoded_body=encoded,
                        headers=headers,
                        timeout=eff_timeout,
                    )
                    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                    if 200 <= status < 300:
                        parsed = json.loads(body_bytes.decode("utf-8"))
                        self._mark_success(base, latency_ms)
                        self.last_forward_meta = {
                            "selected_upstream": base,
                            "failover_count": idx,
                            "connection_reused": was_reused,
                            "failed_attempts": failed_attempts,
                        }
                        return parsed, latency_ms

                    err_raw = body_bytes.decode("utf-8", errors="replace")
                    try:
                        err_json = json.loads(err_raw)
                    except Exception:
                        err_json = {"raw_error": err_raw}
                    last_exc = UpstreamProviderError(
                        status_code=status,
                        message=f"Upstream provider returned HTTP {status}",
                        upstream_body=err_json,
                    )
                    if status >= 500 or status in (408, 429):
                        self._mark_failure(base, f"HTTP {status}")
                        failed_attempts.append(
                            {"upstream": base, "status_code": status}
                        )
                        continue
                    raise last_exc
                except UpstreamProviderError as up_exc:
                    if up_exc.status_code < 500 and up_exc.status_code not in (
                        408,
                        429,
                    ):
                        raise
                    last_exc = up_exc
                    continue
                except (socket.timeout, TimeoutError) as tm_exc:
                    self._mark_failure(base, f"Timeout: {tm_exc}")
                    failed_attempts.append(
                        {"upstream": base, "error": "upstream_timeout"}
                    )
                    last_exc = UpstreamProviderError(
                        status_code=504,
                        error_code="upstream_timeout",
                        message=f"Upstream provider timed out after {eff_timeout}s: {tm_exc}",
                        upstream_body={"failed_attempts": failed_attempts},
                    )
                    continue
                except Exception as exc:
                    self._mark_failure(base, str(exc))
                    failed_attempts.append({"upstream": base, "error": str(exc)})
                    last_exc = UpstreamProviderError(
                        status_code=502,
                        message=f"Upstream provider unreachable: {exc}",
                        upstream_body={"failed_attempts": failed_attempts},
                    )
                    continue

            if last_exc is not None:
                raise last_exc
            raise UpstreamProviderError(
                status_code=502, message="All upstream candidates failed."
            )

    def open_incremental_sse_stream(
        self,
        upstream_payload: Dict[str, Any],
        upstream_url_override: Optional[str] = None,
        upstream_api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        on_complete: Optional[Callable[[Dict[str, Any], float], Dict[str, Any]]] = None,
        on_error: Optional[Callable[[str, float], None]] = None,
    ) -> Iterator[bytes]:
        eff_timeout = (
            float(timeout)
            if timeout is not None
            else self.default_read_timeout_sec
        )
        # Acquire backpressure slot prior to opening stream; released when stream finishes
        acquired = self.backpressure._sem.acquire(
            timeout=self.backpressure.acquire_timeout_sec
        )
        if not acquired:
            with self.backpressure._lock:
                self.backpressure.rejected_backpressure_count += 1
                cur = self.backpressure.current_inflight
            raise UpstreamProviderError(
                status_code=503,
                error_code="upstream_backpressure_shedding",
                message=(
                    f"Gateway backpressure limit reached ({cur}/{self.backpressure.max_inflight} concurrent upstream requests in flight)."
                ),
                upstream_body={
                    "error_code": "upstream_backpressure_shedding",
                    "current_inflight": cur,
                    "max_inflight": self.backpressure.max_inflight,
                },
            )
        with self.backpressure._lock:
            self.backpressure.current_inflight += 1
            if (
                self.backpressure.current_inflight
                > self.backpressure.peak_inflight
            ):
                self.backpressure.peak_inflight = (
                    self.backpressure.current_inflight
                )

        def _release_backpressure() -> None:
            with self.backpressure._lock:
                self.backpressure.current_inflight = max(
                    0, self.backpressure.current_inflight - 1
                )
            self.backpressure._sem.release()

        try:
            candidates = self.resolve_upstream_candidates(upstream_url_override)
            upstream_payload = dict(upstream_payload)
            upstream_payload["stream"] = True
            encoded = json.dumps(
                upstream_payload, ensure_ascii=False
            ).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if upstream_api_key:
                headers["Authorization"] = f"Bearer {upstream_api_key}"

            resp = None
            t0 = time.perf_counter()
            failed_attempts: List[Dict[str, Any]] = []
            last_exc: Optional[UpstreamProviderError] = None
            selected_base = candidates[0]

            for idx, base in enumerate(candidates):
                endpoint = (
                    base
                    if base.endswith("/chat/completions")
                    else f"{base}/chat/completions"
                )
                req = urllib.request.Request(
                    endpoint, data=encoded, headers=headers, method="POST"
                )
                t0 = time.perf_counter()
                try:
                    resp = urllib.request.urlopen(req, timeout=eff_timeout)
                    selected_base = base
                    self._mark_success(base, (time.perf_counter() - t0) * 1000.0)
                    self.last_forward_meta = {
                        "selected_upstream": base,
                        "failover_count": idx,
                        "failed_attempts": failed_attempts,
                    }
                    break
                except urllib.error.HTTPError as http_err:
                    err_raw = http_err.read().decode("utf-8", errors="replace")
                    try:
                        err_json = json.loads(err_raw)
                    except Exception:
                        err_json = {"raw_error": err_raw}
                    last_exc = UpstreamProviderError(
                        status_code=http_err.code,
                        message=f"Upstream provider returned HTTP {http_err.code}",
                        upstream_body=err_json,
                    )
                    if http_err.code >= 500 or http_err.code in (408, 429):
                        self._mark_failure(base, f"HTTP {http_err.code}")
                        failed_attempts.append(
                            {"upstream": base, "status_code": http_err.code}
                        )
                        continue
                    raise last_exc from http_err
                except Exception as exc:
                    self._mark_failure(base, str(exc))
                    failed_attempts.append({"upstream": base, "error": str(exc)})
                    last_exc = UpstreamProviderError(
                        status_code=502,
                        message=f"Upstream provider unreachable: {exc}",
                        upstream_body={"failed_attempts": failed_attempts},
                    )
                    continue

            if resp is None:
                if last_exc is not None:
                    raise last_exc
                raise UpstreamProviderError(
                    status_code=502, message="All upstream candidates failed."
                )
        except Exception:
            _release_backpressure()
            raise

        def _chunk_generator() -> Iterator[bytes]:
            accumulated_content: List[str] = []
            usage_data: Dict[str, Any] = {}
            chunk_id = f"chatcmpl-{int(time.time() * 1000)}"
            saw_done = False
            stream_err_msg: Optional[str] = None
            try:
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    if line == "data: [DONE]":
                        saw_done = True
                        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                        full_text = "".join(accumulated_content)
                        if not usage_data:
                            msgs = upstream_payload.get("messages", [])
                            p_tok = max(
                                12,
                                sum(
                                    len(str(m.get("content", "")))
                                    for m in msgs
                                    if isinstance(m, dict)
                                )
                                // 3,
                            )
                            c_tok = max(8, len(full_text) // 4)
                            usage_data = {
                                "prompt_tokens": p_tok,
                                "completion_tokens": c_tok,
                                "cached_tokens": int(p_tok * 0.25),
                                "total_tokens": p_tok + c_tok,
                            }
                        if on_complete is not None:
                            mg_meta = on_complete(usage_data, elapsed_ms)
                            meta_chunk = {
                                "id": chunk_id,
                                "object": "chat.completion.chunk",
                                "created": int(time.time()),
                                "model": upstream_payload.get("model"),
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {},
                                        "finish_reason": "stop",
                                    }
                                ],
                                "usage": usage_data,
                                "stream_complete": True,
                                "metergate": mg_meta,
                            }
                            yield f"data: {json.dumps(meta_chunk, ensure_ascii=False)}\n\n".encode(
                                "utf-8"
                            )
                        yield b"data: [DONE]\n\n"
                        break
                    else:
                        if line.startswith("data:"):
                            try:
                                c_obj = json.loads(line[5:].strip())
                                chunk_id = c_obj.get("id", chunk_id)
                                for ch in c_obj.get("choices", []):
                                    delta = ch.get("delta", {})
                                    if (
                                        isinstance(delta, dict)
                                        and "content" in delta
                                        and delta["content"]
                                    ):
                                        accumulated_content.append(
                                            str(delta["content"])
                                        )
                                if "usage" in c_obj and isinstance(
                                    c_obj["usage"], dict
                                ):
                                    usage_data = c_obj["usage"]
                            except Exception:
                                pass
                        yield f"{line}\n\n".encode("utf-8")
            except Exception as exc:
                stream_err_msg = f"Mid-stream socket error: {exc}"
                self._mark_failure(selected_base, stream_err_msg)
            finally:
                try:
                    resp.close()
                finally:
                    _release_backpressure()

            if not saw_done:
                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                reason = (
                    stream_err_msg
                    or "Upstream closed SSE connection prematurely before sending [DONE]."
                )
                if on_error is not None:
                    on_error(reason, elapsed_ms)
                interrupted_payload = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": upstream_payload.get("model"),
                    "stream_complete": False,
                    "interrupted": True,
                    "error": {
                        "type": "upstream_stream_interrupted",
                        "code": "stream_incomplete",
                        "message": reason,
                        "chunks_received_before_interruption": len(
                            accumulated_content
                        ),
                    },
                    "choices": [
                        {
                            "index": 0,
                            "delta": {},
                            "finish_reason": "error",
                        }
                    ],
                }
                yield (
                    f"event: error\ndata: {json.dumps(interrupted_payload, ensure_ascii=False)}\n\n"
                ).encode("utf-8")

        return _chunk_generator()


class MeterGateGatewayApp:
    """Core HTTP/SSE dispatcher usable both by ThreadingHTTPServer and direct test harnesses."""

    def __init__(
        self,
        control_plane: Optional[MeterGateControlPlane] = None,
        upstream_base_url: Optional[str] = None,
        allowed_origins: Optional[List[str]] = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8787,
        enable_zero_config_fallback: bool = True,
    ) -> None:
        self.cp = control_plane or MeterGateControlPlane()
        cluster_cfg = self.cp.config_loader.policy.get("upstream_cluster", {})
        cooldown_sec = float(cluster_cfg.get("unhealthy_cooldown_sec", 30.0))
        max_pool = int(cluster_cfg.get("max_pool_size_per_upstream", 16))
        max_inflight = int(
            cluster_cfg.get("max_concurrent_inflight_requests", 32)
        )
        bp_timeout = float(
            cluster_cfg.get("backpressure_acquire_timeout_sec", 0.25)
        )
        read_timeout = float(cluster_cfg.get("upstream_read_timeout_sec", 15.0))
        max_resp_bytes = int(
            cluster_cfg.get("max_upstream_response_bytes", 4194304)
        )
        self.forwarder = UpstreamForwarder(
            default_upstream_base_url=upstream_base_url,
            cooldown_seconds=cooldown_sec,
            enable_zero_config_fallback=enable_zero_config_fallback,
            max_pool_size_per_upstream=max_pool,
            max_concurrent_inflight_requests=max_inflight,
            backpressure_acquire_timeout_sec=bp_timeout,
            default_read_timeout_sec=read_timeout,
            max_response_bytes=max_resp_bytes,
        )
        self.listen_host = str(listen_host).strip() or "127.0.0.1"
        self.listen_port = int(listen_port)
        self._custom_allowed_origins: Optional[Set[str]] = (
            {o.strip().rstrip("/") for o in allowed_origins if o.strip()}
            if allowed_origins is not None
            else None
        )
        self.allowed_origins: Set[str] = (
            set(self._custom_allowed_origins)
            if self._custom_allowed_origins is not None
            else self.derive_allowed_origins(self.listen_host, self.listen_port)
        )
        limits_cfg = self.cp.config_loader.policy.get("resource_limits", {})
        self.max_request_body_bytes = int(
            limits_cfg.get("max_request_body_bytes", 262144)
        )
        self.max_input_payload_chars = int(
            limits_cfg.get("max_input_payload_chars", 65536)
        )
        self.last_request_id: str = ""

    @staticmethod
    def derive_allowed_origins(host: str, port: int) -> Set[str]:
        clean_host = (host or "127.0.0.1").strip().strip("[]")
        p = int(port)
        origins: Set[str] = {
            f"http://127.0.0.1:{p}",
            f"http://localhost:{p}",
            f"http://[::1]:{p}",
        }
        if clean_host not in ("0.0.0.0", "::", ""):
            if ":" in clean_host:
                origins.add(f"http://[{clean_host}]:{p}")
            else:
                origins.add(f"http://{clean_host}:{p}")
        return origins

    def set_listen_address(self, host: str, port: int) -> Set[str]:
        self.listen_host = str(host).strip() or "127.0.0.1"
        self.listen_port = int(port)
        if self._custom_allowed_origins is None:
            self.allowed_origins = self.derive_allowed_origins(
                self.listen_host, self.listen_port
            )
        return set(self.allowed_origins)

    def shutdown(self) -> None:
        self.forwarder.shutdown()

    def is_origin_allowed(self, origin: Optional[str]) -> bool:
        if not origin or not origin.strip():
            return True
        norm = origin.strip().rstrip("/")
        return norm in self.allowed_origins

    @staticmethod
    def _extract_header(
        headers: Dict[str, str], target_key: str
    ) -> Optional[str]:
        tl = target_key.lower()
        for k, v in headers.items():
            if k.lower() == tl and v.strip():
                return v.strip()
        return None

    def handle_request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        stream_as_generator: bool = False,
        raw_body_size_bytes: Optional[int] = None,
    ) -> Tuple[int, Dict[str, Any] | str | Iterator[bytes], str]:
        parsed = urlparse(path)
        route = parsed.path
        qs = parse_qs(parsed.query)
        body = body or {}
        headers = headers or {}

        req_id_hdr = self._extract_header(headers, "X-Request-ID")
        self.last_request_id = (
            req_id_hdr if req_id_hdr else f"req_{uuid.uuid4().hex[:10]}"
        )

        if method == "POST":
            if raw_body_size_bytes is None:
                raw_body_size_bytes = len(
                    json.dumps(body, ensure_ascii=False).encode("utf-8")
                )
            if raw_body_size_bytes > self.max_request_body_bytes:
                return (
                    413,
                    {
                        "error": {
                            "type": "payload_too_large",
                            "message": f"Request body size ({raw_body_size_bytes} bytes) exceeds maximum allowed limit ({self.max_request_body_bytes} bytes).",
                            "max_request_body_bytes": self.max_request_body_bytes,
                        }
                    },
                    "application/json",
                )

        # 0. Serve 100% Offline Web Console UI & 00112238.xyz Pi-Style Bilingual Promo Sites (R7 & P1..P4)
        if method == "GET" and route in ("/promo", "/promo.html", "/promo_zh", "/promo_zh.html", "/site", "/00112238.xyz"):
            if WEB_PROMO_PATH.exists():
                return (
                    200,
                    WEB_PROMO_PATH.read_text(encoding="utf-8"),
                    "text/html; charset=utf-8",
                )
            return 404, "Promo Web UI not found", "text/plain"

        if method == "GET" and route in ("/promo_en", "/promo_en.html", "/en"):
            if WEB_PROMO_EN_PATH.exists():
                return (
                    200,
                    WEB_PROMO_EN_PATH.read_text(encoding="utf-8"),
                    "text/html; charset=utf-8",
                )
            return 404, "Promo English Web UI not found", "text/plain"

        if route == "/api/v1/promo/surprise" and method in ("GET", "POST"):
            persona = str(body.get("persona") or qs.get("persona", ["Autonomous MCP Agent Vanguard"])[0])
            preferred_cli = str(body.get("preferred_cli") or qs.get("cli", ["uvx"])[0])
            return (
                200,
                {
                    "status": "SURPRISE_CAPSULE_SYNTHESIZED",
                    "project": "MeterGate",
                    "version": __version__,
                    "domain": "00112238.xyz",
                    "repository": "https://github.com/wu00112238/MeterGate.git",
                    "style_reference": "https://pi.dev/",
                    "primary_audience": "autonomous_ai_agents_and_mcp_clients",
                    "secondary_audience": "human_developers_and_operators",
                    "zero_cloud_telemetry_bytes": 0,
                    "inferred_persona": persona,
                    "preferred_cli": preferred_cli,
                    "ephemeral_bypass_token": "mg_ephem_surprise_00112238_vip",
                    "recommended_unattended_command": "uvx metergate serve --mcp-stdio",
                    "observe_only_command": "metergate serve --mode observe --port 8787",
                },
                "application/json",
            )

        if method == "GET" and route in ("/", "/index.html", "/console"):
            if WEB_INDEX_PATH.exists():
                return (
                    200,
                    WEB_INDEX_PATH.read_text(encoding="utf-8"),
                    "text/html; charset=utf-8",
                )
            return 404, "Web UI not found", "text/plain"

        # 0a. A2 & A6: Machine-Readable Self-Description & GEO Discovery Endpoints
        if method == "GET" and route in (
            "/.well-known/metergate.json",
            "/.well-known/mcp.json",
            "/api/v1/contract",
            "/api/v1/self-description",
        ):
            return (
                200,
                self.cp.get_machine_self_description(),
                "application/json",
            )

        if method == "GET" and route in (
            "/.well-known/mcp-registry.json",
            "/api/v1/mcp-registry",
        ):
            return (
                200,
                self.cp.get_mcp_registry_manifests(),
                "application/json",
            )

        if method == "GET" and route in ("/llms.txt", "/llms"):
            if LLMS_TXT_PATH.exists():
                return (
                    200,
                    LLMS_TXT_PATH.read_text(encoding="utf-8"),
                    "text/plain; charset=utf-8",
                )
            return 200, f"MeterGate v{__version__}", "text/plain; charset=utf-8"

        if method == "GET" and route in ("/llms-full.txt", "/llms-full"):
            if LLMS_FULL_TXT_PATH.exists():
                return (
                    200,
                    LLMS_FULL_TXT_PATH.read_text(encoding="utf-8"),
                    "text/plain; charset=utf-8",
                )
            return 200, f"MeterGate v{__version__} Full Architecture Spec", "text/plain; charset=utf-8"

        # 0b. Health Check Endpoint (/healthz) — R1: Uses O(1) fast audit status
        if method == "GET" and route == "/healthz":
            chain = self.cp.storage.get_audit_chain_status_fast()
            ov = self.cp.get_overhead_budget_status()
            return (
                200,
                {
                    "status": "ok" if chain["valid"] else "degraded",
                    "project": "MeterGate",
                    "version": __version__,
                    "schema_version": self.cp.storage.get_schema_version(),
                    "audit_chain_valid": chain["valid"],
                    "audit_verification_mode": chain.get("verification_mode"),
                    "overhead_within_budget": ov["within_budget"],
                    "upstream_cluster": self.forwarder.get_cluster_status(),
                    "timestamp": self.cp.storage.now_iso(),
                },
                "application/json",
            )

        # 0c. Prometheus Metrics (/metrics)
        if method == "GET" and route in ("/metrics", "/api/v1/metrics"):
            return (
                200,
                self.cp.export_prometheus_metrics(),
                "text/plain; version=0.0.4; charset=utf-8",
            )

        # Rate Limit Check
        allowed_rl, rl_meta = self.cp.rate_limiter.allow_request(cost=1.0)
        if not allowed_rl:
            return (
                429,
                {
                    "error": {
                        "type": "rate_limit_exceeded",
                        "message": "Local gateway rate limit exceeded.",
                        "rate_limit": rl_meta,
                    }
                },
                "application/json",
            )

        # 1. Status & Cost Ledger Overview (M-08 & R1: O(1) Fast Audit Status)
        if method == "GET" and route in ("/api/v1/status", "/api/v1/ledger"):
            chain = self.cp.storage.get_audit_chain_status_fast()
            ledger = self.cp.get_cost_ledger_summary()
            return (
                200,
                {
                    "status": "ONLINE",
                    "project": "MeterGate",
                    "version": __version__,
                    "mode": self.cp.config_loader.get_mode(),
                    "catalog_freshness": self.cp.get_catalog_freshness_status(),
                    "cost_ledger": ledger,
                    "usage_summary": self.cp.storage.get_usage_summary(),
                    "quota": self.cp.check_daily_quota(),
                    "audit_chain": chain,
                    "allowlist_count": len(self.cp.list_allowlist_entries()),
                    "gateway_overhead": self.cp.get_overhead_budget_status(),
                    "upstream_cluster": self.forwarder.get_cluster_status(),
                    "declared_concurrency_boundary": DECLARED_CONCURRENCY_BOUNDARY,
                    "hub_link": {
                        "label": "更多省时间工具",
                        "url": "https://00112238.xyz",
                    },
                },
                "application/json",
            )

        # 2. Report Center & Daily Agent Behavior Digest (M-09 & R8: Date History, Filter, Pagination)
        if method == "GET" and route == "/api/v1/reports/dates":
            return (
                200,
                {
                    "dates": self.cp.storage.list_available_report_dates(),
                    "current_utc_date": self.cp.storage.now_utc_date(),
                },
                "application/json",
            )

        if method == "GET" and route in ("/api/v1/report", "/api/v1/reports/center"):
            fmt = str(qs.get("format", ["json"])[0]).lower()
            utc_date = qs.get("date", [None])[0] or qs.get("utc_date", [None])[0]
            event_filter = str(qs.get("filter", ["all"])[0]).lower()
            try:
                page = max(1, int(qs.get("page", ["1"])[0]))
            except ValueError:
                page = 1
            try:
                page_size = max(1, min(100, int(qs.get("page_size", ["10"])[0])))
            except ValueError:
                page_size = 10

            rep = self.cp.generate_daily_agent_report(
                fmt=fmt,
                utc_date=utc_date,
                event_filter=event_filter,
                page=page,
                page_size=page_size,
            )
            if isinstance(rep, str):
                if fmt == "svg":
                    return 200, rep, "image/svg+xml; charset=utf-8"
                if fmt == "html":
                    return 200, rep, "text/html; charset=utf-8"
                return 200, rep, "text/markdown; charset=utf-8"
            return 200, rep, "application/json"

        # 2a. A4: Pre-Flight Budget Query & Simulation (/api/v1/budget, /api/v1/budget/preflight)
        if method == "GET" and route in ("/api/v1/budget", "/api/v1/budget/preflight"):
            sess_id = str(qs.get("session_id", ["sess_default"])[0])
            model_q = str(qs.get("model", ["auto"])[0])
            try:
                p_tok = int(qs.get("prompt_tokens", ["500"])[0])
            except ValueError:
                p_tok = 500
            try:
                o_tok = int(qs.get("output_tokens", ["400"])[0])
            except ValueError:
                o_tok = 400
            return (
                200,
                self.cp.query_preflight_budget(
                    session_id=sess_id,
                    estimated_prompt_tokens=p_tok,
                    expected_output_tokens=o_tok,
                    model=model_q,
                ),
                "application/json",
            )

        if method == "POST" and route in ("/api/v1/budget", "/api/v1/budget/preflight"):
            return (
                200,
                self.cp.query_preflight_budget(
                    session_id=str(body.get("session_id", "sess_default")),
                    estimated_prompt_tokens=int(
                        body.get("estimated_prompt_tokens", body.get("prompt_tokens", 500))
                    ),
                    expected_output_tokens=int(
                        body.get("expected_output_tokens", body.get("output_tokens", 400))
                    ),
                    model=str(body.get("model", "auto")),
                ),
                "application/json",
            )

        # 2a-2. B3: Zero-Config Agent Takeover Profiles (/api/v1/takeover)
        if method == "GET" and route == "/api/v1/takeover":
            return (
                200,
                self.cp.get_agent_takeover_profiles(
                    base_url=f"http://{self.listen_host}:{self.listen_port}"
                ),
                "application/json",
            )

        # 2a-3. B4: One-Click Allow & Remember (/api/v1/firewall/allow-and-remember)
        if method == "POST" and route == "/api/v1/firewall/allow-and-remember":
            try:
                res = self.cp.allow_and_remember(
                    payload=str(body.get("payload", "")),
                    source_connector=body.get("source_connector"),
                    note=str(body.get("note", "One-click Allow & Remember")),
                )
                return 200, res, "application/json"
            except ValueError as exc:
                return 400, {"error": str(exc)}, "application/json"

        # 2b. R3: Actionable False-Positive Allowlist Management (/api/v1/firewall/allowlist)
        if method == "GET" and route == "/api/v1/firewall/allowlist":
            return (
                200,
                {
                    "allowlist": self.cp.list_allowlist_entries(),
                    "tier2_engine_type": "heuristic_concept_ngram_scorer",
                    "known_blind_spots": self.cp.firewall.TIER2_KNOWN_BLIND_SPOTS,
                },
                "application/json",
            )

        if method == "POST" and route == "/api/v1/firewall/allowlist":
            action = str(body.get("action", "add")).lower()
            if action == "remove":
                entry_id = str(body.get("entry_id", "")).strip()
                removed = self.cp.remove_allowlist_entry(entry_id)
                return (
                    200,
                    {
                        "removed": removed,
                        "entry_id": entry_id,
                        "allowlist": self.cp.list_allowlist_entries(),
                    },
                    "application/json",
                )
            try:
                entry = self.cp.add_allowlist_entry(
                    entry_type=str(body.get("entry_type", "pattern")),
                    value=str(body.get("value", "")),
                    note=str(body.get("note", "Added via console/API")),
                )
                return (
                    200,
                    {
                        "added": entry,
                        "allowlist": self.cp.list_allowlist_entries(),
                    },
                    "application/json",
                )
            except ValueError as exc:
                return 400, {"error": str(exc)}, "application/json"

        # 3. Full Audit Trail Verification & Export (Low-Frequency Full Chain Scan, R1)
        if method == "GET" and route == "/api/v1/audit":
            fmt = qs.get("format", ["json"])[0]
            if fmt == "csv":
                return (
                    200,
                    self.cp.storage.export_audit_csv(),
                    "text/csv; charset=utf-8",
                )
            return (
                200,
                {
                    "verification": self.cp.storage.verify_audit_chain(),
                    "events": self.cp.storage.list_audit_events(limit=100),
                },
                "application/json",
            )

        # 4. Self-Contained Audit Evidence Package (M-03 `evidence`, R1 Full Scan)
        if method == "GET" and route == "/api/v1/evidence":
            return (
                200,
                self.cp.generate_audit_evidence_package(),
                "application/json",
            )

        # 5. Honest Security Benchmark Suite (M-12)
        if method == "GET" and route in (
            "/api/v1/benchmark",
            "/api/v1/benchmark/report",
        ):
            fmt = str(qs.get("format", ["json"])[0]).lower()
            if route == "/api/v1/benchmark/report" or fmt == "markdown":
                rep = generate_honest_benchmark_report(
                    control_plane=self.cp, fmt=fmt
                )
                if isinstance(rep, str):
                    return 200, rep, "text/markdown; charset=utf-8"
                return 200, rep, "application/json"

            bench = run_security_benchmark(firewall=self.cp.firewall)
            fuzz = run_redteam_fuzzing(firewall=self.cp.firewall)
            real_traffic = run_real_traffic_benchmark(
                storage=self.cp.storage,
                firewall=self.cp.firewall,
            )
            return (
                200,
                {
                    "benchmark": bench,
                    "redteam_fuzzing": fuzz,
                    "real_traffic_benchmark": real_traffic,
                },
                "application/json",
            )

        # 6. Model Catalog & Live Feedback Telemetry
        if method == "GET" and route == "/api/v1/catalog":
            return (
                200,
                {
                    "catalog": self.cp.config_loader.catalog,
                    "live_feedback": self.cp.storage.list_model_feedback(),
                },
                "application/json",
            )

        # 7. Multi-Upstream Cluster Configuration & Health (ARC-3)
        if method == "POST" and route == "/api/v1/upstreams":
            urls = body.get("upstreams") or body.get("endpoints") or []
            if isinstance(urls, str):
                urls = [u.strip() for u in urls.split(",") if u.strip()]
            st = self.forwarder.configure_upstreams(
                upstream_urls=list(urls),
                cooldown_seconds=(
                    float(body["cooldown_seconds"])
                    if "cooldown_seconds" in body
                    else None
                ),
            )
            return 200, st, "application/json"

        if method == "GET" and route == "/api/v1/upstreams/health":
            probe = str(qs.get("probe", ["true"])[0]).lower() != "false"
            st = (
                self.forwarder.check_upstreams_health()
                if probe
                else self.forwarder.get_cluster_status()
            )
            return 200, st, "application/json"

        # 8. Backup, Restore & Diagnostics (`backup`, `restore`, `doctor`)
        if method == "POST" and route == "/api/v1/ops/backup":
            backup_path = body.get("backup_path")
            if not backup_path:
                return 400, {"error": "backup_path is required"}, "application/json"
            manifest = self.cp.storage.create_backup(backup_path)
            verification = self.cp.storage.verify_backup(backup_path)
            return (
                200,
                {"manifest": manifest, "verification": verification},
                "application/json",
            )

        if method == "POST" and route == "/api/v1/ops/restore":
            backup_path = str(body.get("backup_path", "")).strip()
            if not backup_path:
                return 400, {"error": "backup_path is required"}, "application/json"
            try:
                res = self.cp.storage.restore_backup(backup_path)
                return 200, res, "application/json"
            except Exception as exc:
                return 400, {"error": str(exc)}, "application/json"

        if method == "GET" and route == "/api/v1/ops/doctor":
            sec = self.cp.run_security_baseline_check(
                listen_host=self.listen_host, listen_port=self.listen_port
            )
            alerts = self.cp.evaluate_operational_alerts()
            return (
                200,
                {
                    "status": "HEALTHY"
                    if sec["status"] == "PASS"
                    and alerts["active_alerts_count"] == 0
                    else "ATTENTION_REQUIRED",
                    "project": "MeterGate",
                    "version": __version__,
                    "security_baseline": sec,
                    "operational_alerts": alerts,
                    "declared_concurrency_boundary": DECLARED_CONCURRENCY_BOUNDARY,
                    "oncall_runbook": self.cp.config_loader.policy.get(
                        "oncall_runbook", []
                    ),
                },
                "application/json",
            )

        # 9. Switch Gateway Mode (`shadow` | `enforce`)
        if method == "POST" and route == "/api/v1/mode":
            try:
                res = self.cp.set_mode(mode=str(body.get("mode", "enforce")))
                return 200, res, "application/json"
            except ValueError as exc:
                return 400, {"error": str(exc)}, "application/json"

        # 10. 3-Tier Firewall Inspection Endpoint (/api/v1/inspect)
        if method == "POST" and route == "/api/v1/inspect":
            messages = body.get("messages", [])
            if messages and isinstance(messages, list):
                combined_prompt = "\n".join(
                    str(m.get("content", ""))
                    for m in messages
                    if isinstance(m, dict)
                )
            else:
                combined_prompt = str(
                    body.get("task_prompt") or body.get("prompt") or ""
                )
            inbound_payload = str(body.get("inbound_payload", ""))
            if (
                len(combined_prompt) + len(inbound_payload)
                > self.max_input_payload_chars
            ):
                return (
                    413,
                    {
                        "error": {
                            "type": "payload_too_large",
                            "message": f"Inspection payload length exceeds maximum allowed characters ({self.max_input_payload_chars}).",
                            "max_input_payload_chars": self.max_input_payload_chars,
                        }
                    },
                    "application/json",
                )

            session_id = str(
                body.get("session_id")
                or self._extract_header(headers, "X-MeterGate-Session")
                or "sess_inspect"
            )
            source_connector = str(
                body.get("source_connector", "email_webhook")
            )
            target_resources = body.get("target_resources", [])
            outbound_sinks = body.get("outbound_sinks", [])
            ephemeral_token = body.get(
                "ephemeral_token"
            ) or self._extract_header(headers, "X-MeterGate-Ephemeral-Token")

            req_budget_cap = body.get("max_request_cost_usd") or body.get(
                "budget_cap_usd"
            )
            sess_budget_cap = body.get("max_session_cost_usd") or body.get(
                "session_budget_cap_usd"
            )

            try:
                turn_result = self.cp.process_agent_turn(
                    session_id=session_id,
                    task_prompt=combined_prompt,
                    inbound_payload=inbound_payload,
                    source_connector=source_connector,
                    target_resources=target_resources,
                    outbound_sinks=outbound_sinks,
                    ephemeral_token=ephemeral_token,
                    provider_usage=body.get("provider_usage"),
                    trace_steps=body.get("trace_steps"),
                    input_state_hash=body.get("input_state_hash"),
                    output_state_hash=body.get("output_state_hash"),
                    record_ledger=bool(body.get("provider_usage") is not None),
                    caller_plane="control",
                    budget_cap_usd=(
                        float(req_budget_cap)
                        if req_budget_cap is not None
                        else None
                    ),
                    session_budget_cap_usd=(
                        float(sess_budget_cap)
                        if sess_budget_cap is not None
                        else None
                    ),
                )
            except BudgetCapExceededError as b_exc:
                return b_exc.status_code, b_exc.to_dict(), "application/json"

            if "mode" in body:
                turn_result["firewall"]["tier_breakdown"][
                    "ignored_request_mode_override"
                ] = body.get("mode")
            if "utc_date" in body:
                turn_result["firewall"]["tier_breakdown"][
                    "ignored_request_utc_date"
                ] = body.get("utc_date")
            status_code = 200 if turn_result["firewall"]["allowed"] else 403
            return status_code, {"metergate": turn_result}, "application/json"

        # 11. OpenAI & Anthropic Compatible Data-Plane Proxy (/v1/chat/completions & /v1/messages)
        if method == "POST" and route in ("/v1/chat/completions", "/v1/messages"):
            is_anthropic_messages = route == "/v1/messages" 
            quota_check = self.cp.check_daily_quota()
            if not quota_check["allowed"]:
                return (
                    429,
                    {
                        "error": {
                            "type": "daily_quota_exceeded",
                            "message": f"Exhausted daily budget quota (${quota_check['daily_quota_usd']}) for UTC date {quota_check['utc_date']}. Resets at {quota_check['resets_at_utc']}.",
                            "quota": quota_check,
                        }
                    },
                    "application/json",
                )

            upstream_override = body.get(
                "upstream_base_url"
            ) or self._extract_header(headers, "X-MeterGate-Upstream-URL")
            try:
                _ = self.forwarder.resolve_upstream_url(upstream_override)
            except UpstreamNotConfiguredError as exc:
                return (
                    503,
                    {
                        "error": {
                            "type": "upstream_not_configured",
                            "message": str(exc),
                        }
                    },
                    "application/json",
                )

            messages = body.get("messages", [])
            if not isinstance(messages, list):
                messages = []

            full_conversation_text = "\n".join(
                str(m.get("content", ""))
                for m in messages
                if isinstance(m, dict)
            )
            inbound_payload = str(body.get("inbound_payload", ""))
            if (
                len(full_conversation_text) + len(inbound_payload)
                > self.max_input_payload_chars
            ):
                return (
                    413,
                    {
                        "error": {
                            "type": "payload_too_large",
                            "message": f"Conversation payload length ({len(full_conversation_text) + len(inbound_payload)} chars) exceeds maximum allowed limit ({self.max_input_payload_chars} chars).",
                            "max_input_payload_chars": self.max_input_payload_chars,
                        }
                    },
                    "application/json",
                )

            sanitized_messages, _ = (
                self.cp.firewall.sanitize_conversation_messages(messages)
            )

            session_id = str(
                body.get("session_id")
                or self._extract_header(headers, "X-MeterGate-Session")
                or "sess_gateway_live"
            )
            agent_id = str(
                body.get("agent_id")
                or self._extract_header(headers, "X-MeterGate-Agent")
                or "local_agent"
            )
            source_connector = str(body.get("source_connector", "local_cli"))
            target_resources = body.get("target_resources", [])
            outbound_sinks = body.get("outbound_sinks", [])
            ephemeral_token = body.get(
                "ephemeral_token"
            ) or self._extract_header(headers, "X-MeterGate-Ephemeral-Token")
            stream_requested = bool(body.get("stream", False))
            requested_model = str(body.get("model", "auto"))

            req_budget_cap = body.get("max_request_cost_usd") or body.get(
                "budget_cap_usd"
            )
            sess_budget_cap = body.get("max_session_cost_usd") or body.get(
                "session_budget_cap_usd"
            )

            try:
                turn_result = self.cp.process_agent_turn(
                    session_id=session_id,
                    task_prompt=full_conversation_text,
                    inbound_payload=inbound_payload,
                    source_connector=source_connector,
                    target_resources=target_resources,
                    outbound_sinks=outbound_sinks,
                    ephemeral_token=ephemeral_token,
                    provider_usage=None,
                    trace_steps=body.get("trace_steps"),
                    input_state_hash=body.get("input_state_hash"),
                    output_state_hash=body.get("output_state_hash"),
                    agent_id=agent_id,
                    record_ledger=True,
                    caller_plane="data",
                    budget_cap_usd=(
                        float(req_budget_cap)
                        if req_budget_cap is not None
                        else None
                    ),
                    session_budget_cap_usd=(
                        float(sess_budget_cap)
                        if sess_budget_cap is not None
                        else None
                    ),
                    requested_model=requested_model,
                )
            except BudgetCapExceededError as b_exc:
                return b_exc.status_code, b_exc.to_dict(), "application/json"

            if "mode" in body:
                turn_result["firewall"]["tier_breakdown"][
                    "ignored_request_mode_override"
                ] = body.get("mode")
            if "utc_date" in body:
                turn_result["firewall"]["tier_breakdown"][
                    "ignored_request_utc_date"
                ] = body.get("utc_date")

            fw = turn_result["firewall"]
            rt = turn_result["routing"]
            if not fw["allowed"]:
                rem = fw.get("remediation", {})
                return (
                    403,
                    {
                        "error": {
                            "type": "metergate_policy_blocked",
                            "reason_code": fw.get("reason_code", "BLOCK_POLICY"),
                            "verdict_digest": fw.get("verdict_digest", ""),
                            "what_happened_zh": rem.get(
                                "what_happened_zh",
                                f"MeterGate 防火墙已保护你的 Agent 并拦截高危请求 ({fw['action_taken']})。你的配置未出错。",
                            ),
                            "what_to_do_zh": rem.get(
                                "what_to_do_zh",
                                "若确认是误拦，请点击控制台『放行并记住』或调用 POST /api/v1/firewall/allow-and-remember 一键放行。",
                            ),
                            "what_happened_en": rem.get(
                                "what_happened_en",
                                f"Blocked by MeterGate 3-Tier Firewall ({fw['action_taken']}).",
                            ),
                            "what_to_do_en": rem.get(
                                "what_to_do_en",
                                "If benign, call POST /api/v1/firewall/allow-and-remember or use sanitized_safe_payload.",
                            ),
                            "message": f"{rem.get('what_happened_zh', '')} {rem.get('what_to_do_zh', '')} | Blocked by MeterGate 3-Tier Firewall ({fw['action_taken']}) in mode '{fw['mode']}' with confidence {fw['confidence']}",
                            "remediation": rem,
                            "verdict": fw,
                            "ephemeral_auth_request": fw.get(
                                "ephemeral_auth_request"
                            ),
                        },
                        "metergate": turn_result,
                    },
                    "application/json",
                )

            target_model = (
                rt["selected_model"]
                if requested_model in ("", "auto")
                else requested_model
            )
            upstream_payload = (
                self.forwarder.build_transparent_upstream_payload(
                    original_body=body,
                    selected_model=target_model,
                    sanitized_messages=sanitized_messages,
                )
            )
            upstream_api_key = self.forwarder.resolve_upstream_api_key(
                headers=headers
            )

            if stream_requested:
                def _reconcile_on_stream_end(
                    usage_dict: Dict[str, Any], elapsed_ms: float
                ) -> Dict[str, Any]:
                    actual_in = int(
                        usage_dict.get(
                            "prompt_tokens",
                            rt["extracted_features"]["estimated_prompt_tokens"],
                        )
                    )
                    actual_out = int(usage_dict.get("completion_tokens", 120))
                    actual_cached = int(usage_dict.get("cached_tokens", 0))
                    reconciled = self.cp.router.reconcile_usage(
                        request_id=rt["request_id"],
                        selected_model=rt["selected_model"],
                        actual_prompt_tokens=actual_in,
                        actual_completion_tokens=actual_out,
                        actual_cached_tokens=actual_cached,
                        latency_ms=elapsed_ms,
                        failed=False,
                        quality_score=0.95,
                    )
                    turn_result["usage_reconciliation"] = reconciled
                    turn_result["upstream_cluster"] = dict(
                        self.forwarder.last_forward_meta
                    )
                    return turn_result

                def _record_stream_interrupted(
                    reason: str, elapsed_ms: float
                ) -> None:
                    with self.cp.storage.batch_write_transaction():
                        self.cp.storage.update_model_feedback(
                            model_id=rt["selected_model"],
                            latency_ms=elapsed_ms,
                            failed=True,
                            quality_score=0.0,
                        )
                        self.cp.storage.append_audit_event(
                            event_type="UPSTREAM_STREAM_INTERRUPTED",
                            session_id=session_id,
                            mode=fw["mode"],
                            decision_payload={
                                "request_id": fw["request_id"],
                                "route_request_id": rt["request_id"],
                                "agent_id": agent_id,
                                "selected_model": rt["selected_model"],
                                "stream_complete": False,
                                "reason": reason,
                            },
                            agent_id=agent_id,
                        )

                try:
                    gen = self.forwarder.open_incremental_sse_stream(
                        upstream_payload=upstream_payload,
                        upstream_url_override=upstream_override,
                        upstream_api_key=upstream_api_key,
                        on_complete=_reconcile_on_stream_end,
                        on_error=_record_stream_interrupted,
                    )
                except UpstreamProviderError as up_err:
                    self.cp.storage.update_model_feedback(
                        model_id=rt["selected_model"],
                        latency_ms=50.0,
                        failed=True,
                        quality_score=0.0,
                    )
                    return (
                        up_err.status_code,
                        {
                            "error": {
                                "type": up_err.error_code,
                                "status_code": up_err.status_code,
                                "message": up_err.message,
                                "upstream_error": up_err.upstream_body,
                            }
                        },
                        "application/json",
                    )

                if stream_as_generator:
                    return 200, gen, "text/event-stream; charset=utf-8"
                else:
                    raw_text = b"".join(gen).decode("utf-8")
                    return 200, raw_text, "text/event-stream; charset=utf-8"

            try:
                upstream_resp, real_latency_ms = (
                    self.forwarder.forward_json_completion(
                        upstream_payload=upstream_payload,
                        upstream_url_override=upstream_override,
                        upstream_api_key=upstream_api_key,
                    )
                )
            except UpstreamProviderError as up_err:
                self.cp.storage.update_model_feedback(
                    model_id=rt["selected_model"],
                    latency_ms=50.0,
                    failed=True,
                    quality_score=0.0,
                )
                return (
                    up_err.status_code,
                    {
                        "error": {
                            "type": up_err.error_code,
                            "status_code": up_err.status_code,
                            "message": up_err.message,
                            "upstream_error": up_err.upstream_body,
                        }
                    },
                    "application/json",
                )

            up_usage = upstream_resp.get("usage") or {}
            actual_in = int(
                up_usage.get(
                    "prompt_tokens",
                    rt["extracted_features"]["estimated_prompt_tokens"],
                )
            )
            actual_out = int(up_usage.get("completion_tokens", 120))
            actual_cached = int(up_usage.get("cached_tokens", 0))

            reconciled = self.cp.router.reconcile_usage(
                request_id=rt["request_id"],
                selected_model=rt["selected_model"],
                actual_prompt_tokens=actual_in,
                actual_completion_tokens=actual_out,
                actual_cached_tokens=actual_cached,
                latency_ms=real_latency_ms,
                failed=False,
                quality_score=0.95,
            )
            turn_result["usage_reconciliation"] = reconciled
            turn_result["upstream_cluster"] = dict(
                self.forwarder.last_forward_meta
            )

            if is_anthropic_messages:
                first_choice = (upstream_resp.get("choices") or [{}])[0]
                reply_content = (
                    first_choice.get("message", {}).get("content", "")
                    if isinstance(first_choice, dict)
                    else ""
                )
                anthropic_resp = {
                    "id": f"msg_{uuid.uuid4().hex[:12]}",
                    "type": "message",
                    "role": "assistant",
                    "model": rt["selected_model"],
                    "content": [{"type": "text", "text": reply_content}],
                    "stop_reason": "end_turn",
                    "usage": {
                        "input_tokens": actual_in,
                        "output_tokens": actual_out,
                        "cache_read_input_tokens": actual_cached,
                    },
                    "metergate": turn_result,
                }
                return 200, anthropic_resp, "application/json"

            response_payload = copy.deepcopy(upstream_resp)
            response_payload["model"] = rt["selected_model"]
            response_payload["usage"] = {
                "prompt_tokens": actual_in,
                "completion_tokens": actual_out,
                "cached_tokens": actual_cached,
                "total_tokens": actual_in + actual_out,
            }
            response_payload["metergate"] = turn_result
            return 200, response_payload, "application/json"

        # 12. Standard MCP JSON-RPC 2.0 & Tool Call Gateway (/mcp, /mcp/v1, /mcp/v1/call) (A1 & A5)
        if method == "POST" and route in ("/mcp", "/mcp/v1", "/mcp/v1/call"):
            if "jsonrpc" in body or "method" in body:
                rpc_resp = self.cp.handle_mcp_jsonrpc(body)
                return 200, rpc_resp, "application/json"

            # Legacy simplified MCP tool call compatibility with A5 evidence-based empty defaults (never assume .env/exfil without evidence)
            tool_name = str(body.get("tool_name", "mcp_tool"))
            tool_args = json.dumps(
                body.get("arguments", {}), ensure_ascii=False
            )
            session_id = str(body.get("session_id", "sess_mcp"))
            ephemeral_token = body.get(
                "ephemeral_token"
            ) or self._extract_header(headers, "X-MeterGate-Ephemeral-Token")
            try:
                turn_result = self.cp.process_agent_turn(
                    session_id=session_id,
                    task_prompt=f"MCP Tool Call: {tool_name}",
                    inbound_payload=tool_args,
                    source_connector=str(
                        body.get("source_connector", "local_cli")
                    ),
                    target_resources=body.get("target_resources", []),
                    outbound_sinks=body.get("outbound_sinks", []),
                    ephemeral_token=ephemeral_token,
                    record_ledger=False,
                    caller_plane="control",
                )
            except BudgetCapExceededError as b_exc:
                return b_exc.status_code, b_exc.to_dict(), "application/json"
            status_code = 200 if turn_result["firewall"]["allowed"] else 403
            return status_code, turn_result, "application/json"

        # 13. Approve One-Time Ephemeral Token (/api/v1/auth/approve)
        if method == "POST" and route == "/api/v1/auth/approve":
            try:
                with self.cp.storage.batch_write_transaction():
                    res = self.cp.auth_manager.approve_token(
                        token_id=str(body.get("token_id", "")),
                        approved_by=str(body.get("approved_by", "local_operator")),
                    )
                    self.cp.storage.append_audit_event(
                        event_type="EPHEMERAL_TOKEN_APPROVED",
                        session_id="system",
                        mode=self.cp.config_loader.get_mode(),
                        decision_payload=res,
                    )
                return 200, res, "application/json"
            except (ValueError, KeyError) as exc:
                return 400, {"error": str(exc)}, "application/json"

        return 404, {"error": f"Unknown endpoint {method} {route}"}, "application/json"


class _GatewayHTTPHandler(BaseHTTPRequestHandler):
    app: MeterGateGatewayApp

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _apply_cors_headers(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        if not self.app.is_origin_allowed(origin):
            return False
        self.send_header("Access-Control-Allow-Origin", origin.strip().rstrip("/"))
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-MeterGate-Upstream-Key, X-MeterGate-Session, X-MeterGate-Agent, X-MeterGate-Ephemeral-Token, X-MeterGate-Upstream-URL, X-Request-ID",
        )
        return True

    def _send(
        self,
        status: int,
        payload: Dict[str, Any] | str | Iterator[bytes],
        content_type: str,
        request_id: Optional[str] = None,
    ) -> None:
        req_id = request_id or self.app.last_request_id or f"req_{uuid.uuid4().hex[:8]}"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Request-ID", req_id)
        self._apply_cors_headers()
        ov = self.app.cp.get_overhead_budget_status()
        self.send_header(
            "X-MeterGate-Overhead-Ms", str(ov["last_gateway_overhead_ms"])
        )
        self.send_header(
            "X-MeterGate-Overhead-Budget-Status",
            "COMPLIANT" if ov["within_budget"] else "EXCEEDED",
        )
        if content_type.startswith("text/event-stream"):
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        if isinstance(payload, str):
            self.wfile.write(payload.encode("utf-8"))
            self.wfile.flush()
        elif isinstance(payload, dict):
            self.wfile.write(
                json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            )
            self.wfile.flush()
        else:
            for chunk_bytes in payload:
                self.wfile.write(chunk_bytes)
                self.wfile.flush()

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin")
        if origin and not self.app.is_origin_allowed(origin):
            self._send(
                403,
                {"error": "CORS origin forbidden"},
                "application/json",
            )
            return
        self._send(200, {}, "application/json")

    def do_GET(self) -> None:
        status, resp, ctype = self.app.handle_request(
            "GET", self.path, headers=dict(self.headers)
        )
        self._send(status, resp, ctype, request_id=self.app.last_request_id)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1

        if length < 0 or length > self.app.max_request_body_bytes:
            self._send(
                413,
                {
                    "error": {
                        "type": "payload_too_large",
                        "message": f"Content-Length ({length} bytes) exceeds maximum allowed limit ({self.app.max_request_body_bytes} bytes).",
                        "max_request_body_bytes": self.app.max_request_body_bytes,
                    }
                },
                "application/json",
            )
            return

        raw_bytes = self.rfile.read(length) if length > 0 else b"{}"
        raw = raw_bytes.decode("utf-8", errors="replace")
        try:
            body = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            body = {}
        status, resp, ctype = self.app.handle_request(
            "POST",
            self.path,
            body=body,
            headers=dict(self.headers),
            stream_as_generator=True,
            raw_body_size_bytes=len(raw_bytes),
        )
        self._send(status, resp, ctype, request_id=self.app.last_request_id)


class MeterGateProxyServer:
    """Manageable HTTP server wrapper supporting background thread start/stop."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8787,
        control_plane: Optional[MeterGateControlPlane] = None,
        upstream_base_url: Optional[str] = None,
        allowed_origins: Optional[List[str]] = None,
        enable_zero_config_fallback: bool = True,
    ) -> None:
        self.httpd = ThreadingHTTPServer((host, port), _GatewayHTTPHandler)
        self.host = host
        self.port = int(self.httpd.server_address[1])
        self.app = MeterGateGatewayApp(
            control_plane=control_plane,
            upstream_base_url=upstream_base_url,
            allowed_origins=allowed_origins,
            listen_host=self.host,
            listen_port=self.port,
            enable_zero_config_fallback=enable_zero_config_fallback,
        )
        self.app.set_listen_address(self.host, self.port)
        handler_cls = type(
            "BoundMeterGateHandler", (_GatewayHTTPHandler,), {"app": self.app}
        )
        self.httpd.RequestHandlerClass = handler_cls
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start_background(self) -> str:
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self._thread.start()
        return self.base_url

    def shutdown(self) -> None:
        self.app.shutdown()
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)
