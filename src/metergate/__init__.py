"""
MeterGate — Zero-Telemetry Offline AI Agent Security Firewall, Verifiable Cost Ledger & Standard MCP Middleware
Single-Identity, Zero-Config, Observe-Only Onboarding, 100% Free & MIT Licensed (M-01..M-15, R1..R8, A1..A6, B1..B7, O1..O7)
"""

__project__ = "MeterGate"
__version__ = "1.0.1"

from .engine import (
    BudgetCapExceededError,
    ClosedLoopRouter,
    FirewallVerdict,
    GatewayRateLimiter,
    MeterGateControlPlane,
    PolicyConfigLoader,
    ProgressiveAuthManager,
    RegexSafetyGuard,
    RoutingDecision,
    ThreeTierFirewall,
    TopologyCircuitBreaker,
    TopologyHealthReport,
    UnsafeRegexPatternError,
)
from .storage import CURRENT_SCHEMA_VERSION, MeterGateStorage

__all__ = [
    "__project__",
    "__version__",
    "MeterGateControlPlane",
    "MeterGateStorage",
    "CURRENT_SCHEMA_VERSION",
    "PolicyConfigLoader",
    "GatewayRateLimiter",
    "BudgetCapExceededError",
    "ThreeTierFirewall",
    "RegexSafetyGuard",
    "UnsafeRegexPatternError",
    "ClosedLoopRouter",
    "ProgressiveAuthManager",
    "TopologyCircuitBreaker",
    "FirewallVerdict",
    "RoutingDecision",
    "TopologyHealthReport",
]
