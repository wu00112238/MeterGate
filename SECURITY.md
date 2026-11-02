# Security Policy & Local Data Integrity (`MeterGate v1.0.1`)

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.0.x` | Yes | Current MIT-licensed PyPI/uvx & MCP Registry release with Observe-Only mode |
| Prior Releases | No | Legacy internal versions superseded by unified `MeterGate v1.0.1` |

## Capability Boundaries & Positioning Declaration (`B5` / `A2` / `O3`)

- **Deployment Positioning**: Single-instance local developer & single-machine AI Agent security gateway (`<= 32` concurrent in-flight upstream requests). **Not designed for multi-tenant team sharing or high-concurrency public cluster aggregation.**
- **Zero-Telemetry & 100% Offline (`O5`)**: MeterGate collects zero telemetry, makes zero background network calls, and serves its Web Console with 100% inline assets.
- **Zero-Risk Observe-Only Mode (`O4`)**: Start with `metergate serve --mode observe` to log cost ledger and interception evidence without blocking any Agent request.

## Reporting a Security Issue

1. Open a security report in GitHub Issues or contact `wu00112238@users.noreply.github.com`.
2. Include the exact `metergate` version (`1.0.1`) and a reproducible `metergate inspect --payload "..."` sample.

---
🔗 [更多省时间工具](https://00112238.xyz) (`https://00112238.xyz`)
