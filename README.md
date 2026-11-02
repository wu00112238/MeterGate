# 🛡️ MeterGate (v1.0.1)

<p align="center">
  <a href="README.zh-CN.md"><b>🇨🇳 中文说明</b></a> |
  <a href="https://00112238.xyz"><b>🔗 More Tools</b></a>
</p>

**What It Is**: A **zero-telemetry, 100% offline, MIT-licensed (no paywalls)** local AI Agent security firewall, **first-hand token accounting ledger & official-rate cost estimation gateway**, and **standard MCP (JSON-RPC 2.0) middleware**.

**What It Solves**:
- **Primary pain point · first-hand facts**: Measures exactly how many tokens your Agent burns, by **Model ID × Direction** (prompt tokens sent / completion tokens received / cached tokens), 100% aligned with each provider's official Dashboard `usage` responses — never expiring, never distorted;
- **Derived value · two-tier ledger**: Overlays official OpenAI / Anthropic / DeepSeek public rates to estimate cost on top of the token ledger (reconciled actuals and un-filled estimates kept strictly separate, with a 30-day rate-catalog freshness guard);
- **Security line · 3-tier interception**: Real-time blocking of the "prompt injection + `.env` secret exfiltration" Lethal Trifecta, with **one high-resolution poster export (`SVG` / `HTML`)**.

**Zero-Risk Quick Start (`O1` · `O4`)**: No Git needed — one line: `pipx install metergate` or `uvx metergate serve --mode observe`. **Run in Observe-Only mode (ledger-only evidence capture, 0% false-block risk) for a week first**, review the real interception evidence, then flip enforcement on. Supports one-line **zero-residue uninstall** (`metergate serve --clean-state`)!

### 🔒 5 First-Screen Trust Signals (`O5`)

| Trust Signal | Security Guarantee Mechanism |
| :--- | :--- |
| **1. No Telemetry** | 0 bytes transmitted externally; zero telemetry or telemetry collectors running |
| **2. 100% Offline** | Console uses pure inline CSS/JS; zero dependencies on external CDNs or remote resources |
| **3. Observe-Only** | `metergate serve --mode observe` audits usage and logs exfiltration evidence without interrupting running Agents |
| **4. Pure MIT License** | 100% free and open-source under the MIT license without commercial paywalls |
| **5. Zero-Residue Uninstall** | `metergate serve --clean-state && pipx uninstall metergate` purges local SQLite state and keys without leaving junk |

> 📌 **Upfront Positioning & Boundaries (`B5` & `O3`)**
> - **✅ When to Install**:
>   1. You do not know how many tokens Claude Code / Cursor / OpenClaw burns per model each day;
>   2. You worry about `.env`, `sk-*`, or SSH private keys leaking to external models / third-party MCP tools;
>   3. You want a zero-risk Observe-Only audit before enforcing guardrails.
> - **❌ When NOT to Install**:
>   1. **Single-instance desktop design** (concurrency ceiling **<= 32 in-flight requests**) — not for multi-tenant teams or public high-concurrency clusters;
>   2. Tier 2 heuristics is a fast rule scorer, **not deep neural network reasoning** — zero-shot metaphor variants may slip through;
>   3. Does not parse image steganography or PDF binary streams.

![MeterGate Demo Animation](docs/demo.gif)

---

## 🤖 Dimension 1: Agent Ecosystem Integration (`O1` ~ `O3` · `A1` ~ `A6`)

MeterGate comprehensively covers the three agent selection channels: **package indices (`PyPI` / `pipx` / `uvx`)**, **MCP directories (`Official MCP Registry` / `Smithery` / `PulseMCP`)**, and **in-repo decision manifests (`/llms.txt` & `/.well-known/metergate.json`)**.

| Channel | Entrypoint | Machine Contract Description |
| :--- | :--- | :--- |
| **O1 · Git-Free PyPI Install** | `uvx metergate serve --mcp-stdio`<br>`pipx install metergate` | No `git clone` needed; agents can launch unattended in one line |
| **O2 · MCP Directory Manifests** | `GET /.well-known/mcp-registry.json`<br>`data/mcp_registry_manifests.json` | Official MCP Registry, Smithery and PulseMCP directory manifests |
| **O3 · `llms.txt` Selection Matrix** | `GET /llms.txt`<br>`selection_decision_matrix` | Explicit recommended / not-recommended symptoms; agents decide after a single read |
| **A1 · Standard MCP (JSON-RPC 2.0)** | `uvx metergate serve --mcp-stdio`<br>`POST /mcp` · `POST /mcp/v1/call` | Full MCP handshake and 4 core tools |
| **A3 & A4 · Idempotent Self-Healing & Pre-Flight Budget** | `GET /api/v1/budget`<br>`POST /api/v1/firewall/allow-and-remember` | Constant adjudication digest and pre-execution downgrade advisory |

#### Claude Desktop / Cursor / Windsurf `uvx` MCP Configuration
```json
{
  "mcpServers": {
    "metergate": {
      "command": "uvx",
      "args": ["metergate", "serve", "--mcp-stdio"]
    }
  }
}
```

---

## 📊 Dimension 2: Two-Tier Token & Cost Accounting (`R-TOKEN-METER-01` · `B1` · `O7`)

### 1. Why Token Usage is a First-Class Metric
Cost is a secondary estimation dependent on pricing catalogs that distort during discounts or rate changes. Token usage is the only verifiable first-hand fact returned by official provider `usage` payloads — never expiring and never distorted.

### 2. Two-Tier Structure: Token Facts × Cost Rates
- **Tier 1 Facts (Token Facts)**: strictly accounted by **Model ID × Direction** (prompt sent / completion received / cached).
- **Tier 2 Estimation (Derived Cost)**: overlays official rates, keeping reconciled spend (`actual_reconciled_usd`) and estimated spend strictly separate, guarded by a 30-day freshness check (`catalog_freshness`).

| Official Model ID (`model_id`) | Provider | Input (`/ 1K tokens`) | Cached Input (`/ 1K tokens`) | Output (`/ 1K tokens`) | Official Price Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gpt-4o-mini` | OpenAI | `$0.00015` | `$0.000075` | `$0.00060` | [OpenAI Pricing](https://openai.com/api/pricing/) |
| `deepseek-chat` | DeepSeek | `$0.00027` | `$0.000070` | `$0.00110` | [DeepSeek Pricing](https://api-docs.deepseek.com/quick_start/pricing) |
| `claude-3-5-haiku-latest` | Anthropic | `$0.00080` | `$0.000080` | `$0.00400` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |
| `gpt-4o` | OpenAI | `$0.00250` | `$0.001250` | `$0.01000` | [OpenAI Pricing](https://openai.com/api/pricing/) |
| `claude-3-7-sonnet-latest` | Anthropic | `$0.00300` | `$0.000300` | `$0.01500` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |
| `claude-opus-4-6` | Anthropic | `$0.01500` | `$0.001500` | `$0.07500` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |

---

## 🧰 Daily Entrypoints & CLI Commands (`M-03` · `B6` · `O6`)

| Command | Purpose |
| :--- | :--- |
| **`metergate serve`** | **[Primary 1]** Start gateway proxy with observe mode (`--mode observe`), stdio MCP (`--mcp-stdio`), env exports (`--export-env`), and state reset (`--clean-state`) |
| **`metergate report`** | **[Primary 2]** Generate daily report cards (`--format svg\|html\|markdown\|json` with `--output` export) |
| `metergate demo` | Interactive demo, or live inspection of your own prompt via `--prompt` |
| `metergate inspect` | Single payload inspection, self-description contract (`--self-describe`), or allowlist update (`--allow-and-remember`) |
| `metergate doctor` | Diagnostics for local security baseline, permissions, rate catalog freshness, and ReDoS rule safety |
| `metergate audit-verify` / `evidence` | Verify cryptographic audit chain integrity / export offline audit bundle |
| `metergate backup` / `restore` | Online hot backup and restore for the local SQLite ledger |
| `metergate benchmark` | Built-in regression benchmark suite (with explicit non-third-party disclaimer) |

> **Honest Benchmark Disclaimer (`M-12` & `R4`)**: `metergate benchmark` uses 18 built-in synthetic and 19 adversarial internal corpora (**self-test corpora, not third-party verified**) to check for rule regression and single-hop latency only; it does not represent a general interception rate against unknown attacks.

---

## 🛠️ Feature Requests & Custom Builds (`M-15`)

- 👉 **Need a customized version? Submit here**: Visit [GitHub Issues](../../issues/new/choose) and select the **Feature Request** or **Custom Build** template!

---

## ☕ Sponsor & More Tools (`M-13` & `M-14`)

- 💖 **Sponsor**: Support open-source maintenance via GitHub Sponsors.
- 🔗 **[More time-saving tools](https://00112238.xyz)**: Visit **[https://00112238.xyz](https://00112238.xyz)** for the author's full collection of open-source efficiency and automation tools.
