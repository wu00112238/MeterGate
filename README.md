# 🛡️ MeterGate (v1.0.1)

<p align="center">
  <a href="#-中文说明"><b>🇨🇳 中文说明</b></a> | 
  <a href="#-english-summary"><b>🇬🇧 English Summary</b></a> | 
  <a href="https://00112238.xyz"><b>🔗 更多省时间工具 / More Tools</b></a>
</p>

**是什么**：一个**零遥测 (No Telemetry)、100% 离线、MIT 开源无付费墙**的本地 AI Agent 安全防火墙、**一手 Token 对账台账与官方单价成本估算网关**与**标准 MCP (JSON-RPC 2.0) 中间件**。  
**What It Is**: A **zero-telemetry, 100% offline, MIT-licensed (no paywalls)** local AI Agent security firewall, **first-hand token accounting ledger & official-rate cost estimation gateway**, and **standard MCP (JSON-RPC 2.0) middleware**.

**解决什么**：
- **首要痛点·一手事实**：按「模型 ID × 方向」（发出 prompt tokens / 收到 completion tokens / 缓存命中 cached tokens）一手计量你的 Agent 到底烧了多少 Token，与各厂商 Dashboard 官方 usage 响应 100% 对齐，永不过期、永不失真；
- **派生价值·两级账本**：在 Token 台账之上叠加 OpenAI / Anthropic / DeepSeek 官方公开单价推算成本（已对账真实花费与未回填预估分离，内置 30 天价目表保鲜守护）；
- **安全防线·三层阻断**：实时拦截「提示注入 + `.env` 密钥偷跑」致命三角，支持**导出一张高清晒单海报图 (`SVG` / `HTML`)**。  
**What It Solves**: Measures tokens by Model ID × Direction, overlays official rates for two-tier cost accounting, and intercepts the Lethal Trifecta in real time with exportable posters (`SVG`/`HTML`).

**怎么零风险用起来 (`O1` · `O4`)**：免 Git 一行命令 `pipx install metergate` 或 `uvx metergate serve --mode observe` **先以「观察模式（只记账抓证据、0% 误拦风险）」跑一周**，看到真实拦截证据后再一键开启阻断！支持一键**零残留卸载** (`metergate serve --clean-state`)！  
**Zero-Risk Quick Start**: Run via `uvx metergate serve --mode observe` in Observe-Only mode with zero risk! Supports one-line zero-residue uninstall.

### 🔒 首屏五大安心承诺 / 5 First-Screen Trust Signals (`O5`)

| 安心承诺 / Trust Signal | 具体保障机制 (Chinese) | Security Guarantee Mechanism (English) |
| :--- | :--- | :--- |
| **1. 零遥测 / No Telemetry** | 绝不收集或上传任何 Prompt、账单或使用统计；运行期间零后台外发请求 | 0 Bytes transmitted externally; zero telemetry or telemetry collectors running |
| **2. 100% 离线 / 100% Offline** | 控制台纯内联 CSS/JS，无任何公网 CDN 脚本或字体依赖，断网内网环境完整可用 | Pure inline CSS/JS; zero dependencies on external CDNs or remote resources |
| **3. 观察模式 / Observe-Only** | `metergate serve --mode observe` 只记账抓证据，100% 不打断现有工作流 | Audits usage and logs exfiltration evidence without interrupting running Agents |
| **4. MIT 开源 / Pure MIT License** | 100% 免费开源，无商业授权墙、无付费功能阉割 | 100% free and open-source under the MIT license without commercial paywalls |
| **5. 零残留卸载 / Zero-Residue** | `metergate serve --clean-state && pipx uninstall metergate` 彻底清除本地状态库 | Clean state command purges local SQLite state and keys without leaving junk |

> 📌 **前置定位与能力边界声明 / Upfront Positioning & Boundaries (`B5` & `O3`)**
> - **✅ 什么时候该装我 / When to Install**:
>   - *中文*：① 不知道 Claude Code / Cursor / OpenClaw 每天在哪个模型上烧了多少 Token；② 担心 `.env`、`sk-*`、SSH 私钥外泄给外部模型或第三方 MCP 插件；③ 想先用「观察模式」无感摸清 Agent 行为底细。
>   - *English*: ① You do not know how many tokens Claude Code / Cursor / OpenClaw burns per model each day; ② You worry about `.env`, `sk-*`, or SSH private keys leaking to external models/MCP tools; ③ You want a zero-risk Observe-Only audit before enforcing guardrails.
> - **❌ 什么时候别装我 / When NOT to Install**:
>   - *中文*：① **单机单实例定位**（并发上限 **32 并发**在途请求），不适合多租户团队共享或公网高并发集群；② 第二层启发式规则**不是神经网络大模型推理**，零样本隐喻变体可能漏过；③ 不解析图片像素或 PDF 二进制隐写。
>   - *English*: ① Single-instance desktop design (concurrency ceiling **<= 32 in-flight requests**), not for multi-tenant teams or public API clusters; ② Tier 2 heuristics is a fast rule scorer, **not deep neural network reasoning**; ③ Does not parse image steganography or binary streams.

![MeterGate Demo Animation](docs/demo.gif)

---

<a id="-中文说明"></a>
## 🇨🇳 中文说明 / Chinese Details

### ⚡ 30 秒免 Git 安装 & 零风险体验
- **方式一（免安装即用）**：`uvx metergate serve --mode observe`
- **方式二（隔离环境常驻）**：`pipx install metergate && metergate serve --mode observe --port 8787`
- **方式三（一键环境接管）**：`eval "$(metergate serve --export-env)"` 自动接管终端 OpenAI / Anthropic 环境变量。
- **方式四（生成战力海报）**：`metergate report --format svg --output ./my_agent_report.svg` 导出可视化对账与防御海报。

---

<a id="-english-summary"></a>
## 🇬🇧 English Details / 英文详细说明

### ⚡ 30-Second Zero-Git Install & Experience
- **Option 1 (Ephemeral Run)**: `uvx metergate serve --mode observe`
- **Option 2 (Isolated CLI)**: `pipx install metergate && metergate serve --mode observe --port 8787`
- **Option 3 (Shell Takeover)**: `eval "$(metergate serve --export-env)"` automatically proxies OpenAI / Anthropic environment variables.
- **Option 4 (Poster Export)**: `metergate report --format svg --output ./my_agent_report.svg` exports shareable visual report cards.

---

## 🤖 维度一：面向 AI Agent 的检索与接入 / Dimension 1: Agent Ecosystem Integration (`O1` ~ `O3` · `A1` ~ `A6`)

MeterGate 完整覆盖 Agent 选型时的三大信息源：**包管理器索引 (`PyPI` / `pipx` / `uvx`)**、**MCP 目录站 (`Official MCP Registry` / `Smithery` / `PulseMCP`)** 与 **仓库内选型决策契约 (`/llms.txt` & `/.well-known/metergate.json`)**。  
MeterGate comprehensively covers three agent selection channels: package indices, MCP directories, and in-repo decision manifests.

| Agent 渠道与能力 / Channel | 标准入口与命令 / Entrypoint | 机器契约说明 / Machine Contract Description |
| :--- | :--- | :--- |
| **O1 · PyPI 免 Git 安装** | `uvx metergate serve --mcp-stdio`<br>`pipx install metergate` | 无需 `git clone`，Agent 可无人值守一键拉起 / Unattended one-line launch |
| **O2 · MCP 目录站同步清单** | `GET /.well-known/mcp-registry.json`<br>`data/mcp_registry_manifests.json` | 官方 MCP Registry、Smithery 与 PulseMCP 注册清单 / Directory manifests |
| **O3 · `llms.txt` 选型决策段** | `GET /llms.txt`<br>`selection_decision_matrix` | 明确定义适用与不适用症状，Agent 读一遍即可决策 / Agent selection matrix |
| **A1 · 标准 MCP (JSON-RPC 2.0)** | `uvx metergate serve --mcp-stdio`<br>`POST /mcp` · `POST /mcp/v1/call` | 完整实现 MCP 握手与 4 个标准工具 / MCP handshake & 4 core tools |
| **A3 & A4 · 幂等自愈与前置预算** | `GET /api/v1/budget`<br>`POST /api/v1/firewall/allow-and-remember` | 恒定裁决指纹与执行前降级推荐 / Idempotent digest & pre-flight budget |

#### Claude Desktop / Cursor / Windsurf `uvx` MCP 配置 / MCP Configuration
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

## 📊 维度二：两级对账体系 / Dimension 2: Two-Tier Token & Cost Accounting (`R-TOKEN-METER-01` · `B1` · `O7`)

### 1. 为什么把 Token 用量升级为一等指标？ / Why Token Usage is a First-Class Metric
- **中文**：成本是二手推算，依赖价目表容易因厂商调价或阶梯折扣失真；Token 用量是唯一可严格对账的一手事实，API 响应自带官方 `usage` 字段，永不过期、永不失真。
- **English**: Cost is a secondary estimation dependent on pricing catalogs that distort during discounts or rate changes. Token usage is the only verifiable first-hand fact returned by official provider `usage` payloads, never expiring and never distorted.

### 2. 两级结构：一级 Token 事实 × 二级成本推算 / Two-Tier Structure: Token Facts × Cost Rates
- **一级事实 (Token Facts)**：按「模型 ID × 方向」（发出 prompt / 收到 completion / 缓存命中 cached）严格核算。
- **二级推算 (Derived Cost)**：叠加官方单价折算预估，保持已核对花费 (`actual_reconciled_usd`) 与预估花费严格分离，由 30 天保鲜检查 (`catalog_freshness`) 保障时效。

| 官方模型 ID (`model_id`) | 提供商 / Provider | 输入单价 (`/ 1K tokens`) | 缓存输入 (`/ 1K tokens`) | 输出单价 (`/ 1K tokens`) | 官方价格核对源 / Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gpt-4o-mini` | OpenAI | `$0.00015` | `$0.000075` | `$0.00060` | [OpenAI Pricing](https://openai.com/api/pricing/) |
| `deepseek-chat` | DeepSeek | `$0.00027` | `$0.000070` | `$0.00110` | [DeepSeek Pricing](https://api-docs.deepseek.com/quick_start/pricing) |
| `claude-3-5-haiku-latest` | Anthropic | `$0.00080` | `$0.000080` | `$0.00400` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |
| `gpt-4o` | OpenAI | `$0.00250` | `$0.001250` | `$0.01000` | [OpenAI Pricing](https://openai.com/api/pricing/) |
| `claude-3-7-sonnet-latest` | Anthropic | `$0.00300` | `$0.000300` | `$0.01500` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |
| `claude-opus-4-6` | Anthropic | `$0.01500` | `$0.001500` | `$0.07500` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |

---

## 🧰 日常主入口与命令清单 / Daily Entrypoints & CLI Commands (`M-03` · `B6` · `O6`)

| 命令 / Command | 中文用途说明 | English Purpose |
| :--- | :--- | :--- |
| **`metergate serve`** | **[日常主入口 1]** 启动网关（支持 `--mode observe` 观察模式、`--mcp-stdio`、`--export-env`、`--clean-state`） | **[Primary 1]** Start gateway proxy with observe mode, stdio MCP, env exports, and state reset |
| **`metergate report`** | **[日常主入口 2]** 查看或导出日报（支持 `--format svg\|html\|markdown\|json` 与 `--output` 晒单导出） | **[Primary 2]** Generate daily report cards (SVG / HTML / Markdown / JSON) |
| `metergate demo` | 交互演示或用 `--prompt` 实测你自己的真实请求 | Interactive demo or live prompt inspection |
| `metergate inspect` | 检测单条载荷、输出机器契约 (`--self-describe`) 或一键放行并记住 (`--allow-and-remember`) | Single payload inspection, self-description contract, or allowlist update |
| `metergate doctor` | 本地安全基线、权限、单价表保鲜度与 ReDoS 规则自检 | Diagnostics for local security, permissions, rate catalog freshness, and ReDoS safety |
| `metergate audit-verify` / `evidence` | 低频全量校验本地 SQLite 防篡改哈希链 / 导出离线审计证据包 | Verify cryptographic audit chain integrity / export audit bundle |
| `metergate backup` / `restore` | 在线热备与恢复本地 SQLite 账本与审计库 | Online backup and restore for local SQLite ledger |
| `metergate benchmark` | 运行内置合成与对抗性回归自测集（含明确非第三方评测声明） | Built-in regression benchmark suite (with non-third-party disclaimer) |

> **关于基准自测的诚实说明 / Disclaimer (`M-12` & `R4`)**：`metergate benchmark` 使用仓库内置的 18 条合成语料与 19 条对抗语料（**自测语料、非第三方验证**），仅用于验证规则未发生退化及单跳延迟，不代表对未知攻击的通用拦截率。  
> *Disclaimer*: `metergate benchmark` uses internal test corpora for regression checks and local latency measurements; it is not a third-party evaluation.

---

## 🛠️ 提需求 & 专属定制 / Feature Requests & Custom Builds (`M-15`)

- 👉 **想让我帮你改一版？发到这里**：直接前往本仓库 [GitHub Issues](../../issues/new/choose) 选择「**需求建议**」或「**专属定制与改装意向**」模板提交即可！  
- 👉 **Need a customized version? Submit here**: Visit [GitHub Issues](../../issues/new/choose) and select the Feature Request or Custom Build template!

---

## ☕ 打赏支持 & 更多省时间工具 / Sponsor & More Tools (`M-13` & `M-14`)

- 💖 **打赏支持作者 / Sponsor**: 欢迎通过 GitHub Sponsors 支持开源维护。 / Support open-source maintenance via GitHub Sponsors.
- 🔗 **[更多省时间工具](https://00112238.xyz)**：访问 **[https://00112238.xyz](https://00112238.xyz)** 获取作者开发的全部开源效率与自动化工具集。 / Visit **[https://00112238.xyz](https://00112238.xyz)** for more time-saving open-source developer tools.
