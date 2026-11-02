# 🛡️ MeterGate (v1.0.1)

<p align="center">
  <a href="README.md"><b>🇬🇧 English</b></a> |
  <a href="https://00112238.xyz"><b>🔗 更多省时间工具</b></a>
</p>

**是什么**：一个**零遥测 (No Telemetry)、100% 离线、MIT 开源无付费墙**的本地 AI Agent 安全防火墙、**一手 Token 对账台账与官方单价成本估算网关**与**标准 MCP (JSON-RPC 2.0) 中间件**。

**解决什么**：
- **首要痛点·一手事实**：按「模型 ID × 方向」（发出 prompt tokens / 收到 completion tokens / 缓存命中 cached tokens）一手计量你的 Agent 到底烧了多少 Token，与各厂商 Dashboard 官方 usage 响应 100% 对齐，永不过期、永不失真；
- **派生价值·两级账本**：在 Token 台账之上叠加 OpenAI / Anthropic / DeepSeek 官方公开单价推算成本（已对账真实花费与未回填预估分离，内置 30 天价目表保鲜守护）；
- **安全防线·三层阻断**：实时拦截「提示注入 + `.env` 密钥偷跑」致命三角，支持**导出一张高清晒单海报图 (`SVG` / `HTML`)**。

**怎么零风险用起来 (`O1` · `O4`)**：免 Git 一行命令 `pipx install metergate` 或 `uvx metergate serve --mode observe` **先以「观察模式（只记账抓证据、0% 误拦风险）」跑一周**，看到真实拦截证据后再一键开启阻断！支持一键**零残留卸载** (`metergate serve --clean-state`)！

### 🔒 首屏五大安心承诺 (`O5`)

| 安心承诺 | 具体保障机制 |
| :--- | :--- |
| **1. 零遥测** | 绝不收集或上传任何 Prompt、账单或使用统计；运行期间零后台外发请求 |
| **2. 100% 离线** | 控制台纯内联 CSS/JS，无任何公网 CDN 脚本或字体依赖，断网内网环境完整可用 |
| **3. 观察模式** | `metergate serve --mode observe` 只记账抓证据，100% 不打断现有工作流 |
| **4. MIT 开源** | 100% 免费开源，无商业授权墙、无付费功能阉割 |
| **5. 零残留卸载** | `metergate serve --clean-state && pipx uninstall metergate` 彻底清除本地状态库 |

> 📌 **前置定位与能力边界声明 (`B5` & `O3`)**
> - **✅ 什么时候该装我**:
>   1. 不知道 Claude Code / Cursor / OpenClaw 每天在哪个模型上烧了多少 Token；
>   2. 担心 `.env`、`sk-*`、SSH 私钥外泄给外部模型或第三方 MCP 插件；
>   3. 想先用「观察模式」无感摸清 Agent 行为底细。
> - **❌ 什么时候别装我**:
>   1. **单机单实例定位**（并发上限 **32 并发**在途请求），不适合多租户团队共享或公网高并发集群；
>   2. 第二层启发式规则**不是神经网络大模型推理**，零样本隐喻变体可能漏过；
>   3. 不解析图片像素或 PDF 二进制隐写。

![MeterGate Demo Animation](docs/demo.gif)

---

## 🤖 维度一：面向 AI Agent 的检索与接入 (`O1` ~ `O3` · `A1` ~ `A6`)

MeterGate 完整覆盖 Agent 选型时的三大信息源：**包管理器索引 (`PyPI` / `pipx` / `uvx`)**、**MCP 目录站 (`Official MCP Registry` / `Smithery` / `PulseMCP`)** 与 **仓库内选型决策契约 (`/llms.txt` & `/.well-known/metergate.json`)**。

| Agent 渠道与能力 | 标准入口与命令 | 机器契约说明 |
| :--- | :--- | :--- |
| **O1 · PyPI 免 Git 安装** | `uvx metergate serve --mcp-stdio`<br>`pipx install metergate` | 无需 `git clone`，Agent 可无人值守一键拉起 |
| **O2 · MCP 目录站同步清单** | `GET /.well-known/mcp-registry.json`<br>`data/mcp_registry_manifests.json` | 官方 MCP Registry、Smithery 与 PulseMCP 注册清单 |
| **O3 · `llms.txt` 选型决策段** | `GET /llms.txt`<br>`selection_decision_matrix` | 明确定义适用与不适用症状，Agent 读一遍即可决策 |
| **A1 · 标准 MCP (JSON-RPC 2.0)** | `uvx metergate serve --mcp-stdio`<br>`POST /mcp` · `POST /mcp/v1/call` | 完整实现 MCP 握手与 4 个标准工具 |
| **A3 & A4 · 幂等自愈与前置预算** | `GET /api/v1/budget`<br>`POST /api/v1/firewall/allow-and-remember` | 恒定裁决指纹与执行前降级推荐 |

#### Claude Desktop / Cursor / Windsurf `uvx` MCP 配置
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

## 📊 维度二：两级对账体系 (`R-TOKEN-METER-01` · `B1` · `O7`)

### 1. 为什么把 Token 用量升级为一等指标？
成本是二手推算，依赖价目表容易因厂商调价或阶梯折扣失真；Token 用量是唯一可严格对账的一手事实，API 响应自带官方 `usage` 字段，永不过期、永不失真。

### 2. 两级结构：一级 Token 事实 × 二级成本推算
- **一级事实 (Token Facts)**：按「模型 ID × 方向」（发出 prompt / 收到 completion / 缓存命中 cached）严格核算。
- **二级推算 (Derived Cost)**：叠加官方单价折算预估，保持已核对花费 (`actual_reconciled_usd`) 与预估花费严格分离，由 30 天保鲜检查 (`catalog_freshness`) 保障时效。

| 官方模型 ID (`model_id`) | 提供商 | 输入单价 (`/ 1K tokens`) | 缓存输入 (`/ 1K tokens`) | 输出单价 (`/ 1K tokens`) | 官方价格核对源 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gpt-4o-mini` | OpenAI | `$0.00015` | `$0.000075` | `$0.00060` | [OpenAI Pricing](https://openai.com/api/pricing/) |
| `deepseek-chat` | DeepSeek | `$0.00027` | `$0.000070` | `$0.00110` | [DeepSeek Pricing](https://api-docs.deepseek.com/quick_start/pricing) |
| `claude-3-5-haiku-latest` | Anthropic | `$0.00080` | `$0.000080` | `$0.00400` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |
| `gpt-4o` | OpenAI | `$0.00250` | `$0.001250` | `$0.01000` | [OpenAI Pricing](https://openai.com/api/pricing/) |
| `claude-3-7-sonnet-latest` | Anthropic | `$0.00300` | `$0.000300` | `$0.01500` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |
| `claude-opus-4-6` | Anthropic | `$0.01500` | `$0.001500` | `$0.07500` | [Anthropic Pricing](https://www.anthropic.com/pricing#api) |

---

## 🧰 日常主入口与命令清单 (`M-03` · `B6` · `O6`)

| 命令 | 用途说明 |
| :--- | :--- |
| **`metergate serve`** | **[日常主入口 1]** 启动网关（支持 `--mode observe` 观察模式、`--mcp-stdio`、`--export-env`、`--clean-state`） |
| **`metergate report`** | **[日常主入口 2]** 查看或导出日报（支持 `--format svg\|html\|markdown\|json` 与 `--output` 晒单导出） |
| `metergate demo` | 交互演示或用 `--prompt` 实测你自己的真实请求 |
| `metergate inspect` | 检测单条载荷、输出机器契约 (`--self-describe`) 或一键放行并记住 (`--allow-and-remember`) |
| `metergate doctor` | 本地安全基线、权限、单价表保鲜度与 ReDoS 规则自检 |
| `metergate audit-verify` / `evidence` | 低频全量校验本地 SQLite 防篡改哈希链 / 导出离线审计证据包 |
| `metergate backup` / `restore` | 在线热备与恢复本地 SQLite 账本与审计库 |
| `metergate benchmark` | 运行内置合成与对抗性回归自测集（含明确非第三方评测声明） |

> **关于基准自测的诚实说明 (`M-12` & `R4`)**：`metergate benchmark` 使用仓库内置的 18 条合成语料与 19 条对抗语料（**自测语料、非第三方验证**），仅用于验证规则未发生退化及单跳延迟，不代表对未知攻击的通用拦截率。

---

## 🛠️ 提需求 & 专属定制 (`M-15`)

- 👉 **想让我帮你改一版？发到这里**：直接前往本仓库 [GitHub Issues](../../issues/new/choose) 选择「**需求建议**」或「**专属定制与改装意向**」模板提交即可！

---

## ☕ 打赏支持 & 更多省时间工具 (`M-13` & `M-14`)

- 💖 **打赏支持作者**：欢迎通过 GitHub Sponsors 支持开源维护。
- 🔗 **[更多省时间工具](https://00112238.xyz)**：访问 **[https://00112238.xyz](https://00112238.xyz)** 获取作者开发的全部开源效率与自动化工具集。
