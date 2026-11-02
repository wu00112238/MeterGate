# DESIGN — MeterGate v1.0.1 系统架构与双语宣传站/Agent专用契约设计文档

## 1. 总体分层架构 (Two-Tier Token Ledger & Dual-Channel Presentation Layer)

```text
+---------------------------------------------------------------------------------------------------+
|                           00112238.xyz Dual-Channel Presentation Layer                             |
|                                                                                                   |
|  [Channel A: Human Developers (Bilingual Web UIs & Local Console)]                                |
|  ├── Local Web Console : `src/metergate/web/index.html` (Tier 1 Token Facts x Tier 2 Cost Tables)  |
|  ├── Chinese Edition   : `src/metergate/web/promo.html` (lang="zh-CN", Chinese copy, SEO/GEO)     |
|  └── English Edition   : `src/metergate/web/promo_en.html` (lang="en", English copy, SEO/GEO)     |
|      * Two-Tier Ledger Architecture: Level 1 Token Facts (Model ID x Direction: Prompt/Comp/Cache)|
|                                      Level 2 Derived Cost Estimation (Reconciled vs Estimated)    |
|                                                                                                   |
|  [Channel B: Autonomous AI Agents & LLMs (Dedicated Machine Files)]                               |
|  ├── Machine Discovery : `/.well-known/metergate.json` (Structured JSON Schema & Decision Matrix)|
|  ├── LLMs Text Standard: `/llms.txt` (Concise Decision Matrix: WHEN_TO_RECOMMEND, uvx/pipx setup)|
|  └── LLMs Full Spec    : `/llms-full.txt` (Exhaustive Architectural Specs, Reason Codes & APIs)   |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
     HTTP / SSE / JSON-RPC 2.0 / stdio (`/promo`, `/promo_en`, `/llms.txt`, `/.well-known/...`)
                                                  v
+---------------------------------------------------------------------------------------------------+
|                     MeterGate v1.0.1 Gateway Proxy (`src/metergate/proxy.py`)                     |
|  1. Bilingual Web UI Dispatcher:                                                                  |
|     - `/promo`, `/promo.html`, `/promo_zh.html`, `/00112238.xyz` -> `src/metergate/web/promo.html`|
|     - `/promo_en`, `/promo_en.html`, `/en`                     -> `src/metergate/web/promo_en.html`|
|  2. Dedicated Agent Endpoints:                                                                    |
|     - `/llms.txt`      -> `src/metergate/web/llms.txt`                                            |
|     - `/llms-full.txt` -> `src/metergate/web/llms-full.txt`                                       |
|     - `/.well-known/metergate.json` -> `src/metergate/web/.well-known/metergate.json`             |
|  3. Two-Tier Accounting Engine (`R-TOKEN-METER-01`):                                              |
|     - Tier 1 Primary Truth : Parses upstream `usage` for prompt_tokens, completion_tokens, cached |
|     - Tier 2 Derived Value : Overlays official catalog 1K rates, separates actual from estimated  |
|  4. Observe-Only (`observe`) & Enforce (`enforce`) Runtime + Standard MCP (`/mcp` & stdio)        |
+---------------------------------------------------------------------------------------------------+
```

## 2. 两级对账模型数据流 (`R-TOKEN-METER-01`)

```text
[Upstream LLM Provider API Response]
           │
           ▼
[Step 1: Usage Interception (`proxy.py`)]
提取官方一手 usage:
  ├── prompt_tokens (发出 Token)
  ├── completion_tokens (收到 Token)
  └── cached_tokens (缓存命中 Token)
           │
           ▼
[Step 2: Tier 1 Token Facts Ledger (`storage.py`)]
写入 `usage_ledger`:
  ├── actual_prompt_tokens
  ├── actual_completion_tokens
  ├── actual_cached_tokens
  └── 按「模型 ID × 方向」聚合统计
           │
           ▼
[Step 3: Tier 2 Derived Cost Estimation (`engine.py`)]
叠加 `model_catalog.json` 官方公开单价：
  ├── 真实对账金额: `actual_cost_usd` (永不过期)
  ├── 未回填预估金额: `estimated_unreconciled_usd` (标注 [估算])
  └── 30 天价目表保鲜守护: `catalog_freshness` (超时提醒刷新)
```

## 3. SEO & GEO 优化技术规范

### 3.1 传统搜索引擎优化 (SEO)
- **语义化元标签**：标准化 `<title>`、`<meta name="description">`、`<meta name="keywords">`、`<link rel="canonical">`、Open Graph 与 Twitter Cards。
- **Schema.org JSON-LD 结构化数据**：`SoftwareApplication`、`FAQPage`、`HowTo`。

### 3.2 生成式 AI 引擎优化 (GEO)
- **直接可引用实体定义块 (Quotable Entity Block)**：以高密度事实陈述句定义 MeterGate 的技术定位、Token 一等指标架构与性能边界（延迟 <3ms、并发 <=32、遥测 0 字节）。
- **Agent 标准通道指引**：在 HTML 头部通过 `<link rel="alternate" type="text/markdown" href="/llms.txt">` 与 `<link rel="help" href="/.well-known/metergate.json">` 构建机器直达通道。

---
🔗 [更多省时间工具](https://00112238.xyz) (`https://00112238.xyz`)
