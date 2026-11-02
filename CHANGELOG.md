# CHANGELOG — MeterGate 版本演进历史

## [v1.0.1] - 2026-11-02 (Release Hardening, Git Immunity & Bilingual Specification)

> **发版实测缺陷沉淀与架构升级说明**：针对 PyPI 首发（metergate 1.0.0）实测暴露的问题，彻底将「消除本地假设、对齐 CI 环境、中英双语规范化」沉淀为飞轮协议层能力与自动化门禁，消除单次补丁风险。

- **需求一：门禁与测试对 .gitignore 状态免疫（P0 架构强化）**：
  - 清理 `.gitignore`，彻底移除对飞轮脚手架（`.agents/`、`src/flywheel/`、`tests/test_flywheel.py`）与交接文档（`AGENTS.md`、`MEMORY.md`、`docs/OPS_FEEDBACK.md`）的误排除。
  - 升级 `test_all.py` 跨环境统一验收门禁，新增 Git 追踪完整性（`git ls-files`）与 `.gitignore --no-index` 规则免疫检测，严防「本地因存在未提交文件全绿、CI 干净克隆因缺失文件秒挂」的静默窗口。
  - 在脚手架缺失或无 Git 环境下提供确定性容错降级，消除了 `iter_tracked_deliverables` 的 `NoneType` 调用异常与未处理崩溃，确保在任何配置下均输出结构化错误列表与退出码 1。
  - 门禁报错严格遵循三要素规范：明确指明缺失/不一致文件路径、所属门禁项与违规规则、提供人类与 AI 可直接复制执行的明确建议动作。
- **需求二：README 与发布相关产物中英双语工程规范成文与落地（P1 生态扩展）**：
  - `README.md` 全面重构为中英双语结构对称版本，核心信息（是什么、解决什么、首屏五大安心承诺、前置边界声明、免 Git 一行安装、Agent 生态接入、两级 Token 与成本对账、运维命令清单）在两种语言中语义完全等价。
  - 发布相关产物统一对齐双语规范：`pyproject.toml` 中的包描述更新为中英双语组合，`src/metergate/web/llms.txt`、`src/metergate/data/llms.txt` 与 `src/metergate/web/llms-full.txt` 选型矩阵与端点清单逐项实现双语对称。
  - 沉淀成文规范 `docs/BILINGUAL_SPEC.md`，并在 `.github/RELEASE_TEMPLATE.md` 与 `docs/RELEASE_TEMPLATE.md` 中建立标准化双语发版说明模版。
  - `test_all.py` 集成自动化双语校验门禁，自动验证 README、pyproject 与 llms.txt 的双语完整性。
- **需求三：通用飞轮规范沉淀（Flywheel Skill 架构规范沉淀）**：
  - 在 `.agents/skills/flywheel/references/FLYWHEEL_SPEC.md` 中新增「支柱六：CI 与发布环境免疫规范」与「支柱七：对外产物中英双语规范」。
  - 同步更新 `.agents/skills/flywheel/SKILL.md` 与 `README.md`，规范条款表述完全通用抽象，不绑定 MeterGate 项目名与版本号，确保脚手架跨项目可复用。
- **需求四：遗留缺陷清理**：
  - 修正 `pyproject.toml` 与 `src/metergate/data/mcp_registry_manifests.json` 中指向虚构命名空间的仓库 URL，统一对齐至真实地址 `https://github.com/wu00112238/MeterGate`。
  - 落地 `version.json` 指纹漂移治理：在 `src/flywheel/cli.py` 的 `sync_version_json` 与 `cmd_handoff` 中增加指纹提交警示，并在 `test_all.py` 中主动拦截未提交的 `version.json` 变更，阻断「本地重算、远端旧指纹」的静默漂移窗口。
  - 对齐发布工作流名称：将 `.github/workflows/publish-pypi.yml` 名称对齐为 `Publish MeterGate to PyPI`，消除与实际发布能力的名实不符。

## [v1.0.0] - 2026-11-02 (First Official Public SemVer Release)

> **版本重置与历史沿革说明**：自本版本起遵循 SemVer 公开发布，此前版本号为内部演进历史，未对外发布。开启全新版本历史与飞轮轮次纪元。

- **R-TOKEN-METER-01 核心叙事调整与一手 Token 台账体系（P0）**：
  - 将「按模型统计 Token 用量」升级为产品的一等指标与首要痛点叙事，解决「按官方单价算钱」依赖二手价目表推算易失真的痛点。
  - 按「模型 ID × 方向」两个维度一手计量：发出 Token (`prompt_tokens`)、收到 Token (`completion_tokens`) 与缓存命中 Token (`cached_tokens`)，直接对齐厂商 API 官方 usage 响应，永不过期、永不失真。
  - 成本估算降级为派生价值：在 Token 事实台账之上叠加官方公开单价推算成本，保留「已对账真实花费」与「未回填预估」严格分离，并由 30 天价目表保鲜机制保驾护航。
  - 全端叙事结构（README、Web 控制台、日报海报、CLI 启动 Banner）统一为两级呈现：一级展示 Token 事实，二级展示成本推算。
- **Flywheel 版本管理与 SSoT 权威派生体系**：
  - 确立主包 `src/metergate/__init__.py` 中的 `__version__` 为全项目唯一权威真值源（SSoT），解析机制严格断言，解析失败显式报错，严禁静默回退。
  - 实现「一处声明、处处派生、自动校验」的版本管理闭环，涵盖 `pyproject.toml`、`Dockerfile`、`docker-compose.yml`、`SECURITY.md`、`README.md`、`version.json`、`docs/`、机器自描述契约（`.well-known/`、`llms.txt`、MCP 注册清单）、Web 控制台与全部数据 JSON 的 `*_version` 字段。
  - Python 运行时全面消除版本硬编码，统一从包根动态导入引用 `__version__`。
  - 升级 `test_all.py` 自动化验收门禁为全仓库深度扫描，严查游离于 SSoT 之外的残留版本号副本。
- **MeterGate 核心能力正式版交付**：
  - 单实例、零配置、零遥测、100% 离线运行的本地 AI Agent 三层安全防火墙（Lethal Trifecta 阻断与敏感凭据脱敏）。
  - 基于真实厂商公布单价的 Token 成本记账与每日行为日报（SVG / HTML 海报）。
  - 标准 MCP (JSON-RPC 2.0) 中间件与 GEO / llms.txt 机器自描述发现契约。
  - 极简黑客终端美学双语独立宣传站（`00112238.xyz`）。

## [v4.5.0] - 2026-10-29 (Bilingual Dual-Channel Promo Sites & Dedicated Agent-Native Manifests & SEO/GEO Optimization Release)
- **人机受众彻底解耦 (Human-Agent Decoupling)**：彻底剥离嵌入在网页中的机器 JSON 契约脚本与面向 Agent 自测的 `#for-agents` 段落，使其独立沉淀为更易被 AI 消费的标准纯文本与结构化端点（`/llms.txt`、`/llms-full.txt` 与 `/.well-known/metergate.json`）。
- **纯正中英双语独立宣传站 (Dedicated Bilingual Promo Sites)**：
  - 中文版 (`src/metergate/web/promo.html` & `promo_zh.html`，路由 `/promo`, `/promo.html`, `/promo_zh`)：专为国内开发者定制，纯正中文技术语境、清晰操作引导与文案。
  - 英文版 (`src/metergate/web/promo_en.html`，路由 `/promo_en`, `/promo_en.html`, `/en`)：专为国际开源社区打造，地道自然的技术英语文案与排版。
  - 顶栏双向无缝语言切换器（`[🌐 English / 切换英文]` 与 `[🌐 中文 / Switch to Chinese]`），保持极简黑客终端美学。
- **全面 SEO 优化**：标准化 `<title>`、`<meta description>`、`<meta keywords>`、`<link rel="canonical">`、Open Graph 与 Twitter Card 社交标签，集成包含 `SoftwareApplication`、`FAQPage` 与 `HowTo` 的 Schema.org JSON-LD 结构化数据。
- **深度 GEO（生成式引擎优化）**：提供高密度可直接引用的事实定义块（Quotable Entity Definition）、显式问答结构（Structured Q&A）、关键性能与边界对照表，并通过 `<link rel="alternate" type="text/markdown" href="/llms.txt">` 建立直达 Agent 核心选型契约（`WHEN_TO_RECOMMEND` / `WHEN_NOT_TO_RECOMMEND`）的直通通道。
- **100% 离线与极简美学完整传承**：两套页面均严格通过 `R7` 门禁（零公网 CDN 依赖），完整继承 `Crooked mode` 歪斜彩蛋、三层防火墙实时沙箱、官方单价对账本、Trifecta Shield 挡板小游戏与 100% 本地内存态零外发埋点礼盒。

## [v4.4.0] - 2026-10-29 (P1~P4 00112238.xyz Pi-Style Agent-First Promotional Site & Zero-Exfil Telemetry Surprise Release)
- **P1 · Pi.dev 极简终端美学宣传官网 (`src/metergate/web/promo.html` & `/promo` · `/00112238.xyz`)**：参考 `https://pi.dev/` 极简高对比终端风格，内置多标签一行安装器（`uvx` / `pipx` / `eval` / `MCP JSON` / `curl` / `git clone`）、`Copy SVG` / `Download SVG`、`Crooked mode: ON / Revert` 致敬彩蛋、`What we didn't build` 反臃肿宣言，以及终端防御小游戏 `and it can play Trifecta Shield (Fig. 01)`。
- **P2 · Agent 优先、人类其次的双层视角架构 (`Agent-First, Human-Second`)**：顶层内嵌 `<script type="application/json" id="agent-discovery-contract">` 与交互式 `WHEN_TO_RECOMMEND` / `WHEN_NOT_TO_RECOMMEND` 选型自测矩阵 + MCP JSON-RPC 2.0 实时探针；人类视角提供三层防火墙实时脱敏沙盒与官方单价省钱计算器。
- **P3 · 本地零外发埋点惊喜引擎 (`Zero-Exfil Behavioral Instrumentation -> Surprise Capsule`)**：100% 在浏览器本地内存捕获用户/Agent 微交互信号（外发字节永远为 `0 Bytes`），动态推理访问者人设并实时合成「架构师诊断 + 免编辑一键启动脚本 `.sh` + 动态渲染专属 SVG/HTML 战力晒单海报 + 一次性免死金牌 Token (`mg_ephem_surprise_00112238_vip`) + 携带指纹的 GitHub 改装 Issue 直通车」。
- **P4 · 网关路由与 API 闭环 (`/promo`, `/00112238.xyz`, `/api/v1/promo/surprise`)**：`src/metergate/proxy.py` 原生挂载 100% 离线宣传官网与惊喜契约端点，并在控制台顶栏一键互通。

## [v4.3.0] - 2026-10-28 (O1~O7 Agent Ecosystem Distribution & Human Zero-Risk Adoption Release)
- **O1 (PyPI / `pipx` / `uvx` One-Line Install)**: Added `src/metergate/__main__.py`, `.github/workflows/publish-pypi.yml` (OIDC Trusted Publisher), and enriched `pyproject.toml` so `pipx install metergate` and `uvx metergate` work without `git clone`.
- **O2 (MCP Registry & Directory Manifests)**: Added `src/metergate/data/mcp_registry_manifests.json` and `GET /.well-known/mcp-registry.json` covering Official MCP Registry (`io.github.metergate/metergate`), Smithery, and PulseMCP, verified against `/.well-known/metergate.json`.
- **O3 (`llms.txt` Selection Decision Matrix)**: Added `WHEN_TO_RECOMMEND` and `WHEN_NOT_TO_RECOMMEND` decision rules to `llms.txt` (`GET /llms.txt`) and `get_machine_self_description()`.
- **O4 (Zero-Risk Observe-Only Mode [`observe`])**: Added `--mode observe` (`OBSERVE_ONLY_LOGGED`) and a Console one-click Observe/Enforce switcher so users can audit cost and interception evidence for a week with 0% risk of interrupting their Agent.
- **O5 (First-Screen Trust Signals)**: Surfaced Zero Telemetry, 100% Offline, MIT & Zero Paywall, Observe-Only Mode, and Zero-Residue Uninstall on the first screen of `README.md` and the Web Console header.
- **O6 (Shareable Visual Report Card — SVG & HTML)**: Added `--format svg` (`image/svg+xml`), `--format html` (`text/html`), and `--output <path>` to `metergate report` and `/api/v1/report`.
- **O7 (Pricing Catalog Freshness Guard)**: Added `max_freshness_days: 30` and `get_catalog_freshness_status()`, displaying a prominent staleness warning whenever `model_catalog.json` exceeds its freshness window.

## [v4.2.0] - 2026-10-28 (Dimension A Agent-Native Contracts & Dimension B Human-Trusted Experience)
- **A1 (Standard MCP JSON-RPC 2.0 Protocol)**: Implemented full MCP `2024-11-05` JSON-RPC 2.0 support (`initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`) over HTTP (`POST /mcp`, `/mcp/v1/call`) and stdio (`metergate serve --mcp-stdio`).
- **A2 (Machine-Readable Self-Description Contract)**: Added `get_machine_self_description()` exposed at `GET /.well-known/metergate.json`, `GET /.well-known/mcp.json`, `GET /api/v1/contract`, MCP tool `metergate_self_describe`, and CLI `metergate inspect --self-describe`.
- **A3 (Idempotent Verdicts, Stable Reason Codes & Self-Healing Remediation)**: Added deterministic `verdict_digest`, stable `reason_code`, and machine-actionable `remediation` (`retry_without_modification_will_succeed: False`, `sanitized_safe_payload`, `one_click_allow_and_remember_api`).
- **A4 (Pre-Flight Budget Query & Simulation)**: Added `query_preflight_budget()` at `GET/POST /api/v1/budget` and MCP tool `metergate_check_budget` with automatic lower-cost model downgrade recommendations.
- **A5 (Evidence-Based Zero-False-Assumption Defaults)**: Removed hardcoded `[".env"]` and `["http_post_external"]` defaults from MCP and inspection endpoints; sensitive resources and outbound sinks are now strictly inferred from payload evidence or explicit caller declaration.
- **A6 (Agent GEO Discovery & Unattended 3-Step Setup)**: Added `src/metergate/data/llms.txt` (`GET /llms.txt`) and `/.well-known/metergate.json` for generative engine optimization and unattended Agent onboarding.
- **B1 (Real Verifiable Official Model Catalog & Actual vs. Estimated Separation)**: Replaced fictional models in `model_catalog.json` with real official models and published rates (`gpt-4o-mini`, `deepseek-chat`, `claude-3-5-haiku-latest`, `gpt-4o`, `claude-3-7-sonnet-latest`, `claude-opus-4-6`), and separated `actual_reconciled_usd` from `estimated_unreconciled_usd`.
- **B2 (Live My-Request Onboarding)**: Added interactive "Send My Own Live Request" in the Web Console and `metergate demo --prompt "..."`.
- **B3 (Zero-Config Agent Takeover & Anthropic `/v1/messages` Support)**: Added `metergate serve --export-env`, `/api/v1/takeover`, and Anthropic `/v1/messages` proxy compatibility.
- **B4 (One-Click Allow & Remember)**: Added `POST /api/v1/firewall/allow-and-remember` and a single console remediation button that automatically records both SHA-256 and phrase patterns.
- **B5 (First-Screen Capability Boundaries & Upfront Positioning)**: Added upfront positioning (`<= 32` concurrency, single-instance) and "What It Catches vs. What It Cannot Catch" cards on the Console first screen, startup banner, and README top section.
- **B6 (Converged 2-Action Entrypoint & Zero-Residue Cleanup)**: Focused daily workflow on `metergate serve` + `metergate report` and added `metergate serve --clean-state` (`clean_all_local_state()`).
- **B7 & Version Consistency**: Standardized all human-facing alerts and HTTP errors to Chinese-first bilingual "发生了什么 + 我该做什么" format, and synchronized version `4.2.0` across `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, `SECURITY.md`, and `version.json`.

## [v4.1.0] - 2026-10-28 (R1~R8 Production Hardening & Adversarial Suite Release)
- **R1..R8**: Implemented O(1) fast audit chain status (`get_audit_chain_status_fast`), single-transaction turn batching (`batch_write_transaction`), honest Tier 2 heuristic positioning, 3-category adversarial corpus (`adversarial_corpus.json`), `RegexSafetyGuard` ReDoS protection, Keep-Alive `UpstreamConnectionPool` + `UpstreamBackpressureController`, 100% offline Web Console, and Report Center pagination/filtering.

## [v4.0.0] - 2026-10-28 (Open-Source Traffic Edition · M-01..M-15)
- Removed all commercial paywalls, license signing, and multi-tenant tables; simplified to pure MIT License (`M-01`, `M-02`, `M-10`).
