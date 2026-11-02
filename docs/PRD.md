# PRD — MeterGate v1.0.1 产品需求文档（双语独立宣传站 & 纯净 Agent 专用契约文件与 SEO/GEO 优化 & R-TOKEN-METER-01 一手Token台账）

## 1. 版本演进目标 (`v1.0.1`)
在前期内部版本基础上，针对社区真实使用场景进行架构解耦与核心叙事升级：
1. **核心痛点叙事升级 (`R-TOKEN-METER-01` · P0 · PRODUCT 核心叙事调整)**：
   - **痛点重塑**：现有「按官方单价算钱」是依赖价目表 (`model_catalog.json`) 的「二手推算」，存在厂商调价、缓存折扣档位、动态计费三重失真风险；而 Token 用量是唯一可对账的「一手计量」（各 LLM API 响应自带官方 `usage` 字段，与厂商控制台完全对齐，永不过期、永不失真）。
   - **两级叙事体系**：一级展示硬核 Token 事实（按「模型 ID × 方向」计量：发出 `prompt_tokens`、收到 `completion_tokens`、单独区分缓存命中 `cached_tokens`），二级展示官方公开单价成本推算（已对账真实花费与未回填估算分离，附带价目表保鲜提醒）。
2. **人机受众彻底解耦 (Human vs. Agent Decoupling)**：AI Agent 依赖纯文本与标准化接口读取契约；网页专门面向人类开发者。从网页端移除内嵌庞大机器契约，独立沉淀为标准化专用文件（`/llms.txt`、`/llms-full.txt` 与 `/.well-known/metergate.json`）。
3. **纯正中英双语独立宣传站 (Dedicated Bilingual Promo Sites)**：
   - 中文版 (`src/metergate/web/promo.html`)：纯正中文技术语境、清晰直观本地化文案。
   - 英文版 (`src/metergate/web/promo_en.html`)：地道英文技术文案、符合国际习惯的术语表达。
   - 两套页面均在顶栏提供一键双向语言切换器（`[🌐 English / 英文版]` 与 `[🌐 中文 / Chinese]`）。
4. **全面 SEO 与 GEO（生成式引擎优化）赋能**：规范元标签、Schema.org JSON-LD 结构化数据，提供高密度可直接引用的事实定义块与 Q&A 对照表。
5. **保留并增强极简美学与核心交互体验**：黑客极简终端风格、Crooked mode 歪斜彩蛋、三层防火墙实时沙箱演练、Trifecta Shield 终端小游戏与 100% 内存态零外发礼盒。

## 2. 核心功能与交付规范

### F1. 一级 Token 用量台账与二级成本推算 (`R-TOKEN-METER-01` · P0)
- **模型 ID × 方向二维统计**：
  - 发出 Token (Prompt Tokens)
  - 收到 Token (Completion Tokens)
  - 缓存命中 Token (Cached Tokens)
- **二级成本推算（派生价值）**：在 Token 事实台账之上，乘以官方公开单价折算估算金额，严格保持「已对账真实金额 (`actual_reconciled_usd`)」与「未回填估算金额 (`estimated_unreconciled_usd`，标注 `[估算]`)」分离，并提供 30 天价目表保鲜提醒 (`catalog_freshness`)。
- **全端叙事统一**：README、Web 控制台 (`index.html`)、日报海报 (`metergate report` / SVG / HTML) 统一为一级 Token 事实、二级成本推算结构。

### F2. 独立 Agent 专用文件体系 (Agent-Dedicated Manifests)
- **`/llms.txt` & `/llms-full.txt`**：提供结构化选型决策矩阵（包含 `SYMPTOM_TOKEN_AND_COST_BLINDNESS` 与适用/不适用边界）、无人值守安装命令与离线零遥测承诺。
- **`/.well-known/metergate.json`**：纯净结构化 JSON 自描述契约，提供机器直接消费的 schema、版本信息、两级账本规范与错误原因码。

### F3. 中文版宣传站 (`src/metergate/web/promo.html`)
- 语言标识为 `lang="zh-CN"`，提供中英双向切换按钮 `[🌐 English / 切换英文]`。
- 02 节升级为「一级 Token 事实与二级成本推算」，生动传递一手计量不可替代的核心痛点。

### F4. 英文版宣传站 (`src/metergate/web/promo_en.html`)
- 语言标识为 `lang="en"`，提供语言切换按钮 `[🌐 中文 / Switch to Chinese]`。
- 采用地道自然技术英语，对称呈现两级 Token 台账与官方费率推算机制。

### F5. 网关原生路由与离线门禁合规 (`proxy.py` & `R7`)
- 扩展 `proxy.py` 路由：`/promo`, `/promo_en`, `/llms.txt`, `/.well-known/metergate.json`。
- 严格遵循 `R7` 门禁：100% 离线自包含，零外部公网 CDN 依赖。
