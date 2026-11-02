# 对外产物中英双语工程规范 (Bilingual Artifacts Specification)

> 本规范定义 MeterGate 面向全球开发者、开源社区与 AI Agent 生态分发时的双语质量要求与工程约束。规范内容作为通用条款已同步沉淀进 `.agents/skills/flywheel/` 规范体系。

---

## 1. 规范背景与核心宗旨

随着开源项目与 AI Agent 生态的全球化分发，单纯的单语言（中文或英文）文档存在以下痛点：
1. **开发者首触体验脱节**：国际用户在 GitHub、PyPI、MCP Registry 检索与阅读单语包时，因信息缺失直接流失；
2. **AI Agent 选型语义偏差**：仅依赖单一语言描述，跨语言意图理解可能产生歧义，无法准确触发 `WHEN_TO_RECOMMEND` 决策规则；
3. **维护各自为政**：若无成文契约，容易出现中文文档持续演化而英文文档停滞过期的“文档死角”。

**核心宗旨**：**对外产物默认中英双语、段落结构对称映射、核心信息完全等价**。

---

## 2. 必须双语的产物清单与范围 (Mandatory Scope)

| 产物分类 | 目标文件路径 / 端点 | 双语组织形式 | 核心验收要求 |
| :--- | :--- | :--- | :--- |
| **1. 项目主文档** | `README.md` | 同一文件内中英文段落一一对应、结构对称 | 是什么、解决什么、五大承诺、前置边界、安装与快速上手两语完全等价 |
| **2. 包管理器分发元数据** | `pyproject.toml` (`project.description` & `readme`) | `description` 采用中英双语单行组合；`readme` 指向双语 `README.md` | PyPI 首页与搜索结果中英双语自描述完整 |
| **3. 机器自描述与生态契约** | `src/metergate/web/llms.txt`<br>`src/metergate/data/llms.txt`<br>`src/metergate/web/llms-full.txt` | 选型矩阵逐项中英双语、契约端点与边界说明双语标注 | Agent 在中英语境下均能 100% 准确命中适用/不适用决策 |
| **4. 发版说明模板** | `.github/RELEASE_TEMPLATE.md`<br>`docs/RELEASE_TEMPLATE.md` | 双语结构化段落模板（亮点、安全机制、安装、变更清单） | 每次正式 Release / PyPI 公告均产出结构对称的双语文案 |
| **5. 商业化与用户触达官网** | `src/metergate/web/promo.html`<br>`src/metergate/web/promo_zh.html`<br>`src/metergate/web/promo_en.html` | 独立路由双语对开，顶栏双向无缝切换 | 极简终端美学与离线沙箱在双语中体验一致 |

---

## 3. 段落对应关系与语义等价性要求 (Structural Symmetry & Semantic Equivalence)

1. **结构对称原则（Structural Symmetry）**：
   - 核心章节（标题、小节、列表项、表格行）必须在中英两版中保持严格的顺序与层级一致。
   - 不允许出现“中文版有 5 项特性，英文版仅概括为 2 项”或“英文版有参数说明，中文版缺失”的信息不对等。
2. **段落配对组织模式（Paragraph Pairing）**：
   - 在单个文档（如 `README.md`）中，推荐采用**逐段配对**或**对称双区锚点**：
     - 首屏核心叙事（是什么、解决什么、快速开始）：中文段落紧跟英文对应段落；
     - 核心功能表格与对照表：表头与单元格采用双语标注或对齐行；
     - 代码与配置示例：通用命令共享，前后解释说明采用双语说明。
3. **术语映射一致性（Terminology Consistency）**：
   - 全库核心名词必须遵循统一映射字典：
     - `一手 Token 台账`: First-hand Token Accounting Ledger
     - `两级对账体系`: Two-Tier Accounting Framework (Token Facts × Cost Estimation)
     - `观察模式`: Observe-Only Mode
     - `三层安全防火墙`: 3-Tier Security Firewall
     - `致命三角阻断`: Lethal Trifecta Mitigation (Untrusted Input + Secret + Outbound Sink)
     - `零遥测`: Zero Telemetry (0 Bytes transmitted externally)
     - `前置预算接口`: Pre-Flight Budget Interface
     - `机器自描述契约`: Machine-Readable Self-Description Contract

---

## 4. 自动化门禁检验标准 (Automated Gate Enforcement)

`test_all.py` 集成自动化双语规范检验门禁：
1. **`README.md` 双语对称性扫描**：断言文件中同时包含中文字符与英文核心结构标记（`What It Is`, `What It Solves`, `Trust Signals`, `Quick Start` 等），且关键链接与锚点对称存在。
2. **`pyproject.toml` 双语描述验证**：断言 `description` 同时包含中文关键词与英文概要。
3. **`llms.txt` 选型矩阵双语验证**：断言 `WHEN_TO_RECOMMEND` 与 `WHEN_NOT_TO_RECOMMEND` 具备中英文双语对照描述。
4. **发版模板完备性验证**：断言 `.github/RELEASE_TEMPLATE.md` 与 `docs/RELEASE_TEMPLATE.md` 存在且包含双语标记。
