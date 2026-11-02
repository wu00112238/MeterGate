# Flywheel (飞轮) 设计思想、架构哲学与协议规范详述

> **文档定位**：本文档作为 `.agents/skills/flywheel/SKILL.md` 的官方配套参考规范（遵循通用 Agent Skill 的 `references/` 目录规范）。日常执行阶段按需查阅，不强制占用基础会话上下文。

---

## 1. 为什么诞生 Flywheel？（从「约束型 Dev 规范」到「赋能型 AI 管理规范」）

在传统的软件工程或早期的 Agent 研发规范（如旧版 `mydev`）中，设计者往往把 AI 当成单一环节的“被动代码工人”，试图通过繁琐的目录切分（如拆散 `role_pd`、`role_dev`、`role_ops` 胶囊）或死板的条条框框去限制 AI。然而，现代前沿大模型本身就已经具备**敏锐的产品直觉、全栈研发创造力与数据驱动的运营分析能力**。

**Flywheel（飞轮）的本质，是一套面向超级全栈 AI 的「跨环境项目管理协议（AI-Native Project Management Protocol）」**：
1. **赋能而非束缚**：不再把一个完整的 AI 强行肢解为互不相通的碎片角色，而是让同一个全栈 AI 顺畅地沿着 `PRODUCT（产品定义） -> DEV（研发验证） -> OPS（发布与反馈） -> PRODUCT（下一轮进化）` 的飞轮闭环全速运转。
2. **协议与宿主环境彻底解耦（Interface vs. Implementation）**：
   - **飞轮只定义项目内部的「标准接口」**：记忆存在哪里、怎么隔离历史噪音防止上下文污染、每个阶段的输入/输出在哪里、阶段之间用什么工具交接。
   - **触发与同步交给「外部宿主环境」**：
     - **Gemini Task 云端沙箱环境**：通过 `@sync` 技能负责清空本地缓存、从 Google Drive 拉取项目包、开发完成后打包 `.zip` 回传 Drive；通过 Gemini Scheduled Actions 负责定时唤醒。
     - **本地 IDE / CLI 环境（Claude Code / Cursor / Codex 等）**：开发者或本地守护进程直接在本地目录唤醒 Agent，读写同一套 `AGENTS.md` 与 `MEMORY.md`。
     - **云服务器 / CI 容器环境**：通过系统 `crontab`、GitHub Actions 或 Webhook 定时拉起 Agent 会话，执行一个阶段或完整一轮飞轮迭代。

---

## 2. 核心支柱与工程契约

### 支柱一：三层记忆正交分离（解决「记忆存哪里」与「防上下文污染」）

AI 跨会话协作最大的敌人是**上下文污染（Context Pollution）**——如果把几千行历史流水账、废弃需求、报错日志全塞进同一个记忆文件，AI 的推理质量会迅速劣化。Flywheel 将项目记忆严格划分为正交的三层：

| 记忆层级 | 物理路径 | 核心职责与生命周期 | 上下文防污染硬约束 |
| :--- | :--- | :--- | :--- |
| **L1 活状态与交接棒<br>(Active State Baton)** | `MEMORY.md` | 仅记录**此时此刻**的飞轮坐标（版本、当前轮次 `Cycle #N`、当前阶段 `PRODUCT`/`DEV`/`OPS`）、上一棒完成摘要、本棒核心待办、以及当前阶段的读写切片清单。 | **严格 `<= 100` 行**。每次执行 `cli.py handoff` 时以原子替换（Atomic Replace）方式刷新，永不追加历史流水账。 |
| **L2 阶段性领域契约<br>(Stage Domain Contracts)** | `docs/PRD.md`<br>`docs/DESIGN.md`<br>`docs/OPS_FEEDBACK.md` | 存放当前有效版本的**产品需求与验收底线（PRD）**、**系统架构与接口契约（DESIGN）**、以及**线上真实反馈与下一轮演进建议（OPS_FEEDBACK）**。 | 按所处阶段**按需切片读取**（Context Slicing），只保留当前生效规格。 |
| **L3 冷历史归档<br>(Cold Archive)** | `CHANGELOG.md` | 按版本号归档每次迭代的功能变更与演进历史。 | **日常 `PRODUCT` 与 `DEV` 阶段严禁读取**，仅在 `OPS` 阶段发版归档时追加写入。 |

---

### 支柱二：按阶段防污染上下文切片协议（Context Slicing Protocol）

当任何环境的 AI 唤醒项目时，通过 `python3 -m src.flywheel.cli context` 即可获得当前阶段的**最小必读切片（Read Slice）**与**唯一写入目标（Write Target）**：

```text
================================================================================
  [阶段 1: PRODUCT 产品与架构设计]
  · 必读输入 (Read Slice)  : MEMORY.md + docs/OPS_FEEDBACK.md + 用户新增需求
  · 交付输出 (Write Target): docs/PRD.md + docs/DESIGN.md
  · 隔离噪音 (Noise Filter): 忽略 CHANGELOG.md 历史流水与 src/ 底层实现细节
================================================================================
         │
         ▼  python3 -m src.flywheel.cli handoff --to DEV --summary "..." --next "..."
================================================================================
  [阶段 2: DEV 研发实现与自测验证]
  · 必读输入 (Read Slice)  : MEMORY.md + docs/PRD.md + docs/DESIGN.md + src/
  · 交付输出 (Write Target): src/ (全部源码与前端页面) + tests/ (单测) + version.json
  · 隔离噪音 (Noise Filter): 忽略 CHANGELOG.md 与历史运维原始流水
================================================================================
         │
         ▼  python3 -m src.flywheel.cli handoff --to OPS --summary "..." --next "..."
================================================================================
  [阶段 3: OPS 运维发布与反馈回流]
  · 必读输入 (Read Slice)  : MEMORY.md + docs/PRD.md + version.json
  · 交付输出 (Write Target): docs/OPS_FEEDBACK.md + CHANGELOG.md + 宿主环境发布包
  · 隔离噪音 (Noise Filter): 忽略 tests/ 内部测试桩细节，聚焦验收结果与用户反馈收集
================================================================================
         │
         ▼  python3 -m src.flywheel.cli handoff --to PRODUCT --summary "..." --next "..."
  (飞轮轮次 Cycle 自动 +1，进入下一轮自我进化闭环)
```

---

### 支柱三：纯源码收敛与版本唯一权威源（`src/` Convergence & SSoT）

1. **源码唯一收敛于 `src/`**：
   - 无论是后端核心库、CLI 工具、还是单页网站（如 `src/index.html`）与前端静态资源，一律存放在 `src/` 目录下，保持项目根目录高度整洁。
2. **版本唯一权威源（Single Source of Truth, SSoT）**：
   - `src/<primary_pkg>/__init__.py` 中的 `__version__` 与 `__project__` 是全项目唯一的版本与名称真值源。
   - 运行 `python3 -m src.flywheel.cli sync-version` 会自动遍历受控有效源码文件，计算 `SHA-256` 哈希指纹并写入根目录 `version.json`。

---

### 支柱四：跨环境零依赖 CLI 与多重自动化门禁（`test_all.py`）

为了确保在任何无网络沙箱或极简容器中都能 100% 稳定运行，Flywheel 的工具链（`src/flywheel/cli.py` 与 `test_all.py`）**完全基于 Python 3 标准库构建（零第三方 pip 依赖）**。

每次交接或打包发布前，运行 `python3 test_all.py` 将自动执行刚性硬门禁检验：
1. **契约文件完备性检查**：核验核心交接与协议文件齐全且非空，同时断言不存在已废弃的历史残留目录。
2. **`MEMORY.md` 防污染容量检查**：断言 `MEMORY.md` 行数严格 `<= 100` 行。
3. **SSoT 与 `SHA-256` 指纹一致性检查**：断言 `version.json` 中的版本号与 SSoT 完全一致，且所有受控文件的实时 `SHA-256` 与 `version.json` 100% 吻合。
4. **全量单元测试套件（`tests/`）**：自动发现并运行 `tests/test_*.py`，确保飞轮状态机流转、版本同步与业务功能测试 100% 通过。

---

### 支柱五：一处声明、处处派生、全库校验的版本管理机制（SSoT Versioning & Derivation Protocol）

#### 1. 唯一权威真值源（Single Source of Truth, SSoT）
- 全项目版本号与项目名称的唯一权威源（SSoT）必须且只能定义在主业务包入口文件 `src/<primary_pkg>/__init__.py` 中的 `__version__` 与 `__project__`。
- SSoT 读取机制具备刚性强校验：若 `__version__` 或 `__project__` 缺失或解析失败，必须显式抛出异常中断执行，**严禁静默回退（Silent Fallback）到任何默认硬编码版本号**。

#### 2. 处处派生原则（Derivation Everywhere）
全仓库所有对外展示与引用的版本号，一律由自动化工具（`python3 -m src.flywheel.cli sync-version` 或 `derive-version`）从 SSoT 自动派生，禁止任何脱离 SSoT 的手工硬编码副本。派生覆盖范围包括：
- **构建与包管理配置**：`pyproject.toml`（`project.version`）、`Dockerfile`（`image.version` 标签与构建注释）、`docker-compose.yml`（服务镜像版本标签）。
- **安全政策与文档体系**：`SECURITY.md`（当前支持版本表与安全汇报基准）、`README.md`（标题与徽章）、`MEMORY.md`（当前版本坐标）、`docs/PRD.md`、`docs/DESIGN.md`、`docs/OPS_FEEDBACK.md`。
- **机器自描述与生态发现清单**：`.well-known/` 机器清单、`llms.txt` / `llms-full.txt` 检索清单、MCP Registry 注册清单。
- **数据契约与评测语料**：所有数据 JSON 文件中的 `*_version` 字段（如策略版本、语料版本、基准版本、验证记录版本）。
- **Web 界面与控制台**：离线控制台页面、双语推广页的页面标题、版本徽章与元数据。
- **Python 运行时内部引用**：运行时各子模块一律通过相对导入动态引用 `__version__`（如 `from . import __version__`），严禁在业务代码中硬编码版本字符串。

#### 3. 全仓库版本一致性自动扫描门禁（Repository-wide Consistency Gate）
`test_all.py` 必须实现全仓库深度一致性扫描门禁：
- **全库覆盖扫描**：遍历全仓库所有受控文件，核验对外展示的版本声明必须 100% 吻合当前 SSoT 版本。
- **游离版本零容忍**：除 `CHANGELOG.md` 允许在历史记录条目语义下保留过去已归档版本外，全仓库其他任何文件中若存在游离于 SSoT 之外的旧版本号或硬编码版本字符串，门禁均立即判定失败。
- **运行时硬编码静态拦截**：扫描 Python 源码语法树，断言业务模块未在字符串字面量或变量赋值中硬编码版本号。

#### 4. 语义化版本（SemVer）进化与不可变性契约
- **SemVer 语义推进**：严格遵循 `MAJOR.MINOR.PATCH` 规范：
  - 发生破坏性、不向后兼容的架构或 API 变更时，增加主版本号（`MAJOR`）；
  - 新增向后兼容的功能特性或生态扩展时，增加次版本号（`MINOR`）；
  - 向后兼容的缺陷修复、性能优化或内部文档调优时，增加修订号（`PATCH`）。
- **版本不可变性（Version Immutability）**：版本号一经对外公开发布（如 PyPI、GitHub Release、Docker Hub），即成为不可变历史凭据，严禁二次修改或覆写复用。

---

### 支柱六：CI 与发布环境自适应免疫规范（CI & Release Environment Adaptive Immunity Protocol）

#### 1. 核心铁律：追踪状态自适应与零未捕获异常
- **Git 追踪状态为唯一真值（Git Tracking as Single Source of Truth）**：
  - 飞轮脚手架（如 `.agents/`、`src/flywheel/`、`tests/test_flywheel.py`）与管理交接文档（如 `AGENTS.md`、`MEMORY.md`、`docs/OPS_FEEDBACK.md`）属于本地自进化工作流构件。作者与团队拥有合法的工程自由，可根据开源合规或私密性诉求，通过 `.gitignore` 规则选择不将其提交至公共远端仓库。
  - 验收门禁（`test_all.py`）与发布构建流程必须**主动自适应当前的 Git 追踪状态**：以 `git ls-files` 的实际检出结果为唯一真值基准，**严禁对「未被 git 追踪的文件」做出任何强制存在性假设**。
- **未追踪文件确定性跳过（Deterministic Skip for Untracked Files）**：
  - 门禁的所有核验项（文件存在性、指纹校验、双语扫描、版本扫描、派生一致性等）在面对未受 Git 追踪的协议文件时，必须确定性安全跳过，绝不允许抛出未捕获的 `FileNotFoundError`、`TypeError` 或其他未处理异常；
  - 核心业务交付物（业务源码、主包清单、包配置等）仍受严格追踪约束；未追踪协议文件跳过后，门禁聚焦于已入库构建资产的正确性。

#### 2. 本地与 CI 判定结论绝对恒等（Local = Clean Clone = CI Equivalence）
- **杜绝「磁盘有 ≠ 仓库有」导致的判定割裂**：
  - 交付物指纹收集（`iter_tracked_deliverables()`）严禁脱离版本控制私自扫描本地磁盘物理目录；在 Git 仓库环境下必须严格以 `git ls-files` 输出为准，仅在无 Git 的裸分发环境下降级为磁盘扫描；
  - `sync-version` 写入 `version.json` 的指纹清单必须仅包含已追踪文件；若历史记录中包含已被 `.gitignore` 排除的文件，重新同步时必须自动清理；
  - 确保「本地工作区绿 = 干净克隆（Clean Clone）绿 = 远端 CI 绿」三者恒等。

#### 3. 结构化失败诊断三要素（Structured Diagnostic Triad）
门禁输出的每一条失败信息必须严格包含以下三要素，杜绝模糊不清的报错：
1. **明确的文件路径（File Path）**：指明具体缺失、漂移或违规的文件相对路径；
2. **所属门禁项（Gate Item / Violation Rule）**：标明属于哪一项刚性门禁或契约条款；
3. **可执行的建议动作（Suggested Action）**：提供人类或 AI 可直接复制执行的具体修复命令或排查指引。

#### 4. 指纹与提交联动防漂移机制（Version Drift Governance）
- **禁止静默漂移窗口**：每次执行交接（`handoff`）或指纹同步（`sync-version`）重新计算 `version.json` 指纹后，必须建立提醒与校验机制，确保重算结果被纳入 Git 提交。
- **主动拦截未提交指纹**：门禁在 Git 环境下必须检测 `version.json` 的工作区状态。若发现 `version.json` 存在未提交的修改，门禁应主动报错并提示执行 `git commit`，坚决消除「本地重算全绿、远端 CI 旧指纹失败」的漂移窗口。

---

### 支柱七：对外产物中英双语规范（Bilingual Artifacts Specification）

#### 1. 适用范围与核心定位
面向全球开源社区分发、公开包管理器索引（如 PyPI）与 AI Agent 生态检索的所有对外产物，默认遵循中英双语规范。通用覆盖范围包括：
1. **项目主文档**：`README.md`（项目入口文档）；
2. **包管理器发布元数据**：如 `pyproject.toml` 中的 `description` 与 `readme` 指向物；
3. **机器自描述与生态发现清单**：如 `llms.txt`、`llms-full.txt` 与 `.well-known/` 机器清单；
4. **版本发布说明模板**：如 `.github/RELEASE_TEMPLATE.md` 与发版公告模版；
5. **商业化与展示型站点**：对外公开的用户引导页与推广静态站。

#### 2. 段落对称与语义等价原则（Structural Symmetry & Equivalence）
- **同一文件对称组织**：在单文档形态下，中文段落与英文段落一一对应、结构对称；
- **核心信息完全等价**：产品的核心定位（是什么）、解决痛点（解决什么）、安装命令（安装方式）、快速上手指南与能力边界说明，两种语言版本必须在信息密度与语义深度上完整等价，严禁单语缺失；
- **术语字典统一映射**：项目核心概念、安全术语与架构名称在全库双语产物中必须保持映射一致，避免术语混乱。

#### 3. 通用化与脚手架可复用性契约
- 双语规范条款表述完全抽象通用，不与特定项目名称、特定路径或特定发布版本号强行绑定；
- 新项目通过 `flywheel cli init` 初始化后，天然继承双语文档结构与双语门禁校验规则，确保脚手架跨项目通用。
