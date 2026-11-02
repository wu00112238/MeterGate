---
name: flywheel
description: Flywheel (飞轮) AI 全栈产品自进化管理规范与跨环境接口协议。定义记忆存储、上下文防污染切片、产品-研发-运维 (PRODUCT-DEV-OPS) 交接契约与环境解耦标准。
---
# Flywheel (飞轮) — AI 全栈自进化管理协议

> **配套深度文档索引（Skill References）**：
> - 完整的飞轮设计哲学、为什么从传统 `dev` 规范演进为全栈飞轮协议、以及跨环境解耦架构详述，请按需查阅同目录下的 [`references/FLYWHEEL_SPEC.md`](references/FLYWHEEL_SPEC.md) 与导读 [`README.md`](README.md)。
> - **版本派生与全库校验规范**：SSoT 权威源、全库派生、全量一致性扫描与 SemVer 规范详见 [`references/FLYWHEEL_SPEC.md` 支柱五](references/FLYWHEEL_SPEC.md#支柱五一处声明处处派生全库校验的版本管理机制ssot-versioning--derivation-protocol)。
> - **CI 与发布环境自适应免疫规范**：Git 追踪为唯一真值、未追踪文件确定性跳过与防漂移治理详见 [`references/FLYWHEEL_SPEC.md` 支柱六](references/FLYWHEEL_SPEC.md#支柱六ci-与发布环境自适应免疫规范ci--release-environment-adaptive-immunity-protocol)。
> - **对外产物中英双语规范**：面向全球分发的 README、包元数据、llms.txt 契约与发版模板双语标准详见 [`references/FLYWHEEL_SPEC.md` 支柱七](references/FLYWHEEL_SPEC.md#支柱七对外产物中英双语规范bilingual-artifacts-specification)。

## 1. 核心定位：管理协议 vs 传统研发规范

传统的研发规范往往把 AI 当成被动的代码工人，用繁琐的死规则限制 AI；而 **Flywheel（飞轮）** 面向具备产品、研发、运维全栈能力的超级 AI，核心目标是**消除跨会话失忆、消除上下文污染、消除环境差异**，让 AI 在每个阶段都能轻装上阵、发挥最大创造力。

- **协议与实现分离（Interface vs. Implementation）**：
  - **Flywheel 管什么（项目内协议）**：记忆存哪里、每个阶段读哪几个文件避免污染、产品/研发/运维产物放在哪里、怎么交接给下一棒。
  - **外部环境管什么（宿主实现）**：怎么把代码同步到 Google Drive（由云端 `@sync` 技能实现）、怎么定时唤醒 AI（由 Gemini Scheduled Actions 或服务器定时任务实现）、怎么托管网页或服务。任何环境只要读写符合 Flywheel 接口，就能无缝接力同一个项目。

---

## 2. 记忆存哪里？怎么隔离上下文污染？

### 2.1 三层记忆介质正交分离（杜绝把 MEMORY 当垃圾桶）

| 记忆介质 | 存放路径 | 核心职责 | 容量与读写规则 |
| :--- | :--- | :--- | :--- |
| **活状态与交接棒 (Active State)** | `MEMORY.md` | 记录**此时此刻**的项目版本、当前所处阶段 (`PRODUCT`/`DEV`/`OPS`)、核心架构拍板、以及留给下一棒的具体任务 (`Next Handoff`) | **严格 <= 100 行**；每次交接由 `cli.py handoff` 覆写刷新，永远保持精炼 |
| **阶段性领域知识 (Domain Docs)** | `docs/PRD.md`<br>`docs/DESIGN.md`<br>`docs/OPS_FEEDBACK.md` | 分别存放当前有效的产品需求与设计、运维发布配置与线上真实反馈指标 | 按阶段按需读取；只保留当前有效内容，不堆砌废弃设计 |
| **冷历史归档 (Cold History)** | `CHANGELOG.md` | 记录过去每个版本发生了什么变化 | **平时严禁读取**（防止历史废案污染当前上下文），仅在发版时追加写入 |

### 2.2 上下文防污染切片协议（Context Slicing Protocol）

AI 在接手任务时，先运行 `python3 -m src.flywheel.cli context` 查看当前阶段切片，**只读输入切片，只写输出切片**：

| 当前阶段 | 必读最小上下文（Read Slice — 零污染） | 交付输出位置（Write Target） | 严禁读取/干扰（Noise Isolation） |
| :--- | :--- | :--- | :--- |
| **1. `PRODUCT`<br>(产品与架构)** | `MEMORY.md` + `docs/OPS_FEEDBACK.md`（线上反馈）+ 人类新需求 | 更新 `docs/PRD.md`（目标、功能、验收底线）与 `docs/DESIGN.md`（架构与界面设计） | 不读 `src/` 底层实现细节、不读 `CHANGELOG.md` 历史流水 |
| **2. `DEV`<br>(研发与自测)** | `MEMORY.md` + `docs/PRD.md` + `docs/DESIGN.md` + `src/` 现有源码 | 代码统一写入 `src/`，测试写入 `tests/`，运行 `python3 test_all.py` 并同步 `version.json` | 不被历史旧版 PRD 或冗长运维日志干扰，专注高水准工程与视觉实现 |
| **3. `OPS`<br>(发布与反馈)** | `MEMORY.md` + `docs/PRD.md` + `src/` 交付物 + `version.json` | 执行环境发布/打包、更新 `CHANGELOG.md`，将线上表现与改进建议写入 `docs/OPS_FEEDBACK.md` | 不随意篡改核心业务架构，发现产品痛点转化为下一轮 `PRODUCT` 输入 |

---

## 3. 产品 → 研发 → 运维 闭环交接流程（Handoff Workflow）

无论是一次会话跑完三棒，还是分多次会话/定时任务接力跑，每棒结束时通过 `handoff` 完成标准交接：

```text
  ┌────────────────────────────────────────────────────────────────────────────┐
  │                                                                            ▼
[阶段 1: PRODUCT 产品设计] ──(handoff --to DEV)──▶ [阶段 2: DEV 研发实现] ──(handoff --to OPS)──▶ [阶段 3: OPS 运维与进化反馈]
  · 吸收人类意图或 OPS 反馈                        · 读 docs/PRD.md & DESIGN.md                   · 校验 test_all.py 通过
  · 撰写 docs/PRD.md & DESIGN.md                   · 发挥全力开发代码放入 src/                     · 执行发布 / 云端 @sync 打包
  · 明确本轮核心体验与验收标准                     · 补充 tests/ 并跑通 test_all.py                · 沉淀 docs/OPS_FEEDBACK.md
```

### 标准交接动作：
1. **接棒（Check-in）**：读取 `MEMORY.md`（或运行 `python3 -m src.flywheel.cli context`），明确当前处于哪一阶段，按切片读取对应文件。
2. **创造与执行（Create）**：
   - 若人类指令要求直接完成「产品 + 研发 + 交付」，AI 可在单次任务内连续跑完 `PRODUCT -> DEV -> OPS` 全链路；
   - 若由外部定时任务（如每日巡检）触发，则按 `MEMORY.md` 当前焦点阶段推进一棒或一轮。
3. **交棒（Handoff）**：运行 `python3 -m src.flywheel.cli handoff --to <NEXT_STAGE> --summary "本棒完成成果" --next "下一棒具体待办"`，并运行 `python3 test_all.py` 确保项目处于随时可交付的干净状态。

---

## 4. CI/发布环境自适应免疫协议（CI & Release Adaptive Immunity）

1. **追踪状态自适应，尊重工程选择**：
   - 飞轮脚手架（`.agents/`、`src/flywheel/`、`tests/test_flywheel.py`）与交接文档（`AGENTS.md`、`MEMORY.md`、`docs/OPS_FEEDBACK.md`）属于本地自进化工作流资产，作者有权在 `.gitignore` 中配置排除；
   - 门禁与发布链路以 `git ls-files` 为唯一真值：对未受 Git 追踪的协议文件自动确定性跳过，不报错、不崩溃；对已追踪的文件照常严格校验。
2. **本地、干净克隆与 CI 判定绝对恒等**：
   - 交付物指纹集合与盲区校验严格基于 `git ls-files`，杜绝「磁盘有 ≠ 仓库有」导致的 CI 误报；
   - `sync-version` 仅纳入 Git 追踪文件，并自动清除历史指纹中的未追踪排除文件。
3. **结构化失败诊断三要素**：
   - 每一条失败信息必须严格指明：`[所属门禁项]`、`文件路径`、`建议动作`。
4. **指纹与提交联动防漂移**：
   - `handoff` 或 `sync-version` 更新 `version.json` 后，必须提示并确保重算结果提交到 Git，门禁检测到未提交指纹时主动拦截报错。

---

## 5. 对外产物中英双语规范（Bilingual Artifacts Spec）

1. **规范覆盖范围**：
   - 项目主文档（`README.md`）、包管理器元数据（`pyproject.toml` 的 `description` 与 `readme`）、机器可读契约（`llms.txt` 等）、发版说明模板（`.github/RELEASE_TEMPLATE.md`）及对外展示页面默认中英双语。
2. **结构对称与语义等价**：
   - 同一文件内中文段落与英文段落一一对应、结构对称；
   - 是什么、解决什么、安装方式与快速上手等核心信息在两语中保持完全等价的信息深度。
3. **条款抽象通用化**：
   - 规范表述通用抽象，不与具体项目名、版本号或特定业务路径绑定，供所有由脚手架派生的新项目天然继承。
