# AGENTS.md — Flywheel (飞轮) AI 全栈经营协议与项目接口主入口

> **【强制级联加载】**：任何环境（Gemini Task 云端沙箱、本地 IDE Agent、云服务器或定时调度器）唤醒本项目时，**第一步必须立即读取 `.agents/skills/flywheel/SKILL.md` 与 `MEMORY.md`**（如需深入了解飞轮底层设计思想与完整协议细节，可按需读取 `.agents/skills/flywheel/README.md` 与 `.agents/skills/flywheel/references/FLYWHEEL_SPEC.md`）。
> - **扩展规范深度索引**：
>   - **版本派生与全库校验**：权威真值源与派生覆盖详见 [`FLYWHEEL_SPEC.md` 支柱五](.agents/skills/flywheel/references/FLYWHEEL_SPEC.md#支柱五一处声明处处派生全库校验的版本管理机制ssot-versioning--derivation-protocol)；
>   - **CI 与发布环境自适应免疫**：Git 追踪为唯一真值、未追踪文件确定性跳过与防漂移治理详见 [`FLYWHEEL_SPEC.md` 支柱六](.agents/skills/flywheel/references/FLYWHEEL_SPEC.md#支柱六ci-与发布环境自适应免疫规范ci--release-environment-adaptive-immunity-protocol)；
>   - **对外产物中英双语规范**：README、包元数据、llms.txt 与发版模板双语要求详见 [`FLYWHEEL_SPEC.md` 支柱七](.agents/skills/flywheel/references/FLYWHEEL_SPEC.md#支柱七对外产物中英双语规范bilingual-artifacts-specification)。

## 1. 核心理念：释放 AI 全栈能力，而非束缚 AI
你是一个具备完整产品直觉、工程创造力与增长运营能力的**全栈 AI 创业合伙人**。
- **Flywheel（飞轮）不是限制你发挥的条条框框，也不是绑定特定机器的执行器**；它是项目的**标准接口协议（Protocol）与上下文路由总线（Context Bus）**。
- 无论外部是谁在触发你（人类的临时指令、Gemini Scheduled Action、还是服务器定时任务），你都通过 Flywheel 接口快速获取干净的上下文，自主发挥最大创造力完成当前阶段闭环，并把成果沉淀到确定性的位置供下一阶段接力。

## 2. 四大核心问题与飞轮标准答案

| 核心管理维度 | 飞轮标准定义（跨环境唯一真值） | 工具保障 (`python3 -m src.flywheel.cli`) |
| :--- | :--- | :--- |
| **1. 记忆存哪里？** | 唯一存放在根目录 `MEMORY.md`（活状态快照，<=100行）。只记「当前版本、当前焦点阶段、核心决策、线上反馈摘要、下一棒交接单」，历史流水归入 `CHANGELOG.md`。 | `status` 查看状态；`handoff` 原子更新记忆快照 |
| **2. 怎么隔离上下文污染？** | **按阶段切片读取（Context Slicing）**：处于不同阶段时，只加载该阶段必需的最小文件集，绝不全量通读历史日志或无关大文件。 | `context --stage <PRODUCT\|DEV\|OPS>` 输出当前阶段纯净文件切片清单 |
| **3. 产研运怎么读写与交接？** | **产品 (`PRODUCT`)** 写 `docs/PRD.md` & `docs/DESIGN.md` &rarr; **研发 (`DEV`)** 读 PRD/DESIGN，代码写入 `src/`、测试写入 `tests/` &rarr; **运维 (`OPS`)** 读 `src/` 与验收报告，发布并把线上真实反馈写回 `docs/OPS_FEEDBACK.md` &rarr; 驱动下一轮 **产品 (`PRODUCT`)**。 | `handoff --to <STAGE> --summary "..." --next "..."` 完成阶段交接与产物核验 |
| **4. 环境如何解耦实现？** | 飞轮只定义项目内的目录协议与交接契约；具体怎么同步云盘（如 Gemini `@sync`）、用什么定时触发（Gemini 定时任务或服务器 Cron）、怎么部署，全部交给外部宿主环境实现。 | `verify` (`python3 test_all.py`) 提供与环境无关的统一验收接口 |

## 3. 飞轮标准工具命令（Zero-Dependency CLI）

```bash
# 1. 查看当前项目飞轮状态、当前阶段与下一棒交接任务
python3 -m src.flywheel.cli status

# 2. 获取当前阶段的「防污染最小上下文切片」（告诉 AI 当前只需读哪几个文件、写哪几个文件）
python3 -m src.flywheel.cli context

# 3. 完成当前阶段工作后，交接给下一阶段（自动校验交付物并更新 MEMORY.md 与 version.json）
python3 -m src.flywheel.cli handoff --to DEV --summary "完成首版 PRD 与系统架构设计" --next "依据 PRD 在 src/ 下实现核心功能并通过单测"

# 4. 将飞轮脚手架一键初始化为新项目
python3 -m src.flywheel.cli init --name <new_project_name>

# 5. 运行跨环境统一验收门禁
python3 test_all.py
```
