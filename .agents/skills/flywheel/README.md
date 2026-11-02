# Flywheel Skill (`.agents/skills/flywheel`) — 技能包结构与设计思想导读

本目录存放 **Flywheel (飞轮)** 的核心 AI 管理规范与技能定义。

## 1. 通用 Agent Skill 目录规范说明

根据通用 Agent Skill 规范（如 Claude Code / Gemini Skills / Open Agent Skills 标准），一个拥有深度配套设计文档的技能包应采用**“主指令轻量化 + 配套规范放入 `references/`”**的分层结构，以兼顾人类可读性与 AI 上下文效率：

```text
.agents/skills/flywheel/
├── SKILL.md                     # [核心必选] AI 触发与日常执行的精炼主规范（保持高信噪比）
├── README.md                    # [人类导读] 面向开发者与架构师的飞轮设计思想总览与目录说明（本文件）
└── references/                  # [规范配套] 通用 Skill 标准扩展文档目录（供 AI 或人类按需深度查阅）
    └── FLYWHEEL_SPEC.md         # 飞轮完整设计哲学、三层记忆、CI 环境免疫、双语规范与解耦详述
```

> **为什么这样组织？**
> - **`SKILL.md`**：是 AI 级联加载的第一入口，专注于告诉 AI **“当前该读什么、写哪里、用什么命令交接”**，避免长篇大论消耗宝贵的上下文窗口。
> - **`references/FLYWHEEL_SPEC.md`**：符合通用 Skill 规范的 `references/` 资料库约定。当 AI 需要深入理解飞轮的底层架构思想、扩展新命令或排查协议边界时，再按需读取该文件。
> - **`README.md`**：方便你或团队成员在浏览代码库或解压 `.zip` 时，第一时间直观了解该 Skill 的设计初衷与文件组织。

---

## 2. 飞轮（Flywheel）核心设计支柱

1. **释放全栈 AI 潜能，而非束缚 AI（Empowerment over Restriction）**
   - 摒弃传统将 AI 机械切碎为孤立角色的旧规范，让具备产品、研发、运维全栈能力的 AI 沿着 `PRODUCT -> DEV -> OPS -> PRODUCT` 闭环自主驱动项目进化。
2. **协议归飞轮，实现归环境（Protocol vs. Host Implementation）**
   - **飞轮只定义项目内的标准接口**：记忆存哪里、如何做上下文切片、产研运文件如何交接、如何通过 `test_all.py` 验收。
   - **触发与同步交给外部宿主环境**：无论是在 Gemini Task 云端沙箱（配合 `@sync` 同步 Google Drive 与定时任务）、本地 IDE（Claude Code / Cursor），还是云服务器 Crontab，任何环境只需读写同一套飞轮接口即可无缝接力。
3. **三层记忆分离与防上下文污染（Anti-Context-Pollution）**
   - **L1 活状态快照 (`MEMORY.md`, `<= 100` 行)**：只存当前版本、当前所处阶段 (`PRODUCT`/`DEV`/`OPS`)、上一棒摘要与下一棒待办，每次 `handoff` 原子覆写，绝不堆积历史废话。
   - **L2 阶段领域契约 (`docs/PRD.md`, `docs/DESIGN.md`, `docs/OPS_FEEDBACK.md`)**：按阶段切片按需读写。
   - **L3 冷历史归档 (`CHANGELOG.md`)**：平时严禁读取，仅在 `OPS` 发版时追加。
4. **一处声明、处处派生、全库校验（SSoT Versioning & Derivation）**
   - `src/<primary_pkg>/__init__.py` 为唯一权威真值源，全库版本自动派生与游离版本零容忍扫描。
5. **CI 与发布环境免疫（CI & Release Immunity）**
   - 门禁绝不依赖未追踪文件，脚手架与交接文档严禁被 `.gitignore` 排除，干净克隆与本地工作区判定绝对一致，每一条失败均具备三要素（路径、门禁项、建议动作）。
6. **对外产物中英双语规范（Bilingual Artifacts Specification）**
   - 面向全球分发的文档与元数据默认中英双语，段落一一对应、结构对称、核心语义完全等价。
