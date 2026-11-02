# OPS_FEEDBACK — MeterGate v1.0.1 验收反馈（自适应 Git 追踪免疫、真实发布邮箱与指纹漂移闭环）

## 1. 发布状态总览 (Release Summary)
- **项目名称**: `MeterGate`
- **发布版本**: `v1.0.1` (Adaptive Git Immunity · RFC Reserved Email Fix · Semantic B Release Hardening)
- **Schema 版本**: `1.0.1` (Indexed Single-Instance SQLite Schema, zero `ALTER TABLE` branches)
- **验收状态**: 全量交付物指纹、自适应 Git 追踪门禁、真实邮箱规范、双语规范与自动化单元测试 100% 通过 `python3 test_all.py` 严格校验。

## 2. 核心成果与验证结果
1. **需求一：恢复 .gitignore 排除语义（语义 B 落地）**:
   - 恢复 `.gitignore` 第 13-17 行及管理文档排除规则（保留分组注释与完整排除规则），尊重作者对本地自进化工作流构件不入公共仓库的工程选择。
   - 删除 `test_all.py` Check A 的「命中排除即报错」与单测 `forbidden_ignores` 硬性断言。
   - 门禁对「未被 Git 追踪的协议文件」实施自适应确定性跳过，不报错、不崩溃；对「已追踪的核心交付物」严格校验。
   - 在协议文件（如 `AGENTS.md`、`MEMORY.md`）未被追踪且不存在时确定性安全跳过，消除任何未捕获异常。
2. **需求二：追踪真值统一收敛到 git ls-files**:
   - `src/flywheel/cli.py` 的 `iter_tracked_deliverables()` 重构为以 `git ls-files` 为唯一真值源，彻底消除「磁盘有 ≠ 仓库有」导致的 CI 误报根因。
   - `sync-version` 生成的 `version.json` 指纹集合严格限定为 Git 追踪文件，并自动清除历史遗留的未追踪排除文件指纹。
   - 指纹盲区校验（Fingerprint Coverage Gate）期望集合与 `git ls-files` 严格对齐，实现「本地绿 = 干净 clone 绿 = CI 绿」三者绝对恒等。
3. **需求三：PyPI 真实邮箱修复与防回归门禁**:
   - `pyproject.toml` 的作者邮箱与 `SECURITY.md` 安全汇报联系邮箱统一替换为真实可达的 `wu00112238@users.noreply.github.com`，彻底消除 `.local` 保留域名引发的 PyPI 400 拒收风险。
   - `test_all.py` 新增「邮箱元数据真实可达性门禁（Email Validity Gate）」，硬性禁止在包元数据与安全文档中出现 `.local`、`.test`、`example.com` 等保留/占位域名。
4. **需求四：飞轮规范三层语义对齐**:
   - 改写 `.agents/skills/flywheel/references/FLYWHEEL_SPEC.md`「支柱六」，从「禁止排除」修正为「追踪状态自适应免疫」，表述通用解耦。
   - 同步修正 `.agents/skills/flywheel/SKILL.md` 第 4 节与 `tests/test_flywheel.py` 相关断言，保持规范、技能与测试三层高度一致。
   - 在 `AGENTS.md` 首页补充指向支柱六（自适应免疫）与支柱七（双语规范）的快速索引链接。

---
🔗 [更多省时间工具](https://00112238.xyz) (`https://00112238.xyz`)
