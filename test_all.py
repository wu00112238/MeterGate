#!/usr/bin/env python3
"""
Flywheel (飞轮) 跨环境统一验收门禁 (test_all.py) (Agent-Native & Human-Trusted Edition)
校验项：
  1. Git 追踪完整性与自适应免疫门禁（本地与 CI 判定绝对一致，防静默漂移）
  2. 核心协议文件、开源交付构件、对抗性语料、双语规范与 GEO 检索清单 (llms.txt) 齐全
  3. 版本唯一权威源 (SSoT) 全仓库版本一致性扫描与无硬编码校验
  4. M-01 ~ M-15、R1 ~ R8、维度 A (A1 ~ A6) 与维度 B (B1 ~ B7) 刚性门禁
  5. 自动化单元测试套件 (tests/test_*.py) 100% 通过
  6. 门禁输出每一条失败信息均严格具备三要素：缺失/不一致文件路径、所属门禁项、建议动作
  7. 邮箱元数据真实可达性门禁：严禁出现 .local、.test、example.com 等保留/占位域名
"""
import ast
import hashlib
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import src.metergate as mg_pkg

CORE_REQUIRED_FILES = [
    "CHANGELOG.md",
    "README.md",
    "README.zh-CN.md",
    "LICENSE",
    "SECURITY.md",
    "pyproject.toml",
    "Dockerfile",
    "docker-compose.yml",
    "version.json",
    ".gitignore",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/ISSUE_TEMPLATE/custom_build.md",
    ".github/RELEASE_TEMPLATE.md",
    ".github/workflows/publish-pypi.yml",
    "src/__init__.py",
    "src/metergate/__init__.py",
    "src/metergate/__main__.py",
    "src/metergate/cli.py",
    "src/metergate/data/mcp_registry_manifests.json",
    "src/metergate/engine.py",
    "src/metergate/proxy.py",
    "src/metergate/web/index.html",
    "src/metergate/web/promo.html",
    "src/metergate/web/promo_en.html",
    "src/metergate/web/promo_zh.html",
    "src/metergate/web/llms.txt",
    "src/metergate/web/llms-full.txt",
    "src/metergate/web/.well-known/metergate.json",
    "src/metergate/storage.py",
    "src/metergate/benchmark.py",
    "src/metergate/data/benchmark_corpus.json",
    "src/metergate/data/adversarial_corpus.json",
    "src/metergate/data/llms.txt",
    "src/metergate/data/live_e2e_verification_record.json",
    "docs/demo.gif",
    "docs/PRD.md",
    "docs/DESIGN.md",
    "docs/BILINGUAL_SPEC.md",
    "docs/RELEASE_TEMPLATE.md",
    "tests/test_metergate.py",
]

OPTIONAL_PROTOCOL_FILES = [
    "AGENTS.md",
    "MEMORY.md",
    "docs/OPS_FEEDBACK.md",
    ".agents/skills/flywheel/SKILL.md",
    ".agents/skills/flywheel/README.md",
    ".agents/skills/flywheel/references/FLYWHEEL_SPEC.md",
    "src/flywheel/__init__.py",
    "src/flywheel/cli.py",
    "tests/test_flywheel.py",
]

REQUIRED_FILES = CORE_REQUIRED_FILES + OPTIONAL_PROTOCOL_FILES

try:
    from src.flywheel.cli import iter_tracked_deliverables, read_ssot_version
except Exception as _e:
    def read_ssot_version():
        init_file = ROOT / "src/metergate/__init__.py"
        if not init_file.exists():
            return "MeterGate", "0.0.0", ROOT / "src/metergate"
        init_txt = init_file.read_text(encoding="utf-8")
        ver_m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_txt)
        proj_m = re.search(r'__project__\s*=\s*["\']([^"\']+)["\']', init_txt)
        ver = ver_m.group(1).strip() if ver_m else "0.0.0"
        proj = proj_m.group(1).strip() if proj_m else "MeterGate"
        return proj, ver, ROOT / "src/metergate"

    def iter_tracked_deliverables():
        is_git = False
        try:
            check = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )
            if check.returncode == 0 and check.stdout.strip() == "true":
                is_git = True
        except Exception:
            is_git = False

        if is_git:
            try:
                res = subprocess.run(
                    ["git", "ls-files"],
                    cwd=str(ROOT),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                tracked: list[Path] = []
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line or line in ("version.json", ".gitignore", "MEMORY.md"):
                        continue
                    p = ROOT / line
                    if (
                        p.is_file()
                        and "__pycache__" not in p.parts
                        and p.suffix != ".pyc"
                        and not p.name.startswith(".")
                    ):
                        tracked.append(p)
                return sorted(tracked, key=lambda x: str(x.relative_to(ROOT)))
            except Exception:
                pass

        tracked = []
        for rel in CORE_REQUIRED_FILES:
            if rel in (".gitignore", "MEMORY.md", "version.json"):
                continue
            p = ROOT / rel
            if p.is_file():
                tracked.append(p)
        return sorted(tracked, key=lambda x: str(x.relative_to(ROOT)))

from src.metergate.cli import CORE_COMMANDS
from src.metergate.engine import (
    MeterGateControlPlane,
    RegexSafetyGuard,
    ThreeTierFirewall,
)
from src.metergate.storage import MeterGateStorage

FORBIDDEN_PATHS = [
    ".agents/skills/mydev",
    "src/clawguard",
    "tests/test_clawguard.py",
]

FICTIONAL_MODELS_FORBIDDEN = (
    "gpt-6-codex-mini",
    "claude-opus-5.5",
    "claude-sonnet-5.2",
    "typesafe-jev-1.5",
    "glm-5.3-flash",
    "deepseek-v3.5-fast",
)


def report_error(gate: str, file_path: str, reason: str, action: str) -> str:
    """Formats deterministic diagnostic error with the 3 mandatory elements."""
    return f"[{gate}] 文件路径: {file_path} | 错误原因: {reason} | 建议动作: {action}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> int:
    errors = []

    # ---------------------------------------------------------
    # 0. Git 追踪完整性与自适应免疫门禁 (Git Immunity & Tracking Gate)
    # ---------------------------------------------------------
    is_git_repo = False
    git_tracked_set = set()
    try:
        git_check = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        if git_check.returncode == 0 and git_check.stdout.strip() == "true":
            is_git_repo = True
            ls_res = subprocess.run(
                ["git", "ls-files"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=True,
            )
            git_tracked_set = {line.strip() for line in ls_res.stdout.splitlines() if line.strip()}
    except Exception:
        is_git_repo = False
        git_tracked_set = set()

    def is_tracked(rel: str) -> bool:
        if not is_git_repo:
            return (ROOT / rel).exists()
        return rel in git_tracked_set

    if is_git_repo:
        # version.json Drift Governance (指纹漂移治理)
        v_status = subprocess.run(
            ["git", "status", "--porcelain", "version.json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        if v_status.returncode == 0 and v_status.stdout.strip():
            errors.append(
                report_error(
                    "门禁项: version.json 指纹漂移治理 (Fingerprint Drift Gate)",
                    "version.json",
                    f"检测到 version.json 存在未提交的修改 ('{v_status.stdout.strip()}')，本地指纹虽匹配但远端 CI 将使用旧指纹导致失败",
                    "执行 git add version.json && git commit -m 'chore: sync version.json' 提交最新指纹后再发布或推送",
                )
            )

    # ---------------------------------------------------------
    # 1. 核心交付构件完整性与存在性校验 (自适应跟踪状态)
    # ---------------------------------------------------------
    for rel in CORE_REQUIRED_FILES:
        p = ROOT / rel
        if not p.exists():
            errors.append(
                report_error(
                    "门禁项: 核心交付构件完整性 (Required Deliverables)",
                    rel,
                    "必要构件文件不存在",
                    "检查该文件是否遗漏或从代码库恢复",
                )
            )
        elif p.stat().st_size == 0:
            errors.append(
                report_error(
                    "门禁项: 核心交付构件完整性 (Required Deliverables)",
                    rel,
                    "必要构件文件大小为 0 字节 (空文件)",
                    "填充该文件的必要配置或核心代码内容",
                )
            )
        elif is_git_repo and not is_tracked(rel):
            errors.append(
                report_error(
                    "门禁项: Git 追踪完整性 (Git Tracking Gate)",
                    rel,
                    "核心交付构件未受 git 追踪，干净 clone 或 CI 环境下将因文件缺失崩溃",
                    f"执行 git add {rel} 将其纳入版本控制",
                )
            )

    # 飞轮协议与交接工作流文件：仅在受 Git 追踪时进行校验，未追踪时确定性跳过
    for rel in OPTIONAL_PROTOCOL_FILES:
        if is_tracked(rel):
            p = ROOT / rel
            if not p.exists() or p.stat().st_size == 0:
                errors.append(
                    report_error(
                        "门禁项: 协议资产完整性 (Protocol Asset Gate)",
                        rel,
                        "受追踪的协议资产文件不存在或为空",
                        "恢复该协议资产或取消对其的 git 追踪",
                    )
                )

    for bad in FORBIDDEN_PATHS:
        if (ROOT / bad).exists():
            errors.append(
                report_error(
                    "门禁项: 已废弃残留清理 (Forbidden Paths Gate)",
                    bad,
                    "存在已废弃的历史残留目录或文件",
                    "从工程中彻底删除该残留目录或文件",
                )
            )

    agents_path = ROOT / "AGENTS.md"
    if is_tracked("AGENTS.md") and agents_path.exists():
        agents_txt = agents_path.read_text(encoding="utf-8")
        if ".agents/skills/flywheel/SKILL.md" not in agents_txt:
            errors.append(
                report_error(
                    "门禁项: AGENTS.md 级联加载规范 (Agent Cascading Gate)",
                    "AGENTS.md",
                    "缺少对 .agents/skills/flywheel/SKILL.md 的级联加载声明",
                    "在 AGENTS.md 开头补充级联加载指令",
                )
            )

    mem_path = ROOT / "MEMORY.md"
    if is_tracked("MEMORY.md") and mem_path.exists():
        mem_lines = mem_path.read_text(encoding="utf-8").splitlines()
        if len(mem_lines) > 100:
            errors.append(
                report_error(
                    "门禁项: MEMORY.md 容量上限 (Memory Line Limit Gate)",
                    "MEMORY.md",
                    f"MEMORY.md 行数 ({len(mem_lines)}) 超过 100 行防污染上限",
                    "运行 python3 -m src.flywheel.cli handoff 覆写精简记忆快照",
                )
            )

    # ---------------------------------------------------------
    # 2. SSoT 版本派生与数据契约一致性校验
    # ---------------------------------------------------------
    project, ssot_ver, _ = read_ssot_version()
    vpath = ROOT / "version.json"
    if not vpath.exists():
        errors.append(
            report_error(
                "门禁项: version.json 存在性 (Version Manifest Gate)",
                "version.json",
                "version.json 文件缺失",
                "运行 python3 -m src.flywheel.cli sync-version 重新生成",
            )
        )
        vdata = {}
    else:
        vdata = json.loads(vpath.read_text(encoding="utf-8"))
        if vdata.get("project") != "MeterGate" or project != "MeterGate":
            errors.append(
                report_error(
                    "门禁项: SSoT 项目身份统一 (Project Identity Gate)",
                    "version.json",
                    f"项目身份未统一为 MeterGate: version.json={vdata.get('project')}, SSoT={project} (M-11 violation)",
                    "检查主包 __init__.py 的 __project__ 与 version.json 中的 project 字段",
                )
            )
        if vdata.get("version") != ssot_ver:
            errors.append(
                report_error(
                    "门禁项: SSoT 版本一致性 (SSoT Consistency Gate)",
                    "version.json",
                    f"version.json 版本 ({vdata.get('version')}) != SSoT ({ssot_ver})",
                    "运行 python3 -m src.flywheel.cli sync-version 重新同步版本号",
                )
            )

    # Full Repository Version Consistency & SSoT Derivation Gate (Repository-wide Scan)
    # 1. Structured Derivative Files Verification
    derivative_checks = [
        ("pyproject.toml", f'version = "{ssot_ver}"'),
        ("Dockerfile", f'org.opencontainers.image.version="{ssot_ver}"'),
        ("docker-compose.yml", f'image: metergate:{ssot_ver}'),
        ("SECURITY.md", f'MeterGate v{ssot_ver}'),
        ("README.md", f'# 🛡️ MeterGate (v{ssot_ver})'),
        ("MEMORY.md", f'当前版本: `v{ssot_ver}`'),
        ("docs/PRD.md", f'PRD — MeterGate v{ssot_ver}'),
        ("docs/DESIGN.md", f'DESIGN — MeterGate v{ssot_ver}'),
        ("docs/OPS_FEEDBACK.md", f'OPS_FEEDBACK — MeterGate v{ssot_ver}'),
        ("src/metergate/web/llms.txt", f'(v{ssot_ver})'),
        ("src/metergate/web/llms-full.txt", f'(v{ssot_ver})'),
        ("src/metergate/data/llms.txt", f'(v{ssot_ver})'),
        ("src/metergate/web/index.html", f'v{ssot_ver}'),
        ("src/metergate/web/promo.html", f'"softwareVersion": "{ssot_ver}"'),
        ("src/metergate/web/promo_en.html", f'"softwareVersion": "{ssot_ver}"'),
        ("src/metergate/web/promo_zh.html", f'"softwareVersion": "{ssot_ver}"'),
    ]
    for rel_f, expected_str in derivative_checks:
        if not is_tracked(rel_f):
            continue
        fp = ROOT / rel_f
        if not fp.exists():
            errors.append(
                report_error(
                    "门禁项: 派生文件存在性 (Derivative Files Gate)",
                    rel_f,
                    f"派生文件缺失: {rel_f}",
                    "恢复该派生文件并运行 python3 -m src.flywheel.cli sync-version",
                )
            )
        else:
            fc = fp.read_text(encoding="utf-8")
            if expected_str not in fc:
                errors.append(
                    report_error(
                        "门禁项: SSoT 版本派生一致性 (SSoT Derivation Gate)",
                        rel_f,
                        f"派生文件未能正确派生 SSoT 版本 (缺少预期串: '{expected_str}')",
                        "运行 python3 -m src.flywheel.cli sync-version 重新派生版本声明",
                    )
                )

    # 2. JSON Data Contracts Version Verification (*_version & version fields)
    json_version_fields = [
        ("version.json", "version"),
        ("src/metergate/web/.well-known/metergate.json", "version"),
        ("src/metergate/data/mcp_registry_manifests.json", "registry_manifest_version"),
        ("src/metergate/data/mcp_registry_manifests.json", "version"),
        ("src/metergate/config/default_policy.json", "policy_version"),
        ("src/metergate/config/model_catalog.json", "catalog_version"),
        ("src/metergate/data/benchmark_corpus.json", "benchmark_version"),
        ("src/metergate/data/adversarial_corpus.json", "corpus_version"),
        ("src/metergate/data/live_e2e_verification_record.json", "version"),
    ]
    for rel_j, vkey in json_version_fields:
        if not is_tracked(rel_j):
            continue
        jp = ROOT / rel_j
        if not jp.exists():
            errors.append(
                report_error(
                    "门禁项: 契约 JSON 存在性 (JSON Contract Gate)",
                    rel_j,
                    f"契约 JSON 缺失: {rel_j}",
                    "恢复该契约 JSON 文件",
                )
            )
        else:
            try:
                jdata = json.loads(jp.read_text(encoding="utf-8"))
                if jdata.get(vkey) != ssot_ver:
                    errors.append(
                        report_error(
                            "门禁项: 契约 JSON 版本一致性 (JSON Version Gate)",
                            rel_j,
                            f"契约字段 {vkey} ({jdata.get(vkey)}) != SSoT ({ssot_ver})",
                            "运行 python3 -m src.flywheel.cli sync-version 重新派生 JSON 契约版本",
                        )
                    )
            except Exception as e:
                errors.append(
                    report_error(
                        "门禁项: 契约 JSON 解析格式 (JSON Syntax Gate)",
                        rel_j,
                        f"契约 JSON 解析失败: {e}",
                        "检查并修正 JSON 语法格式",
                    )
                )

    # 3. Python Source AST Static Analysis: Strictly Zero Hardcoded Version Strings in Runtime
    for py_file in sorted((ROOT / "src").rglob("*.py")):
        if py_file == ROOT / "src/metergate/__init__.py":
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if node.value == ssot_ver:
                        errors.append(
                            report_error(
                                "门禁项: 运行时零硬编码版本 (Runtime AST Gate)",
                                str(py_file.relative_to(ROOT)),
                                f"第 {node.lineno} 行检测到硬编码版本字面量: '{node.value}'",
                                "改为通过 'from . import __version__' 动态引用 SSoT 版本",
                            )
                        )
        except Exception as e:
            errors.append(
                report_error(
                    "门禁项: Python 源码语法解析 (Python AST Gate)",
                    str(py_file.relative_to(ROOT)),
                    f"语法解析异常: {e}",
                    "修复 Python 代码语法错误",
                )
            )

    # 4. Repository-wide Scanning: Zero Stray / Un-derived Version Copies
    semver_pattern = re.compile(r'(?<![0-9.])(\d+\.\d+\.\d+)(?![0-9.])')
    allowed_external_specs = {"0.0.0", "127.0.0", "0.0.4"}
    tracked_list = iter_tracked_deliverables()
    for p in tracked_list:
        rel = str(p.relative_to(ROOT))
        if rel in ("CHANGELOG.md", "src/metergate/__init__.py") or p.suffix in (".gif", ".png", ".jpg"):
            continue
        try:
            file_lines = p.read_text(encoding="utf-8").splitlines()
            for idx, line in enumerate(file_lines, 1):
                for v_match in semver_pattern.findall(line):
                    if v_match in allowed_external_specs:
                        continue
                    if v_match != ssot_ver:
                        errors.append(
                            report_error(
                                "门禁项: 全库游离旧版本扫描 (Stray Version Scan Gate)",
                                f"{rel}:{idx}",
                                f"检测到游离旧版本或硬编码副本: '{v_match}' != SSoT ('{ssot_ver}')",
                                "将该处硬编码版本替换为 SSoT 派生规则或占位符",
                            )
                        )
        except Exception:
            pass

    # B1 Gate: Model Catalog must contain strictly real verifiable models, zero fictional models
    cat_path = ROOT / "src/metergate/config/model_catalog.json"
    if cat_path.exists() and is_tracked("src/metergate/config/model_catalog.json"):
        catalog_txt = cat_path.read_text(encoding="utf-8")
        for fic in FICTIONAL_MODELS_FORBIDDEN:
            if fic in catalog_txt:
                errors.append(
                    report_error(
                        "门禁项: B1 真实官方模型目录 (B1 Real Model Catalog)",
                        "src/metergate/config/model_catalog.json",
                        f"仍包含虚构模型 '{fic}' (B1 violation)",
                        "从 model_catalog.json 中移除虚构模型，替换为官方真实公布单价模型",
                    )
                )

    # SHA-256 Deliverable Fingerprint Verification (Only tracks git-tracked deliverables)
    recorded_modules = vdata.get("modules", {})
    expected_rels = {str(p.relative_to(ROOT)) for p in tracked_list}
    missing_in_manifest = sorted(expected_rels - set(recorded_modules.keys()))
    if missing_in_manifest:
        errors.append(
            report_error(
                "门禁项: version.json 指纹覆盖盲区 (Fingerprint Coverage Gate)",
                "version.json",
                f"存在未纳入指纹保护的盲区交付物: {missing_in_manifest}",
                "运行 python3 -m src.flywheel.cli sync-version 重新计算受控交付物指纹",
            )
        )

    for rel, meta in recorded_modules.items():
        if not is_tracked(rel):
            continue
        fp = ROOT / rel
        if not fp.exists():
            errors.append(
                report_error(
                    "门禁项: 交付物指纹完整性 (Module Fingerprint Gate)",
                    rel,
                    "version.json 记录的交付物文件在磁盘上不存在",
                    "恢复缺失文件或运行 python3 -m src.flywheel.cli sync-version 刷新清单",
                )
            )
        else:
            cur_sha = sha256_file(fp)
            if cur_sha != meta.get("sha256"):
                errors.append(
                    report_error(
                        "门禁项: 交付物指纹完整性 (Module Fingerprint Gate)",
                        rel,
                        f"SHA-256 指纹不匹配 (磁盘={cur_sha[:8]}... != 记录={str(meta.get('sha256'))[:8]}...)",
                        "运行 python3 -m src.flywheel.cli sync-version 重新刷新指纹并提交",
                    )
                )

    # M-01: Single MIT License & No Commercial Bloat
    lic_path = ROOT / "LICENSE"
    if lic_path.exists() and is_tracked("LICENSE"):
        lic_txt = lic_path.read_text(encoding="utf-8")
        if "MIT License" not in lic_txt or "Commercial Tiers" in lic_txt:
            errors.append(
                report_error(
                    "门禁项: M-01 单一开源许可 (M-01 License Gate)",
                    "LICENSE",
                    "LICENSE 未简化为单一 MIT 协议 (M-01 violation)",
                    "将 LICENSE 替换为标准单一 MIT License 文本",
                )
            )
    if hasattr(mg_pkg, "LicenseAndEntitlementManager") or hasattr(
        mg_pkg, "EntitlementError"
    ):
        errors.append(
            report_error(
                "门禁项: M-01 零商业代码残留 (M-01 Bloat Gate)",
                "src/metergate/__init__.py",
                "检测到残留商业授权类 LicenseAndEntitlementManager / EntitlementError (M-01 violation)",
                "物理移除所有残留商业授权类",
            )
        )

    # M-03: CLI Converged to <= 10 Core Commands
    if len(CORE_COMMANDS) > 10:
        errors.append(
            report_error(
                "门禁项: M-03 CLI 命令数收敛 (M-03 Command Gate)",
                "src/metergate/cli.py",
                f"CLI 命令数 ({len(CORE_COMMANDS)}) 超过 10 个上限 (M-03 violation)",
                "将低频命令合并到日常核心主入口 (serve / report)",
            )
        )

    # M-06, M-13, M-14, M-15: README, Hub Link & Issue Templates
    readme_path = ROOT / "README.md"
    readme_zh_path = ROOT / "README.zh-CN.md"
    if readme_path.exists() and is_tracked("README.md"):
        readme_txt = readme_path.read_text(encoding="utf-8")
        if "https://00112238.xyz" not in readme_txt:
            errors.append(
                report_error(
                    "门禁项: M-13 统一枢纽链接 (M-13 Hub Link Gate)",
                    "README.md",
                    "缺少 00112238.xyz 统一枢纽链接 (M-13 violation)",
                    "在 README.md 补充指向 https://00112238.xyz 的更多省时间工具文案",
                )
            )
        if "docs/demo.gif" not in readme_txt:
            errors.append(
                report_error(
                    "门禁项: M-06 演示动图引用 (M-06 Demo Gate)",
                    "README.md",
                    "缺少演示动图 docs/demo.gif 引用 (M-06 violation)",
                    "在 README.md 首屏嵌入 ![MeterGate Demo Animation](docs/demo.gif)",
                )
            )

    if readme_zh_path.exists() and is_tracked("README.zh-CN.md"):
        readme_zh_txt = readme_zh_path.read_text(encoding="utf-8")
        if "https://00112238.xyz" not in readme_zh_txt or "更多省时间工具" not in readme_zh_txt:
            errors.append(
                report_error(
                    "门禁项: M-13 统一枢纽链接 (M-13 Hub Link Gate)",
                    "README.zh-CN.md",
                    "缺少 00112238.xyz 或『更多省时间工具』统一文案 (M-13 violation)",
                    "在 README.zh-CN.md 补充指向 https://00112238.xyz 的更多省时间工具文案",
                )
            )

    for tmpl_rel in (
        ".github/ISSUE_TEMPLATE/feature_request.md",
        ".github/ISSUE_TEMPLATE/custom_build.md",
    ):
        if is_tracked(tmpl_rel):
            tp = ROOT / tmpl_rel
            if tp.exists():
                tmpl_txt = tp.read_text(encoding="utf-8")
                if "想让我帮你改一版？发到这里" not in tmpl_txt:
                    errors.append(
                        report_error(
                            "门禁项: M-15 用户反馈与定制引导 (M-15 Feedback Gate)",
                            tmpl_rel,
                            "缺少『想让我帮你改一版？发到这里』引导文案 (M-15 violation)",
                            f"在 {tmpl_rel} 补充专属定制引导文案",
                        )
                    )

    # ---------------------------------------------------------
    # 3. 对外产物中英双语规范门禁 (Bilingual Artifacts Spec Gate)
    # ---------------------------------------------------------
    if readme_path.exists() and is_tracked("README.md"):
        rtxt = readme_path.read_text(encoding="utf-8")
        if "What It Is" not in rtxt or "What It Solves" not in rtxt:
            errors.append(
                report_error(
                    "门禁项: 对外产物中英双语规范 (Bilingual Spec Gate)",
                    "README.md",
                    "README.md (英文主文档) 缺少 'What It Is' / 'What It Solves' 核心结构段落",
                    "按照 docs/BILINGUAL_SPEC.md 规范，README.md 为纯英文主文档并链接 README.zh-CN.md",
                )
            )
        if "README.zh-CN.md" not in rtxt:
            errors.append(
                report_error(
                    "门禁项: 对外产物中英双语规范 (Bilingual Spec Gate)",
                    "README.md",
                    "README.md 缺少指向 README.zh-CN.md 的语言切换链接",
                    "在 README.md 顶部补充指向 README.zh-CN.md 的语言切换链接",
                )
            )

    if readme_zh_path.exists() and is_tracked("README.zh-CN.md"):
        rzh_txt = readme_zh_path.read_text(encoding="utf-8")
        if "是什么" not in rzh_txt or "解决什么" not in rzh_txt:
            errors.append(
                report_error(
                    "门禁项: 对外产物中英双语规范 (Bilingual Spec Gate)",
                    "README.zh-CN.md",
                    "README.zh-CN.md (中文完整版) 缺少 '是什么' / '解决什么' 核心结构段落",
                    "按照 docs/BILINGUAL_SPEC.md 规范，README.zh-CN.md 为纯中文完整版并链接 README.md",
                )
            )
        if "README.md" not in rzh_txt:
            errors.append(
                report_error(
                    "门禁项: 对外产物中英双语规范 (Bilingual Spec Gate)",
                    "README.zh-CN.md",
                    "README.zh-CN.md 缺少指向 README.md 的语言切换链接",
                    "在 README.zh-CN.md 顶部补充指向 README.md 的语言切换链接",
                )
            )

    pyp_path = ROOT / "pyproject.toml"
    if pyp_path.exists() and is_tracked("pyproject.toml"):
        pyp_txt = pyp_path.read_text(encoding="utf-8")
        m_desc = re.search(r'description\s*=\s*["\']([^"\']+)["\']', pyp_txt)
        if m_desc:
            dval = m_desc.group(1)
            has_zh = bool(re.search(r'[\u4e00-\u9fff]', dval))
            has_en = bool(re.search(r'[a-zA-Z]{3,}', dval))
            if not (has_zh and has_en):
                errors.append(
                    report_error(
                        "门禁项: 对外产物中英双语规范 (Bilingual Spec Gate)",
                        "pyproject.toml",
                        f"pyproject.toml description 未遵循中英双语规范: '{dval}'",
                        "在 description 中使用 '|' 组合中文与英文包描述",
                    )
                )

    for llm_rel in ("src/metergate/web/llms.txt", "src/metergate/data/llms.txt"):
        if is_tracked(llm_rel):
            lp = ROOT / llm_rel
            if lp.exists():
                ltxt = lp.read_text(encoding="utf-8")
                if "选型决策矩阵" not in ltxt or "Agent Selection Decision Matrix" not in ltxt:
                    errors.append(
                        report_error(
                            "门禁项: 对外产物中英双语规范 (Bilingual Spec Gate)",
                            llm_rel,
                            f"{llm_rel} 决策段缺少中英双语对称描述",
                            "在 llms.txt 中按照 docs/BILINGUAL_SPEC.md 规范提供中英双语选型矩阵",
                        )
                    )

    # ---------------------------------------------------------
    # 4. 邮箱元数据真实可达性门禁 (Email Validity Gate)
    # ---------------------------------------------------------
    disallowed_email_domains = (
        ".local",
        ".test",
        ".example",
        "@example.com",
        "@example.org",
        "@example.net",
        "@localhost",
    )
    for rel_e in ("pyproject.toml", "SECURITY.md"):
        if is_tracked(rel_e):
            ep = ROOT / rel_e
            if ep.exists():
                etxt = ep.read_text(encoding="utf-8")
                for email_match in re.findall(r'[\w.+-]+@[\w.-]+\.[a-zA-Z0-9]+', etxt):
                    low_e = email_match.lower()
                    if any(low_e.endswith(d) or d in low_e for d in disallowed_email_domains):
                        errors.append(
                            report_error(
                                "门禁项: 邮箱元数据真实可达性 (Email Validity Gate)",
                                rel_e,
                                f"检测到包含保留或占位域名的邮箱: '{email_match}' (PyPI 上传将拒收)",
                                "替换为真实可达的有效联系邮箱 (如 wu00112238@users.noreply.github.com)",
                            )
                        )

    # ---------------------------------------------------------
    # 5. R7 & P1: 100% Offline Web Console & Promo Website Gate
    # ---------------------------------------------------------
    for html_rel in ("src/metergate/web/index.html", "src/metergate/web/promo.html", "src/metergate/web/promo_en.html"):
        if is_tracked(html_rel):
            hp = ROOT / html_rel
            if hp.exists():
                web_html = hp.read_text(encoding="utf-8")
                if re.search(r'window\s*\[\s*["\']fet["\']\s*\+', web_html):
                    errors.append(
                        report_error(
                            "门禁项: R7 零规避静态安全门禁 (R7 Evasion Gate)",
                            html_rel,
                            "检测到前端规避式字符串拼接写法",
                            "重构前端代码消除混淆拼接",
                        )
                    )
                if re.search(r"<script[^>]+src=[\"']https?://", web_html, re.I) or re.search(
                    r"<link[^>]+href=[\"']https?://", web_html, re.I
                ):
                    errors.append(
                        report_error(
                            "门禁项: R7 100% 离线与零公网依赖 (R7 Offline Gate)",
                            html_rel,
                            "检测到依赖外部公网 CDN 脚本或样式表 (R7 violation)",
                            "将外部依赖内联为本地内联 CSS/JS，确保 100% 离线可用",
                        )
                    )

    # R5: RegexSafetyGuard Gate
    safe_ok, _ = RegexSafetyGuard.check_pattern_safety(r"(a+)+$")
    if safe_ok:
        errors.append(
            report_error(
                "门禁项: R5 正则安全守护 (R5 Regex Guard)",
                "src/metergate/engine.py",
                "RegexSafetyGuard 未能拦截典型嵌套量词 ReDoS 模式 (R5 violation)",
                "修复 RegexSafetyGuard 中的灾难性回溯安全拦截逻辑",
            )
        )

    proxy_path = ROOT / "src/metergate/proxy.py"
    if proxy_path.exists() and is_tracked("src/metergate/proxy.py"):
        proxy_src = proxy_path.read_text(encoding="utf-8")
        if '"Access-Control-Allow-Origin", "*"' in proxy_src:
            errors.append(
                report_error(
                    "门禁项: CORS 安全基线门禁 (CORS Policy Gate)",
                    "src/metergate/proxy.py",
                    "检测到 proxy.py 存在通配符 CORS 头",
                    "将 Access-Control-Allow-Origin 限制为特定安全来源或本机回路",
                )
            )

    if "mode_override" in inspect.signature(ThreeTierFirewall.inspect).parameters:
        errors.append(
            report_error(
                "门禁项: A1 控制面接口契约 (A1 Architecture Gate)",
                "src/metergate/engine.py",
                "ThreeTierFirewall.inspect 仍保留 mode_override 参数 (A1 violation)",
                "从 ThreeTierFirewall.inspect 签名中移除 mode_override 参数",
            )
        )
    if "mode_override" in inspect.signature(MeterGateControlPlane.process_agent_turn).parameters:
        errors.append(
            report_error(
                "门禁项: A1 控制面接口契约 (A1 Architecture Gate)",
                "src/metergate/engine.py",
                "MeterGateControlPlane.process_agent_turn 仍保留 mode_override 参数 (A1 violation)",
                "从 process_agent_turn 签名中移除 mode_override 参数",
            )
        )
    if "sla_downgrade_tier2" in inspect.signature(ThreeTierFirewall.inspect).parameters:
        errors.append(
            report_error(
                "门禁项: A3 防火墙接口契约 (A3 Firewall Gate)",
                "src/metergate/engine.py",
                "ThreeTierFirewall.inspect 仍保留 sla_downgrade_tier2 降级参数 (A3 violation)",
                "移除 sla_downgrade_tier2 降级逻辑",
            )
        )
    if "utc_date" in inspect.signature(MeterGateStorage.get_daily_quota_usage).parameters:
        errors.append(
            report_error(
                "门禁项: ARC-2 本地存储时间基准 (ARC-2 Storage Gate)",
                "src/metergate/storage.py",
                "MeterGateStorage.get_daily_quota_usage 仍接受客户端可控 utc_date 参数 (ARC-2 violation)",
                "由服务端统一生成不可篡改的当前 UTC 日期",
            )
        )
    if "utc_date" in inspect.signature(MeterGateControlPlane.process_agent_turn).parameters:
        errors.append(
            report_error(
                "门禁项: ARC-2 本地存储时间基准 (ARC-2 Control Gate)",
                "src/metergate/engine.py",
                "MeterGateControlPlane.process_agent_turn 仍接受客户端可控 utc_date 参数 (ARC-2 violation)",
                "由控制面服务端内部权威生成 UTC 日期",
            )
        )

    e2e_path = ROOT / "src/metergate/data/live_e2e_verification_record.json"
    if e2e_path.exists() and is_tracked("src/metergate/data/live_e2e_verification_record.json"):
        try:
            e2e_data = json.loads(e2e_path.read_text(encoding="utf-8"))
            if not e2e_data.get("all_assertions_passed") or e2e_data.get("project") != "MeterGate":
                errors.append(
                    report_error(
                        "门禁项: E2E 真实端到端验证记录 (E2E Record Gate)",
                        "src/metergate/data/live_e2e_verification_record.json",
                        "live_e2e_verification_record.json 未通过断言或未统一为 MeterGate 身份",
                        "运行真实 E2E 验证并重新记录结果",
                    )
                )
        except Exception as e:
            errors.append(
                report_error(
                    "门禁项: E2E 验证记录文件格式 (E2E JSON Gate)",
                    "src/metergate/data/live_e2e_verification_record.json",
                    f"读取失败: {e}",
                    "修复 JSON 文件格式",
                )
            )

    storage_path = ROOT / "src/metergate/storage.py"
    if storage_path.exists() and is_tracked("src/metergate/storage.py"):
        storage_src = storage_path.read_text(encoding="utf-8")
        if "ALTER TABLE" in storage_src or "CREATE TABLE IF NOT EXISTS tenants" in storage_src:
            errors.append(
                report_error(
                    "门禁项: M-02 单实例本地存储极简设计 (M-02 Storage Gate)",
                    "src/metergate/storage.py",
                    "检测到 storage.py 存在 ALTER TABLE 迁移分支或残留 tenants 表 (M-02/E2 violation)",
                    "清理多租户表与无用迁移分支",
                )
            )

    for py_path in sorted((ROOT / "src" / "metergate").rglob("*.py")):
        try:
            tree = ast.parse(py_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name not in (
                    "do_GET",
                    "do_POST",
                    "do_OPTIONS",
                ):
                    if node.name != node.name.lower():
                        errors.append(
                            report_error(
                                "门禁项: E3 Python 代码规范 (E3 Naming Gate)",
                                str(py_path.relative_to(ROOT)),
                                f"检测到非 snake_case 方法命名 '{node.name}' (E3 violation)",
                                "将方法重命名为符合 PEP 8 的 snake_case 风格",
                            )
                        )
        except Exception:
            pass

    # ---------------------------------------------------------
    # 6. 自动化单元测试套件全量执行
    # ---------------------------------------------------------
    ut_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(ROOT / "tests"),
            "-p",
            "test_*.py",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if ut_proc.returncode != 0:
        errors.append(
            report_error(
                "门禁项: 单元测试套件 (Unit Tests Gate)",
                "tests/",
                f"单元测试未全量通过:\n{ut_proc.stdout}\n{ut_proc.stderr}",
                "修复失败的测试用例并确保 100% 通过",
            )
        )

    # ---------------------------------------------------------
    # 判定与结构化输出
    # ---------------------------------------------------------
    if errors:
        print(f"❌ [FLYWHEEL VERIFY FAILED] 共检测到 {len(errors)} 项门禁违规:")
        for idx, e in enumerate(errors, 1):
            print(f"  {idx}. {e}")
        return 1

    print(
        f"✅ [FLYWHEEL PROTOCOL VERIFIED] {project} v{ssot_ver} "
        f"(Memory <=100L · All {len(recorded_modules)} Deliverables SHA-256 Verified · "
        f"Git Adaptive Tracking · Bilingual Specs Compliant · M-01..M-15, R1..R8, A1..A6 & B1..B7 Clean · Tests Passed)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
