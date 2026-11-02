#!/usr/bin/env python3
"""
Flywheel (飞轮) 项目接口与阶段交接工具 (src/flywheel/cli.py)
定位：纯粹的项目状态、上下文防污染切片与阶段交接（Handoff）工具，不包含任何与特定宿主环境绑定的定时任务守护进程。
支持命令：
  1. status         : 查看当前项目版本、所处阶段 (PRODUCT / DEV / OPS) 与下一棒交接单
  2. context        : 打印当前阶段的「防污染最小上下文切片」（Read Slice & Write Target）
  3. handoff        : 完成当前阶段交付，核验产物存在性，原子更新 MEMORY.md 交接棒与 version.json
  4. sync-version   : 从 SSoT 派生更新全库对外版本并刷新受控交付物 SHA-256 清单写入 version.json
  5. derive-version : 从 SSoT 主包 __init__.__version__ 派生全仓库版本声明
  6. init           : 将飞轮脚手架一键初始化为新项目名称
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = PROJECT_ROOT / "src"
TESTS_DIR = PROJECT_ROOT / "tests"
DOCS_DIR = PROJECT_ROOT / "docs"
GITHUB_DIR = PROJECT_ROOT / ".github"
AGENTS_SKILL_DIR = PROJECT_ROOT / ".agents" / "skills" / "flywheel"
MEMORY_FILE = PROJECT_ROOT / "MEMORY.md"
VERSION_FILE = PROJECT_ROOT / "version.json"

TRACKED_ROOT_FILES = (
    "AGENTS.md",
    "CHANGELOG.md",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "docker-compose.yml",
    "pyproject.toml",
    "test_all.py",
)

STAGES = ("PRODUCT", "DEV", "OPS")

STAGE_SLICES = {
    "PRODUCT": {
        "title": "产品定义与架构设计阶段 (Product & Architecture)",
        "read_slice": [
            "MEMORY.md (读取上一轮交接棒与核心目标)",
            "docs/OPS_FEEDBACK.md (读取线上运行反馈与用户痛点)",
        ],
        "write_target": [
            "docs/PRD.md (输出本轮产品目标、核心特性与验收底线)",
            "docs/DESIGN.md (输出系统分层架构、界面设计与数据流)",
        ],
        "ignore_noise": [
            "CHANGELOG.md (历史流水账)",
            "src/ 内部底层实现细节 (避免过早陷入代码细节限制产品创意)",
        ],
        "required_outputs": ["docs/PRD.md", "docs/DESIGN.md"],
    },
    "DEV": {
        "title": "研发实现与自测验证阶段 (Development & Verification)",
        "read_slice": [
            "MEMORY.md (读取本轮研发交接单)",
            "docs/PRD.md (读取产品需求与验收底线)",
            "docs/DESIGN.md (读取架构与接口设计)",
            "src/ (读取现有代码结构)",
        ],
        "write_target": [
            "src/ (所有新增或修改的业务源码、前端页面与组件统一放入 src/)",
            "tests/ (编写或更新自动化验证测试)",
            "version.json (通过 sync-version 自动刷新全量交付物 SHA-256 指纹)",
        ],
        "ignore_noise": [
            "CHANGELOG.md (历史版本流水账)",
            "docs/OPS_FEEDBACK.md (原始运维监控流水)",
        ],
        "required_outputs": ["src", "tests"],
    },
    "OPS": {
        "title": "运维发布与进化反馈阶段 (Operations, Release & Feedback)",
        "read_slice": [
            "MEMORY.md (读取研发交接摘要)",
            "docs/PRD.md (核对产品验收要求)",
            "version.json (核对发布版本与全量交付物指纹)",
        ],
        "write_target": [
            "docs/OPS_FEEDBACK.md (记录发布状态、线上真实指标与下一轮进化洞察)",
            "CHANGELOG.md (追加本版本正式发布记录)",
        ],
        "ignore_noise": [
            "tests/ 内部桩代码细节",
        ],
        "required_outputs": ["docs/OPS_FEEDBACK.md", "CHANGELOG.md"],
    },
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def find_primary_pkg() -> Path:
    candidates = [
        p
        for p in sorted(SRC_DIR.iterdir())
        if p.is_dir()
        and not p.name.startswith(("_", "."))
        and p.name != "flywheel"
        and (p / "__init__.py").exists()
    ]
    if candidates:
        return candidates[0]
    if (SRC_DIR / "flywheel" / "__init__.py").exists():
        return SRC_DIR / "flywheel"
    raise RuntimeError("在 src/ 下未找到包含 __init__.py 的主包目录")


def read_ssot_version() -> tuple:
    pkg_dir = find_primary_pkg()
    init_file = pkg_dir / "__init__.py"
    if not init_file.exists():
        raise RuntimeError(f"SSoT 文件不存在: {init_file}")
    init_text = init_file.read_text(encoding="utf-8")
    ver_m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_text)
    proj_m = re.search(r'__project__\s*=\s*["\']([^"\']+)["\']', init_text)
    if not ver_m:
        raise RuntimeError(
            f"SSoT 版本解析失败: 在 {init_file} 中未找到有效的 __version__ 声明"
        )
    if not proj_m:
        raise RuntimeError(
            f"SSoT 项目名称解析失败: 在 {init_file} 中未找到有效的 __project__ 声明"
        )
    version = ver_m.group(1).strip()
    project = proj_m.group(1).strip()
    return project, version, pkg_dir


def parse_memory() -> dict:
    project, version, _ = read_ssot_version()
    state = {
        "project": project,
        "version": f"v{version}",
        "stage": "PRODUCT",
        "cycle": 1,
        "updated_at": "N/A",
        "last_summary": f"{project} 飞轮初始化就绪",
        "next_handoff": "根据新项目需求编写 docs/PRD.md 与 docs/DESIGN.md",
    }
    if not MEMORY_FILE.exists():
        return state
    text = MEMORY_FILE.read_text(encoding="utf-8")
    patterns = {
        "project": r"-\s*项目名称:\s*`?([^`\n]+)`?",
        "version": r"-\s*当前版本:\s*`?([^`\n]+)`?",
        "stage": r"-\s*当前焦点阶段:\s*`?(PRODUCT|DEV|OPS)`?",
        "cycle": r"-\s*当前飞轮轮次:\s*`?#?(\d+)`?",
        "updated_at": r"-\s*最近交接时间:\s*`?([^`\n]+)`?",
        "last_summary": r"-\s*上棒完成摘要:\s*(.+)",
        "next_handoff": r"-\s*本棒核心任务:\s*(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, text)
        if m:
            val = m.group(1).strip()
            state[key] = int(val) if key == "cycle" else val
    return state


def write_memory(state: dict) -> None:
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    state["updated_at"] = now_iso
    stage = state["stage"]
    slice_info = STAGE_SLICES[stage]

    read_bullets = "\n".join(f"  - `{item}`" for item in slice_info["read_slice"])
    write_bullets = "\n".join(f"  - `{item}`" for item in slice_info["write_target"])

    content = f"""# MEMORY — {state['project']} 飞轮活状态与交接快照

> 本文件是项目的唯一实时状态机与阶段交接棒（保持 <= 100 行，防上下文污染）。

## 1. 当前飞轮坐标 (Flywheel Coordinates)
- 项目名称: `{state['project']}`
- 当前版本: `{state['version']}`
- 当前飞轮轮次: `#{state['cycle']}`
- 当前焦点阶段: `{stage}` — {slice_info['title']}
- 最近交接时间: `{state['updated_at']}`

## 2. 阶段交接棒 (Stage Handoff Baton)
- 上棒完成摘要: {state['last_summary']}
- 本棒核心任务: {state['next_handoff']}

## 3. 当前阶段防污染上下文切片 (`{stage}` Context Slice)
- **本阶段必读输入 (Read Slice)**:
{read_bullets}
- **本阶段交付位置 (Write Target)**:
{write_bullets}
"""
    fd, tmp_path = tempfile.mkstemp(dir=str(PROJECT_ROOT), prefix=".tmp_mem_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, MEMORY_FILE)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def derive_versions() -> list:
    """
    Derives all external and contract version references from SSoT
    across pyproject.toml, Dockerfile, docker-compose.yml, SECURITY.md,
    README.md, MEMORY.md, docs, web pages, and JSON data files.
    """
    project, version, pkg_dir = read_ssot_version()
    pkg_name = pkg_dir.name.lower()
    updated_files: list[str] = []

    # 1. pyproject.toml
    pyproject = PROJECT_ROOT / "pyproject.toml"
    if pyproject.exists():
        txt = pyproject.read_text(encoding="utf-8")
        new_txt = re.sub(
            r'(?m)^(version\s*=\s*)["\'][^"\']+["\']',
            rf'\g<1>"{version}"',
            txt,
        )
        if new_txt != txt:
            pyproject.write_text(new_txt, encoding="utf-8")
            updated_files.append("pyproject.toml")

    # 2. Dockerfile
    dockerfile = PROJECT_ROOT / "Dockerfile"
    if dockerfile.exists():
        txt = dockerfile.read_text(encoding="utf-8")
        new_txt = re.sub(
            r'(org\.opencontainers\.image\.version\s*=\s*)["\'][^"\']+["\']',
            rf'\g<1>"{version}"',
            txt,
        )
        new_txt = re.sub(
            rf"#{re.escape(project)}\s+v\d+\.\d+\.\d+",
            f"#{project} v{version}",
            new_txt,
        )
        new_txt = re.sub(
            rf"#\s+{re.escape(project)}\s+v\d+\.\d+\.\d+",
            f"# {project} v{version}",
            new_txt,
        )
        if new_txt != txt:
            dockerfile.write_text(new_txt, encoding="utf-8")
            updated_files.append("Dockerfile")

    # 3. docker-compose.yml
    compose = PROJECT_ROOT / "docker-compose.yml"
    if compose.exists():
        txt = compose.read_text(encoding="utf-8")
        new_txt = re.sub(
            rf"(image:\s*{re.escape(pkg_name)}:)\d+\.\d+\.\d+",
            rf"\g<1>{version}",
            txt,
        )
        if new_txt != txt:
            compose.write_text(new_txt, encoding="utf-8")
            updated_files.append("docker-compose.yml")

    # 4. SECURITY.md
    sec = PROJECT_ROOT / "SECURITY.md"
    if sec.exists():
        txt = sec.read_text(encoding="utf-8")
        new_txt = re.sub(
            rf"# Security Policy & Local Data Integrity \(`{re.escape(project)}\s+v\d+\.\d+\.\d+`\)",
            f"# Security Policy & Local Data Integrity (`{project} v{version}`)",
            txt,
        )
        major, minor, _ = version.split(".", 2)
        new_txt = re.sub(
            r"\|\s*`\d+\.\d+\.x`\s*\|\s*Yes\s*\|",
            f"| `{major}.{minor}.x` | Yes |",
            new_txt,
        )
        new_txt = re.sub(
            r"Superseded by `\d+\.\d+\.\d+`",
            f"Superseded by `{version}`",
            new_txt,
        )
        new_txt = re.sub(
            rf"superseded by unified `{re.escape(project)}\s+v\d+\.\d+\.\d+`",
            f"superseded by unified `{project} v{version}`",
            new_txt,
        )
        new_txt = re.sub(
            rf"(exact `{re.escape(pkg_name)}` version \(`)\d+\.\d+\.\d+(`\))",
            rf"\g<1>{version}\g<2>",
            new_txt,
        )
        if new_txt != txt:
            sec.write_text(new_txt, encoding="utf-8")
            updated_files.append("SECURITY.md")

    # 5. README.md
    readme = PROJECT_ROOT / "README.md"
    if readme.exists():
        txt = readme.read_text(encoding="utf-8")
        new_txt = re.sub(
            rf"# 🛡️ {re.escape(project)} \(v\d+\.\d+\.\d+\)",
            f"# 🛡️ {project} (v{version})",
            txt,
        )
        if new_txt != txt:
            readme.write_text(new_txt, encoding="utf-8")
            updated_files.append("README.md")

    # 6. MEMORY.md
    if MEMORY_FILE.exists():
        txt = MEMORY_FILE.read_text(encoding="utf-8")
        new_txt = re.sub(
            r"(-\s*当前版本:\s*`?v?)\d+\.\d+\.\d+(`?)",
            rf"\g<1>{version}\g<2>",
            txt,
        )
        if new_txt != txt:
            MEMORY_FILE.write_text(new_txt, encoding="utf-8")
            updated_files.append("MEMORY.md")

    # 7. Docs: PRD, DESIGN, OPS_FEEDBACK
    for doc_name in ("PRD.md", "DESIGN.md", "OPS_FEEDBACK.md"):
        doc_path = DOCS_DIR / doc_name
        if doc_path.exists():
            txt = doc_path.read_text(encoding="utf-8")
            new_txt = re.sub(
                rf"({re.escape(doc_name.split('.')[0])}\s*—\s*{re.escape(project)}\s+v)\d+\.\d+\.\d+",
                rf"\g<1>{version}",
                txt,
            )
            new_txt = re.sub(
                rf"({re.escape(project)}\s+v)\d+\.\d+\.\d+(\s+Gateway Proxy)",
                rf"\g<1>{version}\g<2>",
                new_txt,
            )
            new_txt = re.sub(
                r"(-\s*\*\*发布版本\*\*:\s*`v)\d+\.\d+\.\d+(`)",
                rf"\g<1>{version}\g<2>",
                new_txt,
            )
            new_txt = re.sub(
                r"(-\s*\*\*Schema 版本\*\*:\s*`)\d+\.\d+\.\d+(`)",
                rf"\g<1>{version}\g<2>",
                new_txt,
            )
            new_txt = re.sub(
                r"## 1\. 版本演进目标 \(`v\d+\.\d+\.\d+`\)",
                f"## 1. 版本演进目标 (`v{version}`)",
                new_txt,
            )
            if new_txt != txt:
                doc_path.write_text(new_txt, encoding="utf-8")
                updated_files.append(f"docs/{doc_name}")

    # 8. Primary pkg data and web files
    if pkg_dir.exists():
        for fpath in sorted(pkg_dir.rglob("*")):
            if not fpath.is_file() or "__pycache__" in fpath.parts:
                continue
            rel = str(fpath.relative_to(PROJECT_ROOT))
            # JSON files
            if fpath.suffix == ".json":
                try:
                    jdata = json.loads(fpath.read_text(encoding="utf-8"))
                    changed = False

                    def update_json_versions(obj):
                        nonlocal changed
                        if isinstance(obj, dict):
                            for k, v in list(obj.items()):
                                if (k == "version" or k.endswith("_version")) and isinstance(v, str):
                                    if re.match(r"^\d+\.\d+\.\d+$", v) and v != version:
                                        obj[k] = version
                                        changed = True
                                elif isinstance(v, str) and re.search(rf"{re.escape(project)}\s*\(v\d+\.\d+\.\d+\)", v):
                                    new_v = re.sub(rf"({re.escape(project)}\s*\(v)\d+\.\d+\.\d+(\))", rf"\g<1>{version}\g<2>", v)
                                    if new_v != v:
                                        obj[k] = new_v
                                        changed = True
                                else:
                                    update_json_versions(v)
                        elif isinstance(obj, list):
                            for item in obj:
                                update_json_versions(item)

                    update_json_versions(jdata)
                    if changed:
                        fpath.write_text(
                            json.dumps(jdata, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8",
                        )
                        updated_files.append(rel)
                except Exception:
                    pass
            # llms.txt files
            elif fpath.name.startswith("llms") and fpath.suffix == ".txt":
                txt = fpath.read_text(encoding="utf-8")
                new_txt = re.sub(
                    rf"(#\s*{re.escape(project)}\s*\(v)\d+\.\d+\.\d+(\))",
                    rf"\g<1>{version}\g<2>",
                    txt,
                )
                if new_txt != txt:
                    fpath.write_text(new_txt, encoding="utf-8")
                    updated_files.append(rel)
            # HTML files
            elif fpath.suffix == ".html":
                txt = fpath.read_text(encoding="utf-8")
                new_txt = re.sub(
                    rf"(<title>{re.escape(project)}\s+v)\d+\.\d+\.\d+",
                    rf"\g<1>{version}",
                    txt,
                )
                new_txt = re.sub(
                    r'("softwareVersion":\s*")\d+\.\d+\.\d+(")',
                    rf"\g<1>{version}\g<2>",
                    new_txt,
                )
                new_txt = re.sub(
                    r"(v)\d+\.\d+\.\d+(\s+PyPI\s*/\s*uvx Ready)",
                    rf"\g<1>{version}\g<2>",
                    new_txt,
                )
                new_txt = re.sub(
                    rf"({re.escape(project)}(?:</strong>)?\s+v)\d+\.\d+\.\d+",
                    rf"\g<1>{version}",
                    new_txt,
                )
                new_txt = re.sub(
                    rf"({re.escape(project)}\s*\(v)\d+\.\d+\.\d+(\))",
                    rf"\g<1>{version}\g<2>",
                    new_txt,
                )
                new_txt = re.sub(
                    rf"({re.escape(project.upper())}\s+v)\d+\.\d+\.\d+",
                    rf"\g<1>{version}",
                    new_txt,
                )
                if new_txt != txt:
                    fpath.write_text(new_txt, encoding="utf-8")
                    updated_files.append(rel)

    return updated_files


def iter_tracked_deliverables() -> list:
    """
    Returns all tracked project deliverables.
    Uses 'git ls-files' as the single source of truth when inside a git repository.
    Falls back to disk scanning only in non-git environments.
    """
    is_git = False
    try:
        check = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(PROJECT_ROOT),
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
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                check=True,
            )
            tracked: list[Path] = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line or line in ("version.json", ".gitignore", "MEMORY.md"):
                    continue
                p = PROJECT_ROOT / line
                if (
                    p.is_file()
                    and "__pycache__" not in p.parts
                    and p.suffix != ".pyc"
                    and not p.name.startswith(".")
                ):
                    tracked.append(p)
            return sorted(tracked, key=lambda x: str(x.relative_to(PROJECT_ROOT)))
        except Exception:
            pass

    # Non-git fallback: scan disk
    tracked: list[Path] = []
    for rel_name in TRACKED_ROOT_FILES:
        p = PROJECT_ROOT / rel_name
        if p.is_file():
            tracked.append(p)
    for folder in (SRC_DIR, TESTS_DIR, DOCS_DIR, GITHUB_DIR, AGENTS_SKILL_DIR):
        if folder.exists():
            for path in sorted(folder.rglob("*")):
                if (
                    path.is_file()
                    and "__pycache__" not in path.parts
                    and path.suffix != ".pyc"
                    and not path.name.startswith(".")
                ):
                    tracked.append(path)
    return sorted(tracked, key=lambda x: str(x.relative_to(PROJECT_ROOT)))


def sync_version_json() -> dict:
    derive_versions()
    project, version, _ = read_ssot_version()
    state = parse_memory()
    modules = {}
    for path in iter_tracked_deliverables():
        rel = str(path.relative_to(PROJECT_ROOT))
        modules[rel] = {
            "sha256": sha256_file(path),
        }

    payload = {
        "project": project,
        "version": version,
        "stage": state["stage"],
        "cycle": state["cycle"],
        "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "modules": modules,
    }
    VERSION_FILE.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(
        f"[FLYWHEEL DRIFT GUARD] version.json 已同步刷新 (v{version}, {len(modules)} 个模块)。\n"
        f"  👉 提示: 请执行 'git add version.json && git commit' 提交最新指纹，避免产生「本地绿、远端旧」的静默漂移！"
    )
    return payload


def cmd_status() -> None:
    project, version, _ = read_ssot_version()
    state = parse_memory()
    print(f"=== Flywheel (飞轮) 状态总览 [{project} v{version}] ===")
    print(f"  - 当前飞轮轮次 : Cycle #{state['cycle']}")
    print(f"  - 当前焦点阶段 : {state['stage']} ({STAGE_SLICES[state['stage']]['title']})")
    print(f"  - 最近交接时间 : {state['updated_at']}")
    print(f"  - 上棒完成摘要 : {state['last_summary']}")
    print(f"  - 本棒核心任务 : {state['next_handoff']}")


def cmd_context(target_stage: str = None) -> None:
    state = parse_memory()
    stage = (target_stage or state["stage"]).upper()
    if stage not in STAGE_SLICES:
        sys.exit(f"[ERROR] 未知阶段: {stage}，仅支持 PRODUCT / DEV / OPS")
    info = STAGE_SLICES[stage]
    print(f"=== [{stage}] 阶段防污染最小上下文切片 ===")
    print(f"阶段使命: {info['title']}")
    print("\n[1] 仅需读取 (Read Slice):")
    for r in info["read_slice"]:
        print(f"  - {r}")
    print("\n[2] 交付写入位置 (Write Target):")
    for w in info["write_target"]:
        print(f"  - {w}")
    print("\n[3] 隔离忽略项 (Noise Isolation):")
    for ig in info["ignore_noise"]:
        print(f"  - {ig}")


def cmd_handoff(to_stage: str, summary: str, next_task: str) -> dict:
    to_stage = to_stage.upper()
    if to_stage not in STAGES:
        sys.exit(f"[ERROR] 目标阶段非法: {to_stage}，仅支持 {STAGES}")

    project, version, _ = read_ssot_version()
    state = parse_memory()
    cur_stage = state["stage"]

    for req in STAGE_SLICES[cur_stage]["required_outputs"]:
        p = PROJECT_ROOT / req
        if not p.exists():
            sys.exit(f"[HANDOFF REJECTED] 当前阶段 ({cur_stage}) 缺少必要交付产物: {req}")

    if cur_stage == "OPS" and to_stage == "PRODUCT":
        state["cycle"] += 1

    state["project"] = project
    state["version"] = f"v{version}"
    state["stage"] = to_stage
    state["last_summary"] = summary.strip() or f"完成 {cur_stage} 阶段交付"
    state["next_handoff"] = next_task.strip() or f"执行 {to_stage} 阶段标准任务"

    write_memory(state)
    sync_version_json()
    print(
        f"[FLYWHEEL HANDOFF] {cur_stage} -> {to_stage} (Cycle #{state['cycle']}) 交接成功！\n"
        f"  👉 提示: 交接产物与 version.json 已刷新，请立即执行 'git commit' 提交变更，防止远端 CI 出现指纹漂移。"
    )
    return state


def cmd_init(new_name: str) -> None:
    clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", new_name.strip()).strip("_")
    if not clean_name:
        sys.exit("[ERROR] 非法项目名称")

    _, version, pkg_dir = read_ssot_version()
    for init_file in (pkg_dir / "__init__.py",):
        if init_file.exists():
            init_txt = init_file.read_text(encoding="utf-8")
            init_txt = re.sub(
                r'__project__\s*=\s*["\'][^"\']+["\']',
                f'__project__ = "{clean_name}"',
                init_txt,
            )
            init_file.write_text(init_txt, encoding="utf-8")

    state = parse_memory()
    state["project"] = clean_name
    state["version"] = f"v{version}"
    state["stage"] = "PRODUCT"
    state["cycle"] = 1
    state["last_summary"] = f"基于 Flywheel 脚手架完成 {clean_name} 初始化"
    state["next_handoff"] = (
        f"在 docs/PRD.md 与 docs/DESIGN.md 中定义 {clean_name} 首版产品与架构方案"
    )
    write_memory(state)
    sync_version_json()
    print(f"[OK] 已成功初始化项目: {clean_name} (v{version})")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Flywheel (飞轮) 项目状态、上下文切片与阶段交接工具"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="查看当前项目飞轮状态与交接单")

    p_ctx = sub.add_parser("context", help="查看当前或指定阶段的防污染最小上下文切片")
    p_ctx.add_argument("--stage", choices=STAGES, help="指定阶段 (PRODUCT / DEV / OPS)")

    p_ho = sub.add_parser("handoff", help="完成当前阶段并交接给下一阶段")
    p_ho.add_argument(
        "--to", required=True, choices=STAGES, help="下一棒目标阶段 (PRODUCT / DEV / OPS)"
    )
    p_ho.add_argument("--summary", required=True, help="本棒完成成果摘要")
    p_ho.add_argument(
        "--next", required=True, dest="next_task", help="留给下一棒的具体待办任务"
    )

    sub.add_parser(
        "sync-version", help="扫描全量受控交付物更新 version.json SHA-256 指纹"
    )

    sub.add_parser(
        "derive-version", help="从 SSoT 派生全仓库版本声明"
    )

    p_init = sub.add_parser("init", help="将脚手架初始化为新项目")
    p_init.add_argument("--name", required=True, help="新项目名称")

    args = parser.parse_args(argv)
    if args.cmd == "status":
        cmd_status()
    elif args.cmd == "context":
        cmd_context(args.stage)
    elif args.cmd == "handoff":
        cmd_handoff(args.to, args.summary, args.next_task)
    elif args.cmd == "sync-version":
        payload = sync_version_json()
        print(
            f"[OK] version.json 已同步: {payload['project']} v{payload['version']} ({len(payload['modules'])} 个文件)"
        )
    elif args.cmd == "derive-version":
        updated = derive_versions()
        _, ver, _ = read_ssot_version()
        print(f"[OK] 已从 SSoT ({ver}) 派生同步 {len(updated)} 个文件")
    elif args.cmd == "init":
        cmd_init(args.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
