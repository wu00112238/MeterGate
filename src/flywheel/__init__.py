"""Flywheel Project Governance Package (SSoT derived)."""
import re
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent


def find_primary_pkg() -> Path:
    candidates = [
        p
        for p in sorted(_SRC_DIR.iterdir())
        if p.is_dir()
        and not p.name.startswith(("_", "."))
        and p.name != "flywheel"
        and (p / "__init__.py").exists()
    ]
    if candidates:
        return candidates[0]
    if (_SRC_DIR / "flywheel" / "__init__.py").exists():
        return _SRC_DIR / "flywheel"
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


__project__, __version__, _ = read_ssot_version()
__all__ = ["__project__", "__version__", "read_ssot_version", "find_primary_pkg"]
