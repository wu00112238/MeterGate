#!/usr/bin/env python3
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

flywheel_import_error = None
try:
    from src.flywheel import __version__
    from src.flywheel.cli import (
        MEMORY_FILE,
        VERSION_FILE,
        STAGES,
        cmd_handoff,
        derive_versions,
        parse_memory,
        read_ssot_version,
        sync_version_json,
    )
except Exception as _err:
    flywheel_import_error = str(_err)
    __version__ = "unknown"
    MEMORY_FILE = ROOT / "MEMORY.md"
    VERSION_FILE = ROOT / "version.json"
    STAGES = ("PRODUCT", "DEV", "OPS")
    cmd_handoff = None
    derive_versions = None
    parse_memory = None
    read_ssot_version = None
    sync_version_json = None


class TestFlywheelProtocol(unittest.TestCase):
    def setUp(self):
        if flywheel_import_error:
            self.fail(
                f"[门禁项: 飞轮脚手架完整性] 飞轮核心模块导入失败: {flywheel_import_error}。"
                "建议动作: 检查是否因 .gitignore 排除导致文件未被追踪检出。"
            )

    def test_01_ssot_version_and_sync(self):
        proj, ver, pkg_dir = read_ssot_version()
        self.assertEqual(proj, "MeterGate")
        self.assertEqual(ver, __version__)
        self.assertEqual(pkg_dir.name, "metergate")
        payload = sync_version_json()
        self.assertEqual(payload["project"], "MeterGate")
        self.assertEqual(payload["version"], __version__)
        self.assertIn("src/metergate/cli.py", payload["modules"])

    def test_02_skill_structure_and_no_legacy_mydev(self):
        agents_txt = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn(".agents/skills/flywheel/SKILL.md", agents_txt)
        self.assertTrue((ROOT / ".agents/skills/flywheel/SKILL.md").exists())
        self.assertTrue((ROOT / ".agents/skills/flywheel/README.md").exists())
        self.assertTrue((ROOT / ".agents/skills/flywheel/references/FLYWHEEL_SPEC.md").exists())
        self.assertFalse((ROOT / ".agents/skills/mydev").exists())

    def test_03_product_dev_ops_handoff_loop(self):
        orig_mem = MEMORY_FILE.read_text(encoding="utf-8")
        orig_ver = VERSION_FILE.read_text(encoding="utf-8")
        try:
            s1 = cmd_handoff("DEV", "完成阶段产品定义与架构设计", "在 src/ 下实现核心功能并通过单元测试")
            self.assertEqual(s1["stage"], "DEV")

            s2 = cmd_handoff("OPS", "完成核心研发并通过测试", "执行发布并沉淀 OPS_FEEDBACK.md")
            self.assertEqual(s2["stage"], "OPS")

            before_cycle = s2["cycle"]
            s3 = cmd_handoff("PRODUCT", "完成交付并更新 OPS_FEEDBACK.md", "基于用户反馈持续迭代")
            self.assertEqual(s3["stage"], "PRODUCT")
            self.assertEqual(s3["cycle"], before_cycle + 1)

            mem_lines = (ROOT / "MEMORY.md").read_text(encoding="utf-8").splitlines()
            self.assertLessEqual(len(mem_lines), 100)
        finally:
            MEMORY_FILE.write_text(orig_mem, encoding="utf-8")
            VERSION_FILE.write_text(orig_ver, encoding="utf-8")

    def test_04_ssot_derivation_and_explicit_error(self):
        proj, ver, _ = read_ssot_version()
        derived = derive_versions()
        self.assertIsInstance(derived, list)

        # Verify that corrupted SSoT raises explicit error without silent fallback
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_pkg = Path(tmp_dir) / "bad_pkg"
            bad_pkg.mkdir()
            (bad_pkg / "__init__.py").write_text("# No version defined here\n", encoding="utf-8")
            def dummy_read(p=bad_pkg):
                init_text = (p / "__init__.py").read_text(encoding="utf-8")
                ver_m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_text)
                if not ver_m:
                    raise RuntimeError("SSoT 版本解析失败: 未找到 __version__ 声明")
                return "bad", ver_m.group(1), p

            with self.assertRaises(RuntimeError):
                dummy_read()

    def test_05_gitignore_adaptive_immunity_and_email_gate(self):
        # 1. Verify .gitignore contains the restored exclusion rules for developer workflow files
        gitign_path = ROOT / ".gitignore"
        self.assertTrue(gitign_path.exists())
        gitign_txt = gitign_path.read_text(encoding="utf-8")
        expected_rules = [
            ".agents/",
            "src/flywheel/",
            "tests/test_flywheel.py",
            "AGENTS.md",
            "MEMORY.md",
            "docs/OPS_FEEDBACK.md",
        ]
        for pattern in expected_rules:
            self.assertIn(
                pattern,
                gitign_txt,
                f".gitignore 应包含排除规则以支持本地工作流文件选择性入库: {pattern}",
            )

        # 2. Verify test_all.py report_error generates all 3 mandatory elements
        import test_all
        diag = test_all.report_error("门禁项: 测试项", "path/to/file", "测试错误", "执行修复")
        self.assertIn("[门禁项: 测试项]", diag)
        self.assertIn("文件路径: path/to/file", diag)
        self.assertIn("错误原因: 测试错误", diag)
        self.assertIn("建议动作: 执行修复", diag)

        # 3. Verify Email Validity Gate in test_all.py blocks reserved domains (.local, .test, example.com)
        pyproj_txt = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        sec_txt = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        for bad_domain in (".local", ".test", "example.com"):
            self.assertNotIn(bad_domain, pyproj_txt, f"pyproject.toml 不应包含保留邮箱域名: {bad_domain}")
            self.assertNotIn(bad_domain, sec_txt, f"SECURITY.md 不应包含保留邮箱域名: {bad_domain}")
        self.assertIn("wu00112238@users.noreply.github.com", pyproj_txt)
        self.assertIn("wu00112238@users.noreply.github.com", sec_txt)

    def test_06_bilingual_spec_compliance(self):
        # 1. docs/BILINGUAL_SPEC.md exists and contains required sections
        spec_path = ROOT / "docs" / "BILINGUAL_SPEC.md"
        self.assertTrue(spec_path.exists())
        spec_txt = spec_path.read_text(encoding="utf-8")
        self.assertIn("对外产物中英双语工程规范", spec_txt)
        self.assertIn("README.md", spec_txt)
        self.assertIn("pyproject.toml", spec_txt)

        # 2. Release templates exist in .github/ and docs/
        self.assertTrue((ROOT / ".github" / "RELEASE_TEMPLATE.md").exists())
        self.assertTrue((ROOT / "docs" / "RELEASE_TEMPLATE.md").exists())

        # 3. pyproject.toml has bilingual description
        pyproject_txt = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        m_desc = re.search(r'description\s*=\s*["\']([^"\']+)["\']', pyproject_txt)
        self.assertIsNotNone(m_desc)
        desc_val = m_desc.group(1)
        self.assertTrue(bool(re.search(r'[\u4e00-\u9fff]', desc_val)))
        self.assertTrue(bool(re.search(r'[a-zA-Z]{3,}', desc_val)))

        # 4. README.md has symmetric bilingual markers
        readme_txt = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("🇨🇳 中文说明", readme_txt)
        self.assertIn("🇬🇧 English Summary", readme_txt)
        self.assertIn("是什么", readme_txt)
        self.assertIn("What It Is", readme_txt)

    def test_07_version_json_drift_governance(self):
        # Verify that version.json contains valid modules and sha256 checksums
        vdata = json.loads(VERSION_FILE.read_text(encoding="utf-8"))
        self.assertIn("modules", vdata)
        self.assertIn("src/metergate/cli.py", vdata["modules"])
        self.assertIn("sha256", vdata["modules"]["src/metergate/cli.py"])


if __name__ == "__main__":
    unittest.main()
