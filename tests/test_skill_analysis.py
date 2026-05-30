from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = PROJECT_ROOT / "tools"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import clawmatrix_scan
from clawmatrix.skill_analysis import parse_skill_frontmatter


class SkillAnalysisTests(unittest.TestCase):
    def test_frontmatter_uses_yaml_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            skill_md = Path(temp_dir) / "SKILL.md"
            skill_md.write_text(
                "---\ncapabilities:\n  - file\n  - network\nmetadata:\n  openclaw:\n    permissions:\n      - process\n---\nbody\n",
                encoding="utf-8",
            )
            frontmatter = parse_skill_frontmatter(skill_md, clawmatrix_scan.safe_read_text)
        self.assertTrue(frontmatter["present"])
        self.assertEqual(frontmatter["fields"]["capabilities"], ["file", "network"])
        self.assertEqual(frontmatter["fields"]["metadata"]["openclaw"]["permissions"], ["process"])

    def test_scan_skill_dir_detects_structured_python_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill_md = root / "SKILL.md"
            skill_md.write_text("---\ncapabilities:\n  - file\n---\nbody\n", encoding="utf-8")
            (root / "impl.py").write_text(
                "import subprocess\nimport requests\nfrom pathlib import Path\n\n"
                "def run():\n"
                "    Path('x').write_text('y')\n"
                "    requests.get('https://example.invalid')\n"
                "    subprocess.run(['echo', 'ok'])\n",
                encoding="utf-8",
            )
            report = clawmatrix_scan.run_skill_scan(
                skill_md,
                find_files=clawmatrix_scan.find_files,
                safe_read_text=clawmatrix_scan.safe_read_text,
                scan_secrets=clawmatrix_scan.scan_secrets,
                relative=clawmatrix_scan.relative,
                max_skill_files=100,
                max_text_bytes=500000,
            )
        self.assertIn("file", report["declared_capabilities"])
        self.assertIn("network", report["observed_capabilities"])
        self.assertIn("process", report["observed_capabilities"])
        self.assertIn("network", report["capability_mismatch"])
        self.assertIn("coverage", report)


if __name__ == "__main__":
    unittest.main()
