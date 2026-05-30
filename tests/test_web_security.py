from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = PROJECT_ROOT / "tools"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import clawmatrix_web


class WebSecurityTests(unittest.TestCase):
    def test_report_resolver_rejects_traversal(self) -> None:
        self.assertIsNone(clawmatrix_web.resolve_report_artifact("../outside.html"))
        self.assertIsNone(clawmatrix_web.resolve_report_artifact("subdir/report.html"))

    def test_report_family_paths_use_reports_directory(self) -> None:
        artifacts = clawmatrix_web.report_family_paths("clawmatrix_web_20260514-193049.html")
        self.assertEqual(len(artifacts), 3)
        for artifact in artifacts:
            artifact.relative_to(clawmatrix_web.REPORTS.resolve())


if __name__ == "__main__":
    unittest.main()
