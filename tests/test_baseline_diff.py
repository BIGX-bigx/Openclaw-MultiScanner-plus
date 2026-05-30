from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = PROJECT_ROOT / "tools"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from clawmatrix.report_diff import build_baseline_diff


class BaselineDiffTests(unittest.TestCase):
    def test_reports_new_and_resolved_findings(self) -> None:
        baseline = {
            "generated_at": "2026-01-01T00:00:00Z",
            "summary": {"finding_count": 1},
            "layers": [{"findings": [{"id": "OLD", "severity": "low", "title": "old"}]}],
        }
        current = {
            "summary": {"finding_count": 1},
            "layers": [{"findings": [{"id": "NEW", "severity": "high", "title": "new"}]}],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_path = Path(temp_dir) / "baseline.json"
            baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
            diff = build_baseline_diff(current, baseline_path)
        self.assertIsNotNone(diff)
        assert diff is not None
        self.assertTrue(diff["loaded"])
        self.assertEqual(diff["finding_count_delta"], 0)
        self.assertEqual(diff["highest_new_severity"], "high")
        self.assertEqual(diff["new_findings"][0]["id"], "NEW")
        self.assertEqual(diff["resolved_findings"][0]["id"], "OLD")


if __name__ == "__main__":
    unittest.main()
