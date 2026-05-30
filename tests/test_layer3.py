from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = PROJECT_ROOT / "tools"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from clawmatrix.layer3 import METHOD_FAMILIES, METHOD_PROBES, layer3_trust_boundary


class Layer3Tests(unittest.TestCase):
    def test_plan_mode_expands_all_family_probes(self) -> None:
        report = layer3_trust_boundary(
            gateway_url=None,
            browser_url=None,
            dynamic_mode="plan",
            method_probe_limit=0,
            rpc_paths=[],
            version="test",
        )
        expected_rows = sum(len(METHOD_PROBES[family]) * 4 for family, _ in METHOD_FAMILIES)
        self.assertEqual(len(report["authorization_matrix"]), expected_rows)
        self.assertEqual(report["coverage"]["matrix_rows_total"], expected_rows)
        self.assertEqual(report["skipped_reason"], "dynamic-mode-plan")
        first = report["authorization_matrix"][0]
        self.assertIn("probe_index", first)
        self.assertIn("probe_method", first)


if __name__ == "__main__":
    unittest.main()
