from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = PROJECT_ROOT / "tools"

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import clawmatrix_scan


class ReportSchemaTests(unittest.TestCase):
    def test_report_matches_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir) / ".openclaw"
            home.mkdir()
            args = argparse.Namespace(
                openclaw_home=str(home),
                skill_root=None,
                gateway_url=None,
                browser_url=None,
                skill_guard_engine="off",
                dynamic_mode="plan",
                probe_timeout=2.0,
                rpc_paths="",
                method_probe_limit=0,
                canary_mode="plan",
                canary_dir=None,
                canary_url=None,
                baseline_report=None,
                include_clean_sections=False,
                format="json",
                out=None,
            )
            report = clawmatrix_scan.build_report(args)
        schema = json.loads((PROJECT_ROOT / "schemas" / "clawmatrix-report.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(report, schema)


if __name__ == "__main__":
    unittest.main()
