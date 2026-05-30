from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_report(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def collect_findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    collected: dict[str, dict[str, Any]] = {}
    for layer in report.get("layers", []):
        if not isinstance(layer, dict):
            continue
        for finding in layer.get("findings", []):
            if isinstance(finding, dict) and isinstance(finding.get("id"), str):
                collected[finding["id"]] = finding
    return collected


def higher_severity(left: str, right: str) -> str:
    return left if SEVERITY_ORDER.get(left, -1) >= SEVERITY_ORDER.get(right, -1) else right


def build_baseline_diff(report: dict[str, Any], baseline_path: Path | None) -> dict[str, Any] | None:
    if not baseline_path:
        return None
    baseline = load_report(baseline_path)
    if not baseline:
        return {"baseline_path": str(baseline_path), "loaded": False, "error": "failed-to-load-baseline-report"}

    current_findings = collect_findings(report)
    baseline_findings = collect_findings(baseline)

    new_ids = sorted(set(current_findings) - set(baseline_findings))
    resolved_ids = sorted(set(baseline_findings) - set(current_findings))
    persisted_ids = sorted(set(current_findings) & set(baseline_findings))

    highest_new = "info"
    for finding_id in new_ids:
        highest_new = higher_severity(highest_new, str(current_findings[finding_id].get("severity", "info")))

    layer_deltas: list[dict[str, Any]] = []
    current_layers = report.get("layers", [])
    baseline_layers = baseline.get("layers", [])
    for index, layer in enumerate(current_layers):
        if not isinstance(layer, dict):
            continue
        previous = baseline_layers[index] if index < len(baseline_layers) and isinstance(baseline_layers[index], dict) else {}
        current_count = len(layer.get("findings", []))
        previous_count = len(previous.get("findings", []))
        layer_deltas.append(
            {
                "name": layer.get("name", f"layer-{index + 1}"),
                "current_findings": current_count,
                "baseline_findings": previous_count,
                "delta": current_count - previous_count,
            }
        )

    return {
        "baseline_path": str(baseline_path),
        "loaded": True,
        "baseline_generated_at": baseline.get("generated_at"),
        "finding_count_delta": report.get("summary", {}).get("finding_count", 0) - baseline.get("summary", {}).get("finding_count", 0),
        "new_findings": [current_findings[finding_id] for finding_id in new_ids[:50]],
        "resolved_findings": [baseline_findings[finding_id] for finding_id in resolved_ids[:50]],
        "persisted_finding_ids": persisted_ids[:100],
        "highest_new_severity": highest_new,
        "layer_deltas": layer_deltas,
    }
