from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_PROBE_TIMEOUT = 2.0
DEFAULT_RPC_PATHS = ["", "/rpc", "/api/rpc", "/jsonrpc", "/mcp", "/ws", "/gateway"]

METHOD_FAMILIES = [
    ("sessions.*", "会话读写与上下文恢复"),
    ("config.*", "配置读取、配置变更与模型/认证状态"),
    ("node.*", "节点枚举、节点连接与内部能力面"),
    ("browser.*", "浏览器控制、页面访问与 sidecar 通道"),
    ("agents.files.*", "agent 文件与 workspace 文件访问"),
    ("memory.*", "记忆检索、embedding 缓存与本地知识库"),
    ("tasks.*", "定时任务、任务运行状态与任务派发"),
    ("flows.*", "流程编排、运行记录与 owner/requester 绑定"),
]

METHOD_PROBES = {
    "sessions.*": [
        {"method": "sessions.list", "params": {}, "intent": "metadata-only"},
        {"method": "sessions.getCurrent", "params": {}, "intent": "metadata-only"},
        {"method": "sessions.status", "params": {}, "intent": "metadata-only"},
    ],
    "config.*": [
        {"method": "config.get", "params": {"key": "version"}, "intent": "metadata-only"},
        {"method": "config.list", "params": {}, "intent": "metadata-only"},
        {"method": "config.get", "params": {"key": "gateway.authMode"}, "intent": "metadata-only"},
    ],
    "node.*": [
        {"method": "node.list", "params": {}, "intent": "metadata-only"},
        {"method": "node.status", "params": {}, "intent": "metadata-only"},
        {"method": "node.capabilities", "params": {}, "intent": "metadata-only"},
    ],
    "browser.*": [
        {"method": "browser.status", "params": {}, "intent": "metadata-only"},
        {"method": "browser.snapshot", "params": {"dryRun": True}, "intent": "dry-run"},
        {"method": "browser.tabs", "params": {"limit": 1}, "intent": "metadata-only"},
    ],
    "agents.files.*": [
        {"method": "agents.files.stat", "params": {"path": "."}, "intent": "metadata-only"},
        {"method": "agents.files.list", "params": {"path": ".", "limit": 1}, "intent": "metadata-only"},
        {"method": "agents.files.resolve", "params": {"path": "."}, "intent": "metadata-only"},
    ],
    "memory.*": [
        {"method": "memory.status", "params": {}, "intent": "metadata-only"},
        {"method": "memory.search", "params": {"query": "clawmatrix-canary-nonsecret", "limit": 1}, "intent": "synthetic-query"},
        {"method": "memory.list", "params": {"limit": 1}, "intent": "metadata-only"},
    ],
    "tasks.*": [
        {"method": "tasks.list", "params": {"limit": 1}, "intent": "metadata-only"},
        {"method": "tasks.status", "params": {}, "intent": "metadata-only"},
        {"method": "tasks.describe", "params": {"limit": 1}, "intent": "metadata-only"},
    ],
    "flows.*": [
        {"method": "flows.list", "params": {"limit": 1}, "intent": "metadata-only"},
        {"method": "flows.status", "params": {}, "intent": "metadata-only"},
        {"method": "flows.describe", "params": {"limit": 1}, "intent": "metadata-only"},
    ],
}


def probe_http(url: str, version: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": f"ClawMatrix/{version}"})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return {
                "url": url,
                "reachable": True,
                "status": response.status,
                "headers": dict(response.headers.items()),
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"url": url, "reachable": False, "error": str(exc)}


def expand_probe_urls(urls: list[str], paths: list[str]) -> list[str]:
    expanded: list[str] = []
    for url in urls:
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        base_path = parsed.path or "/"
        candidates = [base_path]
        for path in paths:
            normalized = path if path.startswith("/") else f"/{path}" if path else base_path
            candidates.append(normalized or "/")
        for path in candidates:
            candidate = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path or "/", "", parsed.query, ""))
            if candidate not in expanded:
                expanded.append(candidate)
    return expanded


def scenario_headers(scenario: dict[str, Any], version: str) -> dict[str, str]:
    headers = {
        "User-Agent": f"ClawMatrix/{version}",
        "Origin": scenario.get("origin", "http://127.0.0.1"),
    }
    if scenario.get("host"):
        headers["Host"] = scenario["host"]
    if scenario.get("x_forwarded_for"):
        headers["X-Forwarded-For"] = scenario["x_forwarded_for"]
    return headers


def classify_status(status: int | None, body: str | None = None) -> str:
    if status is None:
        return "transport-error"
    if status in {401, 407}:
        return "auth-required"
    if status == 403:
        return "denied"
    if status == 404:
        return "not-found"
    if status in {400, 405, 415, 426}:
        return "protocol-mismatch"
    if 200 <= status < 300:
        if body:
            lowered = body.lower()
            if '"error"' in lowered or "unauthorized" in lowered or "forbidden" in lowered:
                return "application-error"
        return "accepted"
    return "unexpected"


def json_rpc_payload(method: str, params: Any) -> bytes:
    payload = {
        "jsonrpc": "2.0",
        "id": f"clawmatrix-{int(time.time() * 1000)}",
        "method": method,
        "params": params,
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def probe_http_method(url: str, scenario: dict[str, Any], method_probe: dict[str, Any], timeout: float, version: str) -> dict[str, Any]:
    headers = scenario_headers(scenario, version)
    headers["Content-Type"] = "application/json"
    body = json_rpc_payload(method_probe["method"], method_probe.get("params", {}))
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read(4096).decode("utf-8", errors="replace")
            status = response.status
            return {
                "transport": "http-jsonrpc",
                "url": url,
                "method_family": method_probe["family"],
                "probe_index": method_probe["probe_index"],
                "method": method_probe["method"],
                "intent": method_probe.get("intent"),
                "scenario": scenario["id"],
                "status_code": status,
                "classification": classify_status(status, text),
                "elapsed_ms": int((time.time() - started) * 1000),
                "body_sample": text[:400],
            }
    except urllib.error.HTTPError as exc:
        sample = exc.read(4096).decode("utf-8", errors="replace")
        return {
            "transport": "http-jsonrpc",
            "url": url,
            "method_family": method_probe["family"],
            "probe_index": method_probe["probe_index"],
            "method": method_probe["method"],
            "intent": method_probe.get("intent"),
            "scenario": scenario["id"],
            "status_code": exc.code,
            "classification": classify_status(exc.code, sample),
            "elapsed_ms": int((time.time() - started) * 1000),
            "body_sample": sample[:400],
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "transport": "http-jsonrpc",
            "url": url,
            "method_family": method_probe["family"],
            "probe_index": method_probe["probe_index"],
            "method": method_probe["method"],
            "intent": method_probe.get("intent"),
            "scenario": scenario["id"],
            "status_code": None,
            "classification": "transport-error",
            "elapsed_ms": int((time.time() - started) * 1000),
            "error": str(exc),
        }


def websocket_url_from_http(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urllib.parse.urlunparse((scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def encode_ws_frame(text: str) -> bytes:
    payload = text.encode("utf-8")
    key = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes([0x81, 0x80 | length])
    elif length < 65536:
        header = bytes([0x81, 0x80 | 126]) + length.to_bytes(2, "big")
    else:
        header = bytes([0x81, 0x80 | 127]) + length.to_bytes(8, "big")
    masked = bytes(byte ^ key[i % 4] for i, byte in enumerate(payload))
    return header + key + masked


def recv_ws_frame(sock: socket.socket) -> str:
    header = sock.recv(2)
    if len(header) < 2:
        return ""
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(sock.recv(2), "big")
    elif length == 127:
        length = int.from_bytes(sock.recv(8), "big")
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(min(4096, length - len(chunks)))
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks).decode("utf-8", errors="replace")


def probe_ws_method(url: str, scenario: dict[str, Any], method_probe: dict[str, Any], timeout: float, version: str) -> dict[str, Any]:
    ws_url = websocket_url_from_http(url)
    parsed = urllib.parse.urlparse(ws_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    started = time.time()
    sock: socket.socket | None = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if parsed.scheme == "wss" else raw
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        headers = scenario_headers(scenario, version)
        host_header = headers.get("Host") or parsed.netloc
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            f"Origin: {headers.get('Origin')}",
        ]
        if headers.get("X-Forwarded-For"):
            request_lines.append(f"X-Forwarded-For: {headers['X-Forwarded-For']}")
        request_lines.append("")
        request_lines.append("")
        sock.sendall("\r\n".join(request_lines).encode("ascii"))
        response = sock.recv(4096).decode("iso-8859-1", errors="replace")
        first_line = response.splitlines()[0] if response else ""
        match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d+)", first_line)
        status = int(match.group(1)) if match else None
        if status != 101:
            return {
                "transport": "websocket-jsonrpc",
                "url": ws_url,
                "method_family": method_probe["family"],
                "probe_index": method_probe["probe_index"],
                "method": method_probe["method"],
                "intent": method_probe.get("intent"),
                "scenario": scenario["id"],
                "handshake_status": status,
                "classification": classify_status(status),
                "elapsed_ms": int((time.time() - started) * 1000),
                "handshake_sample": response[:400],
            }
        payload = json.loads(json_rpc_payload(method_probe["method"], method_probe.get("params", {})).decode("utf-8"))
        sock.sendall(encode_ws_frame(json.dumps(payload, ensure_ascii=False)))
        frame = recv_ws_frame(sock)
        return {
            "transport": "websocket-jsonrpc",
            "url": ws_url,
            "method_family": method_probe["family"],
            "probe_index": method_probe["probe_index"],
            "method": method_probe["method"],
            "intent": method_probe.get("intent"),
            "scenario": scenario["id"],
            "handshake_status": status,
            "classification": "accepted" if frame and '"error"' not in frame.lower() else "application-error",
            "elapsed_ms": int((time.time() - started) * 1000),
            "body_sample": frame[:400],
        }
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return {
            "transport": "websocket-jsonrpc",
            "url": ws_url,
            "method_family": method_probe["family"],
            "probe_index": method_probe["probe_index"],
            "method": method_probe["method"],
            "intent": method_probe.get("intent"),
            "scenario": scenario["id"],
            "handshake_status": None,
            "classification": "transport-error",
            "elapsed_ms": int((time.time() - started) * 1000),
            "error": str(exc),
        }
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def summarize_probe_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_class: dict[str, int] = {}
    accepted: list[dict[str, Any]] = []
    for result in results:
        classification = result.get("classification", "unknown")
        by_class[classification] = by_class.get(classification, 0) + 1
        if classification == "accepted":
            accepted.append(
                {
                    "transport": result.get("transport"),
                    "url": result.get("url"),
                    "scenario": result.get("scenario"),
                    "method_family": result.get("method_family"),
                    "probe_index": result.get("probe_index"),
                    "method": result.get("method"),
                    "intent": result.get("intent"),
                }
            )
    return {"count": len(results), "by_classification": by_class, "accepted": accepted[:100]}


def build_difference_matrices(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_probe: dict[tuple[str, int, str], dict[str, set[str]]] = {}
    for result in results:
        key = (
            str(result.get("method_family", "unknown")),
            int(result.get("probe_index", 0)),
            str(result.get("method", "unknown")),
        )
        scenario = str(result.get("scenario", "unknown"))
        classification = str(result.get("classification", "unknown"))
        by_probe.setdefault(key, {}).setdefault(scenario, set()).add(classification)
    condition_differences = []
    inconsistent = []
    for (family, probe_index, method), scenarios in by_probe.items():
        normalized = {scenario: sorted(values) for scenario, values in scenarios.items()}
        distinct = {tuple(values) for values in normalized.values()}
        if len(distinct) > 1:
            condition_differences.append(
                {"method_family": family, "probe_index": probe_index, "method": method, "by_scenario": normalized}
            )
        for scenario, values in normalized.items():
            if len(values) > 1:
                inconsistent.append(
                    {"method_family": family, "probe_index": probe_index, "method": method, "scenario": scenario, "classifications": values}
                )
    return {
        "condition_differences": condition_differences,
        "inconsistent_same_condition": inconsistent,
    }


def expand_method_family_probes(family: str) -> list[dict[str, Any]]:
    probes = METHOD_PROBES.get(family)
    if probes:
        return [dict(item) for item in probes]
    return [{"method": family.replace("*", "status"), "params": {}, "intent": "metadata-only"}]


def risk_driven_family_notes(risk_context: dict[str, Any] | None) -> dict[str, list[str]]:
    notes: dict[str, list[str]] = {}
    if not risk_context:
        return notes

    capabilities = set(risk_context.get("observed_capabilities", [])) | set(risk_context.get("declared_capabilities", []))
    ai_bom = risk_context.get("ai_bom", {}) if isinstance(risk_context.get("ai_bom"), dict) else {}
    mcp_summary = risk_context.get("mcp_tool_schema_summary", {}) if isinstance(risk_context.get("mcp_tool_schema_summary"), dict) else {}

    if "file" in capabilities or ai_bom.get("env_and_config"):
        notes.setdefault("agents.files.*", []).append("第二层发现文件/配置能力，优先验证文件方法族授权边界。")
    if "browser" in capabilities or ai_bom.get("tool_surfaces"):
        notes.setdefault("browser.*", []).append("第二层发现浏览器或工具面能力，优先验证 browser 方法族。")
    if "schedule" in capabilities or "process" in capabilities or mcp_summary.get("dangerous_commands"):
        notes.setdefault("tasks.*", []).append("第二层发现进程/任务/MCP 命令信号，优先验证任务调度方法族。")
    if ai_bom.get("external_services") or "network" in capabilities:
        notes.setdefault("node.*", []).append("第二层发现外部服务或网络能力，优先验证节点/连接方法族。")
    if risk_context.get("toxic_flows_count", 0) or risk_context.get("hidden_instruction_signals", 0):
        notes.setdefault("sessions.*", []).append("第二层发现组合风险或隐藏指令，优先验证会话上下文是否隔离。")
        notes.setdefault("memory.*", []).append("第二层发现组合风险或隐藏指令，优先验证记忆检索边界。")
    if risk_context.get("policy_blocked") or risk_context.get("claims_mismatches", 0):
        notes.setdefault("config.*", []).append("第二层策略/声明证据提示需复核配置方法族授权。")
    return notes


def layer3_trust_boundary(
    gateway_url: str | None,
    browser_url: str | None,
    dynamic_mode: str = "plan",
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    method_probe_limit: int = 0,
    rpc_paths: list[str] | None = None,
    *,
    version: str,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scenarios = [
        {"id": "loopback", "host": "127.0.0.1", "origin": "http://127.0.0.1", "expected": "local-only"},
        {"id": "localhost", "host": "localhost", "origin": "http://localhost", "expected": "local-only"},
        {"id": "nip-io-loopback", "host": "127.0.0.1.nip.io", "origin": "http://127.0.0.1.nip.io", "expected": "must-not-inherit-local-blindly"},
        {"id": "forwarded-loopback", "host": "external", "x_forwarded_for": "127.0.0.1", "expected": "must-require-trusted-proxy"},
    ]

    risk_notes = risk_driven_family_notes(risk_context)
    matrix = []
    for family, meaning in METHOD_FAMILIES:
        for probe_index, probe in enumerate(expand_method_family_probes(family)):
            for scenario in scenarios:
                matrix.append(
                    {
                        "method_family": family,
                        "probe_index": probe_index,
                        "probe_method": probe["method"],
                        "probe_params": probe.get("params", {}),
                        "probe_intent": probe.get("intent"),
                        "meaning": meaning,
                        "scenario": scenario["id"],
                        "expected_policy": "拒绝或要求显式会话令牌",
                        "status": "待验证" if dynamic_mode == "plan" else "待探测",
                        "safe_next_step": "使用授权的 WebSocket/API 测试框架比较允许/拒绝结果，不执行高影响操作。",
                        "risk_driven": family in risk_notes,
                        "risk_notes": risk_notes.get(family, []),
                    }
                )

    probes = []
    if gateway_url:
        probes.append(probe_http(gateway_url, version))
    if browser_url:
        probes.append(probe_http(browser_url, version))

    method_probe_results: list[dict[str, Any]] = []
    targets = expand_probe_urls([url for url in [gateway_url, browser_url] if url], rpc_paths or DEFAULT_RPC_PATHS)
    planned = matrix[: method_probe_limit or None]
    if dynamic_mode == "probe" and targets:
        for row in planned:
            scenario = next(item for item in scenarios if item["id"] == row["scenario"])
            method_probe = {
                "family": row["method_family"],
                "probe_index": row["probe_index"],
                "method": row["probe_method"],
                "params": row.get("probe_params", {}),
                "intent": row["probe_intent"],
            }
            for target in targets:
                method_probe_results.append(probe_http_method(target, scenario, method_probe, probe_timeout, version))
                method_probe_results.append(probe_ws_method(target, scenario, method_probe, probe_timeout, version))
        summary = summarize_probe_results(method_probe_results)
        differences = build_difference_matrices(method_probe_results)
        for row in matrix:
            matching = [
                result
                for result in method_probe_results
                if result.get("scenario") == row["scenario"]
                and result.get("method_family") == row["method_family"]
                and result.get("probe_index") == row["probe_index"]
                and result.get("method") == row["probe_method"]
            ]
            row["status"] = ",".join(sorted({str(item.get("classification", "unknown")) for item in matching})) or "未探测"
    else:
        summary = {"count": 0, "by_classification": {}, "accepted": []}
        differences = {"condition_differences": [], "inconsistent_same_condition": []}

    skipped_reason = None
    if dynamic_mode == "plan":
        skipped_reason = "dynamic-mode-plan"
    elif dynamic_mode == "probe" and not targets:
        skipped_reason = "no-probe-targets"

    findings = [
        {
            "id": "L3-AUTHZ-MATRIX-NEEDED",
            "severity": "info" if dynamic_mode == "plan" else ("high" if summary["accepted"] else "info"),
            "title": "需要进行方法级授权差异验证" if dynamic_mode == "plan" else "已完成方法级授权安全探测",
            "evidence": {
                "method_families": [method for method, _ in METHOD_FAMILIES],
                "scenarios": [scenario["id"] for scenario in scenarios],
                "dynamic_mode": dynamic_mode,
                "risk_driven_families": sorted(risk_notes),
                "probe_summary": summary,
                "differences": differences,
            },
        }
    ]
    if risk_notes:
        findings.append(
            {
                "id": "L3-RISK-DRIVEN-MATRIX",
                "severity": "info",
                "title": "已根据第二层 Agent/Skill 风险增强授权矩阵优先级",
                "evidence": risk_notes,
            }
        )
    if dynamic_mode == "probe" and summary["accepted"]:
        findings.append(
            {
                "id": "L3-METHOD-PROBE-ACCEPTED",
                "severity": "high",
                "title": "存在敏感方法族在探测条件下返回 accepted，需人工复核授权语义",
                "evidence": summary["accepted"],
            }
        )
    if dynamic_mode == "probe" and differences["condition_differences"]:
        findings.append(
            {
                "id": "L3-CONDITION-DIFFERENCE",
                "severity": "medium",
                "title": "同一方法在不同 Host/Origin/Proxy 条件下返回不同授权结果",
                "evidence": differences["condition_differences"][:20],
            }
        )
    if dynamic_mode == "probe" and differences["inconsistent_same_condition"]:
        findings.append(
            {
                "id": "L3-SAME-CONDITION-INCONSISTENCY",
                "severity": "medium",
                "title": "同一配置条件下不同传输或端点返回不一致结果",
                "evidence": differences["inconsistent_same_condition"][:20],
            }
        )

    return {
        "name": "Layer 3 - trust boundary and method authorization",
        "dynamic_mode": dynamic_mode,
        "http_probes": probes,
        "scenarios": scenarios,
        "authorization_matrix": matrix,
        "method_probe_results": method_probe_results,
        "method_probe_summary": summary,
        "difference_matrices": differences,
        "risk_driven_matrix": {
            "enabled": bool(risk_notes),
            "families": sorted(risk_notes),
            "notes": risk_notes,
            "source": "layer2-agent-skill-guard",
        },
        "coverage": {
            "matrix_rows_total": len(matrix),
            "matrix_rows_planned": len(planned) if dynamic_mode == "probe" else len(matrix),
            "probe_targets": targets,
            "probe_results": len(method_probe_results),
            "families": len(METHOD_FAMILIES),
            "risk_driven_families": len(risk_notes),
            "probes_per_family": {family: len(expand_method_family_probes(family)) for family, _ in METHOD_FAMILIES},
        },
        "skipped_reason": skipped_reason,
        "findings": findings,
    }
