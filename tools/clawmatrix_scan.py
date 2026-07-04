#!/usr/bin/env python3
"""
ClawMatrix: a safe four-layer OpenClaw trust-boundary scanner.

This module intentionally avoids exploit payloads. It gathers local evidence,
builds a method-authorization test matrix, and emits a report that can guide
manual verification in an authorized lab.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import html
import json
import math
import os
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from clawmatrix.layer3 import DEFAULT_PROBE_TIMEOUT as MODULE_DEFAULT_PROBE_TIMEOUT
from clawmatrix.layer3 import DEFAULT_RPC_PATHS as MODULE_DEFAULT_RPC_PATHS
from clawmatrix.layer3 import METHOD_FAMILIES as MODULE_METHOD_FAMILIES
from clawmatrix.layer3 import layer3_trust_boundary as run_layer3_trust_boundary
from clawmatrix.report_diff import build_baseline_diff
from clawmatrix.skill_analysis import scan_skill_dir as run_skill_scan


VERSION = "2.0"
SQLITE_HEADER = b"SQLite format 3\x00"
MAX_TEXT_BYTES = 2_000_000
MAX_SKILL_FILES = 800
PROJECT_ROOT = Path(__file__).resolve().parents[1]
AGENT_GUARD_ENGINE_DIR = PROJECT_ROOT / "engines" / "agent-skill-guard"
AGENT_GUARD_CONFIG = AGENT_GUARD_ENGINE_DIR / ".openclaw-guard.yml"
DEFAULT_PROBE_TIMEOUT = 2.0
DEFAULT_RPC_PATHS = ["", "/rpc", "/api/rpc", "/jsonrpc", "/mcp", "/ws", "/gateway"]


SECRET_PATTERNS = [
    ("api_key", re.compile(r'(?i)\b(api[_-]?key|apikey)\b["\']?\s*[:=]\s*["\']?([^"\'\s,}]{8,})')),
    ("bearer", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{12,})")),
    ("sk_key", re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")),
    ("token", re.compile(r'(?i)\b(token|access_token|refresh_token)\b["\']?\s*[:=]\s*["\']?([^"\'\s,}]{8,})')),
]

CAPABILITY_PATTERNS = {
    "file": re.compile(r"(?i)(\bopen\(|readFile|writeFile|fs\.|pathlib|\.openclaw|sqlite|\.sqlite|workspace|home/)"),
    "network": re.compile(r"(?i)(fetch\(|http://|https://|requests\.|curl\s|wget\s|socket|websocket|axios)"),
    "process": re.compile(r"(?i)(subprocess|child_process|exec\(|spawn\(|powershell|cmd\.exe|/bin/sh|bash\s)"),
    "browser": re.compile(r"(?i)(browser|playwright|puppeteer|selenium|chrome|chromium)"),
    "schedule": re.compile(r"(?i)(cron|schedule|timer|interval|task|定时|计划任务)"),
    "prompt_injection": re.compile(
        r"(?i)(ignore previous|system prompt|developer message|exfiltrat|leak|secret|token|绕过|忽略.*指令|提示词注入)"
    ),
}

SKILL_RISK_PATTERNS = {
    "remote_install": re.compile(r"(?i)(curl\s+[^|\n]+\|\s*(sh|bash|python)|wget\s+[^|\n]+\|\s*(sh|bash|python)|irm\s+[^|\n]+\|\s*iex)"),
    "staged_delivery": re.compile(r"(?i)(download.*execute|fetch.*eval|remote.*script|staged|second[- ]stage|二阶段|分阶段)"),
    "exfiltration": re.compile(r"(?i)(webhook\.site|requestbin|pastebin|discord(app)?\.com/api/webhooks|telegram.*sendMessage|exfiltrat|外送|回传)"),
    "obfuscation": re.compile(r"(?i)(base64\s+-d|fromCharCode|atob\(|btoa\(|eval\(.*decode|\\x[0-9a-f]{2})"),
    "persistence": re.compile(r"(?i)(crontab|schtasks|launchctl|systemd|startup|run key|开机启动|计划任务)"),
    "credential_access": re.compile(r"(?i)(process\.env|os\.environ|\.env|credential|secret|token|api[_-]?key|ssh/id_rsa)"),
}

DEPENDENCY_FILES = {"package.json", "requirements.txt", "pyproject.toml", "Cargo.toml", "go.mod"}

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
    ],
    "config.*": [
        {"method": "config.get", "params": {"key": "version"}, "intent": "metadata-only"},
        {"method": "config.list", "params": {}, "intent": "metadata-only"},
    ],
    "node.*": [
        {"method": "node.list", "params": {}, "intent": "metadata-only"},
        {"method": "node.status", "params": {}, "intent": "metadata-only"},
    ],
    "browser.*": [
        {"method": "browser.status", "params": {}, "intent": "metadata-only"},
        {"method": "browser.snapshot", "params": {"dryRun": True}, "intent": "dry-run"},
    ],
    "agents.files.*": [
        {"method": "agents.files.stat", "params": {"path": "."}, "intent": "metadata-only"},
        {"method": "agents.files.list", "params": {"path": ".", "limit": 1}, "intent": "metadata-only"},
    ],
    "memory.*": [
        {"method": "memory.status", "params": {}, "intent": "metadata-only"},
        {"method": "memory.search", "params": {"query": "clawmatrix-canary-nonsecret", "limit": 1}, "intent": "synthetic-query"},
    ],
    "tasks.*": [
        {"method": "tasks.list", "params": {"limit": 1}, "intent": "metadata-only"},
        {"method": "tasks.status", "params": {}, "intent": "metadata-only"},
    ],
    "flows.*": [
        {"method": "flows.list", "params": {"limit": 1}, "intent": "metadata-only"},
        {"method": "flows.status", "params": {}, "intent": "metadata-only"},
    ],
}

SEVERITY_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

LAYER_LABELS = [
    "第一层：安装态与状态面审计",
    "第二层：Skill / Agent 生态与供应链审计",
    "第三层：连接后信任边界与方法授权验证",
    "第四层：Canary 影响面验证",
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def safe_read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_json_file(path: Path) -> dict[str, Any] | None:
    text = safe_read_text(path)
    if not text:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def redact(value: str) -> str:
    if len(value) <= 10:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def redact_sensitive(value: Any, key_hint: str = "") -> Any:
    lowered = key_hint.lower()
    if isinstance(value, dict):
        return {key: redact_sensitive(item, key) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item, key_hint) for item in value]
    if isinstance(value, str) and any(word in lowered for word in ["token", "secret", "key", "password", "credential"]):
        return redact(value)
    return value


def relative(path: Path, base: Path | None) -> str:
    if base:
        try:
            return str(path.resolve().relative_to(base.resolve()))
        except (OSError, ValueError):
            pass
    return str(path)


def path_mode(path: Path) -> str:
    try:
        return stat.filemode(path.stat().st_mode)
    except OSError:
        return "unknown"


def is_group_or_world_readable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
        return bool(mode & (stat.S_IRGRP | stat.S_IROTH))
    except OSError:
        return False


def nested_get(data: dict[str, Any], dotted: str, default: Any = None) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def parse_boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "on", "enabled", "1"}:
            return True
        if lowered in {"false", "no", "off", "disabled", "0"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def find_files(root: Path, names: set[str] | None = None, suffix: str | None = None, max_files: int = 5000) -> list[Path]:
    results: list[Path] = []
    if not root.exists():
        return results
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "target", ".venv", "__pycache__"}]
        for filename in filenames:
            if names and filename not in names:
                continue
            if suffix and not filename.endswith(suffix):
                continue
            results.append(Path(dirpath) / filename)
            if len(results) >= max_files:
                return results
    return results


def scan_secrets(path: Path) -> list[dict[str, Any]]:
    text = safe_read_text(path)
    findings: list[dict[str, Any]] = []
    if not text:
        return findings
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(match.lastindex or 0)
            findings.append({"type": label, "sample": redact(raw), "offset": match.start()})
    return findings[:20]


def inspect_sqlite(path: Path) -> dict[str, Any]:
    value_map = {
        "registry.sqlite": "flows, requester origin, owner key, controller metadata",
        "runs.sqlite": "task runs, child sessions, agent run chain, delivery state",
        "main.sqlite": "memory chunks, file paths, embeddings, full-text index",
    }
    info: dict[str, Any] = {
        "path": str(path),
        "size": path.stat().st_size if path.exists() else None,
        "mode": path_mode(path),
        "sha256": sha256_file(path),
        "sqlite_header": False,
        "tables": [],
        "risk": "info",
        "data_value": value_map.get(path.name, "unknown"),
        "notes": [],
    }
    try:
        with path.open("rb") as f:
            info["sqlite_header"] = f.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError as exc:
        info["notes"].append(f"read_header_failed: {exc}")
        return info

    if is_group_or_world_readable(path):
        info["risk"] = "high"
        info["notes"].append("数据库文件对同组或其他用户可读")
    elif path.name in {"registry.sqlite", "runs.sqlite", "main.sqlite"}:
        info["risk"] = "medium"
        info["notes"].append("已知 OpenClaw 状态数据库未发现应用层加密")

    try:
        uri = f"file:{path.as_posix()}?mode=ro"
        con = sqlite3.connect(uri, uri=True)
        cur = con.cursor()
        cur.execute("select name from sqlite_master where type='table' order by name")
        tables = [row[0] for row in cur.fetchall()]
        for table in tables:
            item: dict[str, Any] = {"name": table, "columns": [], "row_count": None}
            try:
                cur.execute(f'pragma table_info("{table}")')
                item["columns"] = [row[1] for row in cur.fetchall()]
            except sqlite3.Error as exc:
                item["columns_error"] = str(exc)
            try:
                cur.execute(f'select count(*) from "{table}"')
                item["row_count"] = cur.fetchone()[0]
            except sqlite3.Error as exc:
                item["row_count_error"] = str(exc)
            info["tables"].append(item)
        con.close()
    except sqlite3.Error as exc:
        info["notes"].append(f"sqlite_open_failed: {exc}")
    return info


def analyze_openclaw_config(config_path: Path, openclaw_home: Path) -> dict[str, Any]:
    config = load_json_file(config_path)
    result: dict[str, Any] = {
        "path": str(config_path),
        "relative_path": relative(config_path, openclaw_home),
        "parsed": config is not None,
        "version": None,
        "signals": {},
        "findings": [],
    }
    if config is None:
        result["findings"].append(
            {
                "id": "L1-CONFIG-UNPARSEABLE",
                "severity": "low",
                "title": "openclaw.json 无法按 JSON 解析",
                "evidence": {"path": result["relative_path"]},
            }
        )
        return result

    gateway = config.get("gateway", {}) if isinstance(config.get("gateway"), dict) else {}
    security = config.get("security", {}) if isinstance(config.get("security"), dict) else {}
    resources = config.get("resources", {}) if isinstance(config.get("resources"), dict) else {}
    logging_cfg = config.get("logging", {}) if isinstance(config.get("logging"), dict) else {}

    version = config.get("version") or config.get("openclawVersion") or nested_get(config, "app.version")
    bind = gateway.get("bind") or gateway.get("host") or gateway.get("listen")
    auth_mode = gateway.get("authMode") or gateway.get("auth") or security.get("authMode")
    cors = gateway.get("cors") or gateway.get("allowedOrigins") or gateway.get("origins")
    trusted_proxy = gateway.get("trustedProxy") or gateway.get("trustedProxies")
    headers = gateway.get("securityHeaders") or security.get("headers")
    deny_commands = nested_get(config, "gateway.nodes.denyCommands") or nested_get(config, "nodes.denyCommands")

    result["version"] = version
    result["signals"] = {
        "bind": redact_sensitive(bind, "bind"),
        "auth_mode": redact_sensitive(auth_mode, "auth_mode"),
        "cors": redact_sensitive(cors, "cors"),
        "trusted_proxy": redact_sensitive(trusted_proxy, "trusted_proxy"),
        "security_headers": redact_sensitive(headers, "security_headers"),
        "deny_commands": redact_sensitive(deny_commands, "deny_commands"),
        "memory_limit": redact_sensitive(resources.get("memory") or resources.get("memoryLimit"), "memory_limit"),
        "cpu_limit": redact_sensitive(resources.get("cpu") or resources.get("cpuLimit"), "cpu_limit"),
        "log_rotation": redact_sensitive(logging_cfg.get("rotation") or logging_cfg.get("rotate"), "log_rotation"),
        "auto_update": redact_sensitive(config.get("autoUpdate") or nested_get(config, "update.auto"), "auto_update"),
    }

    if bind in {"0.0.0.0", "::"}:
        result["findings"].append(
            {
                "id": "L1-GATEWAY-NON-LOOPBACK-BIND",
                "severity": "high",
                "title": "Gateway 绑定地址可能暴露到非本地网络",
                "evidence": {"bind": bind},
            }
        )
    if not auth_mode:
        result["findings"].append(
            {
                "id": "L1-AUTH-MODE-MISSING",
                "severity": "medium",
                "title": "配置中未识别到显式认证模式",
                "evidence": {"auth_mode": auth_mode},
            }
        )
    if cors is None or cors == "*" or cors == ["*"]:
        result["findings"].append(
            {
                "id": "L1-CORS-UNSCOPED",
                "severity": "medium",
                "title": "CORS 来源未收敛或未配置",
                "evidence": {"cors": cors},
            }
        )
    if not trusted_proxy:
        result["findings"].append(
            {
                "id": "L1-TRUSTED-PROXY-MISSING",
                "severity": "medium",
                "title": "未识别到 trusted proxy 配置",
                "evidence": {"trusted_proxy": trusted_proxy},
            }
        )
    if not headers:
        result["findings"].append(
            {
                "id": "L1-SECURITY-HEADERS-MISSING",
                "severity": "low",
                "title": "未识别到安全响应头配置",
                "evidence": {"security_headers": headers},
            }
        )
    if isinstance(deny_commands, list):
        missing = [cmd for cmd in ["rm", "sudo", "su", "chmod", "chown", "dd", "mkfs"] if cmd not in deny_commands]
        if missing:
            result["findings"].append(
                {
                    "id": "L1-DENY-COMMANDS-INCOMPLETE",
                    "severity": "medium",
                    "title": "关键命令限制列表不完整",
                    "evidence": {"missing": missing},
                }
            )
    else:
        result["findings"].append(
            {
                "id": "L1-DENY-COMMANDS-MISSING",
                "severity": "medium",
                "title": "未识别到关键命令限制列表",
                "evidence": {"deny_commands": deny_commands},
            }
        )
    return result


def inspect_state_layout(openclaw_home: Path) -> dict[str, Any]:
    expected_dirs = {
        "identity": ["device.json"],
        "memory": ["main.sqlite"],
        "tasks": ["runs.sqlite"],
        "flows": ["registry.sqlite"],
        "logs": [],
        "skills": [],
    }
    dirs = []
    findings = []
    for name, important_files in expected_dirs.items():
        path = openclaw_home / name
        item = {
            "name": name,
            "path": str(path),
            "exists": path.exists(),
            "mode": path_mode(path) if path.exists() else None,
            "important_files": [],
        }
        for filename in important_files:
            file_path = path / filename
            item["important_files"].append(
                {
                    "name": filename,
                    "exists": file_path.exists(),
                    "mode": path_mode(file_path) if file_path.exists() else None,
                    "size": file_path.stat().st_size if file_path.exists() else None,
                }
            )
        dirs.append(item)
    baseline_candidates = find_files(openclaw_home, names={"hashes.json", "baseline.json", "file-hash-baseline.json"}, max_files=20)
    backup_candidates = [
        path
        for path in find_files(openclaw_home, max_files=1000)
        if path.suffix.lower() in {".bak", ".backup", ".zip", ".tar", ".gz"} or "backup" in path.name.lower()
    ][:20]
    log_files = [path for path in find_files(openclaw_home / "logs", max_files=200) if path.suffix.lower() in {".log", ".txt", ".jsonl"}]
    if not baseline_candidates:
        findings.append(
            {
                "id": "L1-HASH-BASELINE-MISSING",
                "severity": "medium",
                "title": "未发现文件哈希基线",
                "evidence": {"searched_names": ["hashes.json", "baseline.json", "file-hash-baseline.json"]},
            }
        )
    if not backup_candidates:
        findings.append(
            {
                "id": "L1-BACKUP-MISSING",
                "severity": "low",
                "title": "未发现状态目录备份线索",
                "evidence": {"openclaw_home": str(openclaw_home)},
            }
        )
    if not log_files:
        findings.append(
            {
                "id": "L1-LOGS-MISSING-OR-EMPTY",
                "severity": "low",
                "title": "未发现可审计日志文件",
                "evidence": {"logs_dir": str(openclaw_home / "logs")},
            }
        )
    return {
        "directories": dirs,
        "hash_baselines": [str(path) for path in baseline_candidates],
        "backup_candidates": [str(path) for path in backup_candidates],
        "log_files": [{"path": str(path), "size": path.stat().st_size, "secret_hints": scan_secrets(path)} for path in log_files[:20]],
        "findings": findings,
    }


def inspect_agent_ecosystem_baseline(openclaw_home: Path) -> dict[str, Any]:
    names = {
        "mcp.json",
        "mcp_settings.json",
        "claude_desktop_config.json",
        "settings.json",
        "agents.json",
        "tools.json",
        ".openclaw-guard.yml",
    }
    roots = [openclaw_home, PROJECT_ROOT]
    references: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in roots:
        for path in find_files(root, names=names, max_files=300):
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            text = safe_read_text(path)
            lowered = text.lower()
            signals = []
            if "mcp" in lowered:
                signals.append("mcp")
            if "command" in lowered or "args" in lowered:
                signals.append("command_binding")
            if "env" in lowered or "apikey" in lowered or "api_key" in lowered:
                signals.append("env_or_secret_binding")
            if "http://" in lowered or "https://" in lowered:
                signals.append("external_reference")
            references.append(
                {
                    "path": str(path),
                    "relative_path": relative(path, root),
                    "root": str(root),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "signals": signals,
                    "secret_hints": scan_secrets(path),
                }
            )
    return {
        "summary": f"发现 {len(references)} 个 Agent/MCP/工具配置引用。",
        "references": references[:100],
        "coverage": {"roots": [str(root) for root in roots], "references": len(references)},
    }


def inspect_gateway_urls(urls: list[str]) -> list[dict[str, Any]]:
    results = []
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        localish = host in {"127.0.0.1", "localhost", "::1"} or host.endswith(".localhost")
        results.append(
            {
                "url": url,
                "scheme": parsed.scheme,
                "host": host,
                "port": port,
                "path": parsed.path or "/",
                "localish": localish,
                "tls": parsed.scheme == "https",
            }
        )
    return results


def layer1_baseline(openclaw_home: Path) -> dict[str, Any]:
    config_names = {"openclaw.json", "models.json", "auth-profiles.json", "device.json", "update-check.json"}
    config_files = []
    config_semantics = []
    for path in find_files(openclaw_home, names=config_names):
        config_files.append(
            {
                "path": str(path),
                "relative_path": relative(path, openclaw_home),
                "size": path.stat().st_size,
                "mode": path_mode(path),
                "sha256": sha256_file(path),
                "secret_hints": scan_secrets(path),
                "group_or_world_readable": is_group_or_world_readable(path),
            }
        )
        if path.name == "openclaw.json":
            config_semantics.append(analyze_openclaw_config(path, openclaw_home))

    sqlite_files = [inspect_sqlite(path) for path in find_files(openclaw_home, suffix=".sqlite")]
    state_layout = inspect_state_layout(openclaw_home)
    agent_ecosystem = inspect_agent_ecosystem_baseline(openclaw_home)
    important = {"registry.sqlite", "runs.sqlite", "main.sqlite"}
    present_important = sorted({Path(item["path"]).name for item in sqlite_files if Path(item["path"]).name in important})

    findings = []
    important_db_risks = [
        item.get("risk", "info")
        for item in sqlite_files
        if Path(item["path"]).name in important
    ]
    state_db_severity = "high" if "high" in important_db_risks else "medium"
    if present_important:
        findings.append(
            {
                "id": "L1-STATE-DB-PLAINTEXT",
                "severity": state_db_severity,
                "title": "OpenClaw 状态数据库以明文 SQLite 文件形式存储",
                "evidence": present_important,
                "interpretation": "该问题可作为本地证据和影响面放大器；一旦与任意文件读、恶意 Skill 或方法越权组合，风险会明显上升。",
            }
        )
    for file_item in config_files:
        if file_item["secret_hints"]:
            findings.append(
                {
                    "id": "L1-CONFIG-SECRET-HINT",
                    "severity": "medium",
                    "title": "配置文件中存在疑似 token 或 API key",
                    "evidence": {
                        "path": file_item["relative_path"],
                        "secret_hints": file_item["secret_hints"],
                    },
                }
            )
        if file_item["group_or_world_readable"]:
            findings.append(
                {
                    "id": "L1-CONFIG-PERMISSIVE-MODE",
                    "severity": "medium",
                    "title": "配置文件权限过宽，同组或其他用户可读",
                    "evidence": {"path": file_item["relative_path"], "mode": file_item["mode"]},
                }
            )
    for semantic in config_semantics:
        findings.extend(semantic.get("findings", []))
    findings.extend(state_layout.get("findings", []))
    for log in state_layout.get("log_files", []):
        if log.get("secret_hints"):
            findings.append(
                {
                    "id": "L1-LOG-SECRET-HINT",
                    "severity": "medium",
                    "title": "日志文件中存在疑似 token 或 API key",
                    "evidence": {"path": log["path"], "secret_hints": log["secret_hints"]},
                }
            )
    risky_agent_refs = [
        ref
        for ref in agent_ecosystem.get("references", [])
        if ref.get("secret_hints") or "command_binding" in ref.get("signals", []) or "env_or_secret_binding" in ref.get("signals", [])
    ]
    if risky_agent_refs:
        findings.append(
            {
                "id": "L1-AGENT-ECOSYSTEM-CONFIG-SIGNAL",
                "severity": "low",
                "title": "本地 Agent/MCP/工具配置基线中存在需复核的能力绑定信号",
                "evidence": risky_agent_refs[:10],
            }
        )

    return {
        "name": "Layer 1 - install/state baseline",
        "openclaw_home": str(openclaw_home),
        "config_files": config_files,
        "config_semantics": config_semantics,
        "sqlite_files": sqlite_files,
        "state_layout": state_layout,
        "agent_ecosystem_baseline": agent_ecosystem,
        "coverage": {
            "config_files": len(config_files),
            "config_semantics": len(config_semantics),
            "sqlite_files": len(sqlite_files),
            "log_files": len(state_layout.get("log_files", [])),
            "agent_ecosystem_refs": len(agent_ecosystem.get("references", [])),
        },
        "skipped_reason": None if openclaw_home.exists() else "openclaw-home-missing",
        "findings": findings,
    }


def read_declared_capabilities(skill_md: Path) -> set[str]:
    text = safe_read_text(skill_md).lower()
    declared = set()
    keyword_map = {
        "file": ["file", "filesystem", "workspace", "文件"],
        "network": ["network", "http", "url", "网络"],
        "process": ["process", "shell", "command", "exec", "命令"],
        "browser": ["browser", "浏览器"],
        "schedule": ["schedule", "cron", "task", "定时"],
    }
    for cap, keywords in keyword_map.items():
        if any(keyword in text for keyword in keywords):
            declared.add(cap)
    return declared


def parse_skill_frontmatter(skill_md: Path) -> dict[str, Any]:
    text = safe_read_text(skill_md)
    if not text.startswith("---"):
        return {"present": False, "fields": {}}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {"present": False, "fields": {}}
    fields: dict[str, Any] = {}
    for line in parts[1].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip().strip("'\"")
    return {"present": True, "fields": fields}


def inspect_dependency_file(path: Path, root: Path) -> dict[str, Any]:
    text = safe_read_text(path)
    rel = relative(path, root)
    signals = []
    if not text:
        return {"path": rel, "signals": signals}
    if re.search(r"(?m)(\*|latest|>=|git\+|https?://)", text):
        signals.append("weak_or_remote_version_pin")
    if re.search(r"(?i)(postinstall|preinstall|build.rs|setup.py|scripts\s*=)", text):
        signals.append("install_time_execution")
    if scan_secrets(path):
        signals.append("secret_hint")
    return {"path": rel, "signals": signals[:10]}


def scan_skill_dir(skill_md: Path) -> dict[str, Any]:
    root = skill_md.parent
    declared = read_declared_capabilities(skill_md)
    frontmatter = parse_skill_frontmatter(skill_md)
    observed: set[str] = set()
    evidence: dict[str, list[str]] = {key: [] for key in CAPABILITY_PATTERNS}
    risk_hits: dict[str, list[str]] = {key: [] for key in SKILL_RISK_PATTERNS}
    dependency_audit: list[dict[str, Any]] = []

    scanned = 0
    for path in find_files(root, max_files=MAX_SKILL_FILES):
        if path.stat().st_size > MAX_TEXT_BYTES:
            continue
        text = safe_read_text(path)
        if not text:
            continue
        scanned += 1
        rel = relative(path, root)
        for cap, pattern in CAPABILITY_PATTERNS.items():
            if pattern.search(text):
                observed.add(cap)
                if len(evidence[cap]) < 8:
                    evidence[cap].append(rel)
        for risk, pattern in SKILL_RISK_PATTERNS.items():
            if pattern.search(text) and len(risk_hits[risk]) < 8:
                risk_hits[risk].append(rel)
        if path.name in DEPENDENCY_FILES:
            dependency_audit.append(inspect_dependency_file(path, root))

    mismatch = sorted(cap for cap in observed if cap not in declared and cap != "prompt_injection")
    active_risks = sorted(key for key, hits in risk_hits.items() if hits)
    severity = "info"
    if "remote_install" in active_risks or "exfiltration" in active_risks or "prompt_injection" in observed or {"file", "network", "process"}.issubset(observed):
        severity = "high"
    elif mismatch or active_risks or any(item["signals"] for item in dependency_audit):
        severity = "medium"

    return {
        "skill": str(root),
        "skill_md": str(skill_md),
        "frontmatter": frontmatter,
        "declared_capabilities": sorted(declared),
        "observed_capabilities": sorted(observed),
        "capability_mismatch": mismatch,
        "evidence": {k: v for k, v in evidence.items() if v},
        "risk_patterns": {k: v for k, v in risk_hits.items() if v},
        "dependency_audit": dependency_audit,
        "files_scanned": scanned,
        "severity": severity,
    }


def decode_process_output(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    return data.decode("utf-8", errors="replace")


def parse_json_output(data: bytes) -> dict[str, Any] | None:
    text = decode_process_output(data).strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text[:20000]}
    return value if isinstance(value, dict) else {"raw": text[:20000]}


def find_agent_guard_binary() -> Path | None:
    names = ["agent-skill-guard.exe", "agent-skill-guard"]
    candidates = [
        AGENT_GUARD_ENGINE_DIR / "bin" / name
        for name in names
    ] + [
        PROJECT_ROOT / "bin" / name
        for name in names
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    path_hit = shutil.which("agent-skill-guard") or shutil.which("agent-skill-guard.exe")
    return Path(path_hit) if path_hit else None


def normalize_agent_guard_report(report: dict[str, Any] | None) -> dict[str, Any]:
    if not report:
        return {
            "engine": "agent-skill-guard",
            "score": None,
            "verdict": None,
            "blocked": None,
            "summary_zh": None,
            "top_risks": [],
            "issue_count": 0,
            "issue_codes": [],
            "toxic_flows_count": 0,
            "hidden_instruction_signals": 0,
            "claims_mismatches": 0,
            "mcp_findings": 0,
            "ai_bom_packages": 0,
            "external_services": 0,
            "agent_packages": 0,
            "integrity_digests": 0,
            "policy_blocked": False,
            "declared_capabilities": [],
            "observed_capabilities": [],
            "ai_bom": {},
            "mcp_tool_schema_summary": {},
        }

    findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []
    issue_codes = sorted({str(item.get("issue_code")) for item in findings if isinstance(item, dict) and item.get("issue_code")})
    toxic_summary = report.get("toxic_flow_summary", {}) if isinstance(report.get("toxic_flow_summary"), dict) else {}
    hidden_summary = report.get("hidden_instruction_summary", {}) if isinstance(report.get("hidden_instruction_summary"), dict) else {}
    claims_summary = report.get("claims_review_summary", {}) if isinstance(report.get("claims_review_summary"), dict) else {}
    mcp_summary = report.get("mcp_tool_schema_summary", {}) if isinstance(report.get("mcp_tool_schema_summary"), dict) else {}
    ai_bom = report.get("ai_bom", {}) if isinstance(report.get("ai_bom"), dict) else {}
    package_index = report.get("agent_package_index", {}) if isinstance(report.get("agent_package_index"), dict) else {}
    integrity = report.get("integrity_snapshot", {}) if isinstance(report.get("integrity_snapshot"), dict) else {}
    policy = report.get("policy_evaluation", {}) if isinstance(report.get("policy_evaluation"), dict) else {}
    cap_manifest = report.get("capability_manifest", {}) if isinstance(report.get("capability_manifest"), dict) else {}

    declared: set[str] = set()
    observed: set[str] = set()
    for entry in cap_manifest.get("entries", []) if isinstance(cap_manifest.get("entries"), list) else []:
        if not isinstance(entry, dict):
            continue
        for key, bucket in [("declared", declared), ("observed", observed), ("capabilities", observed), ("permissions", declared)]:
            value = entry.get(key)
            if isinstance(value, list):
                bucket.update(str(item) for item in value)
            elif isinstance(value, str):
                bucket.add(value)

    return {
        "engine": "agent-skill-guard",
        "score": report.get("score"),
        "verdict": report.get("verdict"),
        "blocked": report.get("blocked"),
        "summary_zh": report.get("summary_zh"),
        "top_risks": report.get("top_risks", []) if isinstance(report.get("top_risks"), list) else [],
        "issue_count": len(findings),
        "issue_codes": issue_codes,
        "toxic_flows_count": int(toxic_summary.get("flows_count", 0) or len(report.get("toxic_flows", []) or [])),
        "hidden_instruction_signals": len(hidden_summary.get("signals", []) or []),
        "claims_mismatches": len(claims_summary.get("mismatches", []) or []),
        "mcp_findings": int(mcp_summary.get("findings_count", 0) or 0),
        "ai_bom_packages": len(ai_bom.get("packages", []) or []),
        "external_services": len(ai_bom.get("external_services", []) or []),
        "agent_packages": len(package_index.get("packages", []) or []),
        "integrity_digests": len(integrity.get("skill_file_digests", []) or []),
        "policy_blocked": bool(policy.get("blocked")),
        "policy_reason_zh": policy.get("reason_zh"),
        "declared_capabilities": sorted(declared),
        "observed_capabilities": sorted(observed),
        "ai_bom": ai_bom,
        "mcp_tool_schema_summary": mcp_summary,
    }


def run_skill_guard_engine(root: Path, mode: str, *, agent_ecosystem: bool = True, timeout: int = 120) -> dict[str, Any]:
    result: dict[str, Any] = {
        "enabled": mode != "off",
        "available": False,
        "status": "skipped",
        "engine_name": None,
        "engine_dir": None,
        "target": str(root),
        "runner": None,
        "missing_optional_assets": [],
        "command": None,
        "normalized": normalize_agent_guard_report(None),
        "report": None,
        "error": None,
    }
    if mode == "off":
        result["error"] = "已关闭第二层深度引擎"
        return result

    binary = find_agent_guard_binary()
    if binary:
        result["available"] = True
        result["runner"] = "binary"
        result["engine_name"] = "agent-skill-guard"
        result["engine_dir"] = str(AGENT_GUARD_ENGINE_DIR)
        command = [str(binary), "scan", str(root), "--format", "json", "--lang", "zh-cn"]
        if AGENT_GUARD_CONFIG.exists():
            command.extend(["--config", str(AGENT_GUARD_CONFIG)])
        if agent_ecosystem:
            command.append("--agent-ecosystem")
        cwd = AGENT_GUARD_ENGINE_DIR if AGENT_GUARD_ENGINE_DIR.exists() else PROJECT_ROOT
    else:
        result["error"] = "未找到 Agent Skill Guard 二进制；第二层深度扫描未运行，已保留轻量 Skill/Agent 扫描能力"
        result["runner"] = None
        result["missing_optional_assets"] = [
            name
            for name in ["agent-skill-guard.exe", ".openclaw-guard.yml", "report.schema.json"]
            if not (
                (AGENT_GUARD_ENGINE_DIR / "bin" / name).exists()
                or (AGENT_GUARD_ENGINE_DIR / name).exists()
                or (AGENT_GUARD_ENGINE_DIR / "schemas" / name).exists()
            )
        ]
        return result

    result["command"] = [Path(part).name if index == 0 else part for index, part in enumerate(command)]
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = "第二层深度扫描超时"
        return result
    except OSError as exc:
        result["status"] = "failed"
        result["error"] = str(exc)
        return result

    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if completed.returncode not in {0, 2, 3}:
        result["status"] = "failed"
        result["error"] = decode_process_output(stderr or stdout)
        return result

    result["status"] = "completed"
    parsed = parse_json_output(stdout)
    result["report"] = parsed
    result["normalized"] = normalize_agent_guard_report(parsed)
    return result


def aggregate_layer2_risk_context(skill_reports: list[dict[str, Any]], guard_reports: list[dict[str, Any]]) -> dict[str, Any]:
    declared: set[str] = set()
    observed: set[str] = set()
    risk_patterns: set[str] = set()
    for skill in skill_reports:
        declared.update(str(item) for item in skill.get("declared_capabilities", []))
        observed.update(str(item) for item in skill.get("observed_capabilities", []))
        risk_patterns.update(str(key) for key in skill.get("risk_patterns", {}).keys())

    normalized_runs = [run.get("normalized", {}) for run in guard_reports if isinstance(run.get("normalized"), dict)]
    toxic_flows = sum(int(item.get("toxic_flows_count", 0) or 0) for item in normalized_runs)
    hidden_signals = sum(int(item.get("hidden_instruction_signals", 0) or 0) for item in normalized_runs)
    claims_mismatches = sum(int(item.get("claims_mismatches", 0) or 0) for item in normalized_runs)
    mcp_findings = sum(int(item.get("mcp_findings", 0) or 0) for item in normalized_runs)
    ai_bom_packages = sum(int(item.get("ai_bom_packages", 0) or 0) for item in normalized_runs)
    external_services = sum(int(item.get("external_services", 0) or 0) for item in normalized_runs)
    agent_packages = sum(int(item.get("agent_packages", 0) or 0) for item in normalized_runs)
    policy_blocked = any(bool(item.get("policy_blocked")) for item in normalized_runs)
    top_risks = []
    for item in normalized_runs:
        top_risks.extend(str(risk) for risk in item.get("top_risks", [])[:10])
        declared.update(str(cap) for cap in item.get("declared_capabilities", []))
        observed.update(str(cap) for cap in item.get("observed_capabilities", []))

    return {
        "declared_capabilities": sorted(declared),
        "observed_capabilities": sorted(observed),
        "risk_patterns": sorted(risk_patterns),
        "toxic_flows_count": toxic_flows,
        "hidden_instruction_signals": hidden_signals,
        "claims_mismatches": claims_mismatches,
        "mcp_findings": mcp_findings,
        "ai_bom_packages": ai_bom_packages,
        "external_services": external_services,
        "agent_packages": agent_packages,
        "policy_blocked": policy_blocked,
        "top_risks": sorted(set(top_risks)),
        "ai_bom": next((item.get("ai_bom") for item in normalized_runs if item.get("ai_bom")), {}),
        "mcp_tool_schema_summary": next((item.get("mcp_tool_schema_summary") for item in normalized_runs if item.get("mcp_tool_schema_summary")), {}),
    }


def layer2_skill_supply_chain(
    skill_root: Path | None,
    openclaw_home: Path,
    skill_guard_mode: str,
    *,
    agent_ecosystem: bool = True,
    deep_engine_timeout: int = 120,
) -> dict[str, Any]:
    roots: list[Path] = []
    if skill_root:
        roots.append(skill_root)
    default_skills = openclaw_home / "skills"
    if default_skills.exists() and default_skills not in roots:
        roots.append(default_skills)

    skill_reports: list[dict[str, Any]] = []
    for root in roots:
        for skill_md in find_files(root, names={"SKILL.md"}, max_files=300):
            skill_reports.append(
                run_skill_scan(
                    skill_md,
                    find_files=find_files,
                    safe_read_text=safe_read_text,
                    scan_secrets=scan_secrets,
                    relative=relative,
                    max_skill_files=MAX_SKILL_FILES,
                    max_text_bytes=MAX_TEXT_BYTES,
                )
            )

    guard_reports = []
    if skill_guard_mode != "off":
        for root in roots:
            guard_reports.append(
                run_skill_guard_engine(
                    root,
                    skill_guard_mode,
                    agent_ecosystem=agent_ecosystem,
                    timeout=deep_engine_timeout,
                )
            )

    findings = []
    for item in skill_reports:
        if item["severity"] in {"medium", "high"}:
            findings.append(
                {
                    "id": "L2-SKILL-CAPABILITY-MISMATCH",
                    "severity": item["severity"],
                    "title": "Skill 声明能力与观察到的实现行为可能不一致",
                    "evidence": {
                        "skill": item["skill"],
                        "declared": item["declared_capabilities"],
                        "observed": item["observed_capabilities"],
                        "mismatch": item["capability_mismatch"],
                    },
                }
            )
        if item.get("risk_patterns"):
            findings.append(
                {
                    "id": "L2-SKILL-RISK-PATTERN",
                    "severity": "high" if item["severity"] == "high" else "medium",
                    "title": "Skill 实现中存在供应链、分阶段投递或外送风险信号",
                    "evidence": {
                        "skill": item["skill"],
                        "patterns": item["risk_patterns"],
                    },
                }
            )
        weak_deps = [dep for dep in item.get("dependency_audit", []) if dep.get("signals")]
        if weak_deps:
            findings.append(
                {
                    "id": "L2-SKILL-DEPENDENCY-RISK",
                    "severity": "medium",
                    "title": "Skill 依赖文件存在弱固定版本、远程依赖或安装期执行信号",
                    "evidence": {"skill": item["skill"], "dependencies": weak_deps},
                }
            )
    for guard in guard_reports:
        if guard["enabled"] and guard["status"] != "completed":
            findings.append(
                {
                    "id": "L2-AGENT-GUARD-ENGINE-NOT-RUN",
                    "severity": "info",
                    "title": "Agent Skill Guard 深度扫描引擎未完成运行",
                    "evidence": {
                        "target": guard["target"],
                        "status": guard["status"],
                        "error": guard["error"],
                    },
                }
            )
        normalized = guard.get("normalized", {})
        if guard.get("status") == "completed" and normalized:
            if normalized.get("policy_blocked") or normalized.get("blocked"):
                findings.append(
                    {
                        "id": "L2-AGENT-GUARD-POLICY-BLOCKED",
                        "severity": "high",
                        "title": "Agent Skill Guard 策略判定为阻断",
                        "evidence": {
                            "target": guard.get("target"),
                            "verdict": normalized.get("verdict"),
                            "score": normalized.get("score"),
                            "reason": normalized.get("policy_reason_zh"),
                        },
                    }
                )
            if normalized.get("toxic_flows_count", 0):
                findings.append(
                    {
                        "id": "L2-AGENT-TOXIC-FLOW",
                        "severity": "high",
                        "title": "Agent/Skill 存在不可信输入、敏感数据与外联或执行能力组合风险",
                        "evidence": {"target": guard.get("target"), "count": normalized.get("toxic_flows_count")},
                    }
                )
            if normalized.get("hidden_instruction_signals", 0):
                findings.append(
                    {
                        "id": "L2-HIDDEN-INSTRUCTION-SIGNAL",
                        "severity": "medium",
                        "title": "Agent/Skill 存在隐藏指令、Trojan Source 或 schema 投毒信号",
                        "evidence": {"target": guard.get("target"), "count": normalized.get("hidden_instruction_signals")},
                    }
                )
            if normalized.get("mcp_findings", 0):
                findings.append(
                    {
                        "id": "L2-MCP-TOOL-SCHEMA-RISK",
                        "severity": "medium",
                        "title": "MCP tool/schema 静态审计发现风险信号",
                        "evidence": {"target": guard.get("target"), "count": normalized.get("mcp_findings")},
                    }
                )
            if normalized.get("claims_mismatches", 0):
                findings.append(
                    {
                        "id": "L2-CLAIMS-EVIDENCE-MISMATCH",
                        "severity": "low",
                        "title": "Agent/Skill 自称能力或来源与实际证据不完全一致",
                        "evidence": {"target": guard.get("target"), "count": normalized.get("claims_mismatches")},
                    }
                )

    risk_context = aggregate_layer2_risk_context(skill_reports, guard_reports)

    return {
        "name": "Layer 2 - skill and agent supply-chain audit",
        "roots": [str(root) for root in roots],
        "skills": skill_reports,
        "skill_guard_engine": {
            "mode": skill_guard_mode,
            "preferred_engine": "agent-skill-guard",
            "agent_ecosystem": agent_ecosystem,
            "agent_engine_dir": str(AGENT_GUARD_ENGINE_DIR),
            "runs": guard_reports,
        },
        "risk_context": risk_context,
        "coverage": {
            "roots": len(roots),
            "skills_scanned": len(skill_reports),
            "guard_runs": len(guard_reports),
            "guard_completed": sum(1 for item in guard_reports if item.get("status") == "completed"),
            "agent_guard_completed": sum(1 for item in guard_reports if item.get("status") == "completed" and item.get("engine_name") == "agent-skill-guard"),
            "agent_ecosystem": agent_ecosystem,
            "risk_context_signals": sum(
                int(bool(risk_context.get(key)))
                for key in ["toxic_flows_count", "hidden_instruction_signals", "mcp_findings", "claims_mismatches", "ai_bom_packages", "external_services"]
            ),
        },
        "skipped_reason": None if roots else "no-skill-roots",
        "findings": findings,
    }


def probe_http(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": f"ClawMatrix/{VERSION}"})
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


def scenario_headers(scenario: dict[str, Any]) -> dict[str, str]:
    headers = {
        "User-Agent": f"ClawMatrix/{VERSION}",
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


def probe_http_method(url: str, scenario: dict[str, Any], method_probe: dict[str, Any], timeout: float) -> dict[str, Any]:
    headers = scenario_headers(scenario)
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


def probe_ws_method(url: str, scenario: dict[str, Any], method_probe: dict[str, Any], timeout: float) -> dict[str, Any]:
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
        headers = scenario_headers(scenario)
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
                    "method": result.get("method"),
                    "intent": result.get("intent"),
                }
            )
    return {"count": len(results), "by_classification": by_class, "accepted": accepted[:50]}


def build_difference_matrices(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_method: dict[str, dict[str, set[str]]] = {}
    for result in results:
        method = result.get("method", "unknown")
        scenario = result.get("scenario", "unknown")
        classification = result.get("classification", "unknown")
        by_method.setdefault(method, {}).setdefault(scenario, set()).add(classification)
    condition_differences = []
    inconsistent = []
    for method, scenarios in by_method.items():
        normalized = {scenario: sorted(values) for scenario, values in scenarios.items()}
        distinct = {tuple(values) for values in normalized.values()}
        if len(distinct) > 1:
            condition_differences.append({"method": method, "by_scenario": normalized})
        for scenario, values in normalized.items():
            if len(values) > 1:
                inconsistent.append({"method": method, "scenario": scenario, "classifications": values})
    return {
        "condition_differences": condition_differences,
        "inconsistent_same_condition": inconsistent,
    }


def method_family_probe(family: str) -> dict[str, Any]:
    return METHOD_PROBES.get(family, [{"method": family.replace("*", "status"), "params": {}, "intent": "metadata-only"}])[0]


def layer3_trust_boundary(
    gateway_url: str | None,
    browser_url: str | None,
    dynamic_mode: str = "plan",
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    method_probe_limit: int = 0,
    rpc_paths: list[str] | None = None,
) -> dict[str, Any]:
    scenarios = [
        {"id": "loopback", "host": "127.0.0.1", "origin": "http://127.0.0.1", "expected": "local-only"},
        {"id": "localhost", "host": "localhost", "origin": "http://localhost", "expected": "local-only"},
        {"id": "nip-io-loopback", "host": "127.0.0.1.nip.io", "origin": "http://127.0.0.1.nip.io", "expected": "must-not-inherit-local-blindly"},
        {"id": "forwarded-loopback", "host": "external", "x_forwarded_for": "127.0.0.1", "expected": "must-require-trusted-proxy"},
    ]

    matrix = []
    for method, meaning in METHOD_FAMILIES:
        for scenario in scenarios:
            probe = method_family_probe(method)
            matrix.append(
                {
                    "method_family": method,
                    "probe_method": probe["method"],
                    "probe_intent": probe.get("intent"),
                    "meaning": meaning,
                    "scenario": scenario["id"],
                    "expected_policy": "拒绝或要求显式会话令牌",
                    "status": "待验证" if dynamic_mode == "plan" else "待探测",
                    "safe_next_step": "使用授权的 WebSocket/API 测试框架比较允许/拒绝结果，不执行高影响操作。",
                }
            )

    probes = []
    if gateway_url:
        probes.append(probe_http(gateway_url))
    if browser_url:
        probes.append(probe_http(browser_url))

    method_probe_results: list[dict[str, Any]] = []
    if dynamic_mode == "probe":
        targets = expand_probe_urls([url for url in [gateway_url, browser_url] if url], rpc_paths or DEFAULT_RPC_PATHS)
        planned = matrix[: method_probe_limit or None]
        for row in planned:
            scenario = next(item for item in scenarios if item["id"] == row["scenario"])
            method_probe = {"method": row["probe_method"], "params": method_family_probe(row["method_family"]).get("params", {}), "intent": row["probe_intent"]}
            for target in targets:
                http_result = probe_http_method(target, scenario, method_probe, probe_timeout)
                ws_result = probe_ws_method(target, scenario, method_probe, probe_timeout)
                method_probe_results.extend([http_result, ws_result])
        summary = summarize_probe_results(method_probe_results)
        differences = build_difference_matrices(method_probe_results)
        for row in matrix:
            matching = [
                result
                for result in method_probe_results
                if result.get("scenario") == row["scenario"] and result.get("method") == row["probe_method"]
            ]
            row["status"] = ",".join(sorted({item.get("classification", "unknown") for item in matching})) or "未探测"
    else:
        summary = {"count": 0, "by_classification": {}, "accepted": []}
        differences = {"condition_differences": [], "inconsistent_same_condition": []}

    findings = [
        {
            "id": "L3-AUTHZ-MATRIX-NEEDED",
            "severity": "info" if dynamic_mode == "plan" else ("high" if summary["accepted"] else "info"),
            "title": "需要进行方法级授权差异验证" if dynamic_mode == "plan" else "已完成方法级授权安全探测",
            "evidence": {
                "method_families": [method for method, _ in METHOD_FAMILIES],
                "scenarios": [scenario["id"] for scenario in scenarios],
                "dynamic_mode": dynamic_mode,
                "probe_summary": summary,
                "differences": differences,
            },
        }
    ]
    if dynamic_mode == "probe" and summary["accepted"]:
        findings.append(
            {
                "id": "L3-METHOD-PROBE-ACCEPTED",
                "severity": "high",
                "title": "存在敏感方法族在探测条件下返回 accepted，需要人工复核授权语义",
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
        "findings": findings,
    }


def setup_lab_canaries(canary_dir: Path | None, canary_url: str | None = None) -> dict[str, Any]:
    root = canary_dir or (Path(tempfile.gettempdir()) / "clawmatrix-canary-lab")
    root.mkdir(parents=True, exist_ok=True)
    token = hashlib.sha256(os.urandom(32)).hexdigest()[:24]
    marker = root / f"file-canary-{token}.txt"
    marker.write_text(f"clawmatrix-file-canary:{token}\n", encoding="utf-8")

    db_path = root / f"state-canary-{token}.sqlite"
    con = sqlite3.connect(db_path)
    try:
        con.execute("create table if not exists clawmatrix_canary (id text primary key, token text, created_at text)")
        con.execute("insert or replace into clawmatrix_canary values (?, ?, ?)", ("state-db-canary", token, utc_now()))
        con.commit()
    finally:
        con.close()

    network_observer = None
    if canary_url:
        network_observer = f"{canary_url.rstrip('/')}/clawmatrix/{token}"

    return {
        "root": str(root),
        "token": token,
        "file_marker": str(marker),
        "sqlite_marker": str(db_path),
        "network_observer": network_observer,
        "verification_payloads": [
            {"surface": "agents.files.stat", "params": {"path": str(marker)}, "expected_signal": "marker metadata only"},
            {"surface": "agents.files.list", "params": {"path": str(root), "limit": 5}, "expected_signal": "marker filename only"},
            {"surface": "memory.search", "params": {"query": token, "limit": 1}, "expected_signal": "synthetic marker only"},
            {"surface": "state.sqlite.synthetic", "params": {"path": str(db_path), "table": "clawmatrix_canary"}, "expected_signal": "synthetic row only"},
        ],
        "cleanup_hint": f"删除实验目录即可清理：{root}",
    }


def observe_lab_canaries(lab_setup: dict[str, Any] | None) -> dict[str, Any] | None:
    if not lab_setup:
        return None
    file_marker = Path(lab_setup["file_marker"])
    sqlite_marker = Path(lab_setup["sqlite_marker"])
    observation: dict[str, Any] = {
        "file_marker_exists": file_marker.exists(),
        "file_marker_size": file_marker.stat().st_size if file_marker.exists() else None,
        "sqlite_marker_exists": sqlite_marker.exists(),
        "sqlite_row_visible": False,
        "sqlite_error": None,
    }
    if sqlite_marker.exists():
        try:
            con = sqlite3.connect(f"file:{sqlite_marker.as_posix()}?mode=ro", uri=True)
            try:
                cur = con.cursor()
                cur.execute("select token from clawmatrix_canary where id = ?", ("state-db-canary",))
                row = cur.fetchone()
                observation["sqlite_row_visible"] = bool(row and row[0] == lab_setup.get("token"))
            finally:
                con.close()
        except sqlite3.Error as exc:
            observation["sqlite_error"] = str(exc)
    return observation


def layer4_canary_plan(
    canary_mode: str = "plan",
    canary_dir: Path | None = None,
    canary_url: str | None = None,
    risk_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    canaries = [
        {
            "id": "file-canary",
            "surface": "agents.files.* / workspace",
            "safe_signal": "只读取或列出实验目录中主动创建的标记文件。",
            "blocked_if": "请求来自非可信 Host/Origin，或缺少显式会话令牌。",
        },
        {
            "id": "network-canary",
            "surface": "network/tool reachability",
            "safe_signal": "访问课题组自控 URL，并携带随机 canary 标记；不访问第三方系统。",
            "blocked_if": "Skill 未声明网络能力，或调用上下文不可信。",
        },
        {
            "id": "task-canary",
            "surface": "tasks.* / scheduled jobs",
            "safe_signal": "只创建 dry-run 任务记录，或仅检查方法是否触达任务调度层。",
            "blocked_if": "连接建立后未经用户确认就进入任务变更路径。",
        },
        {
            "id": "state-db-canary",
            "surface": "memory/flows/tasks SQLite state",
            "safe_signal": "观察只读元数据是否能通过高层方法触达，而不是直接读文件系统。",
            "blocked_if": "方法向非可信调用者暴露状态数据库内容。",
        },
    ]
    risk_context = risk_context or {}
    risk_driven_canaries: list[dict[str, Any]] = []
    observed = set(risk_context.get("observed_capabilities", [])) | set(risk_context.get("declared_capabilities", []))
    if risk_context.get("mcp_findings") or risk_context.get("mcp_tool_schema_summary", {}).get("dangerous_commands"):
        risk_driven_canaries.append(
            {
                "id": "mcp-schema-canary",
                "surface": "MCP tool schema / command binding",
                "safe_signal": "只复核 tool schema、command/env 声明和 dry-run 可达性，不启动 MCP server。",
                "blocked_if": "MCP 工具声明危险命令、宽泛 env 传递或未绑定可信来源。",
                "source": "layer2-agent-skill-guard",
            }
        )
    if risk_context.get("hidden_instruction_signals"):
        risk_driven_canaries.append(
            {
                "id": "prompt-instruction-canary",
                "surface": "prompt / companion docs / hidden instruction",
                "safe_signal": "仅使用 synthetic 指令标记验证是否进入报告和审计链，不向运行时注入真实指令。",
                "blocked_if": "隐藏指令可跨越 skill 文档边界影响工具调用策略。",
                "source": "layer2-agent-skill-guard",
            }
        )
    if "browser" in observed:
        risk_driven_canaries.append(
            {
                "id": "browser-canary",
                "surface": "browser.* / browser-control",
                "safe_signal": "只验证 browser.status / tabs metadata，不读取真实页面内容。",
                "blocked_if": "非可信上下文可触达浏览器控制能力。",
                "source": "layer2-agent-skill-guard",
            }
        )
    if risk_context.get("toxic_flows_count") or risk_context.get("external_services") or "network" in observed:
        risk_driven_canaries.append(
            {
                "id": "egress-canary",
                "surface": "network egress / external services",
                "safe_signal": "只使用课题组自控 URL 或 plan-only 观察点，不发送本地数据。",
                "blocked_if": "不可信输入可与敏感数据面和外联能力组合。",
                "source": "layer2-agent-skill-guard",
            }
        )
    canaries.extend(risk_driven_canaries)

    lab_setup = None
    lab_observation = None
    findings = [
        {
            "id": "L4-CANARY-PLAN",
            "severity": "info",
            "title": "已生成 Canary 影响面验证计划",
            "evidence": [item["id"] for item in canaries],
        }
    ]
    if risk_driven_canaries:
        findings.append(
            {
                "id": "L4-RISK-DRIVEN-CANARY",
                "severity": "info",
                "title": "已根据第二层 Agent/Skill 风险增强 Canary 影响面验证计划",
                "evidence": risk_driven_canaries,
            }
        )
    if canary_mode == "lab":
        lab_setup = setup_lab_canaries(canary_dir, canary_url)
        lab_observation = observe_lab_canaries(lab_setup)
        findings.append(
            {
                "id": "L4-CANARY-LAB-READY",
                "severity": "info",
                "title": "已布置本地实验 canary 标记",
                "evidence": lab_setup,
            }
        )
        findings.append(
            {
                "id": "L4-CANARY-LAB-OBSERVED",
                "severity": "info" if lab_observation and lab_observation.get("file_marker_exists") and lab_observation.get("sqlite_row_visible") else "medium",
                "title": "已完成本地 canary 自检观测",
                "evidence": lab_observation,
            }
        )
    return {
        "name": "Layer 4 - harmless canary impact validation",
        "mode": canary_mode,
        "canaries": canaries,
        "risk_driven_canaries": risk_driven_canaries,
        "lab_setup": lab_setup,
        "lab_observation": lab_observation,
        "coverage": {
            "canaries_planned": len(canaries),
            "risk_driven_canaries": len(risk_driven_canaries),
            "lab_enabled": canary_mode == "lab",
            "lab_ready": bool(lab_setup and lab_observation),
        },
        "skipped_reason": None if canary_mode == "lab" else "canary-mode-plan",
        "findings": findings,
    }


def assess_tool_capabilities(report: dict[str, Any]) -> dict[str, Any]:
    l1, l2, l3, l4 = report["layers"]
    guard_runs = l2.get("skill_guard_engine", {}).get("runs", [])
    guard_completed = any(run.get("status") == "completed" for run in guard_runs)
    agent_guard_completed = any(run.get("status") == "completed" and run.get("engine_name") == "agent-skill-guard" for run in guard_runs)
    guard_available = any(run.get("available") for run in guard_runs)
    risk_context = l2.get("risk_context", {})
    dynamic_results = l3.get("method_probe_results", [])
    dynamic_mode = l3.get("dynamic_mode", "plan")
    canary_mode = l4.get("mode", "plan")
    lab_ready = bool(l4.get("lab_setup") and l4.get("lab_observation"))

    layer_status = [
        {
            "layer": "第一层",
            "name": "安装态与状态面审计",
            "status": "已具备实扫能力",
            "evidence": f"配置文件 {len(l1.get('config_files', []))} 个，SQLite 状态库 {len(l1.get('sqlite_files', []))} 个，Agent/MCP 配置引用 {len(l1.get('agent_ecosystem_baseline', {}).get('references', []))} 个。",
            "maps_to": "对应并扩展焦糖布丁的配置/状态目录/默认运行态基线扫描。",
            "advantage": "除发现项外，还抽取配置语义、数据库结构、文件权限、状态目录证据和 Agent/MCP 配置基线，适合做跨版本趋势分析。",
            "gap": "不替代人工判断业务配置是否符合部署策略。",
        },
        {
            "layer": "第二层",
            "name": "Skill / Agent 生态与供应链审计",
            "status": "轻量扫描可用，Agent Skill Guard 按环境自动接入" if not guard_completed else ("轻量扫描与新版 Agent Skill Guard 均已接入" if agent_guard_completed else "轻量扫描与深度引擎均已接入"),
            "evidence": f"轻量 Skill 扫描 {len(l2.get('skills', []))} 个；deep runs={len(guard_runs)}，available={guard_available}，completed={guard_completed}；AI BOM packages={risk_context.get('ai_bom_packages', 0)}，MCP findings={risk_context.get('mcp_findings', 0)}。",
            "maps_to": "对应并升级队友 Skill Guard/SkillDance 的 Skill 静态、供应链、Agent/MCP 生态审计方向。",
            "advantage": "第二层新版深度引擎输出 AI BOM、MCP schema、隐藏指令、claims-vs-evidence 和 toxic flow，并继续流向第三层授权矩阵和第四层 canary 影响验证。",
            "gap": "若本机无新版 Agent Skill Guard 二进制，会自动降级为轻量扫描；远程输入由策略配置控制。",
        },
        {
            "layer": "第三层",
            "name": "连接后信任边界与方法授权验证",
            "status": "已进入动态授权探测" if dynamic_mode == "probe" and dynamic_results else "已生成授权矩阵，动态探测需启用 --dynamic-mode probe",
            "evidence": f"授权矩阵 {len(l3.get('authorization_matrix', []))} 行；动态模式={dynamic_mode}；方法探测结果 {len(dynamic_results)} 条。",
            "maps_to": "这是焦糖布丁、Skill Guard、SkillDance 通常不覆盖的连接后授权逻辑层。",
            "advantage": "围绕 Host/Origin/loopback/nip.io/trusted proxy/WebSocket upgrade，对 sessions/config/node/browser/files/memory/tasks/flows 等方法族做差异矩阵，并根据第二层 Agent/Skill 风险标记优先方法族。",
            "gap": "动态探测默认只做 metadata/dry-run，不会执行高影响能力；发现 accepted 仍需人工复核授权语义。",
        },
        {
            "layer": "第四层",
            "name": "Canary 影响面验证",
            "status": "已完成本地 lab canary 自检" if lab_ready else "已生成 canary 验证计划，lab 模式需启用 --canary-mode lab",
            "evidence": f"Canary 模式={canary_mode}；lab_ready={lab_ready}；风险驱动 canary={len(l4.get('risk_driven_canaries', []))} 个。",
            "maps_to": "超过传统静态扫描，面向能力触达链路验证。",
            "advantage": "用 synthetic 文件、SQLite、网络观察点、任务 dry-run 和 Agent/MCP/prompt 风险驱动 canary 思路验证风险是否继续触达高价值能力面。",
            "gap": "默认不读取真实用户文件、不访问第三方网络、不创建持久任务；真实影响验证应在授权实验环境中完成。",
        },
    ]

    exceeds = [
        "相对焦糖布丁：保留配置/状态目录基线价值，并增加连接后方法授权矩阵与 canary 影响验证。",
        "相对队友 Skill Guard：升级为 Agent Skill Guard 深度审计能力，并把 AI BOM/MCP/hidden instruction/toxic flow 结果纳入四层证据链。",
        "相对 SkillDance：覆盖 Skill 声明/实现差异方向，同时补上 Gateway、状态数据库、动态授权和能力触达链路。",
    ]
    dynamic_statement = (
        "当前可以深入到动态授权逻辑：启用 --dynamic-mode probe 后会执行安全的 HTTP JSON-RPC/WebSocket metadata/dry-run 探测，并输出条件差异矩阵。"
        if dynamic_mode == "probe" and dynamic_results
        else "当前报告处于 plan 模式，只生成授权矩阵；要深入动态授权逻辑，需要使用 --dynamic-mode probe。"
    )
    chain_statement = (
        "当前可以进入能力触达链路的实验准备与本地 synthetic canary 自检；真实文件/网络/任务影响验证仍需授权 lab 场景人工确认。"
        if lab_ready
        else "当前报告只生成能力触达链路的 canary 计划；要布置本地 synthetic canary，需要使用 --canary-mode lab。"
    )
    return {
        "positioning": "多阶段融合型 OpenClaw 信任边界扫描器",
        "layer_status": layer_status,
        "tool_comparison": exceeds,
        "dynamic_authorization": dynamic_statement,
        "capability_chain": chain_statement,
        "github_readiness": [
            "Python 标准库实现主扫描和 Web 前端，默认无需第三方 Python 依赖。",
            "Agent Skill Guard 新版深度引擎作为 engines/agent-skill-guard/bin 接入；没有二进制时降级为轻量 Skill/Agent 扫描并在报告中说明。",
            "reports/ 默认被 .gitignore 忽略，仓库可保持干净；运行后报告保存在本地 reports/。",
        ],
    }


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for layer in report["layers"]:
        findings.extend(layer.get("findings", []))
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    highest = "info"
    for finding in findings:
        if severity_rank.get(finding.get("severity", "info"), 0) > severity_rank[highest]:
            highest = finding.get("severity", "info")
    return {
        "finding_count": len(findings),
        "highest_severity": highest,
        "findings_by_severity": {
            severity: sum(1 for item in findings if item.get("severity") == severity)
            for severity in ["critical", "high", "medium", "low", "info"]
        },
    }


def clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def finding_penalty(findings: list[dict[str, Any]]) -> int:
    weights = {"critical": 34, "high": 24, "medium": 12, "low": 5, "info": 1}
    return sum(weights.get(item.get("severity", "info"), 1) for item in findings)


def visible_findings(layer: dict[str, Any], include_info: bool = False) -> list[dict[str, Any]]:
    findings = layer.get("findings", [])
    if include_info:
        return findings
    return [item for item in findings if item.get("severity") != "info"]


def layer_score(layer: dict[str, Any], base: int = 100) -> int:
    return clamp(base - finding_penalty(visible_findings(layer, include_info=False)))


def layer_status_label(score: int, non_info_count: int, coverage_gap: bool = False) -> str:
    if coverage_gap and non_info_count == 0:
        return "覆盖不足"
    if score < 45:
        return "高风险"
    if score < 70:
        return "需关注"
    if score < 88:
        return "基本可控"
    return "良好"


def build_overall_assessment(report: dict[str, Any]) -> dict[str, Any]:
    l1, l2, l3, l4 = report["layers"]
    findings = [finding for layer in report["layers"] for finding in layer.get("findings", [])]
    non_info_findings = [finding for finding in findings if finding.get("severity") != "info"]
    counts = report["summary"]["findings_by_severity"]
    dynamic_mode = l3.get("dynamic_mode", "plan")
    dynamic_results = l3.get("method_probe_results", [])
    probe_summary = l3.get("method_probe_summary", {})
    accepted_count = len(probe_summary.get("accepted", []))
    difference_count = len(l3.get("difference_matrices", {}).get("condition_differences", []))
    lab_ready = bool(l4.get("lab_setup") and l4.get("lab_observation"))
    guard_runs = l2.get("skill_guard_engine", {}).get("runs", [])
    guard_completed = any(run.get("status") == "completed" for run in guard_runs)
    agent_guard_completed = any(run.get("status") == "completed" and run.get("engine_name") == "agent-skill-guard" for run in guard_runs)
    risk_context = l2.get("risk_context", {})

    l1_score = layer_score(l1)
    if l1.get("sqlite_files"):
        l1_score = clamp(l1_score - min(20, 5 * len(l1.get("sqlite_files", []))))
    if not counts.get("critical", 0) and visible_findings(l1):
        l1_score = max(l1_score, 22)
    l2_base = 96 if agent_guard_completed else (88 if guard_completed else 74)
    l2_score = layer_score(l2, base=l2_base)
    if not l2.get("skills") and not guard_completed:
        l2_score = clamp(l2_score - 10)
    l3_score = layer_score(l3, base=92 if dynamic_mode == "probe" and dynamic_results else 62)
    if accepted_count:
        l3_score = clamp(l3_score - min(35, 4 * accepted_count))
    if difference_count:
        l3_score = clamp(l3_score - min(18, 3 * difference_count))
    l4_score = layer_score(l4, base=90 if lab_ready else 66)

    evidence_score = 55
    evidence_score += 10 if l1.get("config_semantics") else 0
    evidence_score += 10 if l1.get("sqlite_files") else 0
    evidence_score += 10 if agent_guard_completed else 0
    evidence_score += 6 if risk_context.get("ai_bom_packages") else 0
    evidence_score += 15 if dynamic_results else 0
    evidence_score += 10 if lab_ready else 0
    evidence_score = clamp(evidence_score)

    metrics = [
        {"key": "baseline", "label": "配置状态", "score": l1_score, "note": f"配置 {len(l1.get('config_files', []))} 个，SQLite {len(l1.get('sqlite_files', []))} 个，Agent/MCP 引用 {len(l1.get('agent_ecosystem_baseline', {}).get('references', []))} 个"},
        {"key": "skill", "label": "Agent治理", "score": l2_score, "note": f"Skill {len(l2.get('skills', []))} 个，新版深度引擎={'已运行' if agent_guard_completed else '未完成'}，AI BOM {risk_context.get('ai_bom_packages', 0)}"},
        {"key": "authz", "label": "动态授权", "score": l3_score, "note": f"矩阵 {len(l3.get('authorization_matrix', []))} 行，风险驱动族 {len(l3.get('risk_driven_matrix', {}).get('families', []))} 个，探测 {len(dynamic_results)} 条"},
        {"key": "canary", "label": "影响验证", "score": l4_score, "note": f"canary 模式={l4.get('mode')}，风险驱动 {len(l4.get('risk_driven_canaries', []))} 个，lab_ready={lab_ready}"},
        {"key": "evidence", "label": "证据完整度", "score": evidence_score, "note": "配置、状态库、Agent 深度审计、动态探测和 canary 证据综合"},
    ]

    average_score = clamp(sum(item["score"] for item in metrics) / len(metrics))
    risk_index = clamp(100 - average_score)
    if counts.get("critical", 0) or risk_index >= 72:
        level = "高风险"
        conclusion = "当前结果显示存在需要优先处理的高风险信号，应先复核高危发现和动态授权异常。"
    elif counts.get("high", 0) or risk_index >= 50:
        level = "重点关注"
        conclusion = "当前整体可运行，但状态面、授权边界或能力触达链路存在明显关注点，适合进入人工复核阶段。"
    elif counts.get("medium", 0) or risk_index >= 30:
        level = "中等风险"
        conclusion = "当前未出现压倒性高危信号，但仍存在配置和治理层面的改进空间。"
    else:
        level = "低风险"
        conclusion = "当前扫描未发现明显高风险问题，可保留报告作为基线并继续做版本对比。"

    focus_parts: list[str] = []
    if visible_findings(l1):
        focus_parts.append("安装态/状态目录")
    if visible_findings(l2):
        focus_parts.append("Skill 生态")
    if visible_findings(l3):
        focus_parts.append("连接后授权逻辑")
    if visible_findings(l4):
        focus_parts.append("Canary 影响面")
    focus_text = "、".join(focus_parts) if focus_parts else "未发现显著异常层"

    priority_actions: list[str] = []
    finding_ids = {finding.get("id") for finding in findings}
    if "L1-STATE-DB-PLAINTEXT" in finding_ids:
        priority_actions.append("优先复核状态目录内 SQLite 数据库的明文存储、权限和敏感表结构，评估本地文件读取能力下的影响面。")
    if "L1-CONFIG-SECRET-HINT" in finding_ids:
        priority_actions.append("清点配置文件中的 token/API key 痕迹，确认是否需要迁移到外部 secret provider 或降低文件权限。")
    if "L3-METHOD-PROBE-ACCEPTED" in finding_ids:
        priority_actions.append("对返回 accepted 的方法族做人工复核，确认是否只是元数据接口，还是存在越权调用入口。")
    if "L3-CONDITION-DIFFERENCE" in finding_ids:
        priority_actions.append("对 Host/Origin/trusted proxy 条件差异进行复测，确认网络层 trusted/local 结论是否被错误继承。")
    if "L2-AGENT-TOXIC-FLOW" in finding_ids:
        priority_actions.append("优先复核第二层 toxic flow：确认不可信输入、敏感数据面与外联/执行能力是否真的形成可达链路。")
    if "L2-MCP-TOOL-SCHEMA-RISK" in finding_ids:
        priority_actions.append("复核 MCP tool schema、command/env 绑定和来源身份，必要时关闭危险命令或收敛环境变量传递。")
    if not guard_completed:
        priority_actions.append("补充新版 Agent Skill Guard 二进制或确认 engines/agent-skill-guard/bin，使第二层深度审计从降级模式进入完整模式。")
    if not lab_ready:
        priority_actions.append("在授权实验环境中启用 canary lab，将动态授权结果与文件/网络/任务/数据库能力面联动。")
    if not priority_actions:
        priority_actions.append("当前优先保留为安全基线，后续重点做多版本趋势对比。")

    layer_summaries = []
    for idx, layer in enumerate(report["layers"]):
        non_info = visible_findings(layer)
        score = [l1_score, l2_score, l3_score, l4_score][idx]
        coverage_gap = (idx == 1 and not guard_completed) or (idx == 2 and dynamic_mode != "probe") or (idx == 3 and not lab_ready)
        layer_summaries.append(
            {
                "layer": f"第{idx + 1}层",
                "name": LAYER_LABELS[idx],
                "score": score,
                "status": layer_status_label(score, len(non_info), coverage_gap),
                "issue_count": len(non_info),
                "summary": "发现需关注问题" if non_info else ("当前主要是覆盖不足或未启用增强验证" if coverage_gap else "未发现明显问题"),
            }
        )

    omitted_clean_layers = [item["name"] for item in layer_summaries if item["issue_count"] == 0 and item["status"] not in {"覆盖不足", "高风险"}]
    return {
        "level": level,
        "risk_index": risk_index,
        "average_score": average_score,
        "conclusion": conclusion,
        "focus_text": focus_text,
        "metrics": metrics,
        "priority_actions": priority_actions,
        "layer_summaries": layer_summaries,
        "omitted_clean_layers": omitted_clean_layers,
        "compact_policy": "默认只展开存在非信息级发现或覆盖不足的层；无明显问题的详情会在报告正文中自动省略，以降低阅读成本。",
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    openclaw_home = Path(args.openclaw_home).expanduser()
    skill_root = Path(args.skill_root).expanduser() if args.skill_root else None
    canary_dir = Path(args.canary_dir).expanduser() if args.canary_dir else None
    baseline_report = Path(args.baseline_report).expanduser() if args.baseline_report else None
    l1 = layer1_baseline(openclaw_home)
    l2 = layer2_skill_supply_chain(
        skill_root,
        openclaw_home,
        args.skill_guard_engine,
        agent_ecosystem=getattr(args, "agent_ecosystem", True),
        deep_engine_timeout=getattr(args, "deep_engine_timeout", 120),
    )
    risk_context = l2.get("risk_context", {})
    l3 = run_layer3_trust_boundary(
        args.gateway_url,
        args.browser_url,
        args.dynamic_mode,
        args.probe_timeout,
        args.method_probe_limit,
        args.rpc_paths.split(",") if args.rpc_paths else MODULE_DEFAULT_RPC_PATHS,
        version=VERSION,
        risk_context=risk_context,
    )
    l4 = layer4_canary_plan(args.canary_mode, canary_dir, args.canary_url, risk_context)
    report = {
        "reportVersion": "1.2.0",
        "tool": {"name": "ClawMatrix", "version": VERSION},
        "generated_at": utc_now(),
        "subject": {
            "openclaw_home": str(openclaw_home),
            "skill_root": str(skill_root) if skill_root else None,
            "gateway_url": args.gateway_url,
            "browser_url": args.browser_url,
            "dynamic_mode": args.dynamic_mode,
            "canary_mode": args.canary_mode,
            "agent_ecosystem": getattr(args, "agent_ecosystem", True),
            "include_clean_sections": args.include_clean_sections,
            "baseline_report": str(baseline_report) if baseline_report else None,
        },
        "layers": [l1, l2, l3, l4],
    }
    report["summary"] = summarize(report)
    report["capability_assessment"] = assess_tool_capabilities(report)
    report["overall_assessment"] = build_overall_assessment(report)
    report["baseline_diff"] = build_baseline_diff(report, baseline_report)
    report["scan_metadata"] = {
        "coverage": {layer.get("name", f"layer-{index + 1}"): layer.get("coverage", {}) for index, layer in enumerate(report["layers"])},
        "skipped": {
            layer.get("name", f"layer-{index + 1}"): layer.get("skipped_reason")
            for index, layer in enumerate(report["layers"])
            if layer.get("skipped_reason")
        },
    }
    return report


def render_markdown(report: dict[str, Any]) -> str:
    overall = report.get("overall_assessment", {})
    lines = [
        "# ClawMatrix 多阶段融合型 OpenClaw 信任边界扫描报告",
        "",
        f"- 生成时间：`{report['generated_at']}`",
        f"- OpenClaw 状态目录：`{report['subject']['openclaw_home']}`",
        f"- 最高风险：`{SEVERITY_ZH.get(report['summary']['highest_severity'], report['summary']['highest_severity'])}`",
        f"- 发现数量：`{report['summary']['finding_count']}`",
    ]
    
    baseline_diff = report.get("baseline_diff")
    if baseline_diff and not baseline_diff.get("error"):
        lines += [
            "",
            "## 基线对比分析",
            f"- 基线报告文件：`{baseline_diff.get('subject_baseline')}`",
            f"- 总问题数变化：`{baseline_diff.get('finding_count_delta')}`",
            f"- 新增问题数：`{len(baseline_diff.get('new_findings', []))}`",
            f"- 已消失问题数：`{len(baseline_diff.get('disappeared_findings', []))}`",
            f"- 最高新增严重级别：`{SEVERITY_ZH.get(baseline_diff.get('highest_new_severity', 'info'))}`",
            f"- 各层变化：`{json.dumps(baseline_diff.get('layer_deltas', {}), ensure_ascii=False)}`",
        ]
        
    scan_meta = report.get("scan_metadata", {})
    if scan_meta:
        lines += [
            "",
            "## 扫描元数据总览",
            f"- 覆盖率 (Coverage)：`{json.dumps(scan_meta.get('coverage', {}), ensure_ascii=False)}`",
            f"- 跳过原因 (Skipped)：`{json.dumps(scan_meta.get('skipped', {}), ensure_ascii=False)}`",
        ]

    lines += [
        "",
        "## 综合态势评估",
        "",
        f"- 综合等级：`{overall.get('level', '-')}`",
        f"- 风险指数：`{overall.get('risk_index', '-')}/100`",
        f"- 综合评分：`{overall.get('average_score', '-')}/100`",
        f"- 智能评价：{overall.get('conclusion', '-')}",
        f"- 风险集中层：{overall.get('focus_text', '-')}",
        f"- 展示策略：{overall.get('compact_policy', '-')}",
        "",
        "### 能力值面板",
        "",
    ]
    for metric in overall.get("metrics", []):
        lines.append(f"- `{metric['label']}`：{metric['score']}/100；{metric['note']}")
    lines += [
        "",
        "### 优先处理建议",
        "",
    ]
    for action in overall.get("priority_actions", []):
        lines.append(f"- {action}")
    lines += [
        "",
        "## 工具能力评估",
        "",
    ]
    assessment = report.get("capability_assessment", {})
    lines.append(f"- 工具定位：`{assessment.get('positioning', '-')}`")
    lines.append(f"- 动态授权结论：{assessment.get('dynamic_authorization', '-')}")
    lines.append(f"- 能力触达链路结论：{assessment.get('capability_chain', '-')}")
    for item in assessment.get("layer_status", []):
        lines.append(f"- `{item['layer']} {item['name']}`：{item['status']}；证据：{item['evidence']}")
    include_clean = bool(report.get("subject", {}).get("include_clean_sections"))
    shown_layers: list[int] = []
    for idx, layer in enumerate(report["layers"]):
        layer_summary = overall.get("layer_summaries", [{} for _ in report["layers"]])[idx]
        if include_clean or visible_findings(layer) or layer_summary.get("status") == "覆盖不足":
            shown_layers.append(idx)

    if not shown_layers:
        shown_layers = list(range(len(report["layers"])))

    if 0 in shown_layers:
        lines += ["", f"## {LAYER_LABELS[0]}", ""]
    else:
        lines += ["", f"## {LAYER_LABELS[0]}（无明显问题，详情已省略）", ""]
        l1 = None
    if 0 in shown_layers:
        l1 = report["layers"][0]
    if l1 is not None:
        if l1.get("skipped_reason"): lines.append(f"- **跳过执行原因：** {l1['skipped_reason']}")
        lines.append(f"- **覆盖率：** `{json.dumps(l1.get('coverage', {}), ensure_ascii=False)}`")
        lines.append(f"- 已检查配置文件：`{len(l1.get('config_files', []))}`")
        lines.append(f"- 已检查 SQLite 状态库：`{len(l1.get('sqlite_files', []))}`")
        for semantic in l1.get("config_semantics", []):
            lines.append(f"- 配置语义：`{semantic['relative_path']}` 版本=`{semantic.get('version') or '-'}` 信号=`{semantic.get('signals', {})}`")
        for db in l1.get("sqlite_files", []):
            tables = ", ".join(t["name"] for t in db.get("tables", [])[:8])
            lines.append(f"- `{db['path']}` 权限=`{db['mode']}` 风险=`{SEVERITY_ZH.get(db.get('risk', 'info'), db.get('risk', 'info'))}` 表=`{tables}`")

    if 1 in shown_layers:
        lines += ["", f"## {LAYER_LABELS[1]}", ""]
        l2 = report["layers"][1]
        if l2.get("skipped_reason"): lines.append(f"- **跳过执行原因：** {l2['skipped_reason']}")
        lines.append(f"- **覆盖率：** `{json.dumps(l2.get('coverage', {}), ensure_ascii=False)}`")
        lines.append(f"- Skill 根目录：`{', '.join(l2.get('roots', [])) if l2.get('roots') else '无'}`")
        lines.append(f"- 已检查 Skill 数量：`{len(l2.get('skills', []))}`")
        risk_context = l2.get("risk_context", {})
        if risk_context:
            lines.append(
                "- 第二层联动摘要："
                f"AI BOM packages=`{risk_context.get('ai_bom_packages', 0)}`，"
                f"MCP findings=`{risk_context.get('mcp_findings', 0)}`，"
                f"hidden signals=`{risk_context.get('hidden_instruction_signals', 0)}`，"
                f"toxic flows=`{risk_context.get('toxic_flows_count', 0)}`，"
                f"observed=`{risk_context.get('observed_capabilities', [])}`"
            )
        guard_runs = l2.get("skill_guard_engine", {}).get("runs", [])
        if guard_runs:
            lines.append(f"- Agent Skill Guard 深度引擎运行次数：`{len(guard_runs)}`")
            for guard in guard_runs:
                normalized = guard.get("normalized", {})
                lines.append(
                    f"- 深度引擎目标：`{guard['target']}` 引擎=`{guard.get('engine_name')}` 状态=`{guard['status']}` 可用=`{guard['available']}` "
                    f"verdict=`{normalized.get('verdict')}` score=`{normalized.get('score')}` 摘要=`{normalized.get('summary_zh') or '-'}`"
                )
        for skill in l2.get("skills", [])[:30]:
            lines.append(
                f"- `{skill.get('skill', '-')}` 风险=`{SEVERITY_ZH.get(skill.get('severity', 'info'), skill.get('severity', 'info'))}` 声明能力=`{skill.get('declared_capabilities', [])}` 观察能力=`{skill.get('observed_capabilities', [])}` 差异=`{skill.get('capability_mismatch', [])}`"
            )
    else:
        lines += ["", f"## {LAYER_LABELS[1]}（无明显问题，详情已省略）", ""]

    if 2 in shown_layers:
        lines += ["", f"## {LAYER_LABELS[2]}", ""]
        l3 = report["layers"][2]
        if l3.get("skipped_reason"): lines.append(f"- **跳过执行原因：** {l3['skipped_reason']}")
        lines.append(f"- **覆盖率：** `{json.dumps(l3.get('coverage', {}), ensure_ascii=False)}`")
        lines.append(f"- 动态模式：`{l3.get('dynamic_mode', 'plan')}`")
        lines.append(f"- 已生成授权矩阵行数：`{len(l3.get('authorization_matrix', []))}`")
        lines.append(f"- 风险驱动方法族：`{l3.get('risk_driven_matrix', {}).get('families', [])}`")
        lines.append(f"- 方法探测结果：`{l3.get('method_probe_summary', {}).get('by_classification', {})}`")
        for probe in l3.get("http_probes", []):
            lines.append(f"- 探测 `{probe['url']}` 可达=`{probe.get('reachable')}` 状态码=`{probe.get('status', '-')}`")
    else:
        lines += ["", f"## {LAYER_LABELS[2]}（无明显问题，详情已省略）", ""]

    if 3 in shown_layers:
        lines += ["", f"## {LAYER_LABELS[3]}", ""]
        l4 = report["layers"][3]
        if l4.get("skipped_reason"): lines.append(f"- **跳过执行原因：** {l4['skipped_reason']}")
        lines.append(f"- **覆盖率：** `{json.dumps(l4.get('coverage', {}), ensure_ascii=False)}`")
        lines.append(f"- Canary 模式：`{l4.get('mode')}`")
        lines.append(f"- 风险驱动 Canary：`{[item.get('id') for item in l4.get('risk_driven_canaries', [])]}`")
        if l4.get("lab_setup"):
            lines.append(f"- 实验 canary：`{l4['lab_setup']}`")
        for canary in l4.get("canaries", []):
            lines.append(f"- `{canary.get('id', '-')}` 能力面=`{canary.get('surface', '-')}` 安全信号=`{canary.get('safe_signal', '-')}`")
    else:
        lines += ["", f"## {LAYER_LABELS[3]}（无明显问题，详情已省略）", ""]

    lines += ["", "## 风险发现", ""]
    compact_findings = [finding for layer in report["layers"] for finding in visible_findings(layer)]
    if not compact_findings:
        compact_findings = [finding for layer in report["layers"] for finding in layer.get("findings", [])]
    for finding in compact_findings:
        lines.append(f"- `{SEVERITY_ZH.get(finding.get('severity', 'info'), finding.get('severity', 'info'))}` `{finding.get('id', '-')}` {finding.get('title', '-')}")
    return "\n".join(lines) + "\n"


def html_escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def severity_badge(severity: str) -> str:
    label = SEVERITY_ZH.get(severity, severity)
    return f'<span class="badge severity-{html_escape(severity)}">{html_escape(label)}</span>'


def radar_svg(metrics: list[dict[str, Any]]) -> str:
    if not metrics:
        return ""
    cx, cy, radius = 200, 165, 92

    def point(index: int, scale: float) -> tuple[float, float]:
        angle = -math.pi / 2 + 2 * math.pi * index / len(metrics)
        return cx + radius * scale * math.cos(angle), cy + radius * scale * math.sin(angle)

    grid = []
    for scale in [0.25, 0.5, 0.75, 1.0]:
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in [point(i, scale) for i in range(len(metrics))])
        grid.append(f'<polygon points="{pts}" fill="none" stroke="#e5e7ef" stroke-width="1"/>')

    axes = []
    labels = []
    value_points = []
    for idx, metric in enumerate(metrics):
        x, y = point(idx, 1.0)
        axes.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="#e5e7ef" stroke-width="1"/>')
        lx, ly = point(idx, 1.28)
        anchor = "middle"
        if lx < cx - 15:
            anchor = "end"
        elif lx > cx + 15:
            anchor = "start"
        labels.append(
            f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" dominant-baseline="middle" '
            f'font-size="12" font-weight="600" fill="#344054">{html_escape(metric["label"])} {html_escape(metric.get("score", "-"))}</text>'
        )
        
        raw_score = metric.get("score", 0)
        safe_score = float(raw_score) if isinstance(raw_score, (int, float)) else 0
        vx, vy = point(idx, max(0, min(100, safe_score)) / 100)
        value_points.append(f"{vx:.1f},{vy:.1f}")

    return (
        '<svg class="radar-svg" viewBox="0 0 400 330" role="img" aria-label="综合能力雷达图">'
        + "".join(grid)
        + "".join(axes)
        + f'<polygon points="{" ".join(value_points)}" fill="rgba(212,66,50,.22)" stroke="#d44232" stroke-width="3"/>'
        + "".join(labels)
        + f'<circle cx="{cx}" cy="{cy}" r="3" fill="#d44232"/>'
        + "</svg>"
    )


def render_html(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    layers = report.get("layers", [{}, {}, {}, {}])
    l1 = layers[0] if len(layers) > 0 else {}
    l2 = layers[1] if len(layers) > 1 else {}
    l3 = layers[2] if len(layers) > 2 else {}
    l4 = layers[3] if len(layers) > 3 else {}
    
    severity_counts = summary.get("findings_by_severity", {})
    
    def visible_findings(layer: dict[str, Any]) -> list[dict[str, Any]]:
        return [item for item in layer.get("findings", []) if item.get("severity") != "info"]

    compact_findings = [finding for layer in layers for finding in visible_findings(layer)]
    if not compact_findings:
        compact_findings = [finding for layer in layers for finding in layer.get("findings", [])]

    assessment = report.get("capability_assessment", {})
    overall = report.get("overall_assessment", {})
    include_clean = bool(report.get("subject", {}).get("include_clean_sections"))

    radar = radar_svg(overall.get("metrics", []))
    action_items = "".join(f"<li>{html_escape(item)}</li>" for item in overall.get("priority_actions", []))
    metric_cards = "".join(
        '<div class="metric-mini">'
        f'<span>{html_escape(item.get("label", "-"))}</span>'
        f'<strong>{html_escape(item.get("score", "-"))}</strong>'
        f'<small>{html_escape(item.get("note", ""))}</small>'
        "</div>"
        for item in overall.get("metrics", [])
    )
    layer_summary_cards = "".join(
        '<div class="layer-summary-card">'
        f'<b>{html_escape(item.get("name", "-"))}</b>'
        f'<span class="layer-status">{html_escape(item.get("status", "-"))}</span>'
        f'<strong>{html_escape(item.get("score", "-"))}/100</strong>'
        f'<p>{html_escape(item.get("summary", "-"))}；问题数：{html_escape(item.get("issue_count", 0))}</p>'
        "</div>"
        for item in overall.get("layer_summaries", [])
    )
    omitted_clean = overall.get("omitted_clean_layers", [])
    omitted_note = (
        "<p class=\"muted\"><b>已自动省略无明显问题详情：</b>"
        + html_escape("、".join(omitted_clean))
        + "</p>"
        if omitted_clean and not include_clean
        else ""
    )

    capability_cards = []
    for item in assessment.get("layer_status", []):
        capability_cards.append(
            '<div class="cap-card">'
            f"<h3>{html_escape(item.get('layer', ''))}：{html_escape(item.get('name', ''))}</h3>"
            f"<p><b>运行状态：</b>{html_escape(item.get('status', ''))}</p>"
            f"<p><b>证据：</b>{html_escape(item.get('evidence', ''))}</p>"
            f"<p><b>对标：</b>{html_escape(item.get('maps_to', ''))}</p>"
            f"<p><b>优势：</b>{html_escape(item.get('advantage', ''))}</p>"
            f"<p><b>边界：</b>{html_escape(item.get('gap', ''))}</p>"
            "</div>"
        )
        
    config_rows = []
    for semantic in l1.get("config_semantics", []):
        config_rows.append(
            "<tr>"
            f"<td>{html_escape(semantic.get('relative_path', '-'))}</td>"
            f"<td>{html_escape(semantic.get('version') or '-')}</td>"
            f"<td><code>{html_escape(json.dumps(semantic.get('signals', {}), ensure_ascii=False)[:800])}</code></td>"
            "</tr>"
        )

    db_rows = []
    for db in l1.get("sqlite_files", []):
        tables = ", ".join(t["name"] for t in db.get("tables", [])[:10])
        db_rows.append(
            "<tr>"
            f"<td>{html_escape(db['path'])}</td>"
            f"<td>{html_escape(db['mode'])}</td>"
            f"<td>{severity_badge(db.get('risk', 'info'))}</td>"
            f"<td>{html_escape(tables or '-')}</td>"
            f"<td>{html_escape(db.get('size', '-'))}</td>"
            "</tr>"
        )

    agent_ref_rows = []
    for ref in l1.get("agent_ecosystem_baseline", {}).get("references", [])[:30]:
        agent_ref_rows.append(
            "<tr>"
            f"<td>{html_escape(ref.get('relative_path', ref.get('path', '-')))}</td>"
            f"<td>{html_escape(', '.join(ref.get('signals', [])) or '-')}</td>"
            f"<td>{html_escape(ref.get('size', '-'))}</td>"
            "</tr>"
        )

    skill_rows = []
    for skill in l2.get("skills", [])[:80]:
        frontmatter_info = "解析成功" if skill.get("frontmatter", {}).get("present") else "无"
        files_cons = skill.get('files_considered', '-')
        files_scan = skill.get('files_scanned', '-')
        skip_large = skill.get('skipped_large_files', '-')
        trunc = skill.get('truncated', '-')
        scan_meta_text = f"FM:{frontmatter_info} | 考虑:{files_cons} | 扫描:{files_scan} | 跳过大文件:{skip_large} | 截断:{trunc}"
        skill_rows.append(
            "<tr>"
            f"<td>{html_escape(skill.get('skill', '-'))}<br><small class='muted'>{html_escape(scan_meta_text)}</small></td>"
            f"<td>{severity_badge(skill.get('severity', 'info'))}</td>"
            f"<td>{html_escape(', '.join(skill.get('declared_capabilities', [])) or '-')}</td>"
            f"<td>{html_escape(', '.join(skill.get('observed_capabilities', [])) or '-')}</td>"
            f"<td>{html_escape(', '.join(skill.get('capability_mismatch', [])) or '-')}</td>"
            "</tr>"
        )

    guard_rows = []
    for guard in l2.get("skill_guard_engine", {}).get("runs", []):
        normalized = guard.get("normalized", {})
        summary_text = (
            f"引擎={guard.get('engine_name') or '-'}；"
            f"verdict={normalized.get('verdict') or '-'}；"
            f"score={normalized.get('score') if normalized.get('score') is not None else '-'}；"
            f"AI BOM={normalized.get('ai_bom_packages', 0)}；"
            f"MCP={normalized.get('mcp_findings', 0)}；"
            f"toxic={normalized.get('toxic_flows_count', 0)}；"
            f"{normalized.get('summary_zh') or ''}"
        )
        guard_rows.append(
            "<tr>"
            f"<td>{html_escape(guard.get('target', '-'))}</td>"
            f"<td>{html_escape(guard.get('status', '-'))}</td>"
            f"<td>{html_escape('是' if guard.get('available') else '否')}</td>"
            f"<td>{html_escape(guard.get('error') or summary_text or '-')}</td>"
            "</tr>"
        )

    l2_risk = l2.get("risk_context", {})
    l2_risk_html = ""
    if l2_risk:
        l2_risk_html = f"""
        <div class="analysis-box">
          <p><b>新版 Agent Skill Guard 联动摘要：</b>
          AI BOM packages={html_escape(l2_risk.get('ai_bom_packages', 0))}；
          Agent packages={html_escape(l2_risk.get('agent_packages', 0))}；
          MCP findings={html_escape(l2_risk.get('mcp_findings', 0))}；
          hidden signals={html_escape(l2_risk.get('hidden_instruction_signals', 0))}；
          toxic flows={html_escape(l2_risk.get('toxic_flows_count', 0))}；
          observed={html_escape(l2_risk.get('observed_capabilities', []))}</p>
          <p><b>Top risks：</b>{html_escape('；'.join(l2_risk.get('top_risks', [])[:8]) or '-')}</p>
        </div>
        """

    probe_rows = []
    for probe in l3.get("http_probes", []):
        probe_rows.append(
            "<tr>"
            f"<td>{html_escape(probe.get('url', '-'))}</td>"
            f"<td>{html_escape('可达' if probe.get('reachable') else '不可达')}</td>"
            f"<td>{html_escape(probe.get('status', '-') or '-')}</td>"
            f"<td>{html_escape(probe.get('error', '-') or '-')}</td>"
            "</tr>"
        )

    matrix_rows = []
    for row in l3.get("authorization_matrix", []):
        matrix_rows.append(
            "<tr>"
            f"<td>{html_escape(row.get('method_family', '-'))}</td>"
            f"<td>{html_escape(row.get('probe_method', '-'))}</td>"
            f"<td>{html_escape(row.get('meaning', '-'))}</td>"
            f"<td>{html_escape(row.get('scenario', '-'))}</td>"
            f"<td>{html_escape(row.get('expected_policy', '-'))}</td>"
            f"<td>{html_escape(row.get('status', '-'))}</td>"
            "</tr>"
        )

    method_probe_rows = []
    for result in l3.get("method_probe_results", [])[:200]:
        method_probe_rows.append(
            "<tr>"
            f"<td>{html_escape(result.get('transport', '-'))}</td>"
            f"<td>{html_escape(result.get('scenario', '-'))}</td>"
            f"<td>{html_escape(result.get('method', '-'))}</td>"
            f"<td>{html_escape(result.get('classification', '-'))}</td>"
            f"<td>{html_escape(result.get('status_code', result.get('handshake_status', '-')))}</td>"
            f"<td>{html_escape(result.get('elapsed_ms', '-'))}</td>"
            "</tr>"
        )

    canary_cards = []
    for canary in l4.get("canaries", []):
        canary_cards.append(
            '<div class="canary-card">'
            f"<h4>{html_escape(canary.get('id', '-'))}</h4>"
            f"<p><b>能力面：</b>{html_escape(canary.get('surface', '-'))}</p>"
            f"<p><b>安全信号：</b>{html_escape(canary.get('safe_signal', '-'))}</p>"
            f"<p><b>应阻断条件：</b>{html_escape(canary.get('blocked_if', '-'))}</p>"
            "</div>"
        )
    if l4.get("lab_setup"):
        canary_cards.append(
            '<div class="canary-card">'
            "<h4>lab-setup</h4>"
            f"<p><b>实验目录：</b><code>{html_escape(l4['lab_setup'].get('root'))}</code></p>"
            f"<p><b>文件标记：</b><code>{html_escape(l4['lab_setup'].get('file_marker'))}</code></p>"
            f"<p><b>状态库标记：</b><code>{html_escape(l4['lab_setup'].get('sqlite_marker'))}</code></p>"
            "</div>"
        )

    finding_rows = []
    for finding in compact_findings:
        evidence = json.dumps(finding.get("evidence", ""), ensure_ascii=False)
        finding_rows.append(
            "<tr>"
            f"<td>{severity_badge(finding.get('severity', 'info'))}</td>"
            f"<td>{html_escape(finding.get('id', '-'))}</td>"
            f"<td>{html_escape(finding.get('title', '-'))}</td>"
            f"<td><code>{html_escape(evidence[:600])}</code></td>"
            "</tr>"
        )

    detail_sections: list[str] = []

    def should_show_layer(index: int, layer: dict[str, Any]) -> bool:
        layer_summary = overall.get("layer_summaries", [{} for _ in layers])[index]
        return include_clean or bool(visible_findings(layer)) or layer_summary.get("status") in {"覆盖不足", "高风险"}
        
    baseline_diff = report.get("baseline_diff")
    baseline_html = ""
    if baseline_diff and not baseline_diff.get("error"):
        baseline_html = f"""
        <div style="margin-top: 16px; padding: 16px; background: #fffdfc; border-radius: 12px; border: 1px solid var(--line);">
            <h3 style="margin-top: 0;">📊 基线对比分析</h3>
            <ul style="margin: 0; padding-left: 20px; line-height: 1.8; font-size: 13px;">
                <li><b>基线报告文件：</b> <code>{html_escape(baseline_diff.get('subject_baseline', '-'))}</code></li>
                <li><b>总问题数变化：</b> {html_escape(baseline_diff.get('finding_count_delta', 0))}</li>
                <li><b>新增问题数：</b> {len(baseline_diff.get('new_findings', []))}</li>
                <li><b>已消失问题数：</b> {len(baseline_diff.get('disappeared_findings', []))}</li>
                <li><b>最高新增严重级别：</b> {severity_badge(baseline_diff.get('highest_new_severity', 'info'))}</li>
                <li><b>各层 Finding 变化：</b> <code>{html_escape(json.dumps(baseline_diff.get('layer_deltas', {}), ensure_ascii=False))}</code></li>
            </ul>
        </div>
        """

    if should_show_layer(0, l1):
        l1_coverage = l1.get("coverage", {})
        l1_skipped = l1.get("skipped_reason")
        l1_meta_html = f"<p class='muted'><b>层级覆盖率 (Coverage)：</b><code>{html_escape(json.dumps(l1_coverage, ensure_ascii=False))}</code></p>"
        if l1_skipped:
            l1_meta_html += f"<p style='color:var(--high); font-weight:bold;'>跳过执行原因 (Skipped Reason)： {html_escape(l1_skipped)}</p>"
            
        detail_sections.append(
            f"""
    <section>
      <h2><span class="phase">1</span>{LAYER_LABELS[0]}</h2>
      <p class="muted">检查 OpenClaw 配置、认证材料、设备身份、状态目录和 SQLite 明文状态库，判断静态风险是否可作为后续影响链的证据基础。</p>
      {l1_meta_html}
      <h3>配置语义基线</h3>
      <table><thead><tr><th>配置</th><th>版本</th><th>安全信号</th></tr></thead><tbody>{''.join(config_rows) or '<tr><td colspan="3">未发现 openclaw.json</td></tr>'}</tbody></table>
      <h3>SQLite 状态库</h3>
      <table><thead><tr><th>路径</th><th>权限</th><th>风险</th><th>表结构摘要</th><th>大小</th></tr></thead><tbody>{''.join(db_rows) or '<tr><td colspan="5">未发现 SQLite 状态库</td></tr>'}</tbody></table>
      <h3>Agent/MCP 配置基线</h3>
      <table><thead><tr><th>配置引用</th><th>信号</th><th>大小</th></tr></thead><tbody>{''.join(agent_ref_rows) or '<tr><td colspan="3">未发现 Agent/MCP 配置引用</td></tr>'}</tbody></table>
    </section>"""
        )

    if should_show_layer(1, l2):
        l2_coverage = l2.get("coverage", {})
        l2_skipped = l2.get("skipped_reason")
        l2_meta_html = f"<p class='muted'><b>层级覆盖率 (Coverage)：</b><code>{html_escape(json.dumps(l2_coverage, ensure_ascii=False))}</code></p>"
        if l2_skipped:
            l2_meta_html += f"<p style='color:var(--high); font-weight:bold;'>跳过执行原因 (Skipped Reason)： {html_escape(l2_skipped)}</p>"
            
        detail_sections.append(
            f"""
    <section>
      <h2><span class="phase">2</span>{LAYER_LABELS[1]}</h2>
      <p class="muted">检查 Skill/Agent 声明能力与实现行为是否一致，并识别文件、网络、进程、浏览器、计划任务、prompt injection、MCP schema、AI BOM、隐藏指令和 toxic flow 等风险信号。本层包含 ClawMatrix 轻量识别和新版 Agent Skill Guard 深度引擎。</p>
      {l2_meta_html}
      {l2_risk_html}
      <h3>Agent Skill Guard 深度引擎</h3>
      <table><thead><tr><th>目标</th><th>状态</th><th>可用</th><th>说明</th></tr></thead><tbody>{''.join(guard_rows) or '<tr><td colspan="4">未运行深度引擎</td></tr>'}</tbody></table>
      <h3>ClawMatrix 轻量能力识别</h3>
      <table><thead><tr><th>Skill</th><th>风险</th><th>声明能力</th><th>观察能力</th><th>能力差异</th></tr></thead><tbody>{''.join(skill_rows) or '<tr><td colspan="5">未发现可扫描 Skill</td></tr>'}</tbody></table>
    </section>"""
        )

    if should_show_layer(2, l3):
        l3_coverage = l3.get("coverage", {})
        l3_skipped = l3.get("skipped_reason")
        l3_meta_html = f"<p class='muted'><b>层级覆盖率 (Coverage)：</b><code>{html_escape(json.dumps(l3_coverage, ensure_ascii=False))}</code></p>"
        if l3_skipped:
            l3_meta_html += f"<p style='color:var(--high); font-weight:bold;'>跳过执行原因 (Skipped Reason)： {html_escape(l3_skipped)}</p>"
            
        method_families_count = len(set(row.get('method_family') for row in l3.get("authorization_matrix", [])))
        probe_results_count = len(l3.get("method_probe_results", []))
        condition_diff_count = len(l3.get("difference_matrices", {}).get("condition_differences", []))
        
        l3_meta_html += f"""
        <ul class="muted" style="font-size: 13px; background: #fafafa; padding: 12px 12px 12px 30px; border-radius: 8px;">
            <li><b>Method Family 数量：</b> {method_families_count}</li>
            <li><b>实际 Probe 结果数：</b> {probe_results_count}</li>
            <li><b>Condition Difference 数量：</b> {condition_diff_count}</li>
            <li><b>第二层风险驱动方法族：</b> {html_escape(l3.get("risk_driven_matrix", {}).get("families", []))}</li>
        </ul>
        """
        
        detail_sections.append(
            f"""
    <section>
      <h2><span class="phase">3</span>{LAYER_LABELS[2]}</h2>
      <p class="muted">围绕连接建立之后身份与策略是否被正确保留，生成 Host、Origin、loopback、nip.io、trusted proxy、WebSocket upgrade 条件下的方法族授权矩阵。</p>
      {l3_meta_html}
      <p><b>动态模式：</b>{html_escape(l3.get('dynamic_mode', 'plan'))} <b>探测摘要：</b><code>{html_escape(json.dumps(l3.get('method_probe_summary', {}), ensure_ascii=False))}</code></p>
      <h3>轻量连通性探测</h3>
      <table><thead><tr><th>地址</th><th>结果</th><th>状态码</th><th>错误</th></tr></thead><tbody>{''.join(probe_rows) or '<tr><td colspan="4">未配置探测地址</td></tr>'}</tbody></table>
      <h3>动态方法探测结果</h3>
      <table><thead><tr><th>传输</th><th>场景</th><th>方法</th><th>分类</th><th>状态</th><th>耗时 ms</th></tr></thead><tbody>{''.join(method_probe_rows) or '<tr><td colspan="6">未启用动态方法探测</td></tr>'}</tbody></table>
      <h3>方法授权矩阵</h3>
      <table><thead><tr><th>方法族</th><th>探测方法</th><th>含义</th><th>场景</th><th>期望策略</th><th>当前状态</th></tr></thead><tbody>{''.join(matrix_rows)}</tbody></table>
    </section>"""
        )

    if should_show_layer(3, l4):
        l4_coverage = l4.get("coverage", {})
        l4_skipped = l4.get("skipped_reason")
        l4_meta_html = f"<p class='muted'><b>层级覆盖率 (Coverage)：</b><code>{html_escape(json.dumps(l4_coverage, ensure_ascii=False))}</code></p>"
        if l4_skipped:
            l4_meta_html += f"<p style='color:var(--high); font-weight:bold;'>跳过执行原因 (Skipped Reason)： {html_escape(l4_skipped)}</p>"
            
        detail_sections.append(
            f"""
    <section>
      <h2><span class="phase">4</span>{LAYER_LABELS[3]}</h2>
      <p class="muted">使用无害 canary 验证风险是否从“能连接/能调用”继续扩大到文件、网络、任务、状态数据库等高价值能力面。</p>
      {l4_meta_html}
      <p><b>Canary 模式：</b>{html_escape(l4.get('mode', '-'))}</p>
      <div class="grid2">{''.join(canary_cards)}</div>
    </section>"""
        )

    scan_meta = report.get("scan_metadata", {})
    if scan_meta:
        scan_meta_html = f"""
        <section style="background: #fafafa; border-style: dashed;">
          <h2><span class="phase" style="background:#667085">🗃️</span>扫描元数据总览 (Scan Metadata)</h2>
          <p class="muted" style="margin-bottom: 4px;"><b>覆盖率总计 (Coverage)：</b></p>
          <code style="display:block; padding: 12px; background: white; border-radius: 6px; border: 1px solid var(--line); margin-bottom: 12px;">{html_escape(json.dumps(scan_meta.get("coverage", {}), ensure_ascii=False, indent=2))}</code>
          <p class="muted" style="margin-bottom: 4px;"><b>跳过原因汇总 (Skipped)：</b></p>
          <code style="display:block; padding: 12px; background: white; border-radius: 6px; border: 1px solid var(--line);">{html_escape(json.dumps(scan_meta.get("skipped", {}), ensure_ascii=False, indent=2))}</code>
        </section>
        """
        detail_sections.append(scan_meta_html)

    html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ClawMatrix OpenClaw 信任边界扫描报告</title>
  <style>
    :root {{
      --bg: #f6f7fb;
      --panel: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #e5e7ef;
      --brand: #d44232;
      --brand-dark: #8f2118;
      --high: #d92d20;
      --medium: #f79009;
      --low: #1570ef;
      --info: #667085;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: "Microsoft YaHei", "Noto Sans CJK SC", sans-serif; }}
    
    header {{ padding: 34px 0; color: white; background: linear-gradient(135deg, #210f0d, #7c1f16 46%, #ef6a43); }}
    .header-inner {{ max-width: 1280px; margin: 0 auto; padding: 0 24px; }}
    
    header h1 {{ margin: 0 0 10px; font-size: 30px; letter-spacing: .02em; }}
    header p {{ margin: 0; max-width: 980px; color: #ffe2db; line-height: 1.7; }}
    main {{ max-width: 1280px; margin: -24px auto 48px; padding: 0 24px; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-bottom: 18px; }}
    .card, section {{ background: var(--panel); border: 1px solid var(--line); border-radius: 18px; box-shadow: 0 10px 28px rgba(23,32,51,.08); }}
    .card {{ padding: 20px; }}
    .card span {{ color: var(--muted); font-size: 13px; }}
    .card strong {{ display: block; margin-top: 8px; font-size: 28px; }}
    .overview-grid {{ display: grid; grid-template-columns: 1.05fr .95fr; gap: 18px; align-items: stretch; }}
    .overall-hero {{ display: grid; grid-template-columns: 150px 1fr; gap: 18px; align-items: center; }}
    .risk-dial {{ width: 136px; height: 136px; border-radius: 999px; display: grid; place-items: center; color: white; background: conic-gradient(var(--brand) calc(var(--risk) * 1%), #f1d8cf 0); box-shadow: inset 0 0 0 12px rgba(255,255,255,.28); }}
    .risk-dial strong {{ font-size: 34px; line-height: 1; }}
    .risk-dial span {{ display: block; font-size: 12px; opacity: .9; text-align: center; }}
    .overall-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .overall-title h2 {{ margin: 0; }}
    .level-pill {{ display: inline-flex; border-radius: 999px; padding: 6px 12px; background: #fff1ec; color: var(--brand-dark); font-weight: 800; }}
    .priority-list {{ margin: 12px 0 0; padding-left: 20px; line-height: 1.75; }}
    .metric-grid {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; margin-top: 14px; }}
    .metric-mini {{ border: 1px solid var(--line); border-radius: 14px; padding: 12px; background: #fffdfb; }}
    .metric-mini span {{ color: var(--muted); font-size: 12px; }}
    .metric-mini strong {{ display: block; font-size: 24px; margin: 4px 0; color: var(--brand-dark); }}
    .metric-mini small {{ display: block; color: var(--muted); line-height: 1.45; }}
    .radar-wrap {{ display: grid; place-items: center; min-height: 360px; overflow: visible; }}
    .radar-svg {{ width: 100%; max-width: 460px; height: auto; overflow: visible; }}
    .layer-summary-grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 14px; }}
    .layer-summary-card {{ border: 1px solid var(--line); border-radius: 14px; padding: 14px; background: linear-gradient(180deg, #fff, #fbfcff); }}
    .layer-summary-card b {{ display: block; color: var(--brand-dark); min-height: 38px; }}
    .layer-summary-card strong {{ display: block; font-size: 24px; margin-top: 8px; }}
    .layer-summary-card p {{ margin: 6px 0 0; color: var(--muted); line-height: 1.5; font-size: 12px; }}
    .layer-status {{ display: inline-flex; margin-top: 8px; padding: 4px 9px; border-radius: 999px; background: #eef4ff; color: #174ea6; font-size: 12px; font-weight: 800; }}
    section {{ margin: 18px 0; padding: 24px; }}
    h2 {{ margin: 0 0 14px; font-size: 20px; }}
    h3 {{ margin: 18px 0 10px; font-size: 16px; color: var(--brand-dark); }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 12px; }}
    th, td {{ padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ background: #faf3f1; color: #5c271f; }}
    code {{ white-space: pre-wrap; word-break: break-all; color: #344054; }}
    .badge {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 4px 10px; color: white; font-size: 12px; font-weight: 700; }}
    .severity-critical, .severity-high {{ background: var(--high); }}
    .severity-medium {{ background: var(--medium); }}
    .severity-low {{ background: var(--low); }}
    .severity-info {{ background: var(--info); }}
    .grid2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .canary-card {{ border: 1px solid var(--line); border-radius: 14px; padding: 16px; background: #fffdfc; }}
    .canary-card h4 {{ margin: 0 0 8px; color: var(--brand-dark); }}
    .cap-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .cap-card {{ border: 1px solid var(--line); border-radius: 16px; padding: 16px; background: linear-gradient(180deg, #fff, #fff8f4); }}
    .cap-card h3 {{ margin-top: 0; color: var(--brand-dark); }}
    .analysis-box {{ border-left: 5px solid var(--brand); background: #fff7f2; border-radius: 14px; padding: 16px 18px; line-height: 1.75; }}
    .muted {{ color: var(--muted); }}
    .phase {{ display: inline-block; margin-right: 8px; width: 28px; height: 28px; line-height: 28px; text-align: center; border-radius: 9px; background: var(--brand); color: white; font-weight: 800; }}
    @media (max-width: 920px) {{ .cards, .grid2, .overview-grid, .metric-grid, .layer-summary-grid, .overall-hero {{ grid-template-columns: 1fr; }} main {{ padding: 0 12px; }} .header-inner {{ padding: 0 20px; }} }}
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <h1>ClawMatrix 多阶段融合型 OpenClaw 信任边界扫描报告</h1>
      <p>本报告按四层架构组织：安装态与状态面、Skill 生态、连接后信任边界、Canary 影响面。工具目标不是单点静态扫描，而是把 OpenClaw 的配置、状态目录、Gateway、Control UI、browser-control、内部方法族与高价值能力面放在同一条证据链中分析。</p>
    </div>
  </header>
  <main>
    <div class="cards">
      <div class="card"><span>最高风险</span><strong>{severity_badge(summary.get('highest_severity', 'info'))}</strong></div>
      <div class="card"><span>风险发现</span><strong>{html_escape(summary.get('finding_count', 0))}</strong></div>
      <div class="card"><span>授权矩阵</span><strong>{html_escape(len(l3.get('authorization_matrix', [])))}</strong></div>
      <div class="card"><span>SQLite 状态库</span><strong>{html_escape(len(l1.get('sqlite_files', [])))}</strong></div>
    </div>
    <section>
      <div class="overview-grid">
        <div>
          <div class="overall-hero">
            <div class="risk-dial" style="--risk:{html_escape(overall.get('risk_index', 0))}">
              <div><strong>{html_escape(overall.get('risk_index', '-'))}</strong><span>风险指数 / 100</span></div>
            </div>
            <div>
              <div class="overall-title">
                <h2>综合态势评估</h2>
                <span class="level-pill">{html_escape(overall.get('level', '-'))}</span>
              </div>
              <p><b>智能评价：</b>{html_escape(overall.get('conclusion', '-'))}</p>
              <p><b>风险集中层：</b>{html_escape(overall.get('focus_text', '-'))}</p>
              <p class="muted">{html_escape(overall.get('compact_policy', '-'))}</p>
            </div>
          </div>
          <h3>优先处理建议</h3>
          <ol class="priority-list">{action_items}</ol>
          {baseline_html}
        </div>
        <div class="radar-wrap">{radar}</div>
      </div>
      <h3>各方面能力值</h3>
      <div class="metric-grid">{metric_cards}</div>
      <h3>四层摘要</h3>
      <div class="layer-summary-grid">{layer_summary_cards}</div>
      {omitted_note}
    </section>
    <section>
      <h2>总体信息</h2>
      <p><b>生成时间：</b>{html_escape(report.get('generated_at', '-'))}</p>
      <p><b>OpenClaw 状态目录：</b><code>{html_escape(report.get('subject', {}).get('openclaw_home', '-'))}</code></p>
      <p><b>风险分布：</b>严重 {html_escape(severity_counts.get('critical', 0))}，高危 {html_escape(severity_counts.get('high', 0))}，中危 {html_escape(severity_counts.get('medium', 0))}，低危 {html_escape(severity_counts.get('low', 0))}，信息 {html_escape(severity_counts.get('info', 0))}</p>
    </section>
    <section>
      <h2>工具能力评估与对标分析</h2>
      <div class="analysis-box">
        <p><b>工具定位：</b>{html_escape(assessment.get('positioning', '-'))}</p>
        <p><b>动态授权逻辑：</b>{html_escape(assessment.get('dynamic_authorization', '-'))}</p>
        <p><b>能力触达链路：</b>{html_escape(assessment.get('capability_chain', '-'))}</p>
      </div>
      <h3>四层运行能力</h3>
      <div class="cap-grid">{''.join(capability_cards)}</div>
    </section>
    {''.join(detail_sections)}
    <section>
      <h2>风险发现明细</h2>
      <table><thead><tr><th>等级</th><th>编号</th><th>标题</th><th>证据摘要</th></tr></thead><tbody>{''.join(finding_rows) or '<tr><td colspan="4">暂无风险发现</td></tr>'}</tbody></table>
    </section>
  </main>
</body>
</html>"""
    return html_doc


def write_output(data: str, out: str | None) -> None:
    if not out:
        print(data)
        return
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="clawmatrix_scan.py",
        description="ClawMatrix 多阶段融合型 OpenClaw 信任边界扫描器。",
    )
    parser.add_argument("--openclaw-home", default="~/.openclaw", help="OpenClaw state directory, usually ~/.openclaw")
    parser.add_argument("--skill-root", default=None, help="Optional skill root or workspace to inspect")
    parser.add_argument("--gateway-url", default=None, help="Optional safe HTTP probe URL, e.g. http://127.0.0.1:18789/")
    parser.add_argument("--browser-url", default=None, help="Optional safe browser sidecar probe URL, e.g. http://127.0.0.1:18791/")
    parser.add_argument(
        "--agent-guard-engine",
        dest="skill_guard_engine",
        choices=["auto", "off", "on"],
        default="auto",
        help="Whether to run the layer-2 Agent Skill Guard deep engine. Missing engine degrades to lightweight scan.",
    )
    parser.add_argument(
        "--skill-guard-engine",
        dest="skill_guard_engine",
        choices=["auto", "off", "on"],
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--agent-ecosystem",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable generic Agent/MCP/prompt package parsing in the Agent Skill Guard deep engine.",
    )
    parser.add_argument(
        "--deep-engine-timeout",
        type=int,
        default=120,
        help="Timeout in seconds for each layer-2 deep engine run.",
    )
    parser.add_argument(
        "--dynamic-mode",
        choices=["plan", "probe"],
        default="plan",
        help="Layer-3 mode. plan only emits the matrix; probe performs safe metadata/dry-run method authorization probes.",
    )
    parser.add_argument("--probe-timeout", type=float, default=MODULE_DEFAULT_PROBE_TIMEOUT, help="Timeout in seconds for each dynamic probe.")
    parser.add_argument(
        "--rpc-paths",
        default=",".join(MODULE_DEFAULT_RPC_PATHS),
        help="Comma-separated HTTP/WebSocket RPC path candidates used in --dynamic-mode probe.",
    )
    parser.add_argument(
        "--method-probe-limit",
        type=int,
        default=0,
        help="Limit layer-3 matrix rows to probe. 0 means all rows.",
    )
    parser.add_argument(
        "--canary-mode",
        choices=["plan", "lab"],
        default="plan",
        help="Layer-4 mode. lab creates local synthetic canary markers under --canary-dir or temp.",
    )
    parser.add_argument("--canary-dir", default=None, help="Directory for lab canary markers when --canary-mode lab is used.")
    parser.add_argument("--canary-url", default=None, help="Optional lab-controlled URL to print as a network canary observer path.")
    parser.add_argument(
        "--include-clean-sections",
        action="store_true",
        help="Show all layer details in reports. By default, clean/no-issue sections are omitted to reduce reading burden.",
    )
    parser.add_argument("--baseline-report", default=None, help="Optional prior JSON report used to compute a baseline diff.")
    parser.add_argument("--format", choices=["json", "markdown", "html"], default="markdown", help="Output format")
    parser.add_argument("--out", default=None, help="Output file. Prints to stdout when omitted.")
    parser.add_argument("--version", action="version", version=f"ClawMatrix {VERSION}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    report = build_report(args)
    if args.format == "json":
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
    elif args.format == "html":
        rendered = render_html(report)
    else:
        rendered = render_markdown(report)
    write_output(rendered, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
