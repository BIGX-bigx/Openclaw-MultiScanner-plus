from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Callable

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None

try:
    import yaml  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    yaml = None


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

FRONTMATTER_CAPABILITY_KEYS = {
    "capabilities",
    "permissions",
    "allowed_capabilities",
    "declared_capabilities",
}

CAPABILITY_ALIAS = {
    "filesystem": "file",
    "files": "file",
    "workspace": "file",
    "networking": "network",
    "http": "network",
    "https": "network",
    "shell": "process",
    "command": "process",
    "commands": "process",
    "exec": "process",
    "browsing": "browser",
    "web": "browser",
    "scheduler": "schedule",
    "cron": "schedule",
    "timers": "schedule",
}


def parse_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def parse_simple_yaml_block(text: str) -> Any:
    lines = text.splitlines()

    def non_empty(index: int) -> int:
        while index < len(lines) and (not lines[index].strip() or lines[index].lstrip().startswith("#")):
            index += 1
        return index

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        index = non_empty(index)
        if index >= len(lines):
            return {}, index
        line = lines[index]
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent < indent:
            return {}, index

        if line.lstrip().startswith("- "):
            items: list[Any] = []
            while index < len(lines):
                index = non_empty(index)
                if index >= len(lines):
                    break
                line = lines[index]
                current_indent = len(line) - len(line.lstrip(" "))
                if current_indent < indent or not line.lstrip().startswith("- "):
                    break
                content = line.lstrip()[2:].strip()
                if not content:
                    value, index = parse_block(index + 1, current_indent + 2)
                    items.append(value)
                    continue
                if ":" in content and not content.startswith(("'", '"')):
                    key, raw = content.split(":", 1)
                    key = key.strip()
                    raw = raw.strip()
                    if raw:
                        items.append({key: parse_scalar(raw)})
                        index += 1
                    else:
                        value, index = parse_block(index + 1, current_indent + 2)
                        items.append({key: value})
                else:
                    items.append(parse_scalar(content))
                    index += 1
            return items, index

        mapping: dict[str, Any] = {}
        while index < len(lines):
            index = non_empty(index)
            if index >= len(lines):
                break
            line = lines[index]
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent > indent:
                raise ValueError(f"unexpected indentation on line {index + 1}")
            stripped = line.strip()
            if ":" not in stripped:
                raise ValueError(f"expected key/value pair on line {index + 1}")
            key, raw = stripped.split(":", 1)
            key = key.strip()
            raw = raw.strip()
            if raw:
                mapping[key] = parse_scalar(raw)
                index += 1
            else:
                value, index = parse_block(index + 1, indent + 2)
                mapping[key] = value
        return mapping, index

    result, _ = parse_block(0, 0)
    return result


def extract_frontmatter_block(text: str) -> str | None:
    if not text.startswith("---"):
        return None
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    collected: list[str] = []
    for line in lines[1:]:
        if line.strip() in {"---", "..."}:
            return "\n".join(collected)
        collected.append(line)
    return None


def parse_skill_frontmatter(skill_md: Path, safe_read_text: Callable[[Path], str]) -> dict[str, Any]:
    text = safe_read_text(skill_md)
    block = extract_frontmatter_block(text)
    if block is None:
        return {"present": False, "fields": {}, "parser": None, "error": None}
    if yaml is not None:
        try:
            data = yaml.safe_load(block)
            if isinstance(data, dict):
                return {"present": True, "fields": data, "parser": "yaml.safe_load", "error": None}
            return {"present": True, "fields": {}, "parser": "yaml.safe_load", "error": "frontmatter is not a mapping"}
        except Exception as exc:  # pragma: no cover - exercised only with bad external parser input
            return {"present": True, "fields": {}, "parser": "yaml.safe_load", "error": str(exc)}
    try:
        data = parse_simple_yaml_block(block)
        return {
            "present": True,
            "fields": data if isinstance(data, dict) else {},
            "parser": "builtin-fallback",
            "error": None if isinstance(data, dict) else "frontmatter is not a mapping",
        }
    except ValueError as exc:
        return {"present": True, "fields": {}, "parser": "builtin-fallback", "error": str(exc)}


def normalize_capability(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower().replace("-", "_")
    return CAPABILITY_ALIAS.get(lowered, lowered if lowered in {"file", "network", "process", "browser", "schedule"} else None)


def iter_capability_values(node: Any) -> list[str]:
    results: list[str] = []
    if isinstance(node, str):
        normalized = normalize_capability(node)
        if normalized:
            results.append(normalized)
        return results
    if isinstance(node, list):
        for item in node:
            results.extend(iter_capability_values(item))
        return results
    if isinstance(node, dict):
        for key, value in node.items():
            normalized = normalize_capability(key)
            if normalized and value:
                results.append(normalized)
            results.extend(iter_capability_values(value))
        return results
    return results


def declared_capabilities_from_frontmatter(fields: dict[str, Any]) -> set[str]:
    declared: set[str] = set()
    for key, value in fields.items():
        normalized_key = str(key).strip().lower().replace("-", "_")
        if normalized_key in FRONTMATTER_CAPABILITY_KEYS:
            declared.update(iter_capability_values(value))
    metadata = fields.get("metadata")
    if isinstance(metadata, dict):
        openclaw = metadata.get("openclaw")
        if isinstance(openclaw, dict):
            for key in FRONTMATTER_CAPABILITY_KEYS:
                declared.update(iter_capability_values(openclaw.get(key)))
    return declared


def read_declared_capabilities(skill_md: Path, frontmatter: dict[str, Any], safe_read_text: Callable[[Path], str]) -> set[str]:
    declared = declared_capabilities_from_frontmatter(frontmatter.get("fields", {}))
    if declared:
        return declared
    text = safe_read_text(skill_md).lower()
    keyword_map = {
        "file": ["file", "filesystem", "workspace", "文件"],
        "network": ["network", "http", "url", "网络"],
        "process": ["process", "shell", "command", "exec", "命令"],
        "browser": ["browser", "浏览器"],
        "schedule": ["schedule", "cron", "task", "定时"],
    }
    for capability, keywords in keyword_map.items():
        if any(keyword in text for keyword in keywords):
            declared.add(capability)
    return declared


def analyze_python_capabilities(text: str) -> set[str]:
    observed: set[str] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return observed
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name in {"os", "pathlib", "sqlite3"}:
                    observed.add("file")
                if name in {"requests", "socket", "websocket", "urllib"}:
                    observed.add("network")
                if name in {"subprocess"}:
                    observed.add("process")
                if name in {"selenium", "playwright"}:
                    observed.add("browser")
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module in {"pathlib", "sqlite3"}:
                observed.add("file")
            if module in {"urllib", "socket"}:
                observed.add("network")
            if module in {"subprocess"}:
                observed.add("process")
        elif isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Attribute):
                name = f"{getattr(target.value, 'id', '')}.{target.attr}".lower()
            elif isinstance(target, ast.Name):
                name = target.id.lower()
            else:
                name = ""
            if name in {"open", "pathlib.path", "sqlite3.connect"} or name.endswith((".open", ".read_text", ".write_text", ".mkdir")):
                observed.add("file")
            if name in {"subprocess.run", "subprocess.popen", "os.system"}:
                observed.add("process")
            if name in {"requests.get", "requests.post", "urllib.request.urlopen", "socket.create_connection"}:
                observed.add("network")
    return observed


def analyze_manifest_capabilities(path: Path, text: str) -> set[str]:
    observed: set[str] = set()
    suffix = path.suffix.lower()
    name = path.name
    if suffix == ".py":
        return analyze_python_capabilities(text)
    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict) and any(isinstance(v, str) and re.search(r"(?i)(curl|wget|axios|fetch)", v) for v in scripts.values()):
            observed.add("network")
        if isinstance(scripts, dict) and any(isinstance(v, str) and re.search(r"(?i)(node|sh|bash|powershell|cmd\.exe)", v) for v in scripts.values()):
            observed.add("process")
        deps = data.get("dependencies", {})
        if isinstance(deps, dict) and any(dep in deps for dep in ["playwright", "puppeteer", "selenium-webdriver"]):
            observed.add("browser")
        return observed
    if name in {"pyproject.toml", "Cargo.toml"} and tomllib is not None:
        try:
            data = tomllib.loads(text)
        except Exception:
            data = {}
        data_text = json.dumps(data, ensure_ascii=False)
        for capability, pattern in CAPABILITY_PATTERNS.items():
            if pattern.search(data_text):
                observed.add(capability)
        return observed
    return observed


def inspect_dependency_file(
    path: Path,
    root: Path,
    safe_read_text: Callable[[Path], str],
    scan_secrets: Callable[[Path], list[dict[str, Any]]],
    relative: Callable[[Path, Path | None], str],
) -> dict[str, Any]:
    text = safe_read_text(path)
    rel = relative(path, root)
    signals: list[str] = []
    if not text:
        return {"path": rel, "signals": signals}
    if path.name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict) and any(isinstance(v, str) and re.search(r"(?i)(postinstall|preinstall)", v) for v in scripts.values()):
            signals.append("install_time_execution")
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
        if any(isinstance(v, str) and re.search(r"(?i)(\*|latest|github:|git\+|https?://)", v) for v in deps.values()):
            signals.append("weak_or_remote_version_pin")
    elif path.name in {"pyproject.toml", "Cargo.toml"} and tomllib is not None:
        try:
            data = tomllib.loads(text)
        except Exception:
            data = {}
        if re.search(r"(?m)(\*|latest|>=|git\+|https?://)", json.dumps(data, ensure_ascii=False)):
            signals.append("weak_or_remote_version_pin")
        if "build-system" in data or "[[bin]]" in text or "build.rs" in text:
            signals.append("install_time_execution")
    else:
        if re.search(r"(?m)(\*|latest|>=|git\+|https?://)", text):
            signals.append("weak_or_remote_version_pin")
        if re.search(r"(?i)(postinstall|preinstall|build.rs|setup.py|scripts\s*=)", text):
            signals.append("install_time_execution")
    if scan_secrets(path):
        signals.append("secret_hint")
    return {"path": rel, "signals": signals[:10]}


def scan_skill_dir(
    skill_md: Path,
    *,
    find_files: Callable[..., list[Path]],
    safe_read_text: Callable[[Path], str],
    scan_secrets: Callable[[Path], list[dict[str, Any]]],
    relative: Callable[[Path, Path | None], str],
    max_skill_files: int,
    max_text_bytes: int,
) -> dict[str, Any]:
    root = skill_md.parent
    frontmatter = parse_skill_frontmatter(skill_md, safe_read_text)
    declared = read_declared_capabilities(skill_md, frontmatter, safe_read_text)
    observed: set[str] = set()
    evidence: dict[str, list[str]] = {key: [] for key in CAPABILITY_PATTERNS}
    risk_hits: dict[str, list[str]] = {key: [] for key in SKILL_RISK_PATTERNS}
    dependency_audit: list[dict[str, Any]] = []
    skipped_large_files: list[str] = []
    files_considered = 0
    scanned = 0

    for path in find_files(root, max_files=max_skill_files):
        files_considered += 1
        if path.stat().st_size > max_text_bytes:
            skipped_large_files.append(relative(path, root))
            continue
        text = safe_read_text(path)
        if not text:
            continue
        scanned += 1
        rel = relative(path, root)
        structured = analyze_manifest_capabilities(path, text)
        observed.update(structured)
        for capability in structured:
            if len(evidence[capability]) < 8:
                evidence[capability].append(rel)
        for capability, pattern in CAPABILITY_PATTERNS.items():
            if pattern.search(text):
                observed.add(capability)
                if len(evidence[capability]) < 8 and rel not in evidence[capability]:
                    evidence[capability].append(rel)
        for risk, pattern in SKILL_RISK_PATTERNS.items():
            if pattern.search(text) and len(risk_hits[risk]) < 8:
                risk_hits[risk].append(rel)
        if path.name in DEPENDENCY_FILES:
            dependency_audit.append(inspect_dependency_file(path, root, safe_read_text, scan_secrets, relative))

    mismatch = sorted(capability for capability in observed if capability not in declared and capability != "prompt_injection")
    active_risks = sorted(key for key, hits in risk_hits.items() if hits)
    severity = "info"
    if "remote_install" in active_risks or "exfiltration" in active_risks or "prompt_injection" in observed or {"file", "network", "process"}.issubset(observed):
        severity = "high"
    elif mismatch or active_risks or any(item["signals"] for item in dependency_audit) or frontmatter.get("error"):
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
        "coverage": {
            "files_considered": files_considered,
            "files_scanned": scanned,
            "skipped_large_files": skipped_large_files[:20],
            "truncated": files_considered >= max_skill_files,
            "parser": frontmatter.get("parser"),
        },
        "skipped_reason": None if scanned else "no-readable-files",
    }
