#!/usr/bin/env python3
"""
Openclaw-MultiScanner environment doctor.

This helper keeps the local run path friendly: users can run one command and see
whether Python, OpenClaw state, Gateway, browser-control and Agent Skill Guard
are ready.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
AGENT_GUARD_DIR = ROOT / "engines" / "agent-skill-guard"


def expand_path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def check_url(url: str) -> dict[str, str | int | bool]:
    try:
        req = Request(url, method="HEAD")
        with urlopen(req, timeout=4) as response:
            return {"ok": True, "status": response.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def run_version(cmd: list[str]) -> str:
    try:
        completed = subprocess.run(cmd, text=True, capture_output=True, timeout=8)
    except Exception as exc:
        return f"不可用：{exc}"
    if completed.returncode != 0:
        return f"不可用：{completed.stderr.strip() or completed.stdout.strip()}"
    return (completed.stdout or completed.stderr).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Openclaw-MultiScanner 环境自检")
    parser.add_argument("--openclaw-home", default="~/.openclaw")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:18789/")
    parser.add_argument("--browser-url", default="http://127.0.0.1:18791/")
    parser.add_argument("--json", action="store_true", help="输出 JSON，便于自动化读取")
    args = parser.parse_args()

    home = expand_path(args.openclaw_home)
    agent_guard_binary = next(
        (
            candidate
            for candidate in [
                AGENT_GUARD_DIR / "bin" / "agent-skill-guard",
                AGENT_GUARD_DIR / "bin" / "agent-skill-guard.exe",
                ROOT / "bin" / "agent-skill-guard",
                ROOT / "bin" / "agent-skill-guard.exe",
            ]
            if candidate.exists()
        ),
        None,
    )
    result = {
        "python": sys.version.split()[0],
        "openclaw_cli": run_version(["openclaw", "--version"]) if shutil.which("openclaw") else "未发现 openclaw 命令",
        "openclaw_home": str(home),
        "openclaw_home_exists": home.exists(),
        "openclaw_json_exists": (home / "openclaw.json").exists(),
        "gateway": check_url(args.gateway_url),
        "browser_control": check_url(args.browser_url),
        "agent_guard_source": AGENT_GUARD_DIR.exists(),
        "agent_guard_binary": str(agent_guard_binary) if agent_guard_binary else "",
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print("ClawMatrix 环境自检")
    print(f"- Python：{result['python']}")
    print(f"- OpenClaw CLI：{result['openclaw_cli']}")
    print(f"- 状态目录：{result['openclaw_home']} ({'存在' if result['openclaw_home_exists'] else '不存在'})")
    print(f"- openclaw.json：{'存在' if result['openclaw_json_exists'] else '未发现'}")
    print(f"- Gateway：{result['gateway']}")
    print(f"- browser-control：{result['browser_control']}")
    print(f"- Agent Skill Guard 目录：{'存在' if result['agent_guard_source'] else '未发现'}")
    print(f"- Agent Skill Guard 二进制：{result['agent_guard_binary'] or '未发现，第二层将降级为轻量扫描'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
