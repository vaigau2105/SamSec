# backend/app/services/tool_runner.py
"""
Central subprocess runner for all security tools.

- Inside Docker / native Linux → runs tools directly (nuclei, httpx, etc.)
- On Windows with WSL         → prefixes every command with ["wsl"]

Set SAMSEC_ENV=docker in the container (done automatically via docker-compose).
"""

import os
import subprocess
from typing import List, Tuple

# Docker sets this env var automatically via docker-compose.yml
_IN_DOCKER = os.environ.get("SAMSEC_ENV", "").lower() == "docker"


def build_cmd(tool: str, args: List[str]) -> List[str]:
    """
    Build the full command list for a security tool.
    
    Usage:
        cmd = build_cmd("nuclei", ["-u", target, "-silent", "-jsonl"])
        proc = subprocess.run(cmd, ...)
    """
    if _IN_DOCKER:
        return [tool] + args
    else:
        return ["wsl", tool] + args


def run_tool(
    tool: str,
    args: List[str],
    timeout: int = 120,
    input_text: str = None,
) -> Tuple[str, str, int]:
    """
    Run a security tool and return (stdout, stderr, returncode).
    Handles WSL vs Docker automatically.
    """
    cmd = build_cmd(tool, args)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except FileNotFoundError:
        return "", f"{tool} not found", 127
    except Exception as e:
        return "", str(e), -1


def run_tool_shell(command: str, timeout: int = 120, input_text: str = None) -> Tuple[str, str, int]:
    """
    Run a shell pipeline command (e.g. piping to httpx).
    In Docker: runs via bash directly.
    In WSL:    runs via wsl bash.
    """
    if _IN_DOCKER:
        shell_cmd = ["bash", "-c", command]
    else:
        shell_cmd = ["wsl", "bash", "-c", command]

    try:
        proc = subprocess.run(
            shell_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except Exception as e:
        return "", str(e), -1
