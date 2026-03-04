"""
cred_validation_module.py - Credential Validation & Password Reset module for AD-Pathfinder.

Two operations:
  1. Validate a username:password pair against the DC via netexec SMB.
  2. Reset an expired/forced-change password via smbpasswd.

Tools used:
    - netexec / nxc  (pip install netexec OR apt install netexec)
    - smbpasswd      (part of samba-common-bin)

Commands (from playbook):
    # Test compromised credentials
    netexec smb <target_ip> -u '<user>' -p '<pass>' --users

    # Reset password forced by AD policy
    smbpasswd -r <target_ip> -U <user>

    # Validate new password
    netexec smb <target_ip> -u '<user>' -p '<new_pass>' --pass-pol
"""

from __future__ import annotations

import os
import re
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


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns
# ─────────────────────────────────────────────────────────────────────────────

# [+] domain\user:pass  → success
SUCCESS_RE = re.compile(r"\[\+\]\s+\S+\\(\S+):(.+)", re.IGNORECASE)

# STATUS_LOGON_FAILURE, STATUS_ACCOUNT_LOCKED_OUT, etc.
LOCKED_RE  = re.compile(r"STATUS_ACCOUNT_LOCKED_OUT", re.IGNORECASE)
EXPIRED_RE = re.compile(r"STATUS_PASSWORD_MUST_CHANGE|STATUS_PASSWORD_EXPIRED", re.IGNORECASE)

# Password policy line: "Minimum password length: 7"
POLICY_RE  = re.compile(r"(Minimum password length|Password history|Lockout threshold)[:\s]+(\d+)", re.IGNORECASE)


def _detect_nxc(executor: CommandExecutor) -> str | None:
    for binary in ("nxc", "netexec", "crackmapexec"):
        if executor.check_tool(binary):
            return binary
    return None


# ─────────────────────────────────────────────────────────────────────────────
# CredentialValidationModule
# ─────────────────────────────────────────────────────────────────────────────

class CredentialValidationModule:
    """
    Validate AD credentials and optionally reset expired passwords.

    Operations
    ----------
    validate(state)   — test a username:password against the DC (--users)
    reset(state)      — change an expired password via smbpasswd
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, state: AssessmentState) -> dict:
        """
        Present sub-menu: Validate Credentials | Reset Password | Both.

        Returns
        -------
        dict
            {
                "status":      "success" | "error",
                "operation":   "validate" | "reset" | "both",
                "valid_creds": list[dict],   # [{username, password}]
                "reset_done":  bool,
                "error":       str | None,
                "warnings":    list[str],
            }
        """
        nxc = _detect_nxc(self.executor)
        warnings: list[str] = []

        console.print()
        console.print("  [bold bright_cyan]Credential Validation[/bold bright_cyan]\n")
        console.print("  [bright_cyan]1.[/bright_cyan]  Validate credentials (netexec --users)")
        console.print("  [bright_cyan]2.[/bright_cyan]  Reset expired password (smbpasswd)")
        console.print("  [bright_cyan]3.[/bright_cyan]  Both (validate → reset if expired → revalidate)")
        console.print("  [bright_cyan]0.[/bright_cyan]  Cancel")
        console.print()

        op = Prompt.ask(
            "  [bold yellow]Select[/bold yellow]",
            choices=["0", "1", "2", "3"],
            default="1",
        )

        if op == "0":
            return {"status": "error", "operation": "cancelled", "valid_creds": [],
                    "reset_done": False, "error": "Cancelled by operator.", "warnings": []}

        # ── Credential picker ──────────────────────────────────────────
        # Build pool from any known creds in the session
        _cred_pool: list[tuple[str, str, str]] = []  # (user, pass, source)

        def _add(u: str, p: str, src: str) -> None:
            if u and p and not any(c[0] == u and c[1] == p for c in _cred_pool):
                _cred_pool.append((u, p, src))

        for cp in getattr(state, "cracked_passwords", []):
            _add(cp.get("username", ""), cp.get("password", ""), "cracked")
        for vc in getattr(state, "valid_credentials", []):
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
            _ct.add_column("Password", style="dim",               width=28)
            _ct.add_column("Source",   style="bright_blue",       width=10)
            for _i, (_u, _p, _s) in enumerate(_cred_pool, 1):
                _pw_d  = f"[bold green]{_p}[/bold green]" if _s == "cracked" else _p
                _src_d = "[bold green]cracked ✔[/bold green]" if _s == "cracked" else f"[bright_blue]{_s}[/bright_blue]"
                _ct.add_row(str(_i), _u, _pw_d, _src_d)
            console.print()
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

        if not username:
            username = Prompt.ask("  [bold yellow]Username[/bold yellow]", default="").strip()
        if not password and username:
            password = Prompt.ask("  [bold yellow]Password[/bold yellow]", default="").strip()

        if not username or not password:
            return {"status": "error", "operation": "cancelled", "valid_creds": [],
                    "reset_done": False, "error": "No credentials provided.", "warnings": []}

        result: dict = {
            "status":      "success",
            "operation":   "validate" if op == "1" else ("reset" if op == "2" else "both"),
            "valid_creds": [],
            "reset_done":  False,
            "error":       None,
            "warnings":    warnings,
        }

        if op in ("1", "3"):
            validate_result = self._validate(state, nxc, username, password, warnings)
            result.update(validate_result)

        if op == "2" or (op == "3" and self._needs_reset(result)):
            reset_result = self._reset_password(state, username, warnings)
            result["reset_done"] = reset_result

            if reset_result and op == "3":
                # Re-prompt for new password and re-validate
                console.print("\n  [dim]Password reset complete. Please enter your new password to validate.[/dim]")
                new_password = Prompt.ask("  [bold yellow]New password[/bold yellow]").strip()
                validate_result2 = self._validate(state, nxc, username, new_password, warnings)
                if validate_result2.get("valid_creds"):
                    result["valid_creds"] = validate_result2["valid_creds"]

        return result

    # ------------------------------------------------------------------ #
    #  Internal operations                                                 #
    # ------------------------------------------------------------------ #

    def _validate(
        self,
        state: AssessmentState,
        nxc: Optional[str],
        username: str,
        password: str,
        warnings: list[str],
    ) -> dict:
        if not nxc:
            warnings.append("netexec/nxc/crackmapexec not found — cannot validate credentials.")
            return {"valid_creds": []}

        # Exact playbook command: netexec smb <ip> -u '<user>' -p '<pass>' --users
        cmd = [nxc, "smb", state.target_ip, "-u", username, "-p", password, "--users"]
        cmd_str = " ".join(cmd)
        console.print(f"\n  [bold bright_cyan]Running:[/bold bright_cyan] [dim]{cmd_str}[/dim]\n")

        res = self.executor.run(cmd, timeout=60)
        output = res["output"] + "\n" + res["error"]

        valid: list[dict] = []

        if LOCKED_RE.search(output):
            warnings.append(f"Account '{username}' appears to be LOCKED OUT.")
        elif EXPIRED_RE.search(output):
            warnings.append(f"Password for '{username}' has EXPIRED — use smbpasswd to reset.")
        elif res["status"] == "success" or SUCCESS_RE.search(output):
            valid.append({"username": username, "password": password})
            # Merge into state
            if not any(c["username"] == username for c in state.valid_credentials):
                state.valid_credentials.append({"username": username, "password": password, "ntlm_hash": ""})
            state.log_finding(
                "Credential Validation",
                f"Valid credentials confirmed: {username}",
                severity="HIGH",
            )
        else:
            warnings.append(f"Credentials for '{username}' appear INVALID or access was denied.")

        return {"valid_creds": valid}

    def _reset_password(
        self,
        state: AssessmentState,
        username: str,
        warnings: list[str],
    ) -> bool:
        if not self.executor.check_tool("smbpasswd"):
            warnings.append("smbpasswd not found — install: sudo apt install samba-common-bin")
            return False

        # Exact playbook command: smbpasswd -r <target_ip> -U <user>
        cmd = ["smbpasswd", "-r", state.target_ip, "-U", username]
        cmd_str = " ".join(cmd)
        console.print(f"\n  [bold bright_cyan]Running:[/bold bright_cyan] [dim]{cmd_str}[/dim]")
        console.print("  [dim](You will be prompted for old and new passwords)[/dim]\n")

        try:
            import subprocess
            proc = subprocess.run(cmd, timeout=60)
            if proc.returncode == 0:
                state.log_action(f"Password reset via smbpasswd: {username}")
                return True
            else:
                warnings.append("smbpasswd returned non-zero exit code.")
                return False
        except Exception as exc:
            warnings.append(f"smbpasswd error: {exc}")
            return False

    @staticmethod
    def _needs_reset(result: dict) -> bool:
        """True if the validate step indicated an expired password."""
        for w in result.get("warnings", []):
            if "EXPIRED" in w.upper():
                return True
        return False

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":      "error",
            "operation":   "none",
            "valid_creds": [],
            "reset_done":  False,
            "error":       message,
            "warnings":    [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.cred_validation_module import run as cred_run
    result = cred_run(state)
    """
    return CredentialValidationModule(executor).run(state)
