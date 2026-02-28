"""
nmap_module.py - Full TCP port scan and service detection for AD-Pathfinder.

Performs a comprehensive nmap scan against a target Domain Controller,
parses the output into structured data, updates AssessmentState, and
suggests context-aware next actions based on discovered open ports.

Requires:
    - nmap installed on the system (sudo apt install nmap)
    - Root/sudo privileges for SYN scan (-sS)
    - executor.CommandExecutor
    - session.AssessmentState
"""

from __future__ import annotations

import re
import sys
import os
from typing import Optional

# ── Path fix: allow imports from project root when run as a module or directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    _RICH_AVAILABLE = True
    console = Console()
except ImportError:
    _RICH_AVAILABLE = False
    console = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Port → suggestion mapping
# ─────────────────────────────────────────────────────────────────────────────

PORT_SUGGESTIONS: dict[int, str] = {
    88:   "Kerberos detected       → Run Kerberoasting / AS-REP Roasting attacks",
    389:  "LDAP detected           → Run LDAP enumeration (users, groups, GPOs)",
    445:  "SMB detected            → Run SMB enumeration (shares, null sessions, relay)",
    636:  "LDAPS detected          → Run LDAP enumeration over SSL",
    3268: "Global Catalog detected → Run LDAP enumeration against Global Catalog",
    5985: "WinRM detected          → Attempt WinRM access (evil-winrm)",
    5986: "WinRM/HTTPS detected    → Attempt WinRM access over HTTPS",
    3389: "RDP detected            → Attempt RDP brute-force / BlueKeep check",
    1433: "MSSQL detected          → Run MSSQL enumeration / UNC path injection",
    9389: "AD Web Services         → Enumerate via AD Web Services endpoint",
}

# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_results(open_ports: list[int], services: dict[int, str], suggestions: list[str]) -> None:
    """Render scan results and suggestions to the terminal."""
    if _RICH_AVAILABLE:
        table = Table(
            title="[bold bright_cyan]Discovered Ports & Services[/bold bright_cyan]",
            box=box.ROUNDED,
            border_style="bright_blue",
            show_lines=True,
        )
        table.add_column("Port", style="bold bright_cyan", width=8)
        table.add_column("Service", style="white")

        for port in sorted(open_ports):
            table.add_row(str(port), services.get(port, "unknown"))

        console.print(table)

        if suggestions:
            suggestion_text = "\n".join(f"  [bright_cyan]▶[/bright_cyan]  {s}" for s in suggestions)
            console.print(
                Panel(
                    suggestion_text,
                    title="[bold yellow]Suggested Next Actions[/bold yellow]",
                    border_style="yellow",
                )
            )
    else:
        print("\n--- Discovered Ports & Services ---")
        for port in sorted(open_ports):
            print(f"  {port:<6} {services.get(port, 'unknown')}")
        if suggestions:
            print("\n--- Suggested Next Actions ---")
            for s in suggestions:
                print(f"  ▶  {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_nmap_output(raw_output: str) -> tuple[list[int], dict[int, str]]:
    """
    Parse raw nmap stdout into structured data.

    Handles standard nmap table output lines of the form:
        80/tcp   open  http    Apache httpd 2.4.51
        445/tcp  open  microsoft-ds

    Parameters
    ----------
    raw_output : str
        The full stdout string from the nmap process.

    Returns
    -------
    tuple[list[int], dict[int, str]]
        (open_ports, services)
        open_ports — sorted list of integer port numbers
        services   — {port: "service_name version"} dict
    """
    open_ports: list[int] = []
    services: dict[int, str] = {}

    port_line_re = re.compile(
        r"^(\d+)/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$",
        re.MULTILINE,
    )

    for match in port_line_re.finditer(raw_output):
        port    = int(match.group(1))
        service = match.group(2).strip()
        version = (match.group(3) or "").strip()

        service_label = f"{service} {version}".strip() if version else service

        open_ports.append(port)
        services[port] = service_label

    return sorted(open_ports), services


# ─────────────────────────────────────────────────────────────────────────────
# Suggestion engine
# ─────────────────────────────────────────────────────────────────────────────

def _build_suggestions(
    open_ports: list[int],
    performed_actions: list[str],
) -> list[str]:
    """
    Return context-aware suggestions based on open ports.

    Already-performed actions are filtered out to avoid duplicates.

    Parameters
    ----------
    open_ports : list[int]
        Ports discovered as open by the scan.
    performed_actions : list[str]
        Entries from AssessmentState.performed_actions (timestamp-prefixed strings).

    Returns
    -------
    list[str]
        Human-readable suggestion strings.
    """
    performed_flat = " ".join(performed_actions).lower()
    suggestions: list[str] = []

    for port, suggestion in PORT_SUGGESTIONS.items():
        if port in open_ports:
            keyword = suggestion.split("→")[1].strip().split()[1].lower()
            if keyword not in performed_flat:
                suggestions.append(suggestion)

    return suggestions


# ─────────────────────────────────────────────────────────────────────────────
# NmapScanner
# ─────────────────────────────────────────────────────────────────────────────

class NmapScanner:
    """
    Full TCP port scan and service detection against a Domain Controller.

    Parameters
    ----------
    executor : CommandExecutor | None
        Provide a custom executor or leave None to use a default instance.
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=True, default_timeout=600)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, state: AssessmentState) -> dict:
        """
        Execute a full TCP scan against state.target_ip and update state.

        Runs:
            nmap -Pn -sS -sV -p- --open <target_ip>

        Note: -sS (SYN scan) requires root/sudo on Linux.

        Parameters
        ----------
        state : AssessmentState
            The current assessment session. open_ports and services
            are updated in-place.

        Returns
        -------
        dict
            {
                "status":   "success" | "error",
                "findings": {
                    "open_ports": [int, ...],
                    "services":   {int: str, ...},
                },
                "suggestions": [str, ...],
            }
        """
        if not self.executor.check_tool("nmap"):
            return self._error("nmap is not installed. Run: sudo apt install nmap")

        target  = state.target_ip
        command = [
            "nmap",
            "-Pn",      # skip host discovery (DC may block ping)
            "-sS",      # SYN scan (requires root)
            "-sV",      # service/version detection
            "-p-",      # all 65535 ports
            "--open",   # show only open ports
            target,
        ]

        if _RICH_AVAILABLE:
            console.print(f"\n  [bold bright_cyan]▶  Starting full TCP scan against {target}[/bold bright_cyan]")
            console.print("  [dim]This may take several minutes for -p- ...[/dim]\n")
        else:
            print(f"\n[*] Starting full TCP scan against {target} ...")

        result = self.executor.run(command)

        if result["status"] == "timeout":
            return self._error(f"Nmap scan timed out: {result['error']}")

        if result["exit_code"] not in (0,):
            return self._error(
                f"Nmap returned exit code {result['exit_code']}. "
                f"Stderr: {result['error']}"
            )

        open_ports, services = _parse_nmap_output(result["output"])

        if not open_ports:
            return self._error(
                "No open ports found. Check target IP, firewall rules, "
                "or whether the scan requires sudo for SYN mode."
            )

        # ── Update AssessmentState ──────────────────────────────────────
        existing_ports = set(state.open_ports)
        for port in open_ports:
            if port not in existing_ports:
                state.open_ports.append(port)

        state.services.update({str(p): svc for p, svc in services.items()})

        state.log_action(f"nmap full TCP scan against {target}")
        state.log_finding(
            category="Port Scan",
            description=(
                f"Discovered {len(open_ports)} open port(s) on {target}: "
                f"{', '.join(str(p) for p in open_ports)}"
            ),
            severity="INFO",
        )

        suggestions = _build_suggestions(open_ports, state.performed_actions)
        _print_results(open_ports, services, suggestions)

        return {
            "status": "success",
            "findings": {
                "open_ports": open_ports,
                "services":   services,
            },
            "suggestions": suggestions,
        }

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _error(message: str) -> dict:
        """Return a standardised error result."""
        if _RICH_AVAILABLE:
            console.print(f"\n  [bold red]✘  Nmap Error:[/bold red] {message}\n")
        else:
            print(f"\n[!] Nmap Error: {message}\n")

        return {
            "status":      "error",
            "findings":    {"open_ports": [], "services": {}},
            "suggestions": [],
            "error":       message,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience function
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    Convenience wrapper — run a full TCP scan without instantiating NmapScanner.

    Example (from main.py)
    ----------------------
    from modules.nmap_module import run as nmap_run
    result = nmap_run(state)
    """
    return NmapScanner(executor=executor).run(state)


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test — run directly from modules/ folder
# Usage: sudo python modules/nmap_module.py <target_ip> <domain>
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python modules/nmap_module.py <target_ip> <domain>")
        sys.exit(1)

    from session import generate_assessment_id

    test_state = AssessmentState(
        assessment_id=generate_assessment_id(),
        target_ip=sys.argv[1],
        domain=sys.argv[2],
    )

    scanner = NmapScanner()
    output  = scanner.run(test_state)

    print("\nFinal result:")
    print(f"  Status    : {output['status']}")
    print(f"  Open ports: {output['findings']['open_ports']}")
    print(f"  Services  : {output['findings']['services']}")
    print(f"  Suggestions ({len(output['suggestions'])}):")
    for s in output["suggestions"]:
        print(f"    - {s}")