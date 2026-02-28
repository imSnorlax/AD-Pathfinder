"""
main.py - AD-Pathfinder entry point.
A modular Active Directory assessment CLI tool.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.text import Text

from session import (
    AssessmentState,
    Credentials,
    generate_assessment_id,
    save_session,
    load_session,
    list_sessions,
)

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Banner / Header helpers
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
     ___  ____        ____        _   _      __ _           _
    / _ \|  _ \      |  _ \ __ _| |_| |__  / _(_)_ __   __| | ___ _ __
   | | | | | | |_____| |_) / _` | __| '_ \| |_| | '_ \ / _` |/ _ \ '__|
   | |_| | |_| |_____|  __/ (_| | |_| | | |  _| | | | | (_| |  __/ |
    \__\_\____/      |_|   \__,_|\__|_| |_|_| |_|_| |_|\__,_|\___|_|
"""


def print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        "  [dim]Active Directory Assessment Framework[/dim]\n",
        justify="center",
    )


def print_assessment_header(state: AssessmentState) -> None:
    """Print a status header for the current assessment session."""
    table = Table(box=box.ROUNDED, show_header=False, border_style="bright_blue", expand=False)
    table.add_column("Key", style="bold bright_cyan", width=18)
    table.add_column("Value", style="white")

    table.add_row("Assessment ID", state.assessment_id)
    table.add_row("Target IP", state.target_ip)
    table.add_row("Domain", state.domain)
    if state.dns_server:
        table.add_row("DNS Server", state.dns_server)
    if state.initial_credentials.username:
        table.add_row("Username", state.initial_credentials.username)

    console.print(Panel(table, title="[bold bright_cyan]Current Session[/bold bright_cyan]", border_style="bright_blue"))


# ─────────────────────────────────────────────────────────────────────────────
# Input helpers
# ─────────────────────────────────────────────────────────────────────────────

def _prompt_required(label: str) -> str:
    """Prompt until the user provides a non-empty value."""
    while True:
        value = Prompt.ask(f"  [bold yellow]{label}[/bold yellow]").strip()
        if value:
            return value
        console.print("  [red]This field is required.[/red]")


def _prompt_optional(label: str, default: str = "") -> str:
    """Prompt for an optional value, returning default if left blank."""
    value = Prompt.ask(
        f"  [bold dim]{label}[/bold dim]",
        default=default,
        show_default=bool(default),
    ).strip()
    return value


# ─────────────────────────────────────────────────────────────────────────────
# New Assessment flow
# ─────────────────────────────────────────────────────────────────────────────

def start_new_assessment() -> AssessmentState:
    console.rule("[bold bright_cyan]New Assessment Setup[/bold bright_cyan]")
    console.print()

    target_ip = _prompt_required("Target Domain Controller IP")
    domain = _prompt_required("Domain Name (e.g. corp.local)")

    console.print("\n  [dim]Optional fields — press Enter to skip.[/dim]\n")
    dns_server = _prompt_optional("DNS Server IP")
    username = _prompt_optional("Username")

    password = ""
    ntlm_hash = ""
    if username:
        auth_choice = Prompt.ask(
            "  [bold dim]Auth method[/bold dim]",
            choices=["password", "hash", "none"],
            default="none",
        )
        if auth_choice == "password":
            password = Prompt.ask("  [bold dim]Password[/bold dim]", password=True)
        elif auth_choice == "hash":
            ntlm_hash = _prompt_optional("NTLM Hash (LM:NT format)")

    assessment_id = generate_assessment_id()
    creds = Credentials(username=username, password=password, ntlm_hash=ntlm_hash)

    state = AssessmentState(
        assessment_id=assessment_id,
        target_ip=target_ip,
        domain=domain,
        dns_server=dns_server,
        initial_credentials=creds,
    )

    path = save_session(state)
    console.print(f"\n  [bold green]✔  Session created and saved:[/bold green] [dim]{path}[/dim]\n")
    return state


# ─────────────────────────────────────────────────────────────────────────────
# Load Assessment flow
# ─────────────────────────────────────────────────────────────────────────────

def load_existing_assessment() -> AssessmentState | None:
    console.rule("[bold bright_cyan]Load Assessment[/bold bright_cyan]")
    sessions = list_sessions()

    if not sessions:
        console.print("\n  [yellow]No saved sessions found in /reports.[/yellow]\n")
        return None

    table = Table(
        title="Saved Sessions",
        box=box.SIMPLE_HEAVY,
        border_style="bright_blue",
        show_lines=True,
    )
    table.add_column("#", style="bold bright_cyan", width=4)
    table.add_column("Assessment ID", style="white")
    table.add_column("Target IP", style="green")
    table.add_column("Domain", style="yellow")

    for idx, sess in enumerate(sessions, start=1):
        table.add_row(str(idx), sess["assessment_id"], sess["target_ip"], sess["domain"])

    console.print()
    console.print(table)
    console.print()

    choices = [str(i) for i in range(1, len(sessions) + 1)] + ["0"]
    choice = Prompt.ask(
        "  [bold yellow]Select session #[/bold yellow] (0 to cancel)",
        choices=choices,
        show_choices=False,
    )

    if choice == "0":
        return None

    selected = sessions[int(choice) - 1]
    try:
        state = load_session(selected["assessment_id"])
        console.print(f"\n  [bold green]✔  Session loaded:[/bold green] {state.assessment_id}\n")
        return state
    except FileNotFoundError as exc:
        console.print(f"\n  [red]Error: {exc}[/red]\n")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Assessment menu (placeholder for future modules)
# ─────────────────────────────────────────────────────────────────────────────

def assessment_menu(state: AssessmentState) -> None:
    """
    Main interaction loop once an assessment is loaded.
    Module integrations will be wired in here.
    """
    while True:
        console.print()
        print_assessment_header(state)
        console.print()

        console.print("[bold bright_cyan]Assessment Menu[/bold bright_cyan]\n")
        console.print("  [bright_cyan]1.[/bright_cyan]  Port & Service Scan         [dim](coming soon)[/dim]")
        console.print("  [bright_cyan]2.[/bright_cyan]  User Enumeration             [dim](coming soon)[/dim]")
        console.print("  [bright_cyan]3.[/bright_cyan]  Kerberoasting                [dim](coming soon)[/dim]")
        console.print("  [bright_cyan]4.[/bright_cyan]  AS-REP Roasting              [dim](coming soon)[/dim]")
        console.print("  [bright_cyan]5.[/bright_cyan]  Vulnerability Checks         [dim](coming soon)[/dim]")
        console.print("  [bright_cyan]6.[/bright_cyan]  View Findings Log")
        console.print("  [bright_cyan]7.[/bright_cyan]  Save & Return to Main Menu")
        console.print()

        choice = Prompt.ask(
            "  [bold yellow]Select option[/bold yellow]",
            choices=["1", "2", "3", "4", "5", "6", "7"],
            show_choices=False,
        )

        if choice in ("1", "2", "3", "4", "5"):
            console.print("\n  [yellow]⚠  This module is not yet implemented.[/yellow]")
            console.print("  [dim]Stub hook is ready — drop a module in and wire it here.[/dim]\n")

        elif choice == "6":
            _display_findings_log(state)

        elif choice == "7":
            path = save_session(state)
            console.print(f"\n  [bold green]✔  Session saved:[/bold green] [dim]{path}[/dim]\n")
            break


def _display_findings_log(state: AssessmentState) -> None:
    console.rule("[bold bright_cyan]Findings Log[/bold bright_cyan]")
    if not state.findings_log:
        console.print("\n  [dim]No findings logged yet.[/dim]\n")
        return

    table = Table(box=box.SIMPLE, show_lines=True, border_style="bright_blue")
    table.add_column("Timestamp", style="dim", width=20)
    table.add_column("Severity", width=8)
    table.add_column("Category", style="cyan", width=16)
    table.add_column("Description")

    severity_colors = {
        "INFO": "bright_blue",
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }

    for entry in state.findings_log:
        sev = entry.get("severity", "INFO")
        color = severity_colors.get(sev, "white")
        table.add_row(
            entry.get("timestamp", ""),
            f"[{color}]{sev}[/{color}]",
            entry.get("category", ""),
            entry.get("description", ""),
        )

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Main menu
# ─────────────────────────────────────────────────────────────────────────────

def main_menu() -> None:
    print_banner()

    while True:
        console.print("[bold bright_cyan]Main Menu[/bold bright_cyan]\n")
        console.print("  [bright_cyan]1.[/bright_cyan]  Start New Assessment")
        console.print("  [bright_cyan]2.[/bright_cyan]  Load Existing Assessment")
        console.print("  [bright_cyan]3.[/bright_cyan]  Exit")
        console.print()

        choice = Prompt.ask(
            "  [bold yellow]Select option[/bold yellow]",
            choices=["1", "2", "3"],
            show_choices=False,
        )

        if choice == "1":
            state = start_new_assessment()
            assessment_menu(state)

        elif choice == "2":
            state = load_existing_assessment()
            if state:
                assessment_menu(state)

        elif choice == "3":
            console.print("\n  [dim]Goodbye.[/dim]\n")
            sys.exit(0)

        console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n  [dim]Interrupted. Exiting.[/dim]\n")
        sys.exit(0)