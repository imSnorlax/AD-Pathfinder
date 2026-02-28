"""
main.py - AD-Pathfinder entry point.
A modular Active Directory assessment CLI tool.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
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
# Action dispatcher
# Maps suggestion action_key → callable that accepts AssessmentState
# Add new modules here as they are built — nowhere else needs to change.
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch_action(action_key: str, state: AssessmentState) -> None:
    """
    Route a suggestion action_key to its implementing module.
    Each handler imports lazily so missing modules never crash the menu.
    """
    key = action_key.lower().strip()

    if key == "portscan":
        from modules.nmap_module import run as nmap_run
        nmap_run(state)

    elif key == "kerberoasting":
        console.print("\n  [yellow]⚠  Kerberoasting module not yet implemented.[/yellow]\n")

    elif key == "asreproasting":
        console.print("\n  [yellow]⚠  AS-REP Roasting module not yet implemented.[/yellow]\n")

    elif key == "ldap_enum":
        console.print("\n  [yellow]⚠  LDAP Enumeration module not yet implemented.[/yellow]\n")

    elif key == "smb_enum":
        from modules.smb_enum_module import run as smb_run
        smb_run(state)

    elif key == "smbrelay":
        console.print("\n  [yellow]⚠  SMB Relay module not yet implemented.[/yellow]\n")

    elif key == "winrm":
        console.print("\n  [yellow]⚠  WinRM module not yet implemented.[/yellow]\n")

    elif key == "spraying":
        console.print("\n  [yellow]⚠  Password Spraying module not yet implemented.[/yellow]\n")

    elif key == "passthehash":
        console.print("\n  [yellow]⚠  Pass-the-Hash module not yet implemented.[/yellow]\n")

    elif key == "rdp":
        console.print("\n  [yellow]⚠  RDP module not yet implemented.[/yellow]\n")

    elif key == "mssql":
        console.print("\n  [yellow]⚠  MSSQL module not yet implemented.[/yellow]\n")

    elif key == "adws":
        console.print("\n  [yellow]⚠  AD Web Services module not yet implemented.[/yellow]\n")

    else:
        console.print(f"\n  [red]✘  No dispatcher found for action key: '{key}'[/red]\n")


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
    table = Table(
        box=box.ROUNDED,
        show_header=False,
        border_style="bright_blue",
        expand=False,
    )
    table.add_column("Key",   style="bold bright_cyan", width=18)
    table.add_column("Value", style="white")

    table.add_row("Assessment ID", state.assessment_id)
    table.add_row("Target IP",     state.target_ip)
    table.add_row("Domain",        state.domain)
    if state.dns_server:
        table.add_row("DNS Server", state.dns_server)
    if state.initial_credentials.username:
        table.add_row("Username", state.initial_credentials.username)
    if state.open_ports:
        table.add_row(
            "Open Ports",
            ", ".join(str(p) for p in sorted(state.open_ports)),
        )

    console.print(
        Panel(
            table,
            title="[bold bright_cyan]Current Session[/bold bright_cyan]",
            border_style="bright_blue",
        )
    )


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
    return Prompt.ask(
        f"  [bold dim]{label}[/bold dim]",
        default=default,
        show_default=bool(default),
    ).strip()


# ─────────────────────────────────────────────────────────────────────────────
# Suggestion display
# ─────────────────────────────────────────────────────────────────────────────

PRIORITY_COLORS = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "bright_cyan",
    "low":      "dim",
}


def _display_suggestions(suggestions: list[dict]) -> None:
    """Render the current suggestion list as a numbered rich table."""
    table = Table(
        title="[bold bright_cyan]Suggested Next Actions[/bold bright_cyan]",
        box=box.ROUNDED,
        border_style="bright_blue",
        show_lines=True,
        expand=False,
    )
    table.add_column("#",        style="bold bright_cyan", width=4)
    table.add_column("Priority", width=10)
    table.add_column("Action",   style="white", width=36)
    table.add_column("Reason",   style="dim")

    for idx, s in enumerate(suggestions, start=1):
        color = PRIORITY_COLORS.get(s["priority"], "white")
        table.add_row(
            str(idx),
            f"[{color}]{s['priority'].upper()}[/{color}]",
            s["action"],
            s["reason"],
        )

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# New Assessment flow
# ─────────────────────────────────────────────────────────────────────────────

def start_new_assessment() -> AssessmentState:
    console.rule("[bold bright_cyan]New Assessment Setup[/bold bright_cyan]")
    console.print()

    target_ip = _prompt_required("Target Domain Controller IP")
    domain    = _prompt_required("Domain Name (e.g. corp.local)")

    console.print("\n  [dim]Optional fields — press Enter to skip.[/dim]\n")
    dns_server = _prompt_optional("DNS Server IP")
    username   = _prompt_optional("Username")

    password   = ""
    ntlm_hash  = ""
    if username:
        auth_choice = Prompt.ask(
            "  [bold dim]Auth method[/bold dim]",
            choices=["password", "hash", "none"],
            default="none",
        )
        if auth_choice == "password":
            password  = Prompt.ask("  [bold dim]Password[/bold dim]", password=True)
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
    console.print(
        f"\n  [bold green]✔  Session created and saved:[/bold green] [dim]{path}[/dim]\n"
    )
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
    table.add_column("#",             style="bold bright_cyan", width=4)
    table.add_column("Assessment ID", style="white")
    table.add_column("Target IP",     style="green")
    table.add_column("Domain",        style="yellow")

    for idx, sess in enumerate(sessions, start=1):
        table.add_row(
            str(idx),
            sess["assessment_id"],
            sess["target_ip"],
            sess["domain"],
        )

    console.print()
    console.print(table)
    console.print()

    choices = [str(i) for i in range(1, len(sessions) + 1)] + ["0"]
    choice  = Prompt.ask(
        "  [bold yellow]Select session #[/bold yellow] (0 to cancel)",
        choices=choices,
        show_choices=False,
    )

    if choice == "0":
        return None

    selected = sessions[int(choice) - 1]
    try:
        state = load_session(selected["assessment_id"])
        console.print(
            f"\n  [bold green]✔  Session loaded:[/bold green] {state.assessment_id}\n"
        )
        return state
    except FileNotFoundError as exc:
        console.print(f"\n  [red]Error: {exc}[/red]\n")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Execute Suggested Action flow
# ─────────────────────────────────────────────────────────────────────────────

def execute_suggested_action(state: AssessmentState) -> None:
    """
    Generate suggestions via SuggestionEngine, display them, let the user
    pick one, dispatch to the matching module, and update state.
    """
    from modules.suggestion_engine import generate_suggestions

    suggestions = generate_suggestions(state)

    if not suggestions:
        console.print(
            "\n  [bold yellow]⚠  No further logical attack paths detected.[/bold yellow]\n"
            "  [dim]Complete more enumeration steps or add credentials to unlock new paths.[/dim]\n"
        )
        return

    console.print()
    _display_suggestions(suggestions)
    console.print()

    choices = [str(i) for i in range(1, len(suggestions) + 1)] + ["0"]
    choice  = Prompt.ask(
        "  [bold yellow]Select action #[/bold yellow] (0 to cancel)",
        choices=choices,
        show_choices=False,
    )

    if choice == "0":
        return

    selected    = suggestions[int(choice) - 1]
    action_name = selected["action"]
    action_key  = _resolve_action_key(action_name)

    console.rule(f"[bold bright_cyan]Executing: {action_name}[/bold bright_cyan]")
    _dispatch_action(action_key, state)

    # Record that this action was performed
    state.log_action(action_name)
    save_session(state)

    # Regenerate and display updated suggestions
    updated = generate_suggestions(state)
    if updated:
        console.print()
        console.rule("[bold dim]Updated Suggestions[/bold dim]")
        _display_suggestions(updated)
    else:
        console.print(
            "\n  [bold green]✔  All currently actionable paths have been addressed.[/bold green]\n"
        )


def _resolve_action_key(action_name: str) -> str:
    """
    Map a human-readable suggestion action name back to its action_key.
    Keeps dispatcher logic decoupled from display strings.
    """
    name = action_name.lower()

    mapping = {
        "kerberoasting":        "kerberoasting",
        "as-rep roasting":      "asreproasting",
        "winrm":                "winrm",
        "password spraying":    "spraying",
        "smb relay":            "smbrelay",
        "pass-the-hash":        "passthehash",
        "ldap enumeration":     "ldap_enum",
        "smb enumeration":      "smb_enum",
        "rdp":                  "rdp",
        "mssql":                "mssql",
        "ad web services":      "adws",
        "run port":             "portscan",
        "port & service scan":  "portscan",
    }

    for keyword, key in mapping.items():
        if keyword in name:
            return key

    # Fallback: use first word
    return name.split()[0]


# ─────────────────────────────────────────────────────────────────────────────
# Findings log display
# ─────────────────────────────────────────────────────────────────────────────

def _display_findings_log(state: AssessmentState) -> None:
    console.rule("[bold bright_cyan]Findings Log[/bold bright_cyan]")

    if not state.findings_log:
        console.print("\n  [dim]No findings logged yet.[/dim]\n")
        return

    severity_colors = {
        "INFO":     "bright_blue",
        "LOW":      "green",
        "MEDIUM":   "yellow",
        "HIGH":     "red",
        "CRITICAL": "bold red",
    }

    table = Table(
        box=box.SIMPLE,
        show_lines=True,
        border_style="bright_blue",
    )
    table.add_column("Timestamp",   style="dim",  width=20)
    table.add_column("Severity",                  width=10)
    table.add_column("Category",    style="cyan", width=16)
    table.add_column("Description")

    for entry in state.findings_log:
        sev   = entry.get("severity", "INFO")
        color = severity_colors.get(sev, "white")
        table.add_row(
            entry.get("timestamp",   ""),
            f"[{color}]{sev}[/{color}]",
            entry.get("category",    ""),
            entry.get("description", ""),
        )

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Assessment menu
# ─────────────────────────────────────────────────────────────────────────────

def assessment_menu(state: AssessmentState) -> None:
    """Main interaction loop for an active assessment session."""
    while True:
        console.print()
        print_assessment_header(state)
        console.print()

        console.print("[bold bright_cyan]Assessment Menu[/bold bright_cyan]\n")
        console.print("  [bright_cyan]1.[/bright_cyan]  Port & Service Scan")
        console.print("  [bright_cyan]2.[/bright_cyan]  Execute Suggested Action")
        console.print("  [bright_cyan]3.[/bright_cyan]  View Findings Log")
        console.print("  [bright_cyan]4.[/bright_cyan]  Save & Return to Main Menu")
        console.print()

        choice = Prompt.ask(
            "  [bold yellow]Select option[/bold yellow]",
            choices=["1", "2", "3", "4"],
            show_choices=False,
        )

        if choice == "1":
            from modules.nmap_module import run as nmap_run
            nmap_run(state)
            save_session(state)

        elif choice == "2":
            execute_suggested_action(state)

        elif choice == "3":
            _display_findings_log(state)

        elif choice == "4":
            path = save_session(state)
            console.print(
                f"\n  [bold green]✔  Session saved:[/bold green] [dim]{path}[/dim]\n"
            )
            break


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