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
        from modules.kerberoasting_module import run as kerb_run
        result = kerb_run(state)
        _display_kerb_results(result)
        save_session(state)

    elif key == "asreproasting":
        from modules.asrep_roasting_module import run as asrep_run
        result = asrep_run(state)
        _display_asrep_results(result)
        save_session(state)

    elif key == "ldap_enum":
        from modules.ldap_enum_module import run as ldap_run
        result = ldap_run(state)
        _display_ldap_results(result)

    elif key == "smb_enum":
        from modules.smb_enum_module import run as smb_run
        smb_run(state)

    elif key == "smbrelay":
        console.print("\n  [yellow]⚠  SMB Relay module not yet implemented.[/yellow]\n")

    elif key == "winrm":
        console.print("\n  [yellow]⚠  WinRM module not yet implemented.[/yellow]\n")

    elif key == "spraying":
        from modules.password_spray_module import run as spray_run
        passwords = Prompt.ask(
            "  [bold yellow]Password(s) to spray[/bold yellow] "
            "[dim](comma-separated)[/dim]"
        ).split(",")
        passwords = [p.strip() for p in passwords if p.strip()]
        if passwords:
            preview = spray_run(state, passwords=passwords, confirmed=False)
            _display_spray_results(preview)
            confirm = Prompt.ask(
                "\n  [bold red]Execute spray?[/bold red] [dim](yes/no)[/dim]",
                choices=["yes", "no"], default="no",
            )
            if confirm == "yes":
                result = spray_run(state, passwords=passwords, confirmed=True)
                _display_spray_results(result)
                save_session(state)

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


# ────────────────────────────────────────────────────────────────────────────────
# LDAP results display
# ────────────────────────────────────────────────────────────────────────────────

def _display_ldap_results(result: dict) -> None:
    """
    Render the structured result dict from ldap_enum_module using rich.
    Called immediately after the module returns, before session is saved.
    """
    if result["status"] == "error":
        console.print(
            f"\n  [bold red]✘  LDAP Enumeration failed:[/bold red] {result['error']}\n"
        )
        for w in result.get("warnings", []):
            console.print(f"  [yellow]⚠  {w}[/yellow]")
        return

    # ── Summary table ───────────────────────────────────────────
    table = Table(
        title="[bold bright_cyan]LDAP Enumeration Results[/bold bright_cyan]",
        box=box.ROUNDED,
        border_style="bright_blue",
        show_lines=True,
        expand=False,
    )
    table.add_column("Property",  style="bold bright_cyan", width=24)
    table.add_column("Value",     style="white")

    anon = result["anonymous"]
    table.add_row(
        "Anonymous Bind",
        "[bold red]ALLOWED[/bold red]" if anon else "[green]Denied[/green]",
    )
    table.add_row("LDAPS", "[green]Yes[/green]" if result["ldaps"] else "[dim]No[/dim]")
    table.add_row("Users Discovered",  str(len(result["users"])))
    table.add_row("Groups Discovered", str(len(result["groups"])))
    table.add_row("SPNs Found",        str(len(result["spns"])))

    asrep = result["asrep_users"]
    asrep_display = (
        f"[bold red]{len(asrep)} ROASTABLE[/bold red]: " + ", ".join(asrep[:6])
        + (" …" if len(asrep) > 6 else "")
        if asrep else "[green]None detected[/green]"
    )
    table.add_row("AS-REP Roastable", asrep_display)

    desc = result["desc_findings"]
    desc_display = (
        f"[bold red]{len(desc)} suspicious[/bold red]"
        if desc else "[green]None detected[/green]"
    )
    table.add_row("Description Creds", desc_display)

    console.print()
    console.print(table)

    # ── Suspicious descriptions detail ────────────────────────────
    if desc:
        desc_table = Table(
            title="[bold red]⚠  Suspicious Description Fields[/bold red]",
            box=box.SIMPLE,
            border_style="red",
            show_lines=True,
        )
        desc_table.add_column("Username",    style="bold yellow", width=22)
        desc_table.add_column("Description", style="white")
        for f in desc:
            desc_table.add_row(f["username"], f["description"])
        console.print(desc_table)

    # ── SPN list ──────────────────────────────────────────────
    spns = result["spns"]
    if spns:
        spn_table = Table(
            title="[bold bright_cyan]Kerberoastable SPNs[/bold bright_cyan]",
            box=box.SIMPLE,
            border_style="bright_blue",
            show_lines=True,
        )
        spn_table.add_column("Username", style="bold yellow", width=22)
        spn_table.add_column("SPN",      style="white")
        for s in spns:
            spn_table.add_row(s["username"], s["spn"])
        console.print(spn_table)

    # ── Warnings ──────────────────────────────────────────────
    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")

    console.print()


# ────────────────────────────────────────────────────────────────────────────────
# Attack module result display functions
# ────────────────────────────────────────────────────────────────────────────────

def _display_asrep_results(result: dict) -> None:
    """Display AS-REP Roasting results from asrep_roasting_module."""
    if result["status"] == "error":
        console.print(f"\n  [bold red]✘  AS-REP Roasting failed:[/bold red] {result['error']}\n")
        return

    hashes = result["hashes"]
    table  = Table(
        title="[bold bright_cyan]AS-REP Roasting Results[/bold bright_cyan]",
        box=box.ROUNDED, border_style="bright_blue", show_lines=True, expand=False,
    )
    table.add_column("Property", style="bold bright_cyan", width=20)
    table.add_column("Value",    style="white")
    table.add_row("Mode",    result["mode"].upper())
    table.add_row("Hashes",  f"[bold red]{len(hashes)} captured[/bold red]" if hashes else "[green]None[/green]")
    table.add_row("Saved to", result["hash_file"] or "N/A")
    console.print(); console.print(table)

    if hashes:
        console.print(f"\n  [bold yellow]Crack command:[/bold yellow]")
        console.print(f"  [dim]{result['crack_command']}[/dim]\n")
        for h in hashes[:5]:
            console.print(f"  [dim]{h[:100]}[/dim]")
        if len(hashes) > 5:
            console.print(f"  [dim]... and {len(hashes)-5} more in file[/dim]")

    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")
    console.print()


def _display_kerb_results(result: dict) -> None:
    """Display Kerberoasting results from kerberoasting_module."""
    if result["status"] == "error":
        console.print(f"\n  [bold red]✘  Kerberoasting failed:[/bold red] {result['error']}\n")
        return

    hashes = result["hashes"]
    table  = Table(
        title="[bold bright_cyan]Kerberoasting Results[/bold bright_cyan]",
        box=box.ROUNDED, border_style="bright_blue", show_lines=True, expand=False,
    )
    table.add_column("Property", style="bold bright_cyan", width=20)
    table.add_column("Value",    style="white")
    table.add_row("TGS Tickets", f"[bold red]{len(hashes)} captured[/bold red]" if hashes else "[green]None[/green]")
    table.add_row("Saved to",   result["hash_file"] or "N/A")
    console.print(); console.print(table)

    if hashes:
        spn_table = Table(box=box.SIMPLE, border_style="bright_blue", show_lines=True)
        spn_table.add_column("Username", style="bold yellow", width=22)
        spn_table.add_column("SPN",      style="white")
        for entry in hashes:
            spn_table.add_row(entry["username"], entry["spn"])
        console.print(spn_table)
        console.print(f"\n  [bold yellow]Crack command:[/bold yellow]")
        console.print(f"  [dim]{result['crack_command']}[/dim]\n")

    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")
    console.print()


def _display_spray_results(result: dict) -> None:
    """Display Password Spray results from password_spray_module."""
    status = result["status"]

    if status == "error":
        console.print(f"\n  [bold red]✘  Password Spray failed:[/bold red] {result['error']}\n")
        return

    if status == "dry_run":
        console.print("\n  [bold yellow]⚠  DRY RUN — spray NOT executed[/bold yellow]")
        for w in result["warnings"]:
            console.print(f"  [dim]{w}[/dim]")
        console.print()
        return

    valid = result["valid_creds"]
    table = Table(
        title="[bold bright_cyan]Password Spray Results[/bold bright_cyan]",
        box=box.ROUNDED, border_style="bright_blue", show_lines=True, expand=False,
    )
    table.add_column("Property", style="bold bright_cyan", width=22)
    table.add_column("Value",    style="white")
    table.add_row("Users Tested",     str(result["user_count"]))
    table.add_row("Rounds",           str(result["spray_rounds"]))
    table.add_row("Valid Creds Found", f"[bold red]{len(valid)}[/bold red]" if valid else "[green]None[/green]")
    table.add_row("Lockout Detected", "[bold red]YES — SPRAY STOPPED[/bold red]" if result["lockout_detected"] else "[green]No[/green]")
    console.print(); console.print(table)

    if valid:
        cred_table = Table(box=box.SIMPLE, border_style="red", show_lines=True)
        cred_table.add_column("Username", style="bold yellow", width=22)
        cred_table.add_column("Password", style="bold red")
        for c in valid:
            cred_table.add_row(c["username"], c["password"])
        console.print(cred_table)

    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")
    console.print()



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

        console.rule("[bold bright_cyan]Assessment Menu[/bold bright_cyan]")
        console.print()

        # ── Smart guide (promoted — most useful entry point) ──────────────
        console.print("  [bold bright_cyan]★[/bold bright_cyan]  [bold bright_cyan]7.[/bold bright_cyan]  [bold white]Auto-Suggest Next Step[/bold white]  [dim](recommended — engine picks the best action based on current findings)[/dim]")
        console.print()

        # ── RECON ─────────────────────────────────────────────────────────
        console.print("  [dim]── RECON ──────────────────────────────────────────────────[/dim]")
        console.print("  [bright_cyan]1.[/bright_cyan]  Port & Service Scan          [dim](nmap — always run this first)[/dim]")
        console.print("  [bright_cyan]2.[/bright_cyan]  LDAP Enumeration             [dim](users, groups, SPNs, AS-REP targets)[/dim]")
        console.print("  [bright_cyan]3.[/bright_cyan]  SMB Enumeration + RID Brute  [dim](shares, signing, user discovery)[/dim]")
        console.print()

        # ── ATTACKS ───────────────────────────────────────────────────────
        console.print("  [dim]── ATTACKS ────────────────────────────────────────────────[/dim]")
        console.print("  [bright_cyan]4.[/bright_cyan]  AS-REP Roasting              [dim](port 88 required — no creds needed)[/dim]")
        console.print("  [bright_cyan]5.[/bright_cyan]  Kerberoasting                [dim](port 88 + valid creds required)[/dim]")
        console.print("  [bright_cyan]6.[/bright_cyan]  Password Spraying            [dim](users required — lockout detection on)[/dim]")
        console.print()

        # ── SESSION ───────────────────────────────────────────────────────
        console.print("  [dim]── SESSION ────────────────────────────────────────────────[/dim]")
        console.print("  [bright_cyan]8.[/bright_cyan]  View Findings Log")
        console.print("  [bright_cyan]9.[/bright_cyan]  Save & Return to Main Menu")
        console.print()

        choice = Prompt.ask(
            "  [bold yellow]Select option[/bold yellow]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
            show_choices=False,
        )

        if choice == "1":
            from modules.nmap_module import run as nmap_run
            nmap_run(state)
            save_session(state)

        elif choice == "2":
            from modules.ldap_enum_module import run as ldap_run
            result = ldap_run(state)
            _display_ldap_results(result)
            save_session(state)

        elif choice == "3":
            from modules.smb_enum_module import run as smb_run
            smb_run(state)
            save_session(state)

        elif choice == "4":
            from modules.asrep_roasting_module import run as asrep_run
            result = asrep_run(state)
            _display_asrep_results(result)
            save_session(state)

        elif choice == "5":
            from modules.kerberoasting_module import run as kerb_run
            result = kerb_run(state)
            _display_kerb_results(result)
            save_session(state)

        elif choice == "6":
            passwords = Prompt.ask(
                "  [bold yellow]Password(s) to spray[/bold yellow] "
                "[dim](comma-separated, e.g. Password123!)[/dim]"
            ).split(",")
            passwords = [p.strip() for p in passwords if p.strip()]
            if passwords:
                from modules.password_spray_module import run as spray_run
                preview = spray_run(state, passwords=passwords, confirmed=False)
                _display_spray_results(preview)
                confirm = Prompt.ask(
                    "\n  [bold red]Execute spray?[/bold red]",
                    choices=["yes", "no"], default="no",
                )
                if confirm == "yes":
                    result = spray_run(state, passwords=passwords, confirmed=True)
                    _display_spray_results(result)
                    save_session(state)

        elif choice == "7":
            execute_suggested_action(state)

        elif choice == "8":
            _display_findings_log(state)

        elif choice == "9":
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