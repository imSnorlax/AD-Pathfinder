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
        from modules.smb_enum_module import run as smb_run, display_results as smb_display
        result = smb_run(state)
        smb_display(result)
        save_session(state)

    elif key == "smbrelay":
        console.print("\n  [yellow]⚠  SMB Relay module not yet implemented.[/yellow]\n")

    elif key == "winrm":
        from modules.evil_winrm_module import run as winrm_run
        winrm_run(state)
        save_session(state)

    elif key == "passthehash":
        from modules.evil_winrm_module import run as winrm_run
        winrm_run(state)
        save_session(state)

    elif key == "responder":
        from modules.responder_module import run as responder_run
        result = responder_run(state)
        _display_responder_results(result)
        save_session(state)

    elif key == "credvalidation":
        from modules.cred_validation_module import run as cred_run
        result = cred_run(state)
        _display_cred_validation_results(result)
        save_session(state)

    elif key == "aclabuse":
        from modules.acl_abuse_module import run as acl_run
        result = acl_run(state)
        _display_acl_results(result)
        save_session(state)

    elif key == "dcsync":
        from modules.dcsync_module import run as dcsync_run
        result = dcsync_run(state)
        _display_dcsync_results(result)
        save_session(state)

    elif key == "goldenticket":
        from modules.golden_ticket_module import run as gt_run
        result = gt_run(state)
        _display_golden_ticket_results(result)
        save_session(state)

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
            title="[bold red]⚠  Credentials Found in Description Fields[/bold red]",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
        )
        desc_table.add_column("Username",    style="bold yellow", width=22)
        desc_table.add_column("Description", style="bold red")
        for f in desc:
            desc_table.add_row(f["username"], f["description"])
        console.print()
        console.print(desc_table)
        console.print()
        console.print("  [bold red]⚠  IMPORTANT — Temporary Password Workflow:[/bold red]")
        console.print("  [dim]These creds may be temporary (must-change-at-next-logon).[/dim]")
        console.print("  [dim]Test  →  Phase 2 → Credential Validation → netexec smb -u <user> -p <pass> --users[/dim]")
        console.print("  [dim]Reset →  Phase 2 → Credential Validation → smbpasswd -r <dc> -U <user>[/dim]")
        console.print()

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

    # ── Password policy ───────────────────────────────────────
    policy = result.get("password_policy")
    if policy:
        pol_table = Table(
            title="[bold bright_cyan]Password Policy[/bold bright_cyan]",
            box=box.SIMPLE, border_style="bright_blue", show_lines=True,
        )
        pol_table.add_column("Setting", style="bold bright_cyan", width=28)
        pol_table.add_column("Value",   style="white")
        for k, v in policy.items():
            pol_table.add_row(k, str(v))
        console.print(pol_table)
        console.print("  [dim]→ Know the lockout threshold before password spraying.[/dim]")

    # ── Warnings ──────────────────────────────────────────────
    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")

    # ── domain dump ───────────────────────────────────────────
    dump = result.get("domain_dump_path")
    if dump:
        console.print(f"\n  [green]✔  ldapdomaindump saved to:[/green] [dim]{dump}[/dim]")

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


def _display_responder_results(result: dict) -> None:
    """Display Responder LLMNR/NBT-NS poisoning results."""
    if result["status"] == "error":
        console.print(f"\n  [bold red]✘  Responder failed:[/bold red] {result['error']}\n")
        return

    hashes = result["hashes"]
    table  = Table(
        title="[bold bright_cyan]Responder — LLMNR Poisoning Results[/bold bright_cyan]",
        box=box.ROUNDED, border_style="bright_blue", show_lines=True, expand=False,
    )
    table.add_column("Property", style="bold bright_cyan", width=22)
    table.add_column("Value",    style="white")
    table.add_row("Hashes Captured", f"[bold red]{len(hashes)}[/bold red]" if hashes else "[green]None[/green]")
    table.add_row("Saved to", result["hash_file"] or "N/A")
    console.print(); console.print(table)

    if hashes:
        console.print(f"\n  [bold yellow]Crack command (NetNTLMv2 — mode 5600):[/bold yellow]")
        console.print(f"  [dim]{result['crack_command']}[/dim]\n")
        for h in hashes[:3]:
            console.print(f"  [dim]{h[:80]}…[/dim]")
        if len(hashes) > 3:
            console.print(f"  [dim]… and {len(hashes)-3} more[/dim]")

    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")
    console.print()


def _display_cred_validation_results(result: dict) -> None:
    """Display credential validation and password reset results."""
    if result["status"] == "error" and result["operation"] != "cancelled":
        console.print(f"\n  [bold red]✘  Credential Validation error:[/bold red] {result['error']}\n")
        return

    valid = result.get("valid_creds", [])
    table = Table(
        title="[bold bright_cyan]Credential Validation Results[/bold bright_cyan]",
        box=box.ROUNDED, border_style="bright_blue", show_lines=True, expand=False,
    )
    table.add_column("Property", style="bold bright_cyan", width=22)
    table.add_column("Value",    style="white")
    table.add_row("Valid Credentials", f"[bold red]{len(valid)} confirmed[/bold red]" if valid else "[green]None[/green]")
    table.add_row("Password Reset",    "[green]Done[/green]" if result.get("reset_done") else "[dim]No[/dim]")
    console.print(); console.print(table)

    if valid:
        ct = Table(box=box.SIMPLE, border_style="red", show_lines=True)
        ct.add_column("Username", style="bold yellow", width=22)
        ct.add_column("Password", style="bold red")
        for c in valid:
            ct.add_row(c["username"], c["password"])
        console.print(ct)

    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")
    console.print()


def _display_acl_results(result: dict) -> None:
    """Display ACL/WriteDACL abuse results."""
    if result["status"] == "error":
        console.print(f"\n  [bold red]✘  ACL Abuse failed:[/bold red] {result['error']}\n")
        return

    console.print()
    console.print(
        f"  [bold green]✔  WriteDACL success:[/bold green] "
        f"'{result['member']}' added to group '[bold red]{result['group']}[/bold red]'"
    )
    console.print(f"  [dim]Auth:    {result['auth_user']}[/dim]")
    console.print(f"  [dim]Command: {result['command']}[/dim]")
    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")
    console.print()


def _display_dcsync_results(result: dict) -> None:
    """Display DCSync (secretsdump) results."""
    if result["status"] == "error":
        console.print(f"\n  [bold red]✘  DCSync failed:[/bold red] {result['error']}\n")
        return

    hashes = result["hashes"]
    table  = Table(
        title="[bold bright_cyan]DCSync — Hash Dump Results[/bold bright_cyan]",
        box=box.ROUNDED, border_style="bright_blue", show_lines=True, expand=False,
    )
    table.add_column("Property", style="bold bright_cyan", width=22)
    table.add_column("Value",    style="white")
    table.add_row("Accounts Dumped", f"[bold red]{len(hashes)}[/bold red]")
    table.add_row("Saved to",        result["hash_file"] or "N/A")
    table.add_row("krbtgt NT hash",  f"[bold red]{result['krbtgt_nt'][:16]}…[/bold red]" if result.get("krbtgt_nt") else "[dim]Not found[/dim]")
    table.add_row("Admin NT hash",   f"[bold red]{result['admin_nt'][:16]}…[/bold red]" if result.get("admin_nt") else "[dim]Not found[/dim]")
    console.print(); console.print(table)

    # Show first 5 accounts
    if hashes:
        ht = Table(box=box.SIMPLE, border_style="red", show_lines=True)
        ht.add_column("Username",  style="bold yellow", width=22)
        ht.add_column("NT Hash",   style="dim",         width=36)
        for h in hashes[:5]:
            ht.add_row(h["username"], h["nt"])
        if len(hashes) > 5:
            ht.add_row(f"… +{len(hashes)-5} more", "(see dump file)")
        console.print(ht)

    if result.get("krbtgt_nt"):
        console.print(f"\n  [bold yellow]→ krbtgt hash ready for Golden Ticket forging.[/bold yellow]")
        console.print(f"  [dim]Use Phase 3 → Golden Ticket to forge a .ccache[/dim]\n")

    for w in result.get("warnings", []):
        console.print(f"\n  [yellow]⚠  {w}[/yellow]")
    console.print()


def _display_golden_ticket_results(result: dict) -> None:
    """Display Golden Ticket forge results."""
    if result["status"] == "error":
        console.print(f"\n  [bold red]✘  Golden Ticket failed:[/bold red] {result['error']}\n")
        return

    console.print()
    console.print(f"  [bold green]✔  Golden Ticket forged for:[/bold green] [bold red]{result['target_user']}[/bold red]")
    console.print(f"  [dim]Ticket: {result['ticket_path']}[/dim]")
    console.print()
    console.print(f"  [bold yellow]Load ticket:[/bold yellow]")
    console.print(f"  [bright_white]{result['export_cmd']}[/bright_white]")
    console.print()
    console.print(f"  [bold yellow]Use ticket (psexec):[/bold yellow]")
    console.print(f"  [bright_white]{result['use_cmd']}[/bright_white]")

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
        "evil-winrm":           "winrm",
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
        "responder":            "responder",
        "llmnr":                "responder",
        "credential validation":"credvalidation",
        "acl abuse":            "aclabuse",
        "writedacl":            "aclabuse",
        "dcsync":               "dcsync",
        "secretsdump":          "dcsync",
        "golden ticket":        "goldenticket",
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

def _phase1_recon_menu(state: AssessmentState) -> None:
    """Phase 1 — Recon sub-menu."""
    while True:
        console.print()
        console.rule("[bold bright_cyan]Phase 1 — Recon[/bold bright_cyan]")
        console.print()
        console.print("  [bright_cyan]1.[/bright_cyan]  Port & Service Scan        [dim](nmap — run first)[/dim]")
        console.print("  [bright_cyan]2.[/bright_cyan]  LDAP Enumeration           [dim](users/groups/SPNs/policy/ldapdomaindump)[/dim]")
        console.print("  [bright_cyan]3.[/bright_cyan]  SMB Enumeration + RID Brute[dim](shares, guest creds, user/group discovery)[/dim]")
        console.print("  [bright_cyan]0.[/bright_cyan]  Back")
        console.print()
        choice = Prompt.ask("  [bold yellow]Select[/bold yellow]", choices=["0", "1", "2", "3"], show_choices=False)
        if choice == "0":
            break
        elif choice == "1":
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


def _phase2_exploitation_menu(state: AssessmentState) -> None:
    """Phase 2 — Exploitation sub-menu."""
    while True:
        console.print()
        console.rule("[bold bright_cyan]Phase 2 — Exploitation[/bold bright_cyan]")
        console.print()
        console.print("  [bright_cyan]1.[/bright_cyan]  AS-REP Roasting      [dim](port 88 — no creds needed)[/dim]")
        console.print("  [bright_cyan]2.[/bright_cyan]  Kerberoasting        [dim](port 88 + valid creds required)[/dim]")
        console.print("  [bright_cyan]3.[/bright_cyan]  Password Spraying    [dim](users required — lockout detection on)[/dim]")
        console.print("  [bright_cyan]4.[/bright_cyan]  Responder / LLMNR    [dim](same network — captures NetNTLMv2)[/dim]")
        console.print("  [bright_cyan]5.[/bright_cyan]  Credential Validation[dim](netexec --users + smbpasswd reset)[/dim]")
        console.print("  [bright_cyan]0.[/bright_cyan]  Back")
        console.print()
        choice = Prompt.ask("  [bold yellow]Select[/bold yellow]", choices=["0", "1", "2", "3", "4", "5"], show_choices=False)
        if choice == "0":
            break
        elif choice == "1":
            from modules.asrep_roasting_module import run as asrep_run
            result = asrep_run(state)
            _display_asrep_results(result)
            save_session(state)
        elif choice == "2":
            # ── Kerberoasting credential resolution ────────────────────
            # Build a list of all known creds from the session so the user
            # can just pick a number instead of typing them out.
            from session import Credentials as _Creds

            _cred_pool: list[tuple[str, str, str]] = []   # (username, password, source)

            # 1. Description creds found during LDAP enum
            for _df in getattr(state, "desc_findings", []):
                _u = _df.get("username", "")
                _p = _df.get("description", "")   # raw description contains the cred
                if _u and _p:
                    _cred_pool.append((_u, _p, "desc"))

            # 2. Valid creds confirmed by spraying / validation
            for _vc in getattr(state, "valid_credentials", []):
                _u = _vc.get("username", "")
                _p = _vc.get("password", _vc.get("ntlm_hash", ""))
                if _u and _p and not any(c[0] == _u and c[1] == _p for c in _cred_pool):
                    _cred_pool.append((_u, _p, "spray"))

            # 3. Initial credentials (if non-guest with a password set)
            _ic = state.initial_credentials
            if _ic and _ic.username and (_ic.password or _ic.ntlm_hash):
                _p = _ic.password or _ic.ntlm_hash
                if not any(c[0] == _ic.username and c[1] == _p for c in _cred_pool):
                    _cred_pool.append((_ic.username, _p, "session"))

            # 4. Usernames from state.hashes (AS-REP / TGS captures)
            #    PLUS fallback: read the asrep hash file from disk when the
            #    session was saved before the run completed (state.hashes empty).
            _hash_users: list[str] = []

            def _users_from_state_hashes() -> list[str]:
                out = []
                for _h in getattr(state, "hashes", []):
                    _hu = _h.get("username", "")
                    # Strip @DOMAIN suffix if present
                    _hu = _hu.split("@")[0] if "@" in _hu else _hu
                    if _hu and not any(c[0] == _hu for c in _cred_pool) and _hu not in out:
                        out.append(_hu)
                return out

            def _users_from_asrep_file() -> list[str]:
                """Parse $krb5asrep$23$user@DOMAIN:hash lines from the saved file."""
                import re as _re
                _path = os.path.join("reports", f"{state.assessment_id}-asrep.txt")
                if not os.path.isfile(_path):
                    return []
                out = []
                _pat = _re.compile(r"\$krb5asrep\$\d+\$([^@]+)@", _re.IGNORECASE)
                try:
                    with open(_path, encoding="utf-8", errors="replace") as _fh:
                        for _line in _fh:
                            _m = _pat.search(_line)
                            if _m:
                                _hu = _m.group(1).strip()
                                if _hu and not any(c[0] == _hu for c in _cred_pool) and _hu not in out:
                                    out.append(_hu)
                except OSError:
                    pass
                return out

            _hash_users = _users_from_state_hashes() or _users_from_asrep_file()


            # ── Display known creds if any ──────────────────────────────
            console.print()
            console.rule("[bold bright_cyan]Kerberoasting — Select Credentials[/bold bright_cyan]")
            console.print()

            _selected_user = ""
            _selected_pass = ""

            if _cred_pool or _hash_users:
                _ct = Table(
                    title="[bold bright_cyan]Available Credentials[/bold bright_cyan]",
                    box=box.ROUNDED, border_style="bright_blue",
                    show_lines=True, expand=False,
                )
                _ct.add_column("#",        style="bold bright_cyan", width=4)
                _ct.add_column("Username", style="bold yellow",       width=26)
                _ct.add_column("Password", style="dim",               width=36)
                _ct.add_column("Source",   style="bright_blue",       width=10)

                _all_rows: list[tuple[str, str, str]] = []  # (user, pass, source)
                for (_u, _p, _src) in _cred_pool:
                    _all_rows.append((_u, _p, _src))
                    _ct.add_row(str(len(_all_rows)), _u, _p, _src)

                # Hash-captured usernames — password not yet known (needs cracking)
                for _hu in _hash_users:
                    _all_rows.append((_hu, "", "hash"))
                    _ct.add_row(
                        str(len(_all_rows)), _hu,
                        "[dim italic]enter cracked password[/dim italic]",
                        "[yellow]hash[/yellow]",
                    )

                console.print(_ct)
                console.print()
                console.print("  [dim]Pick a number — hash entries will ask for the cracked password.[/dim]")
                console.print()

                _pick = Prompt.ask(
                    "  [bold yellow]Select #[/bold yellow] (Enter to type manually)",
                    default="",
                    show_default=False,
                )
                if _pick.strip().isdigit():
                    _idx = int(_pick.strip()) - 1
                    if 0 <= _idx < len(_all_rows):
                        _sel_u, _sel_p, _sel_src = _all_rows[_idx]
                        if _sel_p:
                            # Full cred — ready to go
                            _selected_user = _sel_u
                            _selected_pass = _sel_p
                            console.print(f"  [green]✔  Using: {_selected_user}[/green]")
                        else:
                            # Hash-user — pre-fill username, ask for cracked password
                            _selected_user = _sel_u
                            console.print(f"  [dim]Pre-selected username: {_selected_user}[/dim]")
                            _selected_pass = Prompt.ask(
                                f"  [bold cyan]Cracked password for {_selected_user}[/bold cyan]",
                                password=True,
                            )
            else:
                console.print("  [dim]No credentials or captured hashes found in session.[/dim]")
                console.print()


            # ── Manual entry fallback ───────────────────────────────────
            if not _selected_user:
                _selected_user = Prompt.ask("  [bold cyan]Username[/bold cyan]")
                _selected_pass = Prompt.ask("  [bold cyan]Password[/bold cyan]", password=True)

            if not _selected_user or not _selected_pass:
                console.print("  [red]No credentials provided — Kerberoasting aborted.[/red]")
                continue

            state.initial_credentials = _Creds(
                username=_selected_user,
                password=_selected_pass,
            )

            # ── Run Kerberoasting ───────────────────────────────────────
            from modules.kerberoasting_module import run as kerb_run
            result = kerb_run(state)

            # ── Handle password-must-change ─────────────────────────────
            _combined_warn = " ".join(result.get("warnings", []) + [result.get("error", "") or ""])
            if any(s in _combined_warn.lower() for s in (
                "password must change", "password has expired",
                "kdc_err_key_expired", "must change", "status_password_must_change"
            )):
                console.print()
                console.print("  [bold red]⚠  Password must be changed before this account can be used.[/bold red]")
                console.print(f"  [dim]Run the following to reset it:[/dim]")
                console.print(f"  [bright_white]smbpasswd -r {state.target_ip} -U {_selected_user}[/bright_white]")
                console.print()
                if Prompt.ask(
                    "  [bold yellow]Change password now?[/bold yellow]",
                    choices=["yes", "no"], default="no"
                ) == "yes":
                    _new_pass = Prompt.ask("  [bold cyan]New password[/bold cyan]", password=True)
                    _new_pass2 = Prompt.ask("  [bold cyan]Confirm new password[/bold cyan]", password=True)
                    if _new_pass == _new_pass2 and _new_pass:
                        from executor import CommandExecutor as _CE
                        import os as _os2
                        _env2 = dict(_os2.environ)
                        for _v in ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"):
                            _env2.pop(_v, None)
                        _ce = _CE(verbose=False, default_timeout=30)
                        _pr = _ce.run(
                            ["smbpasswd", "-r", state.target_ip, "-U", _selected_user],
                            env=_env2,
                        )
                        console.print(f"  [dim]smbpasswd output: {_pr['output'] or _pr['error']}[/dim]")
                        # Retry kerberoasting with new password
                        state.initial_credentials = _Creds(username=_selected_user, password=_new_pass)
                        console.print()
                        console.print("  [dim]Retrying Kerberoasting with new password...[/dim]")
                        result = kerb_run(state)
                    else:
                        console.print("  [red]Passwords do not match — retry manually.[/red]")

            _display_kerb_results(result)
            save_session(state)


        elif choice == "3":
            passwords = Prompt.ask(
                "  [bold yellow]Password(s) to spray[/bold yellow] [dim](comma-separated)[/dim]"
            ).split(",")
            passwords = [p.strip() for p in passwords if p.strip()]
            if passwords:
                from modules.password_spray_module import run as spray_run
                preview = spray_run(state, passwords=passwords, confirmed=False)
                _display_spray_results(preview)
                if Prompt.ask("  [bold red]Execute spray?[/bold red]", choices=["yes", "no"], default="no") == "yes":
                    result = spray_run(state, passwords=passwords, confirmed=True)
                    _display_spray_results(result)
                    save_session(state)
        elif choice == "4":
            from modules.responder_module import run as responder_run
            result = responder_run(state)
            _display_responder_results(result)
            save_session(state)
        elif choice == "5":
            from modules.cred_validation_module import run as cred_run
            result = cred_run(state)
            _display_cred_validation_results(result)
            save_session(state)


def _phase3_postex_menu(state: AssessmentState) -> None:
    """Phase 3 — Post-Exploitation sub-menu."""
    while True:
        console.print()
        console.rule("[bold bright_cyan]Phase 3 — Post-Exploitation[/bold bright_cyan]")
        console.print()
        console.print("  [bright_cyan]1.[/bright_cyan]  ACL Abuse / WriteDACL[dim](net rpc group addmembers)[/dim]")
        console.print("  [bright_cyan]2.[/bright_cyan]  Evil-WinRM Shell     [dim](password auth, port 5985/5986)[/dim]")
        console.print("  [bright_cyan]3.[/bright_cyan]  DCSync               [dim](impacket-secretsdump — all domain hashes)[/dim]")
        console.print("  [bright_cyan]4.[/bright_cyan]  Pass-the-Hash (PTH)  [dim](evil-winrm -H <nt_hash>)[/dim]")
        console.print("  [bright_cyan]5.[/bright_cyan]  Golden Ticket        [dim](impacket-ticketer — needs krbtgt NT hash)[/dim]")
        console.print("  [bright_cyan]0.[/bright_cyan]  Back")
        console.print()
        choice = Prompt.ask("  [bold yellow]Select[/bold yellow]", choices=["0", "1", "2", "3", "4", "5"], show_choices=False)
        if choice == "0":
            break
        elif choice == "1":
            from modules.acl_abuse_module import run as acl_run
            result = acl_run(state)
            _display_acl_results(result)
            save_session(state)
        elif choice in ("2", "4"):
            from modules.evil_winrm_module import run as winrm_run
            winrm_run(state)
            save_session(state)
        elif choice == "3":
            from modules.dcsync_module import run as dcsync_run
            result = dcsync_run(state)
            _display_dcsync_results(result)
            save_session(state)
        elif choice == "5":
            from modules.golden_ticket_module import run as gt_run
            result = gt_run(state)
            _display_golden_ticket_results(result)
            save_session(state)


def assessment_menu(state: AssessmentState) -> None:
    """Main interaction loop for an active assessment session."""

    while True:
        console.print()
        print_assessment_header(state)
        console.print()

        console.rule("[bold bright_cyan]Assessment Menu[/bold bright_cyan]")
        console.print()

        # ── Smart guide ──────────────────────────────────────────────────
        console.print("  [bold bright_cyan]★[/bold bright_cyan]  [bold bright_cyan]A.[/bold bright_cyan]  [bold white]Auto-Suggest Next Step[/bold white]  [dim](recommended)[/dim]")
        console.print()

        # ── PHASES ──────────────────────────────────────────────────
        console.print("  [dim]── PHASES ────────────────────────────────────────────────────[/dim]")
        console.print("  [bright_cyan]1.[/bright_cyan]  Phase 1 — Recon              [dim](nmap, ldap, smb)[/dim]")
        console.print("  [bright_cyan]2.[/bright_cyan]  Phase 2 — Exploitation       [dim](AS-REP, Kerb, Spray, Responder, Cred Validation)[/dim]")
        console.print("  [bright_cyan]3.[/bright_cyan]  Phase 3 — Post-Exploitation  [dim](ACL Abuse, Evil-WinRM, DCSync, PTH, Golden Ticket)[/dim]")
        console.print()

        # ── SESSION ────────────────────────────────────────────────
        console.print("  [dim]── SESSION ────────────────────────────────────────────────[/dim]")
        console.print("  [bright_cyan]4.[/bright_cyan]  View Findings Log")
        console.print("  [bright_cyan]5.[/bright_cyan]  Save & Return to Main Menu")
        console.print()

        choice = Prompt.ask(
            "  [bold yellow]Select option[/bold yellow]",
            choices=["a", "A", "1", "2", "3", "4", "5"],
            show_choices=False,
        )

        if choice.lower() == "a":
            execute_suggested_action(state)
        elif choice == "1":
            _phase1_recon_menu(state)
        elif choice == "2":
            _phase2_exploitation_menu(state)
        elif choice == "3":
            _phase3_postex_menu(state)
        elif choice == "4":
            _display_findings_log(state)
        elif choice == "5":
            path = save_session(state)
            console.print(f"\n  [bold green]✔  Session saved:[/bold green] [dim]{path}[/dim]\n")
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