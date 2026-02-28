"""
smb_enum_module.py - SMB enumeration module for AD-Pathfinder.

Performs structured SMB enumeration against a target Domain Controller using
smbclient (null session + share listing) and crackmapexec (signing/version
detection when available).

Tools used:
    - smbclient   (always required — apt install smbclient)
    - crackmapexec (optional — apt install crackmapexec)

Requires root or sufficient privileges for raw SMB operations.
"""

from __future__ import annotations

import re
import sys
import os
from typing import Optional

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
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Share names that warrant closer inspection
INTERESTING_SHARES = {
    "ADMIN$", "C$", "NETLOGON", "SYSVOL",
    "DATA", "BACKUP", "FILES", "SHARE", "USERS", "PUBLIC",
}


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_findings(findings: dict, suggestions: list[str]) -> None:
    """Render SMB findings and suggestions to the terminal."""
    if _RICH_AVAILABLE:
        # ── Findings table ──────────────────────────────────────────────
        table = Table(
            title="[bold bright_cyan]SMB Enumeration Results[/bold bright_cyan]",
            box=box.ROUNDED,
            border_style="bright_blue",
            show_lines=True,
        )
        table.add_column("Property", style="bold bright_cyan", width=22)
        table.add_column("Value",    style="white")

        anon     = findings.get("anonymous_access", False)
        signing  = findings.get("smb_signing",      None)
        version  = findings.get("smb_version",      "Unknown")
        shares   = findings.get("shares",            [])

        table.add_row(
            "Anonymous Access",
            "[bold red]YES[/bold red]" if anon else "[green]NO[/green]",
        )

        if signing is None:
            signing_display = "[dim]Unknown (crackmapexec not available)[/dim]"
        elif signing:
            signing_display = "[green]Enabled[/green]"
        else:
            signing_display = "[bold red]DISABLED — Relay possible[/bold red]"

        table.add_row("SMB Signing",     signing_display)
        table.add_row("SMB Version",     version)
        table.add_row("Shares Found",    str(len(shares)))

        if shares:
            table.add_row(
                "Share List",
                ", ".join(
                    f"[bold yellow]{s}[/bold yellow]"
                    if s.upper() in INTERESTING_SHARES
                    else s
                    for s in shares
                ),
            )

        console.print(table)

        # ── Suggestions panel ───────────────────────────────────────────
        if suggestions:
            text = "\n".join(
                f"  [bright_cyan]▶[/bright_cyan]  {s}" for s in suggestions
            )
            console.print(
                Panel(
                    text,
                    title="[bold yellow]Suggested Next Actions[/bold yellow]",
                    border_style="yellow",
                )
            )
    else:
        print("\n--- SMB Enumeration Results ---")
        print(f"  Anonymous Access : {findings.get('anonymous_access')}")
        print(f"  SMB Signing      : {findings.get('smb_signing')}")
        print(f"  SMB Version      : {findings.get('smb_version', 'Unknown')}")
        print(f"  Shares           : {', '.join(findings.get('shares', []))}")
        if suggestions:
            print("\n--- Suggested Next Actions ---")
            for s in suggestions:
                print(f"  ▶  {s}")


# ─────────────────────────────────────────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_smbclient_output(output: str, stderr: str) -> tuple[bool, list[str]]:
    """
    Parse smbclient -L output to detect anonymous access and list shares.

    Parameters
    ----------
    output : str
        stdout from smbclient.
    stderr : str
        stderr from smbclient (may contain session error messages).

    Returns
    -------
    tuple[bool, list[str]]
        (anonymous_access, shares)
    """
    shares: list[str] = []

    # Session error patterns indicating null session was denied
    denied_patterns = [
        r"NT_STATUS_ACCESS_DENIED",
        r"NT_STATUS_LOGON_FAILURE",
        r"NT_STATUS_ACCOUNT_DISABLED",
    ]
    for pattern in denied_patterns:
        if re.search(pattern, output + stderr, re.IGNORECASE):
            return False, shares

    # Parse share lines — smbclient output format:
    #   Sharename       Type      Comment
    #   ---------       ----      -------
    #   ADMIN$          Disk      Remote Admin
    share_re = re.compile(r"^\s{1,4}(\S+)\s+(Disk|IPC|Printer)\s*", re.MULTILINE)
    for match in share_re.finditer(output):
        share_name = match.group(1).strip()
        if share_name not in shares:
            shares.append(share_name)

    anonymous_access = bool(shares) or bool(
        re.search(r"Anonymous login successful", output + stderr, re.IGNORECASE)
    )

    return anonymous_access, shares


def _parse_crackmapexec_output(output: str) -> tuple[Optional[bool], str]:
    """
    Parse crackmapexec SMB output for signing status and SMB version.

    crackmapexec output example:
        SMB  10.10.10.100  445  DC01  [*] Windows 10.0 Build 17763 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)

    Parameters
    ----------
    output : str
        Combined stdout + stderr from crackmapexec.

    Returns
    -------
    tuple[Optional[bool], str]
        (smb_signing, smb_version_string)
        smb_signing is None if not detectable.
    """
    smb_signing: Optional[bool] = None
    smb_version = "Unknown"

    # Signing detection
    signing_match = re.search(r"signing[:\s]+(True|False)", output, re.IGNORECASE)
    if signing_match:
        smb_signing = signing_match.group(1).lower() == "true"

    # SMBv1 detection
    smbv1_match = re.search(r"SMBv1[:\s]+(True|False)", output, re.IGNORECASE)
    if smbv1_match:
        smbv1_enabled = smbv1_match.group(1).lower() == "true"
        smb_version   = "SMBv1 (ENABLED — legacy/vulnerable)" if smbv1_enabled else "SMBv2/v3"

    # OS / build string for context
    os_match = re.search(r"\[\*\]\s+(Windows[^\(]+)", output)
    if os_match and smb_version == "Unknown":
        smb_version = os_match.group(1).strip()

    return smb_signing, smb_version


# ─────────────────────────────────────────────────────────────────────────────
# Suggestion builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_suggestions(
    anonymous_access: bool,
    smb_signing: Optional[bool],
    shares: list[str],
    performed_actions: list[str],
) -> list[str]:
    """
    Build context-aware next-step suggestions based on SMB findings.

    Parameters
    ----------
    anonymous_access : bool
    smb_signing      : bool | None
    shares           : list[str]
    performed_actions: list[str]

    Returns
    -------
    list[str]
    """
    performed_flat = " ".join(performed_actions).lower()
    suggestions: list[str] = []

    if anonymous_access and "share content" not in performed_flat:
        suggestions.append(
            "Anonymous access confirmed → Enumerate share contents with smbclient"
        )

    if smb_signing is False and "smb relay" not in performed_flat:
        suggestions.append(
            "SMB signing DISABLED → Launch SMB relay attack with ntlmrelayx"
        )

    interesting = [s for s in shares if s.upper() in INTERESTING_SHARES]
    if interesting and "domain scripts" not in performed_flat:
        suggestions.append(
            f"Interesting shares detected ({', '.join(interesting)}) "
            "→ Check SYSVOL/NETLOGON for scripts, GPP passwords"
        )

    if smb_signing is True and not suggestions:
        suggestions.append(
            "SMB signing enabled — relay attacks blocked; focus on credential-based access"
        )

    return suggestions


# ─────────────────────────────────────────────────────────────────────────────
# SMBEnumerationModule
# ─────────────────────────────────────────────────────────────────────────────

class SMBEnumerationModule:
    """
    Structured SMB enumeration against a Domain Controller.

    Performs:
      A) Null session test via smbclient — detects anonymous access and lists shares.
      B) Signing/version check via crackmapexec — detects relay opportunities and SMBv1.

    Parameters
    ----------
    executor : CommandExecutor | None
        Optional custom executor. Defaults to a new instance with a 60s timeout.
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=True, default_timeout=60)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, state: AssessmentState) -> dict:
        """
        Execute SMB enumeration against state.target_ip and update state.

        Parameters
        ----------
        state : AssessmentState
            Current assessment session. Updated in-place with findings.

        Returns
        -------
        dict
            {
                "status":   "success" | "error",
                "findings": {
                    "shares":            list[str],
                    "anonymous_access":  bool,
                    "smb_signing":       bool | None,
                    "smb_version":       str,
                },
                "suggestions": list[str],
            }
        """
        if not self.executor.check_tool("smbclient"):
            return self._error(
                "smbclient is not installed. Run: sudo apt install smbclient"
            )

        target = state.target_ip
        creds  = state.initial_credentials

        if _RICH_AVAILABLE:
            console.print(
                f"\n  [bold bright_cyan]▶  Starting SMB enumeration against {target}[/bold bright_cyan]\n"
            )
        else:
            print(f"\n[*] Starting SMB enumeration against {target} ...")

        # ── A) Null session / share enumeration ────────────────────────
        anonymous_access, shares = self._null_session_check(target)

        # ── B) Authenticated share listing (if credentials available) ──
        if not shares and (creds.username and (creds.password or creds.ntlm_hash)):
            _, shares = self._authenticated_share_check(target, creds)

        # ── C) SMB signing check via crackmapexec ──────────────────────
        smb_signing, smb_version = self._cme_signing_check(target, creds)

        # ── Compile findings ───────────────────────────────────────────
        findings = {
            "shares":           shares,
            "anonymous_access": anonymous_access,
            "smb_signing":      smb_signing,
            "smb_version":      smb_version,
        }

        suggestions = _build_suggestions(
            anonymous_access,
            smb_signing,
            shares,
            state.performed_actions,
        )

        # ── Update AssessmentState ─────────────────────────────────────
        if smb_signing is False:
            state.vulnerabilities.append({
                "name":        "SMB Signing Disabled",
                "severity":    "HIGH",
                "description": (
                    f"SMB signing is disabled on {target}. "
                    "Host is vulnerable to SMB relay attacks (ntlmrelayx)."
                ),
            })
            state.log_finding(
                category="SMB",
                description=f"SMB signing DISABLED on {target} — relay attack possible.",
                severity="HIGH",
            )

        if anonymous_access:
            state.log_finding(
                category="SMB",
                description=(
                    f"Anonymous (null session) access allowed on {target}. "
                    f"Accessible shares: {', '.join(shares) if shares else 'none listed'}."
                ),
                severity="MEDIUM",
            )

        if smb_version and "SMBv1" in smb_version and "ENABLED" in smb_version:
            state.vulnerabilities.append({
                "name":        "SMBv1 Enabled",
                "severity":    "HIGH",
                "description": (
                    f"SMBv1 is enabled on {target}. "
                    "Potentially vulnerable to EternalBlue (MS17-010)."
                ),
            })
            state.log_finding(
                category="SMB",
                description=f"SMBv1 ENABLED on {target} — check for EternalBlue (MS17-010).",
                severity="HIGH",
            )

        state.log_action(f"SMB enumeration against {target}")

        _print_findings(findings, suggestions)

        return {
            "status":      "success",
            "findings":    findings,
            "suggestions": suggestions,
        }

    # ------------------------------------------------------------------ #
    #  Check methods                                                       #
    # ------------------------------------------------------------------ #

    def _null_session_check(self, target: str) -> tuple[bool, list[str]]:
        """
        Attempt a null (anonymous) session using smbclient -L -N.

        Returns
        -------
        tuple[bool, list[str]]
            (anonymous_access, shares)
        """
        if _RICH_AVAILABLE:
            console.print("  [dim]→ Testing null session...[/dim]")

        result = self.executor.run([
            "smbclient",
            f"//{target}/",
            "-N",           # no password
            "-L",           # list shares
        ])

        return _parse_smbclient_output(result["output"], result["error"])

    def _authenticated_share_check(
        self,
        target: str,
        creds,
    ) -> tuple[bool, list[str]]:
        """
        Attempt an authenticated share listing via smbclient.

        Supports password-based and NTLM hash authentication.

        Returns
        -------
        tuple[bool, list[str]]
            (authenticated_access, shares)
        """
        if _RICH_AVAILABLE:
            console.print(
                f"  [dim]→ Testing authenticated share listing as {creds.username}...[/dim]"
            )

        if creds.ntlm_hash:
            # smbclient accepts --pw-nt-hash with the NT portion
            nt_hash = creds.ntlm_hash.split(":")[-1] if ":" in creds.ntlm_hash else creds.ntlm_hash
            command = [
                "smbclient", f"//{target}/",
                "-U", creds.username,
                "--pw-nt-hash", nt_hash,
                "-L",
            ]
        else:
            command = [
                "smbclient", f"//{target}/",
                "-U", f"{creds.username}%{creds.password}",
                "-L",
            ]

        result = self.executor.run(command)
        return _parse_smbclient_output(result["output"], result["error"])

    def _cme_signing_check(
        self,
        target: str,
        creds,
    ) -> tuple[Optional[bool], str]:
        """
        Use crackmapexec to check SMB signing status and version.
        Gracefully skips if crackmapexec is not installed.

        Returns
        -------
        tuple[Optional[bool], str]
            (smb_signing, smb_version)
            smb_signing is None if crackmapexec is unavailable.
        """
        # Try both common binary names
        cme_bin = None
        for binary in ("crackmapexec", "cme", "nxc"):
            if self.executor.check_tool(binary):
                cme_bin = binary
                break

        if not cme_bin:
            if _RICH_AVAILABLE:
                console.print(
                    "  [dim]→ crackmapexec/nxc not found — skipping signing check.[/dim]"
                )
            return None, "Unknown"

        if _RICH_AVAILABLE:
            console.print(f"  [dim]→ Running {cme_bin} SMB signing check...[/dim]")

        command = [cme_bin, "smb", target]

        # Append credentials if available for richer output
        if creds.username and creds.password:
            command += ["-u", creds.username, "-p", creds.password]
        elif creds.username and creds.ntlm_hash:
            command += ["-u", creds.username, "-H", creds.ntlm_hash]

        result  = self.executor.run(command)
        combined = result["output"] + result["error"]

        return _parse_crackmapexec_output(combined)

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _error(message: str) -> dict:
        """Return a standardised error result."""
        if _RICH_AVAILABLE:
            console.print(f"\n  [bold red]✘  SMB Enum Error:[/bold red] {message}\n")
        else:
            print(f"\n[!] SMB Enum Error: {message}\n")

        return {
            "status":      "error",
            "findings":    {
                "shares":           [],
                "anonymous_access": False,
                "smb_signing":      None,
                "smb_version":      "Unknown",
            },
            "suggestions": [],
            "error":       message,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience function
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    Convenience wrapper — run SMB enumeration without instantiating the class.

    Example (from main.py dispatcher)
    ----------------------------------
    from modules.smb_enum_module import run as smb_run
    result = smb_run(state)
    """
    return SMBEnumerationModule(executor=executor).run(state)


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test
# Usage: sudo python modules/smb_enum_module.py <target_ip> <domain>
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python modules/smb_enum_module.py <target_ip> <domain>")
        sys.exit(1)

    from session import generate_assessment_id

    test_state = AssessmentState(
        assessment_id=generate_assessment_id(),
        target_ip=sys.argv[1],
        domain=sys.argv[2],
    )

    module = SMBEnumerationModule()
    output = module.run(test_state)

    print("\nFinal result:")
    print(f"  Status           : {output['status']}")
    print(f"  Anonymous Access : {output['findings']['anonymous_access']}")
    print(f"  SMB Signing      : {output['findings']['smb_signing']}")
    print(f"  SMB Version      : {output['findings']['smb_version']}")
    print(f"  Shares           : {output['findings']['shares']}")
    print(f"  Suggestions ({len(output['suggestions'])}):")
    for s in output["suggestions"]:
        print(f"    - {s}")