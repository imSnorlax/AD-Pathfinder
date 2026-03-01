"""
smb_enum_module.py - SMB Enumeration module for AD-Pathfinder.

Performs structured SMB enumeration following the standard assessment playbook:

    Step 1  — Share listing         (nxc -u guest -p '' --shares  /  smbmap fallback)
    Step 2  — Signing fingerprint   (nxc smb <target>)
    Step 3  — RID brute-force       (nxc -u '' --rid-brute → nxc -u guest --rid-brute)
    Step 4  — IPC$ RPC analysis     (smbmap -r IPC$ --no-banner)
    Step 5  — Artifact persistence  (reports/<id>/users_rid.txt, smb_raw.txt)

Design contract
---------------
- Zero raw command output printed to the terminal. All raw output is saved to
  smb_raw.txt and optionally returned inside findings when debug=True.
- Caller (main.py) is responsible for all display / formatting.
- state is updated in-place; caller is responsible for saving the session.
- CommandExecutor is used exclusively (shell=False everywhere).

Returned structure
------------------
{
    "status":      "success" | "error",
    "findings": {
        "anonymous_access":  bool,
        "smb_signing":       bool | None,
        "smb_version":       str,
        "shares":            list[str],
        "rid_users_count":   int,
        "rid_groups_count":  int,
        "users_preview":     list[str],   # first 5 users
        "users_file":        str | None,  # abs path to users_rid.txt
        "ipc_channels":      list[str],
        "raw_log":           str,         # only populated when debug=True
    },
    "suggestions": list[str],
    "error":       str | None,
}
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

REPORTS_DIR = "reports"

# Shares that are always interesting to flag in suggestions
INTERESTING_SHARES: set[str] = {
    "SYSVOL", "NETLOGON", "C$", "ADMIN$", "IPC$", "COMMON", "BACKUP",
    "DATA", "FILES", "SHARE", "PUBLIC",
}


# ─────────────────────────────────────────────────────────────────────────────
# Parsers (pure functions — no I/O, no printing)
# ─────────────────────────────────────────────────────────────────────────────

def parse_rid_output(raw: str) -> tuple[list[str], list[str]]:
    """
    Parse nxc/crackmapexec --rid-brute output into (users, groups).

    Extracts the name after the domain backslash and before the '(' SidType
    marker, mirroring the playbook pipeline:
        cut -d '\\' -f2 | cut -d '(' -f1 | sed 's/ *$//'

    Machine accounts (ending in '$') are excluded from the user list — they
    are irrelevant for password spraying or AS-REP roasting.

    Parameters
    ----------
    raw : str
        Raw combined stdout + stderr from the nxc --rid-brute call.

    Returns
    -------
    tuple[list[str], list[str]]
        (users, groups) — deduplicated, preserving discovery order.
    """
    users:  list[str] = []
    groups: list[str] = []
    seen:   set[str]  = set()

    pattern = re.compile(
        r"SMB\s+\S+\s+\d+\s+\S+\s+\S+\\(.+?)\s+\(SidType(User|Group|Alias)\)",
        re.IGNORECASE,
    )

    for match in pattern.finditer(raw):
        name     = match.group(1).strip()
        sid_type = match.group(2).lower()

        if not name or name in seen:
            continue
        seen.add(name)

        if sid_type == "user":
            if not name.endswith("$"):   # skip machine accounts
                users.append(name)
        else:
            groups.append(name)

    return users, groups


def _parse_nxc_shares(raw: str) -> list[str]:
    """
    Extract share names from nxc --shares output.
    Skips status markers ([*], [+]) and header/separator lines.
    """
    shares: list[str] = []
    seen:   set[str]  = set()
    # Pattern: SMB  <ip>  <port>  <hostname>  <share_name>  ...
    pattern = re.compile(
        r"^\s*SMB\s+\S+\s+\d+\s+\S+\s+(\S+)",
        re.IGNORECASE | re.MULTILINE,
    )
    skip = {"share", "----", "permissions", "remark", "comment"}
    for match in pattern.finditer(raw):
        name = match.group(1).strip()
        if name.startswith("["):
            continue
        if name.lower() in skip or name.startswith("-"):
            continue
        if name not in seen:
            shares.append(name)
            seen.add(name)
    return shares


def _parse_smbmap_shares(raw: str) -> list[str]:
    """
    Extract share names from smbmap --no-banner output.
    Share lines are indented; name is the first token.
    """
    shares: list[str] = []
    seen:   set[str]  = set()
    skip = {"disk", "----", "share", "permissions", "comment", "remark"}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("[") or stripped.startswith("-"):
            continue
        parts = stripped.split()
        if not parts:
            continue
        name = parts[0]
        if name.lower() in skip or name.startswith("-"):
            continue
        if name not in seen:
            shares.append(name)
            seen.add(name)
    return shares


def _parse_signing(raw: str) -> tuple[Optional[bool], str]:
    """
    Parse SMB signing and version from nxc plain smb output.
    Returns (smb_signing, smb_version).
    """
    smb_signing: Optional[bool] = None
    smb_version = "Unknown"

    signing_match = re.search(r"signing[:\s]+(True|False)", raw, re.IGNORECASE)
    if signing_match:
        smb_signing = signing_match.group(1).lower() == "true"

    if re.search(r"SMBv1[:\s]*True", raw, re.IGNORECASE):
        smb_version = "SMBv1"
    elif re.search(r"Build\s+\d+", raw, re.IGNORECASE):
        smb_version = "SMBv2/v3"

    return smb_signing, smb_version


def _parse_ipc_channels(raw: str) -> list[str]:
    """
    Extract RPC named pipe names from smbmap -r IPC$ output.
    Lines contain paths like .\\pipe\\netlogon — we extract the final component.
    """
    channels: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        stripped = line.strip()
        if "\\" in stripped or "/" in stripped:
            name = stripped.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip()
            if name and name not in seen and not name.startswith("["):
                channels.append(name)
                seen.add(name)
    return channels


def _build_suggestions(
    anonymous_access: bool,
    smb_signing: Optional[bool],
    shares: list[str],
    performed: list[str],
) -> list[str]:
    """Generate contextual next-step suggestions based on findings."""
    suggestions: list[str] = []

    if smb_signing is False:
        suggestions.append(
            "SMB signing DISABLED — relay attack possible: "
            "sudo ntlmrelayx.py -tf targets.txt -smb2support"
        )
    elif smb_signing is True:
        suggestions.append(
            "SMB signing enabled — relay attacks blocked; "
            "focus on credential-based access"
        )

    share_names_upper = {s.upper() for s in shares}

    if anonymous_access and shares:
        suggestions.append(
            "Anonymous/guest access allowed — enumerate share contents: "
            "smbmap -H <target> -u guest -p '' -r <share>"
        )

    if "SYSVOL" in share_names_upper or "NETLOGON" in share_names_upper:
        suggestions.append(
            "SYSVOL/NETLOGON accessible — hunt for Group Policy Passwords (GPP): "
            "findstr /S /I cpassword \\\\<dc>\\SYSVOL"
        )

    if any(s.upper() not in {"IPC$", "ADMIN$", "C$"} for s in shares):
        suggestions.append(
            "Non-default share(s) found — inspect contents for sensitive files"
        )

    return suggestions


# ─────────────────────────────────────────────────────────────────────────────
# Artifact helpers
# ─────────────────────────────────────────────────────────────────────────────

def _assessment_report_dir(assessment_id: str) -> str:
    """Return (and create) reports/<assessment_id>/ directory."""
    path = os.path.join(os.path.abspath(REPORTS_DIR), assessment_id)
    os.makedirs(path, exist_ok=True)
    return path


def _write_users_file(assessment_id: str, users: list[str]) -> str:
    """
    Write clean usernames to reports/<assessment_id>/users_rid.txt.
    Returns the absolute path.
    """
    dirpath  = _assessment_report_dir(assessment_id)
    filepath = os.path.join(dirpath, "users_rid.txt")
    clean    = [u.strip() for u in users if u.strip()]
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(clean) + ("\n" if clean else ""))
    return filepath


def _write_raw_log(assessment_id: str, raw_log: str) -> str:
    """
    Append raw SMB tool output to reports/<assessment_id>/smb_raw.txt.
    Returns the absolute path.
    """
    dirpath  = _assessment_report_dir(assessment_id)
    filepath = os.path.join(dirpath, "smb_raw.txt")
    separator = f"\n{'='*60}\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n{'='*60}\n"
    with open(filepath, "a", encoding="utf-8") as fh:
        fh.write(separator + raw_log + "\n")
    return filepath


def _write_generated(users: list[str], groups: list[str]) -> None:
    """
    Mirror discovered users/groups to generated/ directory so attack modules
    (AS-REP, spray, Kerberoasting) can pick them up as fallbacks.
    """
    try:
        from modules.file_export import save_rid_users, save_rid_groups
        if users:
            save_rid_users(users)
        if groups:
            save_rid_groups(groups)
    except Exception:
        pass   # generated/ sync is best-effort


# ─────────────────────────────────────────────────────────────────────────────
# Main module class
# ─────────────────────────────────────────────────────────────────────────────

class SMBEnumerationModule:
    """
    Professional SMB enumeration engine for AD-Pathfinder.

    Parameters
    ----------
    executor : CommandExecutor | None
        Optional custom executor. Defaults to a verbose instance used only
        for the signing check; all heavy enumeration uses a silent executor.
    debug : bool
        When True, raw tool output is included in the returned findings dict.
        When False (default), raw output is saved to smb_raw.txt only.
    """

    def __init__(
        self,
        executor: Optional[CommandExecutor] = None,
        debug: bool = False,
    ) -> None:
        # Signing check executor: verbose so operator sees the fingerprint line
        self._verbose_exec = executor or CommandExecutor(verbose=True,  default_timeout=60)
        # Silent executor for everything else (RID brute, shares, IPC$)
        self._quiet_exec   = CommandExecutor(verbose=False, default_timeout=120)
        self.debug         = debug

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, state: AssessmentState) -> dict:
        """
        Execute the full SMB enumeration playbook against state.target_ip.

        Updates state in-place:
            state.users              — discovered user accounts
            state.groups             — discovered groups
            state.vulnerabilities    — SMB signing disabled entry (if applicable)
            state.findings_log       — structured log entries
            state.performed_actions  — timestamped audit trail

        Returns a structured findings dict (see module docstring).
        """
        target        = state.target_ip
        creds         = state.initial_credentials
        assessment_id = state.assessment_id
        raw_log_parts: list[str] = []   # accumulate raw output for smb_raw.txt

        # ── Step 1: Guest share listing ──────────────────────────────────────
        shares, anonymous_access = self._step1_shares(target, raw_log_parts)

        # ── Step 2: Signing / version fingerprint ────────────────────────────
        smb_signing, smb_version = self._step2_signing(target, creds, raw_log_parts)

        # ── Step 3: RID brute-force ───────────────────────────────────────────
        rid_users, rid_groups = self._step3_rid_brute(target, raw_log_parts)

        # ── Step 4: IPC$ RPC channel analysis ────────────────────────────────
        ipc_channels: list[str] = []
        if any(s.upper() == "IPC$" for s in shares):
            ipc_channels = self._step4_ipc(target, raw_log_parts)

        # ── Step 5: Persist artifacts ─────────────────────────────────────────
        raw_combined  = "\n".join(raw_log_parts)
        users_file    = None

        _write_raw_log(assessment_id, raw_combined)

        if rid_users:
            users_file = _write_users_file(assessment_id, rid_users)
            _write_generated(rid_users, rid_groups)

        # ── Update AssessmentState ────────────────────────────────────────────
        self._update_state(
            state, shares, smb_signing, rid_users, rid_groups,
            ipc_channels, anonymous_access, users_file,
        )

        # ── Build return dict ─────────────────────────────────────────────────
        findings: dict = {
            "anonymous_access": anonymous_access,
            "smb_signing":      smb_signing,
            "smb_version":      smb_version,
            "shares":           shares,
            "rid_users_count":  len(rid_users),
            "rid_groups_count": len(rid_groups),
            "users_preview":    rid_users[:5],
            "users_file":       users_file,
            "ipc_channels":     ipc_channels,
            # Full lists for display layer
            "rid_users":        rid_users,
            "rid_groups":       rid_groups,
        }

        if self.debug:
            findings["raw_log"] = raw_combined

        suggestions = _build_suggestions(
            anonymous_access, smb_signing, shares, state.performed_actions
        )

        return {
            "status":      "success",
            "findings":    findings,
            "suggestions": suggestions,
            "error":       None,
        }

    # ------------------------------------------------------------------ #
    #  Step implementations                                                #
    # ------------------------------------------------------------------ #

    def _step1_shares(
        self, target: str, raw_log: list[str]
    ) -> tuple[list[str], bool]:
        """
        Step 1 — List shares as guest.
        Tries nxc --shares first, falls back to smbmap, then smbclient -N.
        Returns (shares, anonymous_access_flag).
        """
        # ── Try nxc --shares ───────────────────────────────────────────
        cme = self._find_cme()
        if cme:
            raw_log.append(f"## Step 1: {cme} smb {target} -u guest -p '' --shares")
            result  = self._quiet_exec.run(
                [cme, "smb", target, "-u", "guest", "-p", "", "--shares"]
            )
            combined = result["output"] + result["error"]
            raw_log.append(combined)
            shares = _parse_nxc_shares(combined)
            if shares:
                return shares, True

        # ── Fallback: smbmap --no-banner ────────────────────────────────
        if self._quiet_exec.check_tool("smbmap"):
            raw_log.append(f"## Step 1 (fallback): smbmap -H {target} -u guest -p '' --no-banner")
            result   = self._quiet_exec.run(
                ["smbmap", "-H", target, "-u", "guest", "-p", "", "--no-banner"],
                ok_exit_codes=(0, 1),
            )
            combined = result["output"] + result["error"]
            raw_log.append(combined)
            shares = _parse_smbmap_shares(combined)
            if shares:
                return shares, True

        # ── Fallback: smbclient null session ────────────────────────────
        if self._quiet_exec.check_tool("smbclient"):
            raw_log.append(f"## Step 1 (fallback): smbclient //{target}/ -N -L")
            result   = self._quiet_exec.run(
                ["smbclient", f"//{target}/", "-N", "-L"],
                ok_exit_codes=(0, 1),
            )
            combined = result["output"] + result["error"]
            raw_log.append(combined)
            if "Sharename" in combined or "IPC$" in combined:
                shares = _parse_nxc_shares(combined)
                return shares, True

        return [], False

    def _step2_signing(
        self, target: str, creds, raw_log: list[str]
    ) -> tuple[Optional[bool], str]:
        """
        Step 2 — SMB signing / version check via nxc (verbose — one line).
        Returns (smb_signing, smb_version).
        """
        cme = self._find_cme()
        if not cme:
            return None, "Unknown"

        command = [cme, "smb", target]
        if creds.username and creds.password:
            command += ["-u", creds.username, "-p", creds.password]
        elif creds.username and creds.ntlm_hash:
            command += ["-u", creds.username, "-H", creds.ntlm_hash]

        raw_log.append(f"## Step 2: {' '.join(command)}")
        # Verbose here so the operator sees the signing line in real-time
        result   = self._verbose_exec.run(command)
        combined = result["output"] + result["error"]
        raw_log.append(combined)

        return _parse_signing(combined)

    def _step3_rid_brute(
        self, target: str, raw_log: list[str]
    ) -> tuple[list[str], list[str]]:
        """
        Step 3 — RID brute-force. Tries null session first then guest.
        Runs silently — raw output logged to smb_raw.txt, not printed.
        Returns (users, groups).
        """
        cme = self._find_cme()
        if not cme:
            return [], []

        for user, label in [("", "null"), ("guest", "guest")]:
            raw_log.append(
                f"## Step 3 ({label}): {cme} smb {target} "
                f"-u '{user}' -p '' --rid-brute"
            )
            result   = self._quiet_exec.run(
                [cme, "smb", target, "-u", user, "-p", "", "--rid-brute"],
                ok_exit_codes=(0, 1),
            )
            combined = result["output"] + result["error"]
            raw_log.append(combined)

            if "[+]" in combined or "SidType" in combined:
                users, groups = parse_rid_output(combined)
                if users or groups:
                    return users, groups

        return [], []

    def _step4_ipc(
        self, target: str, raw_log: list[str]
    ) -> list[str]:
        """
        Step 4 — Enumerate exposed RPC named pipes via IPC$.
        smbmap -H target -u guest -p '' -r IPC$ --no-banner
        """
        if not self._quiet_exec.check_tool("smbmap"):
            return []

        raw_log.append(
            f"## Step 4: smbmap -H {target} -u guest -p '' -r IPC$ --no-banner"
        )
        result   = self._quiet_exec.run(
            ["smbmap", "-H", target, "-u", "guest", "-p", "",
             "-r", "IPC$", "--no-banner"],
            ok_exit_codes=(0, 1),
        )
        combined = result["output"] + result["error"]
        raw_log.append(combined)
        return _parse_ipc_channels(combined)

    # ------------------------------------------------------------------ #
    #  State updates                                                       #
    # ------------------------------------------------------------------ #

    def _update_state(
        self,
        state: AssessmentState,
        shares: list[str],
        smb_signing: Optional[bool],
        rid_users: list[str],
        rid_groups: list[str],
        ipc_channels: list[str],
        anonymous_access: bool,
        users_file: Optional[str],
    ) -> None:
        """Apply all state mutations from this module's run."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Merge discovered users (avoid duplicates)
        existing = {u.lower() for u in state.users}
        new_users = [u for u in rid_users if u.lower() not in existing]
        state.users.extend(new_users)

        # Merge discovered groups
        existing_g = {g.lower() for g in state.groups}
        new_groups = [g for g in rid_groups if g.lower() not in existing_g]
        state.groups.extend(new_groups)

        # Vulnerability: SMB signing disabled
        if smb_signing is False:
            already = any(
                v.get("name") == "SMB Signing Disabled"
                for v in state.vulnerabilities
            )
            if not already:
                state.vulnerabilities.append({
                    "name":        "SMB Signing Disabled",
                    "severity":    "HIGH",
                    "description": (
                        f"SMB signing is disabled on {state.target_ip}. "
                        "Host is vulnerable to SMB relay attacks (ntlmrelayx)."
                    ),
                    "timestamp":   ts,
                })

        # Findings log
        state.log_finding(
            category    = "SMB Enumeration",
            description = (
                f"Shares: {len(shares)}  |  "
                f"Users (RID): {len(rid_users)}  |  "
                f"Groups: {len(rid_groups)}  |  "
                f"Anonymous: {anonymous_access}  |  "
                f"Signing: {smb_signing}  |  "
                f"IPC$ channels: {len(ipc_channels)}  |  "
                f"Users file: {users_file or 'N/A'}"
            ),
            severity    = "INFO" if smb_signing is not False else "HIGH",
        )

        # Audit trail
        state.log_action(
            f"SMB enumeration completed — "
            f"{len(rid_users)} users, {len(shares)} shares, "
            f"signing={'disabled' if smb_signing is False else str(smb_signing)}"
        )

        if "smb_enumeration" not in state.performed_actions:
            state.performed_actions.append("smb_enumeration")

    # ------------------------------------------------------------------ #
    #  Error helper                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _error(message: str) -> dict:
        """Return a standardised error result dict."""
        return {
            "status": "error",
            "findings": {
                "anonymous_access": False,
                "smb_signing":      None,
                "smb_version":      "Unknown",
                "shares":           [],
                "rid_users_count":  0,
                "rid_groups_count": 0,
                "users_preview":    [],
                "users_file":       None,
                "ipc_channels":     [],
                "rid_users":        [],
                "rid_groups":       [],
            },
            "suggestions": [],
            "error":       message,
        }

    # ------------------------------------------------------------------ #
    #  Internal utilities                                                  #
    # ------------------------------------------------------------------ #

    def _find_cme(self) -> Optional[str]:
        """Return the first available nxc/crackmapexec binary name, or None."""
        for binary in ("nxc", "crackmapexec", "cme"):
            if self._quiet_exec.check_tool(binary):
                return binary
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience function (used by main.py dispatcher)
# ─────────────────────────────────────────────────────────────────────────────

def run(
    state: AssessmentState,
    executor: Optional[CommandExecutor] = None,
    debug: bool = False,
) -> dict:
    """
    Convenience wrapper — run SMB enumeration without instantiating the class.

    Example (from main.py)
    ----------------------
    from modules.smb_enum_module import run as smb_run
    result = smb_run(state)
    """
    return SMBEnumerationModule(executor=executor, debug=debug).run(state)


# ─────────────────────────────────────────────────────────────────────────────
# Display helper (called by main.py after run())
# ─────────────────────────────────────────────────────────────────────────────

def display_results(result: dict) -> None:
    """
    Render the structured result dict from run() to the terminal using rich.
    Separated from business logic so the module itself never prints.
    Called by main.py immediately after smb_run(state).
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.markup import escape
        from rich import box
        _rich = True
    except ImportError:
        _rich = False

    if result["status"] == "error":
        msg = result.get("error", "Unknown error")
        if _rich:
            Console().print(f"\n  [bold red]✘  SMB Enumeration failed:[/bold red] {msg}\n")
        else:
            print(f"\n[!] SMB Enumeration failed: {msg}\n")
        return

    findings    = result["findings"]
    suggestions = result["suggestions"]
    con         = Console() if _rich else None

    if not _rich:
        print("\n--- SMB Enumeration Results ---")
        print(f"  Anonymous Access : {findings['anonymous_access']}")
        print(f"  SMB Signing      : {findings['smb_signing']}")
        print(f"  SMB Version      : {findings['smb_version']}")
        print(f"  Shares           : {', '.join(findings['shares'])}")
        print(f"  RID Users        : {findings['rid_users_count']}")
        if findings["users_file"]:
            print(f"  Users File       : {findings['users_file']}")
        return

    # ── Summary table ────────────────────────────────────────────────────
    t = Table(
        title="[bold bright_cyan]SMB Enumeration Results[/bold bright_cyan]",
        box=box.ROUNDED, border_style="bright_blue",
        show_lines=True, expand=False,
    )
    t.add_column("Property", style="bold bright_cyan", width=22)
    t.add_column("Value",    style="white")

    anon = findings["anonymous_access"]
    t.add_row("Anonymous Access",
              "[bold red]YES[/bold red]" if anon else "[green]NO[/green]")

    signing = findings["smb_signing"]
    if signing is None:
        signing_display = "[dim]Unknown[/dim]"
    elif signing:
        signing_display = "[green]Enabled[/green]"
    else:
        signing_display = "[bold red]DISABLED — Relay possible[/bold red]"
    t.add_row("SMB Signing",  signing_display)
    t.add_row("SMB Version",  findings["smb_version"])

    shares = findings["shares"]
    t.add_row("Shares Found", str(len(shares)))
    if shares:
        share_list = ", ".join(
            f"[bold yellow]{escape(s)}[/bold yellow]"
            if s.upper() in INTERESTING_SHARES else escape(s)
            for s in shares
        )
        t.add_row("Share List", share_list)

    rid_count = findings["rid_users_count"]
    grp_count = findings["rid_groups_count"]
    if rid_count:
        t.add_row("RID Users Found",
                  f"[bold green]{rid_count}[/bold green]")
        preview = ", ".join(escape(u) for u in findings["users_preview"])
        t.add_row("Users (preview)", f"[dim]{preview}[/dim]")
    if grp_count:
        t.add_row("RID Groups Found", f"[bold green]{grp_count}[/bold green]")

    ipc = findings["ipc_channels"]
    if ipc:
        ch_str = ", ".join(escape(c) for c in ipc[:8])
        if len(ipc) > 8:
            ch_str += f" … (+{len(ipc)-8} more)"
        t.add_row("IPC$ Channels",
                  f"[bold yellow]{len(ipc)} pipe(s)[/bold yellow]: [dim]{ch_str}[/dim]")

    con.print()
    con.print(t)

    # ── Users table ──────────────────────────────────────────────────────
    rid_users = findings.get("rid_users", [])
    if rid_users:
        u_table = Table(
            title=f"[bold bright_cyan]Users via RID Brute ({rid_count} total)[/bold bright_cyan]",
            box=box.SIMPLE, border_style="bright_blue",
            show_lines=False, expand=False,
        )
        u_table.add_column("#",        style="dim",         width=4)
        u_table.add_column("Username", style="bold yellow", width=30)
        for i, u in enumerate(rid_users, 1):
            u_table.add_row(str(i), escape(u))
        con.print()
        con.print(u_table)

    # ── Groups table ─────────────────────────────────────────────────────
    rid_groups = findings.get("rid_groups", [])
    if rid_groups:
        g_table = Table(
            title=f"[bold bright_cyan]Groups via RID Brute ({grp_count} total)[/bold bright_cyan]",
            box=box.SIMPLE, border_style="bright_blue",
            show_lines=False, expand=False,
        )
        g_table.add_column("#",     style="dim",  width=4)
        g_table.add_column("Group", style="white", width=40)
        for i, g in enumerate(rid_groups, 1):
            g_table.add_row(str(i), escape(g))
        con.print()
        con.print(g_table)

    # ── Files written panel ───────────────────────────────────────────────
    users_file = findings.get("users_file")
    if users_file:
        con.print(
            Panel(
                f"[green]✔[/green]  {escape(users_file)}\n"
                f"[green]✔[/green]  generated/users-all.txt  (merged)\n"
                f"[dim]smb_raw.txt saved to reports/<assessment_id>/[/dim]",
                title="[bold green]Artifacts Written[/bold green]",
                border_style="green",
                expand=False,
            )
        )

    # ── Suggestions ───────────────────────────────────────────────────────
    if suggestions:
        text = "\n".join(f"  [bright_cyan]▶[/bright_cyan]  {escape(s)}"
                         for s in suggestions)
        con.print(
            Panel(text,
                  title="[bold yellow]Suggested Next Actions[/bold yellow]",
                  border_style="yellow")
        )
    con.print()


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test — Usage: sudo python modules/smb_enum_module.py <target> <domain>
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

    result = run(test_state, debug="--debug" in sys.argv)
    display_results(result)

    print(f"\n  State users  : {len(test_state.users)}")
    print(f"  State groups : {len(test_state.groups)}")
    print(f"  Vulns        : {len(test_state.vulnerabilities)}")