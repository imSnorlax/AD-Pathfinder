"""
ldap_enum_module.py - LDAP Enumeration module for AD-Pathfinder.

Performs structured LDAP enumeration against a Domain Controller using
ldapsearch (anonymous + authenticated), with graceful fallback when the
tool is unavailable.

Enumeration steps:
    A) Anonymous bind test  — ALWAYS attempted first (no -D / -W).
       Exact command: ldapsearch -H ldap://<domain> -x -b "<dc_base>"
    B) Authenticated fallback — used ONLY if anonymous fails AND session
       credentials already exist.  Never prompts the user for credentials.
    C) User enumeration     — extracts sAMAccountName, description, and the
       userAccountControl bitmask from all user objects.
    D) AS-REP detection     — flags accounts with the DONT_REQUIRE_PREAUTH
       bit set (0x400000), indicating they are roastable without credentials.
    E) Description scanning — applies regex patterns to description fields to
       detect cleartext or weakly-obfuscated credentials.
    F) SPN discovery        — queries servicePrincipalName to identify
       Kerberoastable service accounts.
    G) Group enumeration    — lists AD groups for context.

Design contract:
    - Zero CLI output — all results returned as a structured dict.
    - Caller (main.py) is responsible for all display/formatting.
    - state is updated in-place; caller is responsible for saving the session.
    - CommandExecutor is used exclusively (no shell=True anywhere).
    - NO credential prompts during Phase 1 Recon.

Tools used:
    - ldapsearch   (required — part of ldap-utils: apt install ldap-utils)
"""

from __future__ import annotations

import re
import sys
import os
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# userAccountControl bit: account does not require Kerberos pre-authentication
UAC_DONT_REQUIRE_PREAUTH: int = 0x400000

# Patterns that suggest a description field contains a plaintext credential.
# Deliberately broad — false positives are better than missed findings.
PASSWORD_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bpass(?:word)?\b", re.IGNORECASE),
    re.compile(r"\bpwd\b",           re.IGNORECASE),
    re.compile(r"\bcreds?\b",        re.IGNORECASE),
    re.compile(r"\bsecret\b",        re.IGNORECASE),
    re.compile(r"\btemp(?:orary)?\b",re.IGNORECASE),
    re.compile(r"\bwelcome\b",       re.IGNORECASE),
    re.compile(r"\bdefault\b",       re.IGNORECASE),
    re.compile(r"[A-Z][a-z]+\d{2,}", ),  # e.g. "Summer2023" — common spray passwords
]

# LDAP attribute list requested per user object
USER_ATTRIBUTES = [
    "sAMAccountName",
    "description",
    "userAccountControl",
    "memberOf",
    "servicePrincipalName",
    "mail",
    "displayName",
]

# LDAP attribute list requested per group object
GROUP_ATTRIBUTES = ["cn", "description", "member"]


# ─────────────────────────────────────────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────────────────────────────────────────

def _build_base_dn(domain: str) -> str:
    """
    Convert a domain name to an LDAP base DN.

    Example
    -------
    "corp.local" → "DC=corp,DC=local"
    """
    parts = domain.lower().split(".")
    return ",".join(f"DC={p}" for p in parts if p)


def _parse_ldif_entries(raw: str) -> list[dict[str, list[str]]]:
    """
    Parse raw ldapsearch LDIF output into a list of attribute dicts.

    Each entry is separated by a blank line.  Multi-value attributes become
    lists.  Continuation lines (RFC 2849 folded with a leading space) are
    joined before parsing.

    Parameters
    ----------
    raw : str
        Raw stdout text from ldapsearch -o ldif-wrap=no.

    Returns
    -------
    list[dict[str, list[str]]]
        Each dict maps lowercase attribute names to their value list.
    """
    # Unfold continuation lines (line starting with a single space continues
    # the previous line, per RFC 2849 § 5.1).
    raw = re.sub(r"\n ", "", raw)

    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}

    for line in raw.splitlines():
        line = line.rstrip()

        # Blank line → entry boundary
        if not line:
            if current:
                entries.append(current)
                current = {}
            continue

        # Skip comment lines
        if line.startswith("#"):
            continue

        # Attribute: value  (may use "attr:: base64value" notation)
        if ":" in line:
            attr, _, value = line.partition(":")
            # Handle base64-encoded values (attr::)
            if value.startswith(":"):
                value = value.lstrip(": ").strip()
                try:
                    import base64
                    value = base64.b64decode(value).decode("utf-8", errors="replace")
                except Exception:
                    pass
            else:
                value = value.strip()

            key = attr.lower().strip()
            if key and value and key != "dn":
                current.setdefault(key, []).append(value)

    # Flush last entry without trailing blank line
    if current:
        entries.append(current)

    return entries


def _parse_users(entries: list[dict]) -> tuple[list[str], list[str], list[dict], list[dict]]:
    """
    Extract users, AS-REP roastable accounts, potential credential descriptions,
    and SPN records from parsed LDIF entries.

    Returns
    -------
    tuple[list[str], list[str], list[dict], list[dict]]
        (users, asrep_users, desc_findings, spn_records)

        desc_findings : [{"username": str, "description": str}]
        spn_records   : [{"username": str, "spn": str}]
    """
    users:         list[str]  = []
    asrep_users:   list[str]  = []
    desc_findings: list[dict] = []
    spn_records:   list[dict] = []

    for entry in entries:
        sam = entry.get("samaccountname", [None])[0]
        if not sam:
            continue

        users.append(sam)

        # ── AS-REP roastable detection ─────────────────────────────────
        uac_raw = entry.get("useraccountcontrol", [None])[0]
        if uac_raw:
            try:
                uac = int(uac_raw)
                if uac & UAC_DONT_REQUIRE_PREAUTH:
                    asrep_users.append(sam)
            except ValueError:
                pass

        # ── Description credential scanning ───────────────────────────
        for desc in entry.get("description", []):
            for pattern in PASSWORD_PATTERNS:
                if pattern.search(desc):
                    desc_findings.append({"username": sam, "description": desc})
                    break  # one finding per user/description combo is enough

        # ── SPN discovery ─────────────────────────────────────────────
        for spn in entry.get("serviceprincipalname", []):
            spn_records.append({"username": sam, "spn": spn})

    return users, asrep_users, desc_findings, spn_records


def _parse_groups(entries: list[dict]) -> list[str]:
    """Extract group common names from parsed LDIF entries."""
    return [
        entry["cn"][0]
        for entry in entries
        if entry.get("cn")
    ]


# ─────────────────────────────────────────────────────────────────────────────
# LDAPEnumerationModule
# ─────────────────────────────────────────────────────────────────────────────

class LDAPEnumerationModule:
    """
    Structured LDAP enumeration against a Domain Controller.

    Performs anonymous or authenticated LDAP/LDAPS queries using ldapsearch,
    parses the LDIF output, and updates AssessmentState with all discovered
    objects and findings.

    Parameters
    ----------
    executor : CommandExecutor | None
        Optional custom executor.  Defaults to a 120-second timeout instance.

    Design notes
    ------------
    - All display is deferred to the caller.  This module produces only
      structured data and state mutations.
    - ldapsearch is invoked with ``-o ldif-wrap=no`` so multi-value
      attributes land on a single line and the parser stays simple.
    - Anonymous bind on port 389 is attempted first; port 636 (LDAPS) is
      tried if flag is set; authenticated queries follow if credentials
      are present and anonymous bind failed.
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False, default_timeout=120)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(self, state: AssessmentState) -> dict:
        """
        Run LDAP enumeration against the target and update state in-place.

        Parameters
        ----------
        state : AssessmentState
            Active assessment session.  Updated in-place.

        Returns
        -------
        dict
            {
                "status":      "success" | "error",
                "anonymous":   bool,
                "ldaps":       bool,
                "users":       list[str],
                "asrep_users": list[str],
                "groups":      list[str],
                "spns":        list[dict],        # {username, spn}
                "desc_findings": list[dict],      # {username, description}
                "error":       str | None,
                "warnings":    list[str],
            }
        """
        from rich.console import Console as _Con
        _con = _Con()

        def _info(msg: str) -> None:
            _con.print(f"  [dim]{msg}[/dim]")

        def _step_banner(n: int, title: str) -> None:
            _con.print(f"\n  [bold cyan][ Step {n} ][/bold cyan]  {title}")

        if not self.executor.check_tool("ldapsearch"):
            return self._error(
                "ldapsearch is not installed. Run: sudo apt install ldap-utils"
            )

        target          = state.target_ip
        domain          = state.domain
        base_dn         = _build_base_dn(domain)
        assessment_id   = state.assessment_id
        creds           = state.initial_credentials
        warnings: list[str] = []
        policy: dict        = {}

        # Use domain name in LDAP URI (matches user's working command:
        #   ldapsearch -H ldap://VulnAD.ma -x -b "DC=..." ...)
        # Falls back to IP if domain not set.
        ldap_host = domain if domain else target
        use_ldaps = 636 in state.open_ports
        port      = 636 if use_ldaps else 389

        # ── Bind negotiation ──────────────────────────────────────────────────
        # Rule 1: ALWAYS attempt anonymous bind first — no -D / -W flags.
        #         ldapsearch -H ldap://<domain> -x -b "<dc_base>"
        # Rule 2: Only fall back to session credentials if anonymous fails
        #         AND credentials are already stored in the session.
        # Rule 3: NEVER prompt the user for credentials during Phase 1 Recon.
        # ─────────────────────────────────────────────────────────────────────
        has_creds = bool(creds.username and (creds.password or creds.ntlm_hash))
        bind_creds: object = None
        bind_label: str    = "anonymous"
        anon_ok            = False

        # Step 1 — Anonymous bind (always tried first, regardless of session creds)
        _info("Attempting anonymous bind (no credentials)...")
        anon_raw = self._query_users(
            ldap_host, base_dn, port, use_ldaps, creds=None, domain=domain
        )
        if anon_raw.strip() and "sAMAccountName" in anon_raw:
            bind_creds = None
            bind_label = "anonymous"
            anon_ok    = True
            _info("Anonymous bind succeeded.")
        else:
            _info("Anonymous bind returned no data.")

            # Step 2 — Authenticated fallback (only if session creds exist)
            if has_creds:
                _info(f"Falling back to session credentials: {creds.username}")
                bind_creds = creds
                bind_label = creds.username
                anon_ok    = False
                warnings.append(
                    f"Anonymous bind denied; using session credentials '{creds.username}'."
                )
            else:
                # No session credentials — do not prompt; fail gracefully.
                return {
                    "status": "error", "anonymous": False, "ldaps": use_ldaps,
                    "users": [], "asrep_users": [], "groups": [], "spns": [],
                    "desc_findings": [], "valid_creds": [],
                    "error": (
                        "LDAP anonymous bind failed and no session credentials are available. "
                        "Provide credentials via session setup before running LDAP enumeration."
                    ),
                    "warnings": warnings,
                }

        # ══════════════════════════════════════════════════════════════════
        # STEP 1 — User enumeration
        # ldapsearch -H ldap://<domain> -x -b "<base_dn>" '(objectClass=User)' sAMAccountName
        # ══════════════════════════════════════════════════════════════════
        _step_banner(1, "User enumeration via LDAP")
        users:       list[str]  = []
        asrep_users: list[str]  = []
        spn_records: list[dict] = []

        try:
            user_raw = self._query_users(
                ldap_host, base_dn, port, use_ldaps, creds=bind_creds, domain=domain
            )
            user_entries = _parse_ldif_entries(user_raw)
            users, asrep_users, _, spn_records = _parse_users(user_entries)
            _info(f"Users found: {len(users)}  |  AS-REP roastable: {len(asrep_users)}")
            if users:
                path = self._save_users_ldap(assessment_id, users)
                _info(f"Saved → {path}")
        except Exception as exc:
            warnings.append(f"Step 1 error: {exc}")
            _info(f"User enumeration failed: {exc}")

        # ══════════════════════════════════════════════════════════════════
        # STEP 2 — Description scan for credentials
        # ldapsearch ... '(objectClass=User)' sAMAccountName description
        # ══════════════════════════════════════════════════════════════════
        _step_banner(2, "Description scan for embedded credentials")
        desc_findings: list[dict] = []

        try:
            desc_raw = self._query_descriptions(
                ldap_host, base_dn, port, use_ldaps, creds=bind_creds, domain=domain
            )
            desc_entries  = _parse_ldif_entries(desc_raw)
            _, _, desc_findings, _ = _parse_users(desc_entries)
            _info(f"Suspicious descriptions found: {len(desc_findings)}")
            if desc_findings:
                path = self._save_creds_from_ldap(assessment_id, desc_findings)
                _info(f"Saved → {path}")
                for f in desc_findings:
                    _info(f"  [{f['username']}] {f['description']}")
        except Exception as exc:
            warnings.append(f"Step 2 error: {exc}")
            _info(f"Description scan failed: {exc}")

        # ══════════════════════════════════════════════════════════════════
        # STEP 3 — Validate credentials found in descriptions
        # netexec smb <target_ip> -u <user> -p <pass> --users
        # ══════════════════════════════════════════════════════════════════
        _step_banner(3, "Credential validation via netexec")
        valid_creds: list[dict] = []

        if desc_findings:
            for finding in desc_findings:
                username    = finding["username"]
                description = finding["description"]
                # Attempt to extract a password-like token from the description
                candidates = self._extract_password_candidates(description)
                for candidate in candidates:
                    result = self._validate_credential(target, username, candidate)
                    if result == "valid":
                        _info(f"  [green]✔  VALID[/green]  {username}:{candidate}")
                        valid_creds.append({"username": username, "password": candidate})
                    elif result == "must_change":
                        _con.print(
                            f"\n  [yellow bold]⚠  TEMPORARY PASSWORD[/yellow bold]  "
                            f"[cyan]{username}[/cyan]:[cyan]{candidate}[/cyan]\n"
                            f"  [dim]The password is temporary and must be changed before use.[/dim]\n"
                            f"  [dim]Run:[/dim] [bold]smbpasswd -r {domain} -U {username}[/bold]\n"
                            f"  [dim]Then retry:[/dim] [bold]netexec smb {target} -u '{username}' -p '<new_pass>' --users[/bold]"
                        )
                        valid_creds.append({
                            "username": username, "password": candidate,
                            "note": f"Temporary — change via: smbpasswd -r {domain} -U {username}"
                        })
                    else:
                        _info(f"  [red]✘  invalid[/red]  {username}:{candidate}")

            if valid_creds:
                path = self._save_valid_creds(assessment_id, valid_creds)
                _info(f"Valid credentials saved → {path}")
                # Persist first valid set as stored creds for subsequent modules
                if not state.initial_credentials.username:
                    vc = valid_creds[0]
                    from session import Credentials as _Creds
                    state.initial_credentials = _Creds(
                        username=vc["username"], password=vc["password"]
                    )
            else:
                _info("No credentials validated from descriptions.")
        else:
            _info("No suspicious descriptions — skipping validation.")

        # ── Additional enumeration ─────────────────────────────────────────
        # Groups, SPNs from dedicated query, password policy, ldapdomaindump
        groups: list[str] = []
        try:
            group_raw    = self._query_groups(ldap_host, base_dn, port, use_ldaps, creds=bind_creds, domain=domain)
            group_entries = _parse_ldif_entries(group_raw)
            groups = _parse_groups(group_entries)
        except Exception as exc:
            warnings.append(f"Group enumeration error: {exc}")

        try:
            spn_raw = self._query_spns(ldap_host, base_dn, port, use_ldaps, creds=bind_creds, domain=domain)
            spn_entries = _parse_ldif_entries(spn_raw)
            _, _, _, extra_spns = _parse_users(spn_entries)
            seen = {(r["username"], r["spn"]) for r in spn_records}
            for s in extra_spns:
                if (s["username"], s["spn"]) not in seen:
                    spn_records.append(s)
                    seen.add((s["username"], s["spn"]))
        except Exception as exc:
            warnings.append(f"SPN enumeration error: {exc}")

        try:
            policy = self._query_password_policy(ldap_host, base_dn, port, use_ldaps, creds=bind_creds, domain=domain)
            if policy:
                state.password_policy = policy
        except Exception as exc:
            warnings.append(f"Password policy error: {exc}")

        try:
            if bind_creds and bind_creds.username:
                dump_path = self._run_ldapdomaindump(target, domain, bind_creds)
                if dump_path:
                    state.domain_dump_path = dump_path
                    warnings.append(f"ldapdomaindump → {dump_path}")
        except Exception as exc:
            warnings.append(f"ldapdomaindump error: {exc}")

        # ── State update ───────────────────────────────────────────────────
        self._update_state(state, target, users, asrep_users, groups,
                           spn_records, desc_findings, anon_ok, warnings)

        # Persist valid creds in state
        for vc in valid_creds:
            entry = {"username": vc["username"], "password": vc.get("password", ""),
                     "source": "ldap_description"}
            if entry not in state.valid_credentials:
                state.valid_credentials.append(entry)

        return {
            "status":           "success",
            "anonymous":        anon_ok,
            "ldaps":            use_ldaps,
            "users":            users,
            "asrep_users":      asrep_users,
            "groups":           groups,
            "spns":             spn_records,
            "desc_findings":    desc_findings,
            "valid_creds":      valid_creds,
            "password_policy":  policy,
            "domain_dump_path": getattr(state, "domain_dump_path", None),
            "error":            None,
            "warnings":         warnings,
        }

    # ------------------------------------------------------------------ #
    #  Artifact helpers                                                    #
    # ------------------------------------------------------------------ #

    def _report_dir(self, assessment_id: str) -> str:
        path = os.path.join("reports", assessment_id)
        os.makedirs(path, exist_ok=True)
        return path

    def _save_users_ldap(self, assessment_id: str, users: list[str]) -> str:
        """Save enumerated usernames to reports/<assessment_id>/users_ldap.txt."""
        dirpath  = self._report_dir(assessment_id)
        filepath = os.path.join(dirpath, "users_ldap.txt")
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(u.strip() for u in users if u.strip()))
            fh.write("\n")
        return filepath

    def _save_creds_from_ldap(self, assessment_id: str, findings: list[dict]) -> str:
        """Save username:description pairs to reports/<assessment_id>/creds_from_ldap.txt."""
        dirpath  = self._report_dir(assessment_id)
        filepath = os.path.join(dirpath, "creds_from_ldap.txt")
        with open(filepath, "w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(f"{f['username']}  |  {f['description']}\n")
        return filepath

    def _save_valid_creds(self, assessment_id: str, valid: list[dict]) -> str:
        """Save validated credentials to reports/<assessment_id>/valid_credentials.txt."""
        dirpath  = self._report_dir(assessment_id)
        filepath = os.path.join(dirpath, "valid_credentials.txt")
        with open(filepath, "w", encoding="utf-8") as fh:
            for v in valid:
                note = f"  [{v['note']}]" if v.get("note") else ""
                fh.write(f"{v['username']}:{v['password']}{note}\n")
        return filepath

    # ------------------------------------------------------------------ #
    #  Credential validation                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_password_candidates(description: str) -> list[str]:
        """
        Heuristically extract password-like tokens from a description string.
        Looks for standalone words that resemble passwords (non-trivial length,
        mixed characters, or follow known patterns like Word+Digits).
        """
        import re as _re
        candidates: list[str] = []
        # Split on whitespace and common separators
        tokens = _re.split(r"[\s:=,;|]+", description)
        for token in tokens:
            t = token.strip().strip("\"'")
            # Skip too-short, empty, or all-lowercase common words
            if len(t) < 4:
                continue
            # Must contain at least one letter (not just numbers/symbols)
            if not any(c.isalpha() for c in t):
                continue
            # Skip tokens that look like attribute names
            if t.lower() in {"pass", "password", "pwd", "creds", "credentials",
                              "temp", "temporary", "welcome", "default", "secret",
                              "change"}:
                continue
            candidates.append(t)
        return candidates

    def _validate_credential(self, target: str, username: str, password: str) -> str:
        """
        Validate a username/password pair against the target via:
            netexec smb <target> -u <user> -p <password> --users

        Returns:
            "valid"       — authentication succeeded
            "must_change" — auth OK but password must be changed
            "invalid"     — authentication failed
        """
        import subprocess as _sp
        import shutil

        cme = None
        for binary in ("netexec", "nxc", "crackmapexec"):
            if shutil.which(binary):
                cme = binary
                break
        if not cme:
            return "invalid"

        cmd = [cme, "smb", target, "-u", username, "-p", password, "--users"]
        try:
            result = _sp.run(
                cmd,
                stdout=_sp.PIPE,
                stderr=_sp.PIPE,
                timeout=30,
            )
            output = (result.stdout or b"").decode("utf-8", errors="replace")
            output += (result.stderr or b"").decode("utf-8", errors="replace")
        except Exception:
            return "invalid"

        out_lower = output.lower()

        if "password must be changed" in out_lower or "must change password" in out_lower:
            return "must_change"

        # netexec marks success with [+]
        if "[+]" in output:
            return "valid"

        return "invalid"

    # ------------------------------------------------------------------ #
    #  ldapsearch — description query                                      #
    # ------------------------------------------------------------------ #

    def _query_descriptions(
        self, target: str, base_dn: str, port: int, use_ldaps: bool,
        creds, domain: str = "",
    ) -> str:
        """Query user objects requesting both sAMAccountName and description."""
        args = self._build_base_args(target, port, use_ldaps, creds, domain=domain)
        args += [
            "-b", base_dn,
            "-s", "sub",
            "(objectClass=user)",
            "sAMAccountName",
            "description",
            "userAccountControl",
        ]
        result = self.executor.run(args)
        return result["output"]

    # ------------------------------------------------------------------ #
    #  State mutation                                                      #
    # ------------------------------------------------------------------ #

    #  State mutation                                                       #
    # ------------------------------------------------------------------ #

    def _update_state(
        self,
        state:         AssessmentState,
        target:        str,
        users:         list[str],
        asrep_users:   list[str],
        groups:        list[str],
        spn_records:   list[dict],
        desc_findings: list[dict],
        anonymous:     bool,
        warnings:      list[str],
    ) -> None:
        """Merge discovered data into AssessmentState, avoiding duplicates."""

        # ── Users ──────────────────────────────────────────────────────
        existing_users = set(state.users)
        new_users = [u for u in users if u not in existing_users]
        state.users.extend(new_users)

        # Export user list to generated/
        if state.users:
            from modules.file_export import save_ldap_users
            save_ldap_users(state.users)

        # ── AS-REP roastable accounts ──────────────────────────────────
        existing_asrep = set(state.asrep_users)
        new_asrep = [u for u in asrep_users if u not in existing_asrep]
        state.asrep_users.extend(new_asrep)

        # Export AS-REP targets to generated/
        if state.asrep_users:
            from modules.file_export import save_asrep_targets
            save_asrep_targets(state.asrep_users)

        if new_asrep:
            state.log_finding(
                category="LDAP",
                description=(
                    f"AS-REP roastable accounts detected: {', '.join(new_asrep)}. "
                    "These accounts do not require Kerberos pre-authentication — "
                    "request AS-REP hashes and crack offline."
                ),
                severity="HIGH",
            )

        # ── Groups ─────────────────────────────────────────────────────
        existing_groups = set(state.groups)
        state.groups.extend(g for g in groups if g not in existing_groups)

        # ── SPNs ───────────────────────────────────────────────────────
        existing_spns = {(s["username"], s["spn"]) for s in state.spns}
        new_spns = [
            s for s in spn_records
            if (s["username"], s["spn"]) not in existing_spns
        ]
        state.spns.extend(new_spns)

        # Export SPNs to generated/
        if state.spns:
            from modules.file_export import save_spns
            save_spns(state.spns)

        if new_spns:
            spn_summary = ", ".join(
                f"{s['username']} → {s['spn']}" for s in new_spns[:5]
            )
            if len(new_spns) > 5:
                spn_summary += " (…)"
            state.log_finding(
                category="LDAP",
                description=(
                    f"{len(new_spns)} SPN(s) discovered: {spn_summary}. "
                    "Service accounts may be Kerberoastable."
                ),
                severity="MEDIUM",
            )

        # ── Description credential hints ───────────────────────────────
        for finding in desc_findings:
            state.vulnerabilities.append({
                "name":        "Potential Cleartext Credential in Description",
                "severity":    "HIGH",
                "description": (
                    f"User '{finding['username']}' has a suspicious description: "
                    f"\"{finding['description']}\""
                ),
            })
            state.log_finding(
                category="LDAP",
                description=(
                    f"Potential credential in description for '{finding['username']}': "
                    f"\"{finding['description']}\""
                ),
                severity="HIGH",
            )

        # ── Anonymous bind ────────────────────────────────────────────
        if anonymous:
            state.log_finding(
                category="LDAP",
                description=(
                    f"Anonymous LDAP bind allowed on {target}. "
                    "DC permits unauthenticated directory queries."
                ),
                severity="MEDIUM",
            )

        # ── Audit trail ────────────────────────────────────────────────
        state.log_action(
            f"LDAP enumeration against {target} — "
            f"{len(users)} users, {len(asrep_users)} AS-REP, "
            f"{len(new_spns)} SPNs, {len(desc_findings)} desc findings"
        )

    # ------------------------------------------------------------------ #
    #  ldapsearch query helpers                                            #
    # ------------------------------------------------------------------ #

    def _build_base_args(
        self,
        target:    str,
        port:      int,
        use_ldaps: bool,
        creds,            # Credentials | None
        domain:    str = "",
    ) -> list[str]:
        """
        Build the common ldapsearch arguments (host, port, bind DN, auth).

        Bind DN format:
          - user@domain  (UPN — most compatible with Windows DCs)
          - Falls back to bare username if no domain provided.
        """
        scheme = "ldaps" if use_ldaps else "ldap"
        args = [
            "ldapsearch",
            "-x",
            "-H", f"{scheme}://{target}:{port}",
            "-o", "ldif-wrap=no",
        ]

        if use_ldaps:
            args += ["-o", "TLS_REQCERT=never"]

        if creds and creds.username:
            user = creds.username
            # Build UPN: user@domain (preferred by Windows DCs)
            if "@" in user:
                bind_dn = user          # already user@domain
            elif domain:
                bind_dn = f"{user}@{domain}"
            else:
                bind_dn = user          # last resort bare username

            args += ["-D", bind_dn, "-w", creds.password]

        return args

    def _try_anonymous_bind(
        self,
        target:   str,
        base_dn:  str,
        port:     int,
        use_ldaps: bool,
        domain:   str = "",
    ) -> tuple[bool, str, str]:
        """
        Attempt an anonymous LDAP bind by requesting only the root DSE.

        Returns
        -------
        tuple[bool, str, str]
            (success, stdout, stderr)
        """
        args = self._build_base_args(target, port, use_ldaps, creds=None, domain=domain)
        args += [
            "-b", "",
            "-s", "base",
            "(objectClass=*)",
            "namingContexts",
        ]

        result = self.executor.run(args)

        # Determine bind success: no error status codes in stderr and
        # either output contains namingContexts or exit code 0
        denied_patterns = [
            "invalid credentials",
            "ldap_bind:",
            "can't contact ldap server",
            "operations error",
        ]
        err_lower = result["error"].lower() + result["output"].lower()
        failed = any(p in err_lower for p in denied_patterns)

        success = result["exit_code"] == 0 and not failed
        return success, result["output"], result["error"]

    def _try_guest_bind(
        self,
        target:    str,
        base_dn:   str,
        port:      int,
        use_ldaps: bool,
        domain:    str = "",
    ) -> bool:
        """
        Attempt an LDAP bind using 'guest' account with an empty password.
        Many DCs block anonymous (no credentials) but accept guest login,
        which grants the same read access for enumeration purposes.

        Returns True if the bind succeeds.
        """
        from session import Credentials as _Creds
        guest = _Creds(username="guest", password="")

        args = self._build_base_args(target, port, use_ldaps, creds=guest, domain=domain)
        args += [
            "-b", "",
            "-s", "base",
            "(objectClass=*)",
            "namingContexts",
        ]

        result = self.executor.run(args)

        denied_patterns = [
            "invalid credentials",
            "ldap_bind:",
            "can't contact ldap server",
            "operations error",
            "unwilling to perform",
        ]
        err_lower = result["error"].lower() + result["output"].lower()
        failed = any(p in err_lower for p in denied_patterns)

        return result["exit_code"] == 0 and not failed

    def _query_users(
        self, target: str, base_dn: str, port: int, use_ldaps: bool,
        creds, domain: str = "",
    ) -> str:
        """Query all user objects and return raw LDIF output."""
        args = self._build_base_args(target, port, use_ldaps, creds, domain=domain)
        args += [
            "-b", base_dn,
            "-s", "sub",
            "(objectClass=user)",
            *USER_ATTRIBUTES,
        ]
        result = self.executor.run(args)
        return result["output"]

    def _query_groups(
        self, target: str, base_dn: str, port: int, use_ldaps: bool,
        creds, domain: str = "",
    ) -> str:
        """Query all group objects and return raw LDIF output."""
        args = self._build_base_args(target, port, use_ldaps, creds, domain=domain)
        args += [
            "-b", base_dn,
            "-s", "sub",
            "(objectClass=group)",
            *GROUP_ATTRIBUTES,
        ]
        result = self.executor.run(args)
        return result["output"]

    def _query_spns(
        self, target: str, base_dn: str, port: int, use_ldaps: bool,
        creds, domain: str = "",
    ) -> str:
        """Query Kerberoastable service accounts."""
        args = self._build_base_args(target, port, use_ldaps, creds, domain=domain)
        args += [
            "-b", base_dn,
            "-s", "sub",
            "(&(objectClass=user)(servicePrincipalName=*))",
            "sAMAccountName",
            "servicePrincipalName",
        ]
        result = self.executor.run(args)
        return result["output"]

    def _query_password_policy(
        self, target: str, base_dn: str, port: int, use_ldaps: bool,
        creds, domain: str = "",
    ) -> dict:
        """Query domain password policy attributes."""
        args = self._build_base_args(target, port, use_ldaps, creds, domain=domain)
        args += [
            "-b", base_dn,
            "-s", "base",
            "(objectClass=domain)",
            "maxPwdAge", "minPwdLength", "pwdHistoryLength",
            "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
        ]
        result = self.executor.run(args, timeout=30)
        if not result["output"]:
            return {}
        policy: dict = {}
        for line in result["output"].splitlines():
            if ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                k = k.strip().lower()
                v = v.strip()
                if k in (
                    "minpwdlength", "pwdhistorylength", "lockoutthreshold",
                    "maxpwdage", "lockoutduration", "lockoutobservationwindow",
                ):
                    policy[k] = v
        return policy

    def _run_ldapdomaindump(
        self,
        target: str,
        domain: str,
        creds,
    ) -> "str | None":
        """
        Run ldapdomaindump if available.

        Exact playbook command:
            ldapdomaindump -u <domain>\\<user> -p <pass> ldap://<target> --no-json --no-grep -o <dir>
        """
        if not self.executor.check_tool("ldapdomaindump"):
            return None
        safe_domain = domain.replace(".", "_")
        output_dir = os.path.abspath(os.path.join("reports", f"{safe_domain}-dump"))
        os.makedirs(output_dir, exist_ok=True)
        cmd = [
            "ldapdomaindump",
            "-u", f"{domain}\\{creds.username}",
            "-p", creds.password,
            f"ldap://{target}",
            "--no-json",
            "--no-grep",
            "-o", output_dir,
        ]
        result = self.executor.run(cmd, timeout=60)
        if result["status"] == "success" or os.path.isdir(output_dir):
            return output_dir
        return None


    @staticmethod
    def _error(message: str) -> dict:
        """Return a standardised error result dict."""
        return {
            "status":        "error",
            "anonymous":     False,
            "ldaps":         False,
            "users":         [],
            "asrep_users":   [],
            "groups":        [],
            "spns":          [],
            "desc_findings": [],
            "error":         message,
            "warnings":      [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience function
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    Convenience wrapper — run LDAP enumeration without instantiating the class.

    Example (from main.py dispatcher)
    ----------------------------------
    from modules.ldap_enum_module import run as ldap_run
    result = ldap_run(state)
    """
    return LDAPEnumerationModule(executor=executor).run(state)


# ─────────────────────────────────────────────────────────────────────────────
# Smoke-test
# Usage: python modules/ldap_enum_module.py <target_ip> <domain> [username] [password]
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python modules/ldap_enum_module.py <target_ip> <domain> [username] [password]")
        sys.exit(1)

    from session import AssessmentState, Credentials, generate_assessment_id

    username = sys.argv[3] if len(sys.argv) > 3 else ""
    password = sys.argv[4] if len(sys.argv) > 4 else ""

    test_state = AssessmentState(
        assessment_id=generate_assessment_id(),
        target_ip=sys.argv[1],
        domain=sys.argv[2],
        open_ports=[389, 636, 445, 88],
        initial_credentials=Credentials(username=username, password=password),
    )

    module = LDAPEnumerationModule(executor=CommandExecutor(verbose=True, default_timeout=120))
    result = module.run(test_state)

    print("\n" + "─" * 60)
    print(f"  Status         : {result['status']}")
    print(f"  Anonymous Bind : {result['anonymous']}")
    print(f"  LDAPS          : {result['ldaps']}")
    print(f"  Users          : {len(result['users'])} found")
    print(f"  AS-REP Users   : {result['asrep_users']}")
    print(f"  Groups         : {len(result['groups'])} found")
    print(f"  SPNs           : {len(result['spns'])} found")
    print(f"  Desc Findings  : {len(result['desc_findings'])}")
    if result["error"]:
        print(f"  Error          : {result['error']}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  ⚠  {w}")
    print("─" * 60)

    if result["desc_findings"]:
        print("\n  Suspicious descriptions:")
        for f in result["desc_findings"]:
            print(f"    [{f['username']}] {f['description']}")

    if result["asrep_users"]:
        print("\n  AS-REP roastable accounts:")
        for u in result["asrep_users"]:
            print(f"    ✘  {u}  (DONT_REQUIRE_PREAUTH)")

    if result["spns"]:
        print("\n  Kerberoastable SPNs:")
        for s in result["spns"]:
            print(f"    {s['username']} → {s['spn']}")
