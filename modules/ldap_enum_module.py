"""
ldap_enum_module.py - LDAP Enumeration module for AD-Pathfinder.

Performs structured LDAP enumeration against a Domain Controller using
ldapsearch (anonymous + authenticated), with graceful fallback when the
tool is unavailable.

Enumeration steps:
    A) Anonymous bind test  — determines whether the DC allows unauthenticated
       LDAP queries (ports 389 / 636).
    B) User enumeration     — extracts sAMAccountName, description, and the
       userAccountControl bitmask from all user objects.
    C) AS-REP detection     — flags accounts with the DONT_REQUIRE_PREAUTH
       bit set (0x400000), indicating they are roastable without credentials.
    D) Description scanning — applies regex patterns to description fields to
       detect cleartext or weakly-obfuscated credentials.
    E) SPN discovery        — queries servicePrincipalName to identify
       Kerberoastable service accounts.
    F) Group enumeration    — lists AD groups for context.

Design contract:
    - Zero CLI output — all results returned as a structured dict.
    - Caller (main.py) is responsible for all display/formatting.
    - state is updated in-place; caller is responsible for saving the session.
    - CommandExecutor is used exclusively (no shell=True anywhere).

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
        if not self.executor.check_tool("ldapsearch"):
            return self._error(
                "ldapsearch is not installed. Run: sudo apt install ldap-utils"
            )

        target   = state.target_ip
        domain   = state.domain
        base_dn  = _build_base_dn(domain)
        creds    = state.initial_credentials
        warnings: list[str] = []

        # Determine which LDAP port(s) to use
        use_ldaps = 636 in state.open_ports
        port      = 636 if use_ldaps else 389

        # ── Step A: Anonymous bind test ────────────────────────────────
        anon_ok, anon_output, anon_err = self._try_anonymous_bind(
            target, base_dn, port, use_ldaps
        )

        # ── Step B: Choose query auth mode ────────────────────────────
        has_creds = bool(creds.username and (creds.password or creds.ntlm_hash))

        if anon_ok:
            # Use anonymous to pull users, then groups, then SPNs
            user_raw  = self._query_users(target, base_dn, port, use_ldaps, creds=None)
            group_raw = self._query_groups(target, base_dn, port, use_ldaps, creds=None)
            spn_raw   = self._query_spns(target, base_dn, port, use_ldaps, creds=None)
        elif has_creds:
            # Fallback to authenticated queries
            warnings.append(
                "Anonymous bind was denied; falling back to authenticated queries."
            )
            user_raw  = self._query_users(target, base_dn, port, use_ldaps, creds=creds)
            group_raw = self._query_groups(target, base_dn, port, use_ldaps, creds=creds)
            spn_raw   = self._query_spns(target, base_dn, port, use_ldaps, creds=creds)
        else:
            warnings.append(
                "Anonymous bind denied and no credentials available. "
                "Supply credentials to enable authenticated LDAP enumeration."
            )
            return {
                "status":        "error",
                "anonymous":     False,
                "ldaps":         use_ldaps,
                "users":         [],
                "asrep_users":   [],
                "groups":        [],
                "spns":          [],
                "desc_findings": [],
                "error":         "LDAP bind failed: anonymous and no credentials.",
                "warnings":      warnings,
            }

        # ── Step C: Parse results ──────────────────────────────────────
        user_entries  = _parse_ldif_entries(user_raw)
        group_entries = _parse_ldif_entries(group_raw)
        spn_entries   = _parse_ldif_entries(spn_raw)

        users, asrep_users, desc_findings, spn_records = _parse_users(user_entries)

        # Also parse SPNs from the dedicated SPN query (may overlap; deduplicate)
        _, _, _, extra_spns = _parse_users(spn_entries)
        seen_spns = {(r["username"], r["spn"]) for r in spn_records}
        for spn in extra_spns:
            key = (spn["username"], spn["spn"])
            if key not in seen_spns:
                spn_records.append(spn)
                seen_spns.add(key)

        groups = _parse_groups(group_entries)

        # ── Step D: Update AssessmentState ────────────────────────────
        self._update_state(state, target, users, asrep_users, groups,
                           spn_records, desc_findings, anon_ok, warnings)

        return {
            "status":        "success",
            "anonymous":     anon_ok,
            "ldaps":         use_ldaps,
            "users":         users,
            "asrep_users":   asrep_users,
            "groups":        groups,
            "spns":          spn_records,
            "desc_findings": desc_findings,
            "error":         None,
            "warnings":      warnings,
        }

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

        # ── AS-REP roastable accounts ──────────────────────────────────
        existing_asrep = set(state.asrep_users)
        new_asrep = [u for u in asrep_users if u not in existing_asrep]
        state.asrep_users.extend(new_asrep)

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
        target:   str,
        port:     int,
        use_ldaps: bool,
        creds,            # Credentials | None
    ) -> list[str]:
        """
        Build the common ldapsearch arguments (host, port, bind DN, auth).

        Anonymous mode:   -x -H ldap(s)://target:port
        Authenticated:    -x -H ... -D "user@domain" -w "password"
        """
        scheme = "ldaps" if use_ldaps else "ldap"
        args = [
            "ldapsearch",
            "-x",                          # simple authentication (not SASL)
            "-H", f"{scheme}://{target}:{port}",
            "-o", "ldif-wrap=no",          # disable line-folding for clean parsing
        ]

        if use_ldaps:
            # Disable certificate validation — assessment context, not production
            args += ["-o", "TLS_REQCERT=never"]

        if creds and creds.username and creds.password:
            # Build bind DN — try user@domain format (most compatible)
            bind_dn = (
                f"{creds.username}@{creds.username.split('@')[-1]}"
                if "@" in creds.username
                else creds.username
            )
            args += ["-D", bind_dn, "-w", creds.password]
        # else: anonymous — no -D / -w flags

        return args

    def _try_anonymous_bind(
        self,
        target:   str,
        base_dn:  str,
        port:     int,
        use_ldaps: bool,
    ) -> tuple[bool, str, str]:
        """
        Attempt an anonymous LDAP bind by requesting only the root DSE.

        Returns
        -------
        tuple[bool, str, str]
            (success, stdout, stderr)
        """
        args = self._build_base_args(target, port, use_ldaps, creds=None)
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

    def _query_users(
        self,
        target:    str,
        base_dn:   str,
        port:      int,
        use_ldaps: bool,
        creds,
    ) -> str:
        """Query all user objects and return raw LDIF output."""
        args = self._build_base_args(target, port, use_ldaps, creds)
        args += [
            "-b", base_dn,
            "-s", "sub",
            "(objectClass=user)",
            *USER_ATTRIBUTES,
        ]
        result = self.executor.run(args)
        return result["output"]

    def _query_groups(
        self,
        target:    str,
        base_dn:   str,
        port:      int,
        use_ldaps: bool,
        creds,
    ) -> str:
        """Query all group objects and return raw LDIF output."""
        args = self._build_base_args(target, port, use_ldaps, creds)
        args += [
            "-b", base_dn,
            "-s", "sub",
            "(objectClass=group)",
            *GROUP_ATTRIBUTES,
        ]
        result = self.executor.run(args)
        return result["output"]

    def _query_spns(
        self,
        target:    str,
        base_dn:   str,
        port:      int,
        use_ldaps: bool,
        creds,
    ) -> str:
        """
        Query objects with a servicePrincipalName set (Kerberoastable accounts).
        Uses a dedicated query with a filter on servicePrincipalName presence.
        """
        args = self._build_base_args(target, port, use_ldaps, creds)
        args += [
            "-b", base_dn,
            "-s", "sub",
            "(&(objectClass=user)(servicePrincipalName=*))",
            "sAMAccountName",
            "servicePrincipalName",
        ]
        result = self.executor.run(args)
        return result["output"]

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

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
