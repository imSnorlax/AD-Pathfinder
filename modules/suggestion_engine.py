"""
suggestion_engine.py - Central intelligence engine for AD-Pathfinder.

Analyses the current AssessmentState and produces a prioritised, deduplicated
list of suggested next attack/enumeration steps based on discovered ports,
credentials, users, SPNs, and previously performed actions.

Design principles:
  - Pure logic module — zero CLI code, zero I/O side effects.
  - Each rule is a self-contained method, making it trivial to add/remove rules.
  - Suggestions are ranked by impact tier: critical → high → medium → low.
  - All suggestions are deduplicated against performed_actions before returning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from session import AssessmentState


# ─────────────────────────────────────────────────────────────────────────────
# Suggestion data structure
# ─────────────────────────────────────────────────────────────────────────────

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Suggestion:
    """
    A single actionable suggestion produced by the engine.

    Attributes
    ----------
    action : str
        Short human-readable name for the suggested action.
    priority : str
        One of: "critical", "high", "medium", "low".
    reason : str
        Explanation of why this action is being suggested.
    action_key : str
        Normalised lowercase key used for deduplication against
        AssessmentState.performed_actions (e.g. "kerberoasting").
    """
    action:     str
    priority:   str
    reason:     str
    action_key: str

    def to_dict(self) -> dict:
        return {
            "action":   self.action,
            "priority": self.priority,
            "reason":   self.reason,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Rule type alias
# ─────────────────────────────────────────────────────────────────────────────

# A rule is any callable that accepts an AssessmentState and returns a
# Suggestion or None.  This makes rules first-class and easy to register.
RuleFn = Callable[[AssessmentState], "Suggestion | None"]


# ─────────────────────────────────────────────────────────────────────────────
# SuggestionEngine
# ─────────────────────────────────────────────────────────────────────────────

class SuggestionEngine:
    """
    Analyses AssessmentState and returns a prioritised list of suggested
    next steps for an Active Directory assessment.

    Usage
    -----
    engine      = SuggestionEngine()
    suggestions = engine.generate_suggestions(state)

    for s in suggestions:
        print(s["priority"].upper(), "-", s["action"])
        print(" ", s["reason"])

    Extending
    ---------
    To add a new rule, define a method prefixed with ``_rule_`` that accepts
    an AssessmentState and returns a Suggestion or None.  The engine
    auto-discovers all such methods at instantiation time.
    """

    def __init__(self) -> None:
        # Auto-discover all methods prefixed with _rule_
        self._rules: list[RuleFn] = [
            getattr(self, name)
            for name in sorted(dir(self))
            if name.startswith("_rule_")
        ]

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def generate_suggestions(self, state: AssessmentState) -> list[dict]:
        """
        Evaluate all rules against the current state and return a ranked,
        deduplicated list of suggestion dicts.

        Parameters
        ----------
        state : AssessmentState
            The current assessment session snapshot.

        Returns
        -------
        list[dict]
            Each dict has keys: "action", "priority", "reason".
            Sorted by priority: critical → high → medium → low.
            Actions already present in state.performed_actions are excluded.
        """
        performed = self._normalise_performed(state.performed_actions)
        suggestions: list[Suggestion] = []
        seen_keys: set[str] = set()

        for rule in self._rules:
            result = rule(state)
            if result is None:
                continue
            # Skip if already performed or already suggested this run
            if result.action_key in performed:
                continue
            if result.action_key in seen_keys:
                continue
            suggestions.append(result)
            seen_keys.add(result.action_key)

        # Sort by priority tier
        suggestions.sort(key=lambda s: PRIORITY_ORDER.get(s.priority, 99))

        return [s.to_dict() for s in suggestions]

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalise_performed(performed_actions: list[str]) -> set[str]:
        """
        Flatten performed_actions (which are timestamp-prefixed strings) into
        a set of lowercase keywords for fast membership testing.
        """
        flat = " ".join(performed_actions).lower()
        return {word.strip(".:,") for word in flat.split()}

    @staticmethod
    def _has_credentials(state: AssessmentState) -> bool:
        """Return True if at least one set of valid credentials is stored."""
        return bool(state.valid_credentials)

    @staticmethod
    def _has_initial_credentials(state: AssessmentState) -> bool:
        """Return True if initial credentials (username + secret) were supplied."""
        creds = state.initial_credentials
        return bool(creds.username and (creds.password or creds.ntlm_hash))

    @staticmethod
    def _any_credential(state: AssessmentState) -> bool:
        """Return True if any credential source is available."""
        return (
            SuggestionEngine._has_credentials(state)
            or SuggestionEngine._has_initial_credentials(state)
        )

    # ------------------------------------------------------------------ #
    #  Rules — each method must start with _rule_ and return               #
    #  Suggestion | None                                                   #
    # ------------------------------------------------------------------ #

    # ── Critical ───────────────────────────────────────────────────────

    def _rule_kerberoasting(self, state: AssessmentState) -> Suggestion | None:
        """Kerberoasting: valid creds + Kerberos port + SPNs present."""
        if 88 in state.open_ports and self._any_credential(state) and state.spns:
            return Suggestion(
                action="Kerberoasting",
                priority="critical",
                reason=(
                    f"Valid credentials available, Kerberos (port 88) is open, "
                    f"and {len(state.spns)} SPN(s) discovered. "
                    "Request TGS tickets and crack offline."
                ),
                action_key="kerberoasting",
            )
        return None

    def _rule_kerberoasting_no_spns(self, state: AssessmentState) -> Suggestion | None:
        """Kerberoasting pre-check: creds + port 88 but SPNs not yet enumerated."""
        if 88 in state.open_ports and self._any_credential(state) and not state.spns:
            return Suggestion(
                action="Kerberoasting (enumerate SPNs first)",
                priority="critical",
                reason=(
                    "Valid credentials and Kerberos port (88) detected but no SPNs "
                    "enumerated yet. Run LDAP enumeration to discover service accounts."
                ),
                action_key="kerberoasting",
            )
        return None

    def _rule_asrep_roasting(self, state: AssessmentState) -> Suggestion | None:
        """AS-REP Roasting: port 88 open with no credentials required."""
        if 88 in state.open_ports and not self._any_credential(state):
            return Suggestion(
                action="AS-REP Roasting",
                priority="critical",
                reason=(
                    "Kerberos port (88) is open and no credentials are required. "
                    "Check for accounts with pre-authentication disabled and request AS-REP hashes."
                ),
                action_key="asreproasting",
            )
        return None

    def _rule_asrep_known_users(self, state: AssessmentState) -> Suggestion | None:
        """AS-REP Roasting with known vulnerable users."""
        if state.asrep_users:
            return Suggestion(
                action="AS-REP Roasting (targeted)",
                priority="critical",
                reason=(
                    f"{len(state.asrep_users)} user(s) with pre-auth disabled identified: "
                    f"{', '.join(state.asrep_users[:5])}{'...' if len(state.asrep_users) > 5 else ''}. "
                    "Request and crack their AS-REP hashes immediately."
                ),
                action_key="asreproasting",
            )
        return None

    # ── High ───────────────────────────────────────────────────────────

    def _rule_winrm(self, state: AssessmentState) -> Suggestion | None:
        """WinRM access: valid creds + port 5985 or 5986."""
        winrm_ports = {5985, 5986} & set(state.open_ports)
        if winrm_ports and self._any_credential(state):
            port = sorted(winrm_ports)[0]
            proto = "HTTPS" if port == 5986 else "HTTP"
            return Suggestion(
                action="WinRM Remote Access",
                priority="high",
                reason=(
                    f"WinRM port {port} ({proto}) is open and credentials are available. "
                    "Attempt remote shell access via evil-winrm."
                ),
                action_key="winrm",
            )
        return None

    def _rule_password_spraying(self, state: AssessmentState) -> Suggestion | None:
        """Password spraying: users discovered but no valid credentials yet."""
        if state.users and not self._any_credential(state):
            return Suggestion(
                action="Password Spraying",
                priority="high",
                reason=(
                    f"{len(state.users)} user(s) enumerated but no valid credentials found. "
                    "Spray common/weak passwords carefully to avoid account lockout."
                ),
                action_key="spraying",
            )
        return None

    def _rule_smb_relay(self, state: AssessmentState) -> Suggestion | None:
        """SMB relay opportunity: port 445 open without credentials."""
        if 445 in state.open_ports and not self._any_credential(state):
            return Suggestion(
                action="SMB Relay / LLMNR Poisoning",
                priority="high",
                reason=(
                    "SMB (port 445) is open and no credentials are available. "
                    "Consider LLMNR/NBT-NS poisoning with Responder to capture NTLMv2 hashes."
                ),
                action_key="smbrelay",
            )
        return None

    def _rule_pass_the_hash(self, state: AssessmentState) -> Suggestion | None:
        """Pass-the-Hash: NTLM hash in valid_credentials + SMB open."""
        has_hash = any(c.get("ntlm_hash") for c in state.valid_credentials)
        if has_hash and 445 in state.open_ports:
            return Suggestion(
                action="Pass-the-Hash",
                priority="high",
                reason=(
                    "NTLM hash(es) available in valid credentials and SMB (port 445) is open. "
                    "Attempt lateral movement via Pass-the-Hash (psexec, smbexec, wmiexec)."
                ),
                action_key="passthehash",
            )
        return None

    # ── Medium ─────────────────────────────────────────────────────────

    def _rule_ldap_enum(self, state: AssessmentState) -> Suggestion | None:
        """LDAP enumeration: port 389 or 636 open."""
        ldap_ports = {389, 636, 3268} & set(state.open_ports)
        if ldap_ports:
            port = sorted(ldap_ports)[0]
            return Suggestion(
                action="LDAP Enumeration",
                priority="medium",
                reason=(
                    f"LDAP port {port} is open. "
                    "Enumerate users, groups, GPOs, password policies, and SPNs."
                ),
                action_key="ldap_enum",
            )
        return None

    def _rule_smb_enum(self, state: AssessmentState) -> Suggestion | None:
        """SMB enumeration: port 445 open."""
        if 445 in state.open_ports:
            return Suggestion(
                action="SMB Enumeration",
                priority="medium",
                reason=(
                    "SMB (port 445) is open. "
                    "Enumerate shares, sessions, null sessions, and check for EternalBlue."
                ),
                action_key="smb_enum",
            )
        return None

    def _rule_rdp_check(self, state: AssessmentState) -> Suggestion | None:
        """RDP checks: port 3389 open."""
        if 3389 in state.open_ports:
            cred_note = (
                "Credentials available — attempt RDP login."
                if self._any_credential(state)
                else "No credentials yet — check for BlueKeep (CVE-2019-0708) or NLA misconfig."
            )
            return Suggestion(
                action="RDP Enumeration / Access",
                priority="medium",
                reason=f"RDP (port 3389) is open. {cred_note}",
                action_key="rdp",
            )
        return None

    def _rule_mssql_enum(self, state: AssessmentState) -> Suggestion | None:
        """MSSQL: port 1433 open."""
        if 1433 in state.open_ports:
            return Suggestion(
                action="MSSQL Enumeration",
                priority="medium",
                reason=(
                    "MSSQL (port 1433) is open. "
                    "Enumerate databases, attempt UNC path injection (xp_dirtree), "
                    "and check for xp_cmdshell if credentials are available."
                ),
                action_key="mssql",
            )
        return None

    # ── Low ────────────────────────────────────────────────────────────

    def _rule_adws_enum(self, state: AssessmentState) -> Suggestion | None:
        """AD Web Services: port 9389 open."""
        if 9389 in state.open_ports:
            return Suggestion(
                action="AD Web Services Enumeration",
                priority="low",
                reason=(
                    "AD Web Services (port 9389) is open. "
                    "Enumerate via the ADWS endpoint using PowerShell or ADExplorer."
                ),
                action_key="adws",
            )
        return None

    def _rule_no_scan_yet(self, state: AssessmentState) -> Suggestion | None:
        """Nudge: no ports discovered yet — run a port scan first."""
        if not state.open_ports:
            return Suggestion(
                action="Run Port & Service Scan",
                priority="low",
                reason=(
                    "No open ports have been discovered yet. "
                    "Run the Nmap module first to identify available services."
                ),
                action_key="portscan",
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience function
# ─────────────────────────────────────────────────────────────────────────────

def generate_suggestions(state: AssessmentState) -> list[dict]:
    """
    Convenience wrapper — generate suggestions without instantiating the engine.

    Example
    -------
    from modules.suggestion_engine import generate_suggestions
    suggestions = generate_suggestions(state)
    """
    return SuggestionEngine().generate_suggestions(state)