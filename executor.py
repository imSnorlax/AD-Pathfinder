"""
executor.py - Secure command execution engine for AD-Pathfinder.

Provides CommandExecutor: a safe, structured wrapper around subprocess
for running system tools (nmap, ldapsearch, impacket, etc.) during
Active Directory assessments.

Security model:
  - Commands MUST be passed as a list — raw strings are rejected.
  - shell=True is never used, preventing shell injection.
  - Input type is validated before any execution occurs.

Future expansion:
  - async_run() stub is included for future asyncio integration.
  - Result dicts are uniform, making them trivial to store in AssessmentState.
"""

from __future__ import annotations

import subprocess
import shutil
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.table import Table
    _RICH_AVAILABLE = True
    console = Console()
except ImportError:
    _RICH_AVAILABLE = False
    console = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Type alias for the structured result dict
# ─────────────────────────────────────────────────────────────────────────────

CommandResult = dict  # keys: status, command, output, error, exit_code, timestamp


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _print_rich(result: CommandResult) -> None:
    """Render a CommandResult using rich for clean terminal output."""
    status_color = "bold green" if result["status"] == "success" else "bold red"
    status_icon  = "✔" if result["status"] == "success" else "✘"

    cmd_str = " ".join(result["command"])

    table = Table(box=box.ROUNDED, show_header=False, border_style="bright_blue", expand=False)
    table.add_column("Key",   style="bold bright_cyan", width=12)
    table.add_column("Value", style="white")

    table.add_row("Command",   f"[bright_white]{cmd_str}[/bright_white]")
    table.add_row("Status",    f"[{status_color}]{status_icon}  {result['status'].upper()}[/{status_color}]")
    table.add_row("Exit Code", str(result["exit_code"]))
    table.add_row("Timestamp", result["timestamp"])

    if result["output"]:
        output_preview = result["output"][:300] + ("…" if len(result["output"]) > 300 else "")
        table.add_row("Output",   f"[dim]{output_preview}[/dim]")

    if result["error"]:
        error_preview = result["error"][:300] + ("…" if len(result["error"]) > 300 else "")
        table.add_row("Stderr",   f"[yellow]{error_preview}[/yellow]")

    console.print(
        Panel(
            table,
            title=f"[bold bright_cyan]Command Execution[/bold bright_cyan]",
            border_style="bright_blue",
        )
    )


def _print_plain(result: CommandResult) -> None:
    """Fallback renderer when rich is not installed."""
    sep = "-" * 60
    status_icon = "✔" if result["status"] == "success" else "✘"
    print(sep)
    print(f"  [{result['timestamp']}] {status_icon} {result['status'].upper()}")
    print(f"  CMD : {' '.join(result['command'])}")
    print(f"  EXIT: {result['exit_code']}")
    if result["output"]:
        print(f"  OUT : {result['output'][:300]}")
    if result["error"]:
        print(f"  ERR : {result['error'][:300]}")
    print(sep)


# ─────────────────────────────────────────────────────────────────────────────
# CommandExecutor
# ─────────────────────────────────────────────────────────────────────────────

class CommandExecutor:
    """
    Secure, structured wrapper around subprocess for AD assessment tooling.

    Usage
    -----
    executor = CommandExecutor(verbose=True)
    result   = executor.run(["nmap", "-sV", "10.10.10.100"], timeout=60)

    if result["status"] == "success":
        print(result["output"])

    Parameters
    ----------
    verbose : bool
        When True, each execution is printed to the terminal in colour.
    default_timeout : int | None
        Default timeout in seconds applied when run() is called without
        an explicit timeout.  None means wait indefinitely.
    """

    def __init__(
        self,
        verbose: bool = True,
        default_timeout: Optional[int] = None,
    ) -> None:
        self.verbose         = verbose
        self.default_timeout = default_timeout

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(
        self,
        command: list[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> CommandResult:
        """
        Execute a command and return a structured result dict.

        Parameters
        ----------
        command : list[str]
            The command and its arguments, e.g. ["nmap", "-sV", "10.0.0.1"].
            Passing a plain string raises TypeError.
        timeout : int | None
            Per-call timeout override.  Falls back to self.default_timeout.
        cwd : str | None
            Working directory for the subprocess.
        env : dict | None
            Environment variables for the subprocess.
            None inherits the parent process environment.

        Returns
        -------
        CommandResult
            {
                "status":    "success" | "error" | "timeout",
                "command":   list[str],
                "output":    str,
                "error":     str,
                "exit_code": int,
                "timestamp": str,
            }

        Raises
        ------
        TypeError  — if command is not a list.
        ValueError — if command is an empty list.
        """
        self._validate(command)

        effective_timeout = timeout if timeout is not None else self.default_timeout

        try:
            proc = subprocess.run(  # noqa: S603  (shell=False is explicit)
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=effective_timeout,
                cwd=cwd,
                env=env,
                shell=False,          # ← always False; never overridden
            )

            result: CommandResult = {
                "status":    "success" if proc.returncode == 0 else "error",
                "command":   command,
                "output":    proc.stdout.decode("utf-8", errors="replace").strip(),
                "error":     proc.stderr.decode("utf-8", errors="replace").strip(),
                "exit_code": proc.returncode,
                "timestamp": _now(),
            }

        except subprocess.TimeoutExpired:
            result = {
                "status":    "timeout",
                "command":   command,
                "output":    "",
                "error":     f"Command timed out after {effective_timeout}s.",
                "exit_code": -1,
                "timestamp": _now(),
            }

        except FileNotFoundError:
            binary = command[0]
            result = {
                "status":    "error",
                "command":   command,
                "output":    "",
                "error":     (
                    f"Executable '{binary}' not found. "
                    f"Is it installed and on PATH? "
                    f"(which {binary}: {shutil.which(binary)})"
                ),
                "exit_code": -1,
                "timestamp": _now(),
            }

        except Exception as exc:  # noqa: BLE001
            result = {
                "status":    "error",
                "command":   command,
                "output":    "",
                "error":     f"Unexpected error: {type(exc).__name__}: {exc}",
                "exit_code": -1,
                "timestamp": _now(),
            }

        if self.verbose:
            self._print(result)

        return result

    def check_tool(self, binary: str) -> bool:
        """
        Return True if *binary* is available on PATH, False otherwise.

        Example
        -------
        if not executor.check_tool("nmap"):
            print("nmap is not installed")
        """
        return shutil.which(binary) is not None

    # ------------------------------------------------------------------ #
    #  Future: async stub                                                  #
    # ------------------------------------------------------------------ #

    async def async_run(
        self,
        command: list[str],
        timeout: Optional[int] = None,
    ) -> CommandResult:
        """
        Async execution stub — intended for future asyncio integration.

        Will use asyncio.create_subprocess_exec internally to avoid
        blocking the event loop during long-running scans.

        Not yet implemented; raises NotImplementedError.
        """
        raise NotImplementedError(
            "async_run() is reserved for future asyncio integration. "
            "Use run() for synchronous execution."
        )

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _validate(command: list[str]) -> None:
        """Validate that command is a non-empty list of strings."""
        if not isinstance(command, list):
            raise TypeError(
                f"command must be a list, not {type(command).__name__}. "
                "Raw strings are rejected to prevent shell injection."
            )
        if len(command) == 0:
            raise ValueError("command list must not be empty.")
        if not all(isinstance(arg, str) for arg in command):
            raise TypeError("All command arguments must be strings.")

    def _print(self, result: CommandResult) -> None:
        """Dispatch to rich or plain printer based on availability."""
        if _RICH_AVAILABLE:
            _print_rich(result)
        else:
            _print_plain(result)


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience instance
# ─────────────────────────────────────────────────────────────────────────────

#: Drop-in executor with default settings.  Import and use directly:
#:   from executor import default_executor
#:   result = default_executor.run(["whoami"])
default_executor = CommandExecutor(verbose=True)


# ─────────────────────────────────────────────────────────────────────────────
# Quick smoke-test when run directly
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ex = CommandExecutor(verbose=True, default_timeout=10)

    # Basic success
    ex.run(["echo", "AD-Pathfinder executor online"])

    # Intentional failure (exit code != 0)
    ex.run(["ping", "-c", "1", "-W", "1", "0.0.0.0"])

    # Missing binary
    ex.run(["nonexistent_tool", "--version"])

    # Security: string rejection
    try:
        ex.run("echo hello")  # type: ignore
    except TypeError as e:
        if _RICH_AVAILABLE:
            console.print(f"  [bold red]TypeError caught (expected):[/bold red] {e}")
        else:
            print(f"TypeError caught (expected): {e}")