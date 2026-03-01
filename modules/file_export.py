"""
file_export.py - Generated file manager for AD-Pathfinder.

Writes discovered users, groups, SPNs, and hashes to the
'generated/' directory as plain .txt files so that external tools
(hashcat, netexec, GetNPUsers, etc.) can consume them directly.

All functions are safe to call repeatedly — they overwrite the file
each time so it always reflects the latest state.

Directory layout
----------------
generated/
    users-rid.txt       <- users from SMB RID brute-force
    groups-rid.txt      <- groups from SMB RID brute-force
    users-ldap.txt      <- users from LDAP enumeration
    users-asrep.txt     <- AS-REP roastable accounts (no preauth needed)
    users-all.txt       <- merged / de-duped union of all user sources
    spns.txt            <- Kerberoastable SPNs (user:spn)
"""

from __future__ import annotations

import os
from typing import Optional

# Root of the generated directory, relative to wherever main.py is executed
GENERATED_DIR = "generated"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_dir() -> str:
    """Create generated/ if it doesn't exist and return its absolute path."""
    path = os.path.abspath(GENERATED_DIR)
    os.makedirs(path, exist_ok=True)
    return path


def _write(filename: str, lines: list[str]) -> str:
    """
    Write lines to generated/<filename>, one entry per line.
    Skips empty/whitespace-only entries.
    Returns the absolute path of the written file.
    """
    dirpath = _ensure_dir()
    filepath = os.path.join(dirpath, filename)
    clean = [l.strip() for l in lines if l.strip()]
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(clean) + ("\n" if clean else ""))
    return filepath


def _read(filename: str) -> list[str]:
    """
    Read lines from generated/<filename>.
    Returns an empty list if the file does not exist.
    """
    filepath = os.path.join(os.path.abspath(GENERATED_DIR), filename)
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip()]


def _merge_all_users() -> str:
    """
    Merge users-rid.txt + users-ldap.txt into users-all.txt (deduped).
    Returns the path to users-all.txt.
    """
    combined: dict[str, None] = {}  # ordered set via dict
    for source in ("users-rid.txt", "users-ldap.txt"):
        for u in _read(source):
            combined[u.lower()] = None
    # Write in original-case order using the keys (already lowercased)
    # Re-read to preserve casing
    all_users: list[str] = []
    seen: set[str] = set()
    for source in ("users-rid.txt", "users-ldap.txt"):
        for u in _read(source):
            key = u.lower()
            if key not in seen:
                all_users.append(u)
                seen.add(key)
    return _write("users-all.txt", all_users)


# ─────────────────────────────────────────────────────────────────────────────
# Public write helpers  (called by each module after it discovers data)
# ─────────────────────────────────────────────────────────────────────────────

def save_rid_users(users: list[str]) -> str:
    """Write RID-brute users to generated/users-rid.txt and refresh users-all.txt."""
    path = _write("users-rid.txt", users)
    _merge_all_users()
    return path


def save_rid_groups(groups: list[str]) -> str:
    """Write RID-brute groups to generated/groups-rid.txt."""
    return _write("groups-rid.txt", groups)


def save_ldap_users(users: list[str]) -> str:
    """Write LDAP users to generated/users-ldap.txt and refresh users-all.txt."""
    path = _write("users-ldap.txt", users)
    _merge_all_users()
    return path


def save_asrep_targets(users: list[str]) -> str:
    """Write AS-REP target accounts to generated/users-asrep.txt."""
    return _write("users-asrep.txt", users)


def save_spns(spn_records: list[dict]) -> str:
    """
    Write Kerberoastable SPNs to generated/spns.txt.
    Each line: username:spn
    """
    lines = [f"{r['username']}:{r['spn']}" for r in spn_records if r.get("username") and r.get("spn")]
    return _write("spns.txt", lines)


def save_all_users(users: list[str]) -> str:
    """Directly overwrite users-all.txt (useful after combining sources)."""
    return _write("users-all.txt", users)


# ─────────────────────────────────────────────────────────────────────────────
# Public read helpers  (called by spray / asrep / kerb modules as fallback)
# ─────────────────────────────────────────────────────────────────────────────

def load_users_all() -> list[str]:
    """Load users-all.txt — merged union of all discovered users."""
    return _read("users-all.txt")


def load_rid_users() -> list[str]:
    return _read("users-rid.txt")


def load_ldap_users() -> list[str]:
    return _read("users-ldap.txt")


def load_asrep_targets() -> list[str]:
    return _read("users-asrep.txt")


# ─────────────────────────────────────────────────────────────────────────────
# State ↔ file sync
# ─────────────────────────────────────────────────────────────────────────────

def sync_users_from_state(state) -> str:
    """
    Write state.users to users-all.txt.
    Call this after any operation that populates state.users from memory
    (e.g. loading a saved session) so the file system stays in sync.
    """
    return save_all_users(state.users)


def load_users_into_state(state) -> int:
    """
    If state.users is empty, try to populate it from generated/users-all.txt.
    Returns the number of users loaded (0 if state was already populated).
    """
    if state.users:
        return 0
    users = load_users_all()
    if users:
        state.users = users
    return len(users)


def list_generated_files() -> list[dict]:
    """
    Return metadata for all .txt files in the generated/ directory.
    Each entry: {name, path, lines}
    """
    dirpath = os.path.abspath(GENERATED_DIR)
    if not os.path.isdir(dirpath):
        return []
    result = []
    for fname in sorted(os.listdir(dirpath)):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(dirpath, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                count = sum(1 for l in fh if l.strip())
        except OSError:
            count = 0
        result.append({"name": fname, "path": fpath, "lines": count})
    return result
