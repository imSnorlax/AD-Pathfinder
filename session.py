"""
session.py - Assessment session handling for AD-Pathfinder.
Responsible for creating, saving, and loading AssessmentState objects.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional

REPORTS_DIR = "reports"


@dataclass
class Credentials:
    username: str = ""
    password: str = ""
    ntlm_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Credentials":
        return cls(**data)


@dataclass
class AssessmentState:
    assessment_id: str
    target_ip: str
    domain: str
    dns_server: str = ""
    initial_credentials: Credentials = field(default_factory=Credentials)

    # Discovered data (populated by future modules)
    valid_credentials: list[dict] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: dict[str, Any] = field(default_factory=dict)
    users: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    spns: list[dict] = field(default_factory=list)
    asrep_users: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)

    # Audit trail
    performed_actions: list[str] = field(default_factory=list)
    findings_log: list[dict] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    #  Serialisation helpers                                               #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        data = asdict(self)
        # Credentials is a nested dataclass — asdict handles it automatically
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "AssessmentState":
        creds_data = data.pop("initial_credentials", {})
        state = cls(**data)
        state.initial_credentials = Credentials.from_dict(creds_data)
        return state

    # ------------------------------------------------------------------ #
    #  Convenience helpers for future modules                              #
    # ------------------------------------------------------------------ #

    def log_action(self, action: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.performed_actions.append(f"[{timestamp}] {action}")

    def log_finding(self, category: str, description: str, severity: str = "INFO") -> None:
        self.findings_log.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "category": category,
                "severity": severity,
                "description": description,
            }
        )


# ------------------------------------------------------------------ #
#  Session persistence                                                #
# ------------------------------------------------------------------ #


def _ensure_reports_dir() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _session_path(assessment_id: str) -> str:
    return os.path.join(REPORTS_DIR, f"{assessment_id}.json")


def save_session(state: AssessmentState) -> str:
    """
    Persist an AssessmentState to disk.
    Returns the full path of the saved file.
    """
    _ensure_reports_dir()
    path = _session_path(state.assessment_id)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state.to_dict(), fh, indent=2)
    return path


def load_session(assessment_id: str) -> AssessmentState:
    """
    Load an AssessmentState from disk by assessment_id.
    Raises FileNotFoundError if the session does not exist.
    """
    path = _session_path(assessment_id)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No session found for ID: {assessment_id}")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return AssessmentState.from_dict(data)


def list_sessions() -> list[dict]:
    """
    Return a list of dicts with basic info for each saved session.
    Each dict contains: assessment_id, target_ip, domain, path.
    """
    _ensure_reports_dir()
    sessions = []
    for filename in sorted(os.listdir(REPORTS_DIR)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(REPORTS_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            sessions.append(
                {
                    "assessment_id": data.get("assessment_id", "unknown"),
                    "target_ip": data.get("target_ip", ""),
                    "domain": data.get("domain", ""),
                    "path": path,
                }
            )
        except (json.JSONDecodeError, KeyError):
            continue
    return sessions


def generate_assessment_id() -> str:
    """Generate a unique timestamp-based assessment ID."""
    return datetime.now().strftime("ADPF-%Y%m%d-%H%M%S")