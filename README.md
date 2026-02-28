# 🔍 AD-Pathfinder

A modular, extensible Active Directory assessment CLI framework written in Python.

---

## Features

- Clean interactive CLI using `rich`
- Session persistence — save & reload assessments as JSON
- Timestamp-based unique Assessment IDs
- Structured `AssessmentState` dataclass ready for module integration
- Findings log with severity levels
- Works against any AD environment — no hardcoded IPs or domains

---

## Project Structure

```
AD-Pathfinder/
├── main.py           # Entry point, menus, UI
├── session.py        # AssessmentState, session save/load
├── requirements.txt
├── reports/          # Auto-created; stores session JSON files
└── modules/          # (future) Drop-in assessment modules
```

---

## Getting Started

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/AD-Pathfinder.git
cd AD-Pathfinder

# 2. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python main.py
```

---

## Usage

### Main Menu
```
1. Start New Assessment   — collects DC IP, domain, optional creds
2. Load Existing          — browse and reload saved sessions
3. Exit
```

### Assessment Menu
Once inside a session:
- View / extend via future modules (port scan, enum, Kerberoasting, etc.)
- Browse the Findings Log
- Save & return to main menu

Sessions are stored in `/reports/<assessment_id>.json`.

---

## Extending with Modules

Each future module should follow this pattern:

```python
# modules/port_scan.py
from session import AssessmentState

def run(state: AssessmentState) -> None:
    # perform scan, populate state.open_ports / state.services
    # call state.log_action() and state.log_finding()
    pass
```

Wire it into `assessment_menu()` in `main.py` by importing and calling `module.run(state)`.

---

## Session Format

Sessions are plain JSON — easy to inspect, diff, and version:

```json
{
  "assessment_id": "ADPF-20250228-143512",
  "target_ip": "10.10.10.100",
  "domain": "corp.local",
  "dns_server": "",
  "initial_credentials": { "username": "jdoe", "password": "", "ntlm_hash": "" },
  "open_ports": [],
  "users": [],
  ...
}
```

---

## Roadmap

- [ ] Port & Service Scan module
- [ ] LDAP User/Group Enumeration
- [ ] Kerberoasting
- [ ] AS-REP Roasting
- [ ] BloodHound data collection
- [ ] HTML/PDF report export

---

## Disclaimer

This tool is intended for **authorized penetration testing and security assessments only**. Always obtain proper written authorization before testing any environment.
