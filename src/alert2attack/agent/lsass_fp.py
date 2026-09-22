"""LSASS-access false-positive ceiling (EXP-002 lever 6).

``win_susp_lsass_access`` fires on VBoxService/svchost opening LSASS with
limited rights. Cap those windows to likely_benign and drop containment.
Dump corroboration (dump-tool name or PROCESS_VM_READ to lsass) is left
alone. DR-017 Option A: skip the ceiling when boxed events show encoded
PowerShell **and** a whoami or C2 child. Never reads gold.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from alert2attack.domain.alert import Alert
from alert2attack.domain.casefile import ActionRecommendation, CaseFile, Claim, NextAction, Verdict
from alert2attack.domain.events import Event, EventKind
from alert2attack.knowledge.powershell import decode_powershell

LSASS_ALERT_RULE = "win_susp_lsass_access"
PROCESS_VM_READ = 0x0010

_DUMP_MARKERS = re.compile(
    r"dumpert|mimikatz|sekurlsa|procdump|nanodump|comsvcs|ntdsutil|"
    r"lsassy|pypykatz|hashdump|lsadump|minidump|outflank",
    re.IGNORECASE,
)
_HEX_ACCESS = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
_CONTAINMENT = frozenset({NextAction.ISOLATE_HOST, NextAction.KILL_PROCESS})

CEILING_NOTE = (
    "LSASS-access alert lacks dump-tool or PROCESS_VM_READ corroboration; "
    "treat as a limited-rights false positive (likely_benign)."
)
_MONITOR_RATIONALE = "Continue monitoring; boxed LSASS access has no dump corroboration."


def _blob(event: Event) -> str:
    parts = (
        event.image,
        event.target_image,
        event.target_path,
        event.command_line,
        event.details,
        event.parent_image,
        event.parent_command_line,
    )
    return " ".join(p for p in parts if p)


def _access_mask(details: str | None) -> int | None:
    if not details:
        return None
    text = details.strip()
    if not _HEX_ACCESS.fullmatch(text):
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def has_lsass_dump_corroboration(events: Sequence[Event]) -> bool:
    for event in events:
        if _DUMP_MARKERS.search(_blob(event)):
            return True
        if event.kind is not EventKind.PROCESS_ACCESS:
            continue
        target = (event.target_image or "").lower()
        if not target.endswith("\\lsass.exe") and not target.endswith("/lsass.exe"):
            continue
        mask = _access_mask(event.details)
        if mask is not None and mask & PROCESS_VM_READ:
            return True
    return False


def _powershellish(text: str | None) -> bool:
    if not text:
        return False
    return "powershell" in text.lower()


def _basename_is(path: str | None, name: str) -> bool:
    if not path:
        return False
    lower = path.lower().replace("/", "\\")
    return lower.endswith("\\" + name) or lower == name


def _encoded_powershell(command_line: str | None, image: str | None) -> bool:
    """True when ``command_line`` is ``-enc`` PowerShell (via ``decode_powershell``)."""
    if not command_line:
        return False
    if not (_powershellish(command_line) or _powershellish(image)):
        return False
    return decode_powershell(command_line).encoded


def has_lsass_soft_dump_adjacent_corroboration(events: Sequence[Event]) -> bool:
    """Skip-ceiling gate: encoded PowerShell **and** a whoami or C2 child.

    Uses ``decode_powershell`` to detect ``-enc`` / ``-EncodedCommand``. Decoded
    Empire stager fingerprints (DownloadData / IEX / ``/admin/get.php``) are
    not a sole skip signal — encoded PowerShell alone still caps. Does not
    read gold. ``lsass.exe`` is not a marker.
    """
    encoded_pids: set[int] = set()
    has_encoded = False

    for event in events:
        if _encoded_powershell(event.command_line, event.image):
            has_encoded = True
            if event.pid is not None:
                encoded_pids.add(event.pid)
        if _encoded_powershell(event.parent_command_line, event.parent_image):
            has_encoded = True
            if event.ppid is not None:
                encoded_pids.add(event.ppid)

    if not has_encoded:
        return False

    has_whoami_child = False
    has_c2_child = False
    for event in events:
        if event.kind is EventKind.PROCESS_CREATE and _basename_is(event.image, "whoami.exe"):
            parent_encoded = _encoded_powershell(event.parent_command_line, event.parent_image)
            ppid_encoded = event.ppid is not None and event.ppid in encoded_pids
            if parent_encoded or ppid_encoded:
                has_whoami_child = True
        if (
            event.kind is EventKind.NETWORK_CONNECT
            and event.pid is not None
            and event.pid in encoded_pids
        ):
            has_c2_child = True

    return has_whoami_child or has_c2_child


def is_lsass_fp_window(alert: Alert, events: Sequence[Event]) -> bool:
    if alert.rule_id != LSASS_ALERT_RULE:
        return False
    return not (
        has_lsass_dump_corroboration(events) or has_lsass_soft_dump_adjacent_corroboration(events)
    )


def apply_lsass_fp_ceiling(
    case_file: CaseFile,
    events: Sequence[Event],
    alert: Alert,
) -> CaseFile:
    if not is_lsass_fp_window(alert, events):
        return case_file
    questions = list(case_file.open_questions)
    if CEILING_NOTE not in questions:
        questions.append(CEILING_NOTE)
    actions = [item for item in case_file.next_actions if item.action not in _CONTAINMENT]
    if not actions:
        actions = [
            ActionRecommendation(
                action=NextAction.MONITOR,
                rationale=Claim(text=_MONITOR_RATIONALE, evidence=[alert.trigger_event_id]),
            )
        ]
    return case_file.model_copy(
        update={
            "verdict": Verdict.LIKELY_BENIGN,
            "open_questions": questions,
            "next_actions": actions,
        }
    )
