"""Build boxed scenarios from OTRF JSON / JSONL (and optional download)."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast
from urllib.request import urlopen

import yaml

from alert2attack.dataset.otrf import iter_normalized
from alert2attack.dataset.window import box_events
from alert2attack.domain.alert import Alert, Severity
from alert2attack.domain.events import Event, EventKind
from alert2attack.domain.scenario import Gold, Provenance, Scenario, Window


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_and_extract(url: str, expected_sha256: str, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    zip_path = dest_dir / "download.zip"
    with urlopen(url, timeout=120) as resp:  # noqa: S310 - curated catalog URLs only
        zip_path.write_bytes(resp.read())
    digest = sha256_file(zip_path)
    if digest != expected_sha256.lower():
        raise ValueError(f"sha256 mismatch: got {digest}, expected {expected_sha256}")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)
    jsons = sorted(dest_dir.rglob("*.json"))
    if not jsons:
        raise FileNotFoundError(f"no .json in extracted archive under {dest_dir}")
    return jsons[0]


def load_otrf_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    # OTRF host exports are almost always one JSON object per line.
    if len(lines) > 1:
        try:
            return [json.loads(line) for line in lines]
        except json.JSONDecodeError:
            pass
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    raise ValueError(f"unsupported OTRF JSON shape in {path}")


def choose_host(events: list[Event], preferred_substring: str | None = None) -> str:
    counts: dict[str, int] = {}
    for e in events:
        counts[e.host] = counts.get(e.host, 0) + 1
    if preferred_substring:
        for host, _ in sorted(counts.items(), key=lambda kv: -kv[1]):
            if preferred_substring.lower() in host.lower():
                return host
    return max(counts, key=counts.get)  # type: ignore[arg-type]


def pick_trigger(events: list[Event]) -> Event:
    return next(
        (
            e
            for e in events
            if e.kind is EventKind.PROCESS_CREATE
            and e.command_line
            and ("-enc" in e.command_line.lower() or "-e " in e.command_line.lower())
        ),
        next(
            (e for e in events if e.kind is EventKind.PROCESS_CREATE),
            events[0],
        ),
    )


def auto_window(
    events: list[Event],
    *,
    host: str,
    pad_before: timedelta = timedelta(seconds=30),
    pad_after: timedelta = timedelta(minutes=2),
    max_events: int = 48,
) -> tuple[datetime, datetime]:
    on_host = [e for e in events if e.host.lower() == host.lower()]
    if not on_host:
        raise ValueError(f"no events for host {host}")
    trigger = pick_trigger(on_host)
    start, end = trigger.ts - pad_before, trigger.ts + pad_after
    boxed = [e for e in on_host if start <= e.ts <= end]
    # Shrink the window until the boxed set is small enough for a committed scenario.
    while len(boxed) > max_events and pad_after > timedelta(seconds=15):
        pad_after = pad_after / 2
        pad_before = min(pad_before, timedelta(seconds=20))
        start, end = trigger.ts - pad_before, trigger.ts + pad_after
        boxed = [e for e in on_host if start <= e.ts <= end]
    if len(boxed) > max_events:
        # Last resort: keep trigger neighborhood by taking closest max_events by time.
        ordered = sorted(on_host, key=lambda e: abs((e.ts - trigger.ts).total_seconds()))[:max_events]
        start = min(e.ts for e in ordered)
        end = max(e.ts for e in ordered)
    return start, end


def write_scenario_dir(scenario: Scenario, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = scenario.model_dump(mode="json", exclude={"events"}, exclude_none=True)
    (out_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    with (out_dir / "events.jsonl").open("w", encoding="utf-8") as f:
        for e in scenario.events:
            f.write(e.model_dump_json(exclude_none=True) + "\n")
    return out_dir


def _alert_id(scenario_id: str) -> str:
    slug = scenario_id[-8:] if len(scenario_id) >= 8 else scenario_id
    return f"alr-{slug}"


def _key_pids_for(boxed: list[Event], trigger: Event) -> tuple[int | None, list[int]]:
    root = next(
        (e for e in boxed if e.kind is EventKind.PROCESS_CREATE and e.pid == trigger.ppid),
        trigger,
    )
    key_pids = [p for p in [root.pid, trigger.pid] if p is not None]
    children = [e for e in boxed if e.kind is EventKind.PROCESS_CREATE and e.ppid == trigger.pid]
    for c in children:
        if c.pid is not None and c.pid not in key_pids:
            key_pids.append(c.pid)
    return root.pid, key_pids


def pick_trigger_preferring(
    events: list[Event],
    *,
    prefer_kind: EventKind | None = None,
    image_substrings: tuple[str, ...] = (),
) -> Event:
    """Pick an alert trigger, optionally preferring kind/image heuristics."""
    ranked = list(events)
    if prefer_kind is not None:
        preferred = [e for e in ranked if e.kind is prefer_kind]
        if preferred:
            ranked = preferred
    if image_substrings:
        matched = [
            e
            for e in ranked
            if any(
                s.lower() in (e.image or "").lower() or s.lower() in (e.target_image or "").lower()
                for s in image_substrings
            )
        ]
        if matched:
            ranked = matched
    return pick_trigger(ranked) if ranked else events[0]


def build_scenario_from_records(
    records: list[dict[str, Any]],
    *,
    scenario_id: str,
    split: str = "dev",
    techniques: list[str] | None = None,
    preferred_host_substring: str | None = None,
    rule_id: str = "win_powershell_encoded_command",
    rule_title: str = "Suspicious Encoded PowerShell Command Line",
    provenance: Provenance | None = None,
    gold_narrative: str | None = None,
    gold_verdict: Literal["malicious", "likely_benign", "not_enough_evidence"] = "malicious",
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    max_events: int = 48,
    trigger: Event | None = None,
    description: str | None = None,
) -> Scenario:
    normalized = iter_normalized(records)
    if not normalized:
        raise ValueError("no supported events after normalization")
    host = choose_host(normalized, preferred_host_substring)
    if window_start is not None and window_end is not None:
        start, end = window_start, window_end
    else:
        start, end = auto_window(normalized, host=host, max_events=max_events)
    boxed = box_events(normalized, host=host, start=start, end=end)
    if not boxed:
        raise ValueError("window boxing dropped all events")
    # Dense Sysmon process_access floods can still exceed max_events after time boxing.
    if len(boxed) > max_events:
        anchor = trigger or pick_trigger(boxed)
        nearest = sorted(boxed, key=lambda e: abs((e.ts - anchor.ts).total_seconds()))[:max_events]
        start = min(e.ts for e in nearest)
        end = max(e.ts for e in nearest)
        boxed = box_events(nearest, host=host, start=start, end=end)

    if trigger is not None:
        # Re-resolve trigger after boxing reassigned evidence ids.
        match = next(
            (
                e
                for e in boxed
                if e.ts == trigger.ts
                and e.kind is trigger.kind
                and e.pid == trigger.pid
                and (e.image or "") == (trigger.image or "")
            ),
            None,
        )
        chosen = match or pick_trigger(boxed)
    else:
        chosen = pick_trigger(boxed)
    # Prefer a process_create trigger when the boxed set has one.
    if chosen.kind is not EventKind.PROCESS_CREATE:
        proc = next((e for e in boxed if e.kind is EventKind.PROCESS_CREATE), None)
        if proc is not None and gold_verdict == "malicious":
            chosen = proc

    root_pid, key_pids = _key_pids_for(boxed, chosen)
    tech = techniques if techniques is not None else (["T1059.001"] if gold_verdict == "malicious" else [])
    narrative = gold_narrative or (
        f"GOLD-MARKER-OTRF. OTRF-derived scenario {scenario_id} on {host}: "
        f"trigger {chosen.event_id} image={chosen.image} pid={chosen.pid}."
    )
    if gold_verdict == "malicious":
        acceptable = ["isolate_host", "kill_process", "collect_script", "escalate"]
        unacceptable = ["close_as_benign"]
    elif gold_verdict == "likely_benign":
        acceptable = ["close_as_benign", "monitor"]
        unacceptable = ["isolate_host", "kill_process"]
    else:
        acceptable = ["collect_script", "collect_memory", "escalate", "monitor"]
        unacceptable = ["close_as_benign"]

    alert = Alert(
        alert_id=_alert_id(scenario_id),
        host=host,
        fired_at=chosen.ts,
        rule_id=rule_id,
        rule_title=rule_title,
        severity=Severity.HIGH,
        trigger_event_id=chosen.event_id,
    )
    gold = Gold(
        verdict=gold_verdict,
        techniques=tech,
        root_pid=root_pid,
        key_pids=key_pids,
        persistence_evidence=[
            e.event_id
            for e in boxed
            if e.kind is EventKind.REGISTRY_SET and e.target_path and "\\Run\\" in e.target_path
        ],
        acceptable_actions=acceptable,
        unacceptable_actions=unacceptable,
        narrative=narrative,
    )
    if split not in ("dev", "test"):
        raise ValueError(f"invalid split {split!r}")
    return Scenario(
        scenario_id=scenario_id,
        split=cast(Literal["dev", "test"], split),
        origin="otrf",
        description=description or f"OTRF-derived boxed case for {scenario_id}",
        window=Window(start=start, end=end),
        alert=alert,
        events=boxed,
        gold=gold,
        provenance=provenance,
    )


def truncate_to_trigger_context(events: list[Event], trigger: Event) -> list[Event]:
    """Keep only the trigger and its parent process_create (real events, thinner window)."""
    keep: list[Event] = [trigger]
    if trigger.ppid is not None:
        parent = next(
            (
                e
                for e in events
                if e.kind is EventKind.PROCESS_CREATE and e.pid == trigger.ppid and e.ts <= trigger.ts
            ),
            None,
        )
        if parent is not None:
            keep.append(parent)
    # If trigger is not process_create, also keep the nearest prior process_create for context.
    if trigger.kind is not EventKind.PROCESS_CREATE:
        prior = [
            e for e in events if e.kind is EventKind.PROCESS_CREATE and e.ts <= trigger.ts and e.pid == trigger.pid
        ]
        if prior:
            keep.append(max(prior, key=lambda e: e.ts))
    # Unique by original identity before re-id.
    uniq: list[Event] = []
    seen: set[tuple[Any, ...]] = set()
    for e in sorted(keep, key=lambda x: x.ts):
        key = (e.ts, e.kind, e.pid, e.image, e.command_line)
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    return uniq


def build_scenario_from_otrf_json(
    path: Path,
    *,
    scenario_id: str,
    out_dir: Path,
    **kwargs: Any,
) -> Path:
    records = load_otrf_records(path)
    scenario = build_scenario_from_records(records, scenario_id=scenario_id, **kwargs)
    return write_scenario_dir(scenario, out_dir)
