"""SQLite-backed case store.

One case = one alert + the boxed telemetry around it (one host, one window).
Gold labels are rejected at the door: ``load_case`` only accepts ``Scenario.public()``.
"""

import base64
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


def encode_event_cursor(ts: str, event_id: str) -> str:
    """Opaque keyset cursor. Base64 so callers do not parse or construct one by hand."""
    return base64.urlsafe_b64encode(f"{ts}|{event_id}".encode()).decode("ascii")


def decode_event_cursor(cursor: str) -> tuple[str, str] | None:
    """``None`` for anything malformed — a bad cursor is a 400, never a 500."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    ts, sep, event_id = raw.partition("|")
    if not sep or not ts or not event_id:
        return None
    return ts, event_id


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

    def page_events(
        self,
        case_id: str,
        *,
        kinds: Sequence[EventKind] | None = None,
        pid: int | None = None,
        contains: str | None = None,
        after: str | None = None,
        limit: int = 50,
    ) -> tuple[list[Event], str | None]:
        """Keyset page over ``(ts, event_id)``. Returns the page and the next cursor.

        Keyset rather than OFFSET: the console pages through a window while the
        agent may be writing to it, and OFFSET silently skips or repeats rows when
        the underlying set shifts. The cursor is opaque to callers on purpose, so
        the stored timestamp format stays an implementation detail of this module.
        """
        sql = ["SELECT ts, event_id, event_json FROM events WHERE case_id = ?"]
        params: list[object] = [case_id]
        if kinds:
            sql.append(f"AND kind IN ({','.join('?' * len(kinds))})")
            params.extend(k.value for k in kinds)
        if pid is not None:
            sql.append("AND pid = ?")
            params.append(pid)
        if contains:
            sql.append("AND search_text LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(contains.lower())}%")
        if after is not None:
            cursor = decode_event_cursor(after)
            if cursor is None:
                raise ValueError(f"malformed cursor: {after!r}")
            sql.append("AND (ts, event_id) > (?, ?)")
            params.extend(cursor)
        # Fetch one extra row to learn whether another page exists without a COUNT.
        sql.append("ORDER BY ts, event_id LIMIT ?")
        params.append(limit + 1)
        rows = self._conn.execute(" ".join(sql), params).fetchall()

        has_more = len(rows) > limit
        page = rows[:limit]
        events = [Event.model_validate_json(r["event_json"]) for r in page]
        next_cursor = encode_event_cursor(page[-1]["ts"], page[-1]["event_id"]) if has_more else None
        return events, next_cursor

    # -- diagnostics -------------------------------------------------------------

    def dump_text(self) -> str:
        parts = [json.dumps(dict(r)) for r in self._conn.execute("SELECT * FROM cases")]
        parts += [json.dumps(dict(r)) for r in self._conn.execute("SELECT * FROM events")]
        return "\n".join(parts)
