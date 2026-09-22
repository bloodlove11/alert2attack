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
            return ToolResult.fail(f"no process_create event for pid {args.pid} inside the case window")
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
            return ToolResult.fail(f"no process_create event for pid {args.pid} inside the case window")
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
