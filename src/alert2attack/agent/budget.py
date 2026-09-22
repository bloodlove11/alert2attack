"""Investigation budgets (tool calls, LLM calls, wall clock).

Default is **unbounded**: ``None`` on a cap means no limit. ``0`` on
``max_tool_calls`` / ``max_llm_calls`` still means “none allowed” (B0 uses
``max_tool_calls=0``). Restore the old 12 / 20 / 180 caps with
``ALERT2ATTACK_MAX_TOOL_CALLS``, ``ALERT2ATTACK_MAX_LLM_CALLS``, ``ALERT2ATTACK_TIMEOUT_S``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from time import monotonic

# Leave headroom so write (+ one validation retry) can still run after investigate.
WRITE_LLM_RESERVE = 2
WRITE_TIME_RESERVE_S = 60.0


def _env_int_cap(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or raw.strip() in {"", "0"}:
        return None
    return int(raw)


def _env_float_cap(name: str) -> float | None:
    raw = os.environ.get(name)
    if raw is None or raw.strip() in {"", "0"}:
        return None
    return float(raw)


def budget_from_env() -> Budget:
    """Eval/API budget. Unset or 0 env caps → unbounded."""
    return Budget(
        max_tool_calls=_env_int_cap("ALERT2ATTACK_MAX_TOOL_CALLS"),
        max_llm_calls=_env_int_cap("ALERT2ATTACK_MAX_LLM_CALLS"),
        timeout_s=_env_float_cap("ALERT2ATTACK_TIMEOUT_S"),
    )


def max_investigate_turns_from_env() -> int:
    """0 (default) means no investigate-turn cap."""
    raw = os.environ.get("ALERT2ATTACK_MAX_INVESTIGATE_TURNS")
    if raw is None or raw.strip() in {"", "0"}:
        return 0
    return int(raw)


@dataclass
class Budget:
    max_tool_calls: int | None = None
    max_llm_calls: int | None = None
    timeout_s: float | None = None
    tool_calls: int = 0
    llm_calls: int = 0
    _started: float = field(default_factory=monotonic)
    tool_exhausted: bool = False
    llm_exhausted: bool = False
    timed_out: bool = False

    def remaining_tools(self) -> int | None:
        if self.max_tool_calls is None:
            return None
        return max(0, self.max_tool_calls - self.tool_calls)

    def remaining_llm(self) -> int | None:
        if self.max_llm_calls is None:
            return None
        return max(0, self.max_llm_calls - self.llm_calls)

    def remaining_time_s(self) -> float | None:
        if self.timeout_s is None:
            return None
        return max(0.0, self.timeout_s - (monotonic() - self._started))

    def should_reserve_for_write(
        self,
        *,
        llm_reserve: int = WRITE_LLM_RESERVE,
        time_reserve_s: float = WRITE_TIME_RESERVE_S,
    ) -> bool:
        """True when investigate should stop to preserve write headroom.

        Unbounded LLM / wall-clock caps never reserve — write is not starved by a cap.
        """
        remaining_llm = self.remaining_llm()
        if remaining_llm is not None and remaining_llm <= llm_reserve:
            return True
        remaining_time = self.remaining_time_s()
        if remaining_time is not None and remaining_time <= time_reserve_s:
            return True
        return False

    def check_timeout(self) -> bool:
        if self.timeout_s is None:
            return False
        if (monotonic() - self._started) >= self.timeout_s:
            self.timed_out = True
            return True
        return False

    def consume_tool(self) -> bool:
        """Return True if the call is allowed and counted."""
        if self.check_timeout():
            self.tool_exhausted = True
            return False
        if self.max_tool_calls is not None and self.tool_calls >= self.max_tool_calls:
            self.tool_exhausted = True
            return False
        self.tool_calls += 1
        return True

    def consume_llm(self) -> bool:
        if self.check_timeout():
            self.llm_exhausted = True
            return False
        if self.max_llm_calls is not None and self.llm_calls >= self.max_llm_calls:
            self.llm_exhausted = True
            return False
        self.llm_calls += 1
        return True

    def snapshot(self) -> dict[str, int | float | bool | None]:
        return {
            "max_tool_calls": self.max_tool_calls,
            "max_llm_calls": self.max_llm_calls,
            "timeout_s": self.timeout_s,
            "tool_calls": self.tool_calls,
            "llm_calls": self.llm_calls,
            "tool_exhausted": self.tool_exhausted,
            "llm_exhausted": self.llm_exhausted,
            "timed_out": self.timed_out,
        }
