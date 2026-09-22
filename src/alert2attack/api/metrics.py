"""Prometheus metrics for investigations."""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest


def RENDER_PROM() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


INVESTIGATIONS_TOTAL = Counter(
    "alert2attack_investigations_total",
    "Investigations finished",
    ["verdict", "status", "model"],
)
VERIFICATION_FAILURES = Counter(
    "alert2attack_verification_failures_total",
    "Verification errors by code",
    ["code"],
)
TOOL_CALLS = Histogram(
    "alert2attack_tool_calls",
    "Tool calls per investigation",
    buckets=(0, 1, 2, 4, 8, 12, 16, 24),
)
LLM_LATENCY_MS = Histogram(
    "alert2attack_llm_latency_ms",
    "Sum of recorded LLM call durations per investigation (ms)",
    buckets=(50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000),
)
BUDGET_EXHAUSTION = Counter(
    "alert2attack_budget_exhaustion_total",
    "Budget exhaustion events",
    ["kind"],
)


def observe_result(
    *,
    verdict: str,
    status: str,
    model: str,
    tool_calls: int,
    llm_ms: float,
    budget: dict[str, object],
) -> None:
    INVESTIGATIONS_TOTAL.labels(verdict=verdict, status=status, model=model).inc()
    TOOL_CALLS.observe(tool_calls)
    LLM_LATENCY_MS.observe(llm_ms)
    if budget.get("tool_exhausted"):
        BUDGET_EXHAUSTION.labels(kind="tool").inc()
    if budget.get("llm_exhausted"):
        BUDGET_EXHAUSTION.labels(kind="llm").inc()
    if budget.get("timed_out"):
        BUDGET_EXHAUSTION.labels(kind="timeout").inc()


def observe_verification_errors(codes: list[str]) -> None:
    for code in codes:
        VERIFICATION_FAILURES.labels(code=code).inc()
