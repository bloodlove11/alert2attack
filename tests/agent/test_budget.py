from pytest import MonkeyPatch

from alert2attack.agent.budget import Budget, budget_from_env


def test_budget_counts_and_exhausts_tools() -> None:
    b = Budget(max_tool_calls=2, max_llm_calls=5, timeout_s=60)
    assert b.consume_tool() and b.consume_tool()
    assert not b.consume_tool()
    assert b.tool_exhausted
    assert b.tool_calls == 2


def test_budget_snapshot() -> None:
    b = Budget(max_tool_calls=3)
    b.consume_llm()
    snap = b.snapshot()
    assert snap["llm_calls"] == 1
    assert snap["max_tool_calls"] == 3


def test_remaining_time_s_decreases_from_timeout() -> None:
    b = Budget(timeout_s=100.0)
    remaining = b.remaining_time_s()
    assert 0.0 < remaining <= 100.0


def test_write_reserve_blocks_investigate_when_llm_nearly_spent() -> None:
    from alert2attack.agent.budget import WRITE_LLM_RESERVE

    b = Budget(max_llm_calls=5, timeout_s=120.0)
    for _ in range(5 - WRITE_LLM_RESERVE):
        assert b.consume_llm()
    assert b.remaining_llm() == WRITE_LLM_RESERVE
    assert b.should_reserve_for_write()


def test_write_reserve_blocks_investigate_when_time_nearly_spent() -> None:
    from alert2attack.agent.budget import WRITE_TIME_RESERVE_S

    b = Budget(max_llm_calls=20, timeout_s=WRITE_TIME_RESERVE_S + 1.0)
    b._started = b._started - (WRITE_TIME_RESERVE_S + 0.5)  # noqa: SLF001
    assert b.should_reserve_for_write()


def test_default_budget_is_unbounded() -> None:
    """Eval/API default: no tool, LLM, or wall-clock cap (EXP-003 hit 12-tool cap on 17/20)."""
    b = Budget()
    assert b.max_tool_calls is None
    assert b.max_llm_calls is None
    assert b.timeout_s is None
    for _ in range(40):
        assert b.consume_tool()
        assert b.consume_llm()
    assert b.tool_calls == 40
    assert b.llm_calls == 40
    assert not b.tool_exhausted
    assert not b.llm_exhausted
    assert not b.timed_out
    assert b.remaining_tools() is None
    assert b.remaining_llm() is None
    assert not b.should_reserve_for_write()


def test_zero_tool_cap_still_means_no_tools() -> None:
    """B0 uses max_tool_calls=0 as 'no tools', not unlimited."""
    b = Budget(max_tool_calls=0, max_llm_calls=2)
    assert not b.consume_tool()
    assert b.tool_exhausted
    assert b.consume_llm()


def test_unbounded_timeout_never_fires() -> None:
    b = Budget()
    b._started = b._started - 10_000.0  # noqa: SLF001
    assert not b.check_timeout()
    assert b.remaining_time_s() is None


def test_budget_from_env_blank_is_unbounded(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("ALERT2ATTACK_MAX_TOOL_CALLS", raising=False)
    monkeypatch.delenv("ALERT2ATTACK_MAX_LLM_CALLS", raising=False)
    monkeypatch.delenv("ALERT2ATTACK_TIMEOUT_S", raising=False)
    b = budget_from_env()
    assert b.max_tool_calls is None
    assert b.max_llm_calls is None
    assert b.timeout_s is None


def test_budget_from_env_reads_caps(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ALERT2ATTACK_MAX_TOOL_CALLS", "12")
    monkeypatch.setenv("ALERT2ATTACK_MAX_LLM_CALLS", "20")
    monkeypatch.setenv("ALERT2ATTACK_TIMEOUT_S", "180")
    b = budget_from_env()
    assert b.max_tool_calls == 12
    assert b.max_llm_calls == 20
    assert b.timeout_s == 180.0
