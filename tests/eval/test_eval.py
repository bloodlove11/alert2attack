import json
from pathlib import Path

import pytest

from alert2attack.agent.investigator import InvestigationResult
from alert2attack.agent.llm import ChatResponse, ScriptedChat
from alert2attack.agent.trace import Trace
from alert2attack.domain.casefile import CaseFile, Claim, Scope, TimelineEntry, Verdict
from alert2attack.domain.scenario import Gold
from alert2attack.eval.distill import append_distill_jsonl, distill_record
from alert2attack.eval.metrics import aggregate, score_case, verdict_cost
from alert2attack.eval.runner import build_arm_llm, preflight_live_model, run_eval
from alert2attack.verify.models import VerificationReport


def test_verdict_cost_matrix() -> None:
    assert verdict_cost("malicious", "malicious") == 0
    assert verdict_cost("malicious", "likely_benign") == 5
    assert verdict_cost("malicious", "suspicious") == 1


def test_score_case_and_aggregate(downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    gold = Gold(
        verdict="malicious",
        techniques=["T1059.001"],
        root_pid=4120,
        key_pids=[4120, 5288],
        persistence_evidence=[],
        acceptable_actions=["isolate_host"],
        unacceptable_actions=["close_as_benign"],
        narrative="GOLD-MARKER-TEST",
    )
    cf = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Encoded PowerShell downloaded a payload.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps", evidence=["ev-0004"])],
        techniques=[],
        scope=Scope(root_process=Claim(text="cmd", evidence=["ev-0004"]), involved_pids=[4120, 5288]),
        next_actions=[],
        open_questions=[],
    )
    result = InvestigationResult(
        case_file=cf,
        trace=Trace(case_id="x", model="scripted", budget={"tool_calls": 2, "llm_calls": 3}),
        verification=VerificationReport(passed=True, status="passed"),
    )
    score = score_case(scenario_id="x", gold=gold, result=result, ledger_ids={"ev-0004"})
    assert score.verdict_match
    assert score.citation_validity_post == 1.0
    assert score.key_pid_recall == 1.0
    report = aggregate("agent-scripted", "dev", [score])
    assert report.n == 1
    assert "agent-scripted" in report.markdown_table()


def test_score_case_details_include_pre_repair_verdict_when_provided() -> None:
    gold = Gold(
        verdict="malicious",
        techniques=["T1059.001"],
        root_pid=4120,
        key_pids=[4120, 5288],
        persistence_evidence=[],
        acceptable_actions=["isolate_host"],
        unacceptable_actions=["close_as_benign"],
        narrative="GOLD-MARKER-TEST",
    )
    post = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Repaired write: encoded PowerShell downloaded a payload.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps", evidence=["ev-0004"])],
        techniques=[],
        scope=Scope(root_process=Claim(text="cmd", evidence=["ev-0004"]), involved_pids=[4120, 5288]),
        next_actions=[],
        open_questions=[],
    )
    pre = CaseFile(
        verdict=Verdict.SUSPICIOUS,
        confidence="medium",
        summary="Write-step verdict before repair.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps", evidence=["ev-0004"])],
        techniques=[],
        scope=Scope(root_process=Claim(text="cmd", evidence=["ev-0004"]), involved_pids=[4120, 5288]),
        next_actions=[],
        open_questions=[],
    )
    result = InvestigationResult(
        case_file=post,
        trace=Trace(case_id="x", model="scripted", budget={"tool_calls": 2, "llm_calls": 4}),
        verification=VerificationReport(passed=True, status="repaired", repairs_used=1),
    )
    without = score_case(scenario_id="x", gold=gold, result=result, ledger_ids={"ev-0004"})
    score = score_case(
        scenario_id="x",
        gold=gold,
        result=result,
        ledger_ids={"ev-0004"},
        pre_repair_case_file=pre,
    )
    assert score.details["pre_repair_verdict"] == "suspicious"
    assert score.details["pred_verdict"] == "malicious"
    assert score.details["repairs_used"] == 1
    assert score.details["verification_status"] == "repaired"
    # Scoring stays on the post-repair case file; the hook is observability only.
    assert score.verdict_match is without.verdict_match
    assert score.verdict_cost == without.verdict_cost
    assert score.citation_validity_pre == without.citation_validity_pre
    assert score.citation_validity_post == without.citation_validity_post
    assert score.unsupported_claim_rate == without.unsupported_claim_rate
    payload = aggregate("agent-scripted", "dev", [score]).to_dict()
    assert payload["cases"][0]["details"]["pre_repair_verdict"] == "suspicious"
    assert "verdict_accuracy" in payload
    assert "pre_repair_verdict" not in payload


def test_score_case_details_include_scope_pids() -> None:
    """Additive observability: persist pred/gold pids in details; scoring formulas unchanged."""
    gold = Gold(
        verdict="malicious",
        techniques=["T1059.001"],
        root_pid=4120,
        key_pids=[4120, 5288],
        persistence_evidence=[],
        acceptable_actions=["isolate_host"],
        unacceptable_actions=["close_as_benign"],
        narrative="GOLD-MARKER-TEST",
    )
    cf = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Encoded PowerShell downloaded a payload.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps", evidence=["ev-0004"])],
        techniques=[],
        scope=Scope(root_process=Claim(text="cmd", evidence=["ev-0004"]), involved_pids=[5288, 9999]),
        next_actions=[],
        open_questions=[],
    )
    result = InvestigationResult(
        case_file=cf,
        trace=Trace(case_id="x", model="scripted", budget={"tool_calls": 2, "llm_calls": 3}),
        verification=VerificationReport(passed=True, status="passed"),
    )
    score = score_case(scenario_id="x", gold=gold, result=result, ledger_ids={"ev-0004"})
    assert score.details["pred_involved_pids"] == [5288, 9999]
    assert score.details["gold_key_pids"] == [4120, 5288]
    assert score.details["gold_root_pid"] == 4120
    assert score.details["pred_has_root_claim"] is True
    # Frozen formulas: recall is set-intersection / |gold|; root_hit is involved_pids membership.
    assert score.key_pid_recall == 0.5  # 5288 hit, 4120 miss
    assert score.root_hit is False  # gold.root_pid 4120 not in involved_pids
    payload = aggregate("agent-scripted", "dev", [score]).to_dict()
    case_details = payload["cases"][0]["details"]
    assert case_details["pred_involved_pids"] == [5288, 9999]
    assert case_details["gold_key_pids"] == [4120, 5288]
    assert case_details["gold_root_pid"] == 4120
    assert case_details["pred_has_root_claim"] is True
    assert "pred_involved_pids" not in payload
    assert "gold_key_pids" not in payload
    assert payload["mean_key_pid_recall"] == 0.5

    # root_hit quirk (unchanged): empty involved_pids + a root claim still scores True.
    empty_scope = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Claimed a root but omitted pids.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps", evidence=["ev-0004"])],
        techniques=[],
        scope=Scope(root_process=Claim(text="cmd", evidence=["ev-0004"]), involved_pids=[]),
        next_actions=[],
        open_questions=[],
    )
    quirk = score_case(
        scenario_id="x",
        gold=gold,
        result=InvestigationResult(
            case_file=empty_scope,
            trace=Trace(case_id="x", model="scripted"),
            verification=VerificationReport(passed=True, status="passed"),
        ),
        ledger_ids={"ev-0004"},
    )
    assert quirk.root_hit is True
    assert quirk.key_pid_recall == 0.0
    assert quirk.details["pred_involved_pids"] == []
    assert quirk.details["gold_key_pids"] == [4120, 5288]
    assert quirk.details["gold_root_pid"] == 4120
    assert quirk.details["pred_has_root_claim"] is True


def test_score_case_result_snapshot_is_details_only() -> None:
    """Investigator snapshot must not change numeric scores (aggregates stay frozen)."""
    gold = Gold(
        verdict="malicious",
        techniques=[],
        root_pid=None,
        key_pids=[],
        persistence_evidence=[],
        acceptable_actions=[],
        unacceptable_actions=["close_as_benign"],
        narrative="GOLD-MARKER-TEST",
    )
    post = CaseFile(
        verdict=Verdict.NOT_ENOUGH_EVIDENCE,
        confidence="low",
        summary="Degraded after repairs.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="kept", evidence=["ev-0004"])],
        techniques=[],
        scope=Scope(),
        next_actions=[],
        open_questions=[],
    )
    pre = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Write-step before degrade.",
        timeline=[
            TimelineEntry(ts="2024-03-12T10:00:00Z", text="a", evidence=["ev-0004"]),
            TimelineEntry(ts="2024-03-12T10:00:01Z", text="b", evidence=["ev-0004"]),
            TimelineEntry(ts="2024-03-12T10:00:02Z", text="c", evidence=["ev-0004"]),
        ],
        techniques=[],
        scope=Scope(root_process=Claim(text="cmd", evidence=["ev-0004"])),
        next_actions=[],
        open_questions=[],
    )
    vr = VerificationReport(passed=False, status="degraded", repairs_used=2, stripped_claims=3)
    without = score_case(
        scenario_id="x",
        gold=gold,
        result=InvestigationResult(
            case_file=post,
            trace=Trace(case_id="x", model="scripted"),
            verification=vr,
        ),
        ledger_ids={"ev-0004"},
    )
    score = score_case(
        scenario_id="x",
        gold=gold,
        result=InvestigationResult(
            case_file=post,
            trace=Trace(case_id="x", model="scripted"),
            verification=vr,
            pre_repair_case_file=pre,
        ),
        ledger_ids={"ev-0004"},
    )
    assert score.details["pre_repair_verdict"] == "malicious"
    assert score.details["pred_verdict"] == "not_enough_evidence"
    assert score.details["repairs_used"] == 2
    assert score.unsupported_claim_rate == without.unsupported_claim_rate
    assert score.citation_validity_pre == without.citation_validity_pre
    assert score.verdict_match is without.verdict_match
    assert score.verdict_cost == without.verdict_cost


def test_run_eval_scripted_on_fixture(tmp_path: Path, downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    # Point a tiny scenarios root at the fixture by copying
    root = tmp_path / "scenarios"
    src = Path(__file__).resolve().parents[1] / "fixtures" / "scenarios" / "enc_ps_downloader_001"
    dest = root / "enc_ps_downloader_001"
    dest.mkdir(parents=True)
    for name in ("manifest.yaml", "events.jsonl"):
        (dest / name).write_text((src / name).read_text(encoding="utf-8"), encoding="utf-8")

    eid = "ev-0004"
    casefile = {
        "verdict": "malicious",
        "confidence": "high",
        "summary": "Encoded PowerShell downloaded a remote script.",
        "timeline": [{"ts": "2024-03-12T10:00:00Z", "text": "ps", "evidence": [eid]}],
        "techniques": [{"technique_id": "T1059.001", "evidence": [eid], "note": ""}],
        "scope": {
            "root_process": {"text": "cmd", "evidence": [eid]},
            "involved_pids": [5288],
            "persistence": [],
            "beyond_process": False,
        },
        "next_actions": [
            {"action": "isolate_host", "rationale": {"text": "c2", "evidence": [eid]}},
        ],
        "open_questions": [],
    }

    def factory(_s: object) -> ScriptedChat:
        payload = json.dumps(casefile)
        return ScriptedChat(
            [
                ChatResponse(content="plan"),
                ChatResponse(content="ready"),
                ChatResponse(content=payload),
                ChatResponse(content=payload),
                ChatResponse(content=payload),
            ]
        )

    distill = tmp_path / "distill.jsonl"
    out = tmp_path / "reports"
    report = run_eval(
        arm="agent-scripted",
        split="test",
        root=root,
        out_dir=out,
        scripted_factory=factory,
        export_distill=distill,
    )
    assert report.n == 1
    assert report.verdict_accuracy == 1.0
    assert report.mean_citation_post == 1.0
    assert distill.exists() and distill.read_text(encoding="utf-8").strip()
    report_json = next(out.glob("*-agent-scripted-test.json"))
    payload = json.loads(report_json.read_text(encoding="utf-8"))
    details = payload["report"]["cases"][0]["details"]
    assert details["pre_repair_verdict"] == "malicious"
    assert details["pred_verdict"] == "malicious"
    assert details["repairs_used"] >= 0
    assert details["verification_status"] == report.cases[0].verification_status
    assert 5288 in details["pred_involved_pids"]
    assert details["gold_key_pids"] == [4120, 5288, 5304]
    assert details["gold_root_pid"] == 4120
    assert details["pred_has_root_claim"] is True


def test_distill_record_shape(downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    cf = CaseFile(
        verdict=Verdict.NOT_ENOUGH_EVIDENCE,
        confidence="low",
        summary="Need more data.",
    )
    result = InvestigationResult(
        case_file=cf,
        trace=Trace(case_id=downloader_scenario.scenario_id, model="scripted"),
        verification=VerificationReport(passed=True, status="passed"),
    )
    rec = distill_record(downloader_scenario, result)
    assert rec["scenario_id"] == downloader_scenario.scenario_id
    path = Path("/tmp/alert2attack-distill-test.jsonl")
    if path.exists():
        path.unlink()
    append_distill_jsonl(path, rec)
    assert path.read_text(encoding="utf-8").startswith("{")


def test_build_arm_llm_b0_uses_explabs_when_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXPLABS_API_KEY", "explabs-test-key")
    monkeypatch.setenv("ALERT2ATTACK_TEACHER_MODEL", "deepseek-v4-flash")
    monkeypatch.delenv("ALERT2ATTACK_TEACHER_BASE_URL", raising=False)
    llm = build_arm_llm("b0")
    assert llm.model_name == "deepseek-v4-flash"
    assert "experientiallabs.ai" in str(llm._client.base_url)


def test_build_arm_llm_local_7b_honors_remote_ollama_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lightning / any remote Ollama is still the product 7B arm — only the host changes."""
    monkeypatch.delenv("ALERT2ATTACK_OLLAMA_MODEL", raising=False)
    monkeypatch.setenv("ALERT2ATTACK_OLLAMA_BASE_URL", "https://studio.example/v1")
    llm = build_arm_llm("agent-local-7b")
    assert llm.model_name == "qwen2.5:7b-instruct"
    assert "studio.example" in str(llm._client.base_url)


def test_build_arm_llm_b0_uses_ollama_without_explabs_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EXPLABS_API_KEY", raising=False)
    monkeypatch.delenv("ALERT2ATTACK_OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("ALERT2ATTACK_B0_MODEL", raising=False)
    llm = build_arm_llm("b0")
    assert llm.model_name == "qwen2.5:7b-instruct"
    assert "11434" in str(llm._client.base_url)


def test_build_arm_llm_b0_model_override_beats_key_presence(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present-but-unusable teacher key must not strand the $0 Ollama baseline."""
    monkeypatch.setenv("EXPLABS_API_KEY", "explabs-test-key")
    monkeypatch.delenv("ALERT2ATTACK_OLLAMA_MODEL", raising=False)
    monkeypatch.setenv("ALERT2ATTACK_B0_MODEL", "ollama")
    llm = build_arm_llm("b0")
    assert llm.model_name == "qwen2.5:7b-instruct"
    assert "11434" in str(llm._client.base_url)

    monkeypatch.setenv("ALERT2ATTACK_TEACHER_MODEL", "deepseek-v4-flash")
    monkeypatch.delenv("ALERT2ATTACK_TEACHER_BASE_URL", raising=False)
    monkeypatch.setenv("ALERT2ATTACK_B0_MODEL", "teacher")
    assert build_arm_llm("b0").model_name == "deepseek-v4-flash"

    monkeypatch.setenv("ALERT2ATTACK_B0_MODEL", "nonsense")
    with pytest.raises(RuntimeError, match="ALERT2ATTACK_B0_MODEL"):
        build_arm_llm("b0")


def test_preflight_live_model_names_model_and_endpoint() -> None:
    """A dead route must fail with an actionable message, not an SDK traceback mid-split."""

    class DeadRoute:
        model_name = "gpt-5.6-luna"
        base_url = "https://gateway.example/v1/"

        def complete(self, messages, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("503 unavailable_route")

    with pytest.raises(RuntimeError) as excinfo:
        preflight_live_model(DeadRoute(), arm="agent-teacher")  # type: ignore[arg-type]
    message = str(excinfo.value)
    assert "gpt-5.6-luna" in message
    assert "gateway.example" in message
    assert "No scenarios were run" in message
    assert "ALERT2ATTACK_B0_MODEL=ollama" in message

    ok = ScriptedChat([ChatResponse(content="ok")])
    preflight_live_model(ok, arm="b0")


def test_run_eval_preflights_live_arm_before_touching_scenarios(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "scenarios"
    src = Path(__file__).resolve().parents[1] / "fixtures" / "scenarios" / "enc_ps_downloader_001"
    dest = root / "enc_ps_downloader_001"
    dest.mkdir(parents=True)
    for name in ("manifest.yaml", "events.jsonl"):
        (dest / name).write_text((src / name).read_text(encoding="utf-8"), encoding="utf-8")

    calls: list[str] = []

    class DeadRoute:
        model_name = "qwen2.5:7b-instruct"
        base_url = "http://127.0.0.1:11434/v1/"

        def complete(self, messages, **kwargs):  # type: ignore[no-untyped-def]
            calls.append("complete")
            raise RuntimeError("connection refused")

    monkeypatch.setattr("alert2attack.eval.runner.build_arm_llm", lambda arm, **kw: DeadRoute())
    out = tmp_path / "reports"
    with pytest.raises(RuntimeError, match="preflight failed"):
        run_eval(arm="agent-local-7b", split="test", root=root, out_dir=out)
    assert calls == ["complete"]
    assert not out.exists()


def test_eval_cli_reports_unusable_route_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from alert2attack.cli import app

    def _dead(arm: str, **kwargs: object) -> object:
        class DeadRoute:
            model_name = "gpt-5.6-luna"
            base_url = "https://gateway.example/v1/"

            def complete(self, messages, **kw):  # type: ignore[no-untyped-def]
                raise RuntimeError("503 unavailable_route")

        return DeadRoute()

    monkeypatch.setattr("alert2attack.eval.runner.build_arm_llm", _dead)
    out = tmp_path / "reports"
    result = CliRunner().invoke(
        app, ["eval", "run", "--arm", "agent-teacher", "--split", "dev", "--out", str(out)]
    )
    assert result.exit_code == 2
    assert "preflight failed" in result.output
    assert "gpt-5.6-luna" in result.output
    assert "Traceback" not in result.output
    assert not out.exists()


def test_score_case_details_flag_wall_clock_timeout() -> None:
    """budget_exhaustion_rate cannot separate a slow host from a call-cap hit; details can."""
    gold = Gold(
        verdict="malicious",
        techniques=[],
        root_pid=None,
        key_pids=[],
        persistence_evidence=[],
        acceptable_actions=[],
        unacceptable_actions=["close_as_benign"],
        narrative="GOLD-MARKER-TEST",
    )
    cf = CaseFile(verdict=Verdict.MALICIOUS, confidence="low", summary="Ran out of wall clock.")
    timed_out = score_case(
        scenario_id="x",
        gold=gold,
        result=InvestigationResult(
            case_file=cf,
            trace=Trace(
                case_id="x",
                model="qwen2.5:7b-instruct",
                budget={"llm_calls": 6, "max_llm_calls": 20, "llm_exhausted": True, "timed_out": True},
            ),
            verification=VerificationReport(passed=True, status="passed"),
        ),
        ledger_ids=set(),
    )
    capped = score_case(
        scenario_id="y",
        gold=gold,
        result=InvestigationResult(
            case_file=cf,
            trace=Trace(
                case_id="y",
                model="qwen2.5:7b-instruct",
                budget={"llm_calls": 20, "max_llm_calls": 20, "llm_exhausted": True, "timed_out": False},
            ),
            verification=VerificationReport(passed=True, status="passed"),
        ),
        ledger_ids=set(),
    )
    assert timed_out.details["budget_timed_out"] is True
    assert capped.details["budget_timed_out"] is False
    # Both count as budget exhaustion: the headline aggregate is unchanged, details disambiguate.
    assert timed_out.llm_exhausted and capped.llm_exhausted
    assert aggregate("agent-local-7b", "dev", [timed_out, capped]).budget_exhaustion_rate == 1.0
