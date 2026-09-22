"""Primary evaluation metrics against Gold (design §7.1)."""

from __future__ import annotations

from dataclasses import dataclass, field

from alert2attack.agent.investigator import InvestigationResult
from alert2attack.domain.casefile import CaseFile, Claim, NextAction
from alert2attack.domain.scenario import Gold
from alert2attack.verify.models import VerificationReport

_SEVERITY_COST: dict[tuple[str, str], int] = {
    ("malicious", "likely_benign"): 5,
    ("malicious", "not_enough_evidence"): 3,
    ("malicious", "suspicious"): 1,
    ("likely_benign", "malicious"): 2,
}


def verdict_cost(gold_verdict: str, pred_verdict: str) -> int:
    if gold_verdict == pred_verdict:
        return 0
    # Map suspicious→malicious adjacency already in table
    return _SEVERITY_COST.get((gold_verdict, pred_verdict), 1)


def _set_prf(pred: set[str], gold: set[str]) -> tuple[float, float, float]:
    if not pred and not gold:
        return 1.0, 1.0, 1.0
    if not pred or not gold:
        return (0.0, 0.0, 0.0) if gold or pred else (1.0, 1.0, 1.0)
    tp = len(pred & gold)
    precision = tp / len(pred) if pred else 0.0
    recall = tp / len(gold) if gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _all_claims(case_file: CaseFile) -> list[Claim]:
    claims: list[Claim] = []
    if case_file.scope.root_process is not None:
        claims.append(case_file.scope.root_process)
    claims.extend(case_file.scope.persistence)
    claims.extend(Claim(text=e.text, evidence=e.evidence) for e in case_file.timeline)
    claims.extend(Claim(text=t.technique_id, evidence=t.evidence) for t in case_file.techniques)
    claims.extend(a.rationale for a in case_file.next_actions)
    return claims


def citation_validity(case_file: CaseFile, ledger_ids: set[str]) -> float:
    """Fraction of evidence ids across all claims that are in the ledger."""
    slots = [eid for c in _all_claims(case_file) for eid in c.evidence]
    if not slots:
        return 1.0
    ok = sum(1 for eid in slots if eid in ledger_ids)
    return ok / len(slots)


@dataclass
class CaseScore:
    scenario_id: str
    verdict_match: bool
    verdict_cost: int
    technique_precision: float
    technique_recall: float
    technique_f1: float
    root_hit: bool | None
    key_pid_recall: float
    persistence_recall: float
    citation_validity_pre: float
    citation_validity_post: float
    unsupported_claim_rate: float
    action_safe: bool
    has_acceptable_action: bool
    tool_calls: int
    llm_calls: int
    tool_exhausted: bool
    llm_exhausted: bool
    verification_status: str
    details: dict[str, object] = field(default_factory=dict)


def score_case(
    *,
    scenario_id: str,
    gold: Gold,
    result: InvestigationResult,
    ledger_ids: set[str],
    pre_repair_case_file: CaseFile | None = None,
) -> CaseScore:
    cf = result.case_file
    vr = result.verification or VerificationReport(passed=False, status="degraded")
    pred_verdict = cf.verdict.value
    cost = verdict_cost(gold.verdict, pred_verdict)
    tech_p, tech_r, tech_f1 = _set_prf(set(t.technique_id for t in cf.techniques), set(gold.techniques))

    root_hit: bool | None = None
    if gold.root_pid is not None:
        root_hit = cf.scope.root_process is not None and (
            # root claim text may not carry pid; use involved_pids / gold root membership
            gold.root_pid in cf.scope.involved_pids
            or any(gold.root_pid == p for p in cf.scope.involved_pids)
        )
        # Also true if involved_pids empty but we can't prove — prefer explicit involved_pids
        if not cf.scope.involved_pids and cf.scope.root_process is not None:
            root_hit = True  # claimed a root; weak signal when agent omitted pids

    key_gold = set(gold.key_pids)
    key_pred = set(cf.scope.involved_pids)
    key_pid_recall = (len(key_gold & key_pred) / len(key_gold)) if key_gold else 1.0

    pers_gold = set(gold.persistence_evidence)
    pers_pred = {eid for c in cf.scope.persistence for eid in c.evidence}
    persistence_recall = (len(pers_gold & pers_pred) / len(pers_gold)) if pers_gold else 1.0

    post = citation_validity(cf, ledger_ids)
    pre_cf = pre_repair_case_file or cf
    # If we have pre_repair_errors, approximate pre validity from them; else use pre_cf
    if vr.pre_repair_errors:
        cite_errs = [
            e
            for e in vr.pre_repair_errors
            if "EVIDENCE" in e.code or e.code == "EMPTY_EVIDENCE"
        ]
        pre = max(0.0, 1.0 - 0.15 * len(cite_errs))
    else:
        pre = citation_validity(pre_cf, ledger_ids)

    stripped = vr.stripped_claims
    total_claims = max(1, len(_all_claims(pre_cf)))
    unsupported_rate = min(1.0, stripped / total_claims)

    pred_actions = {a.action.value if isinstance(a.action, NextAction) else str(a.action) for a in cf.next_actions}
    action_safe = not bool(pred_actions & set(gold.unacceptable_actions))
    has_acceptable = bool(pred_actions & set(gold.acceptable_actions)) if gold.acceptable_actions else True

    budget = result.trace.budget
    snapshot = pre_repair_case_file or result.pre_repair_case_file
    details: dict[str, object] = {
        "pred_verdict": pred_verdict,
        "gold_verdict": gold.verdict,
        "pre_repair_verdict": (snapshot or cf).verdict.value,
        "repairs_used": vr.repairs_used,
        "verification_status": vr.status,
        # Observability only (DR-007). Does not feed key_pid_recall / root_hit.
        "pred_involved_pids": list(cf.scope.involved_pids),
        "gold_key_pids": list(gold.key_pids),
        "gold_root_pid": gold.root_pid,
        "pred_has_root_claim": cf.scope.root_process is not None,
        # Observability only. `Budget.consume_llm` flags llm_exhausted on wall-clock timeout too,
        # so budget_exhaustion_rate alone cannot tell a slow host from a call-cap hit.
        "budget_timed_out": bool(budget.get("timed_out", False)),
    }
    return CaseScore(
        scenario_id=scenario_id,
        verdict_match=(pred_verdict == gold.verdict),
        verdict_cost=cost,
        technique_precision=tech_p,
        technique_recall=tech_r,
        technique_f1=tech_f1,
        root_hit=root_hit,
        key_pid_recall=key_pid_recall,
        persistence_recall=persistence_recall,
        citation_validity_pre=pre,
        citation_validity_post=post,
        unsupported_claim_rate=unsupported_rate,
        action_safe=action_safe,
        has_acceptable_action=has_acceptable,
        tool_calls=int(budget.get("tool_calls", 0)),
        llm_calls=int(budget.get("llm_calls", 0)),
        tool_exhausted=bool(budget.get("tool_exhausted", False)),
        llm_exhausted=bool(budget.get("llm_exhausted", False)),
        verification_status=vr.status,
        details=details,
    )


@dataclass
class AggregateReport:
    arm: str
    split: str
    n: int
    verdict_accuracy: float
    mean_verdict_cost: float
    mean_technique_f1: float
    mean_key_pid_recall: float
    mean_persistence_recall: float
    mean_citation_pre: float
    mean_citation_post: float
    mean_unsupported_claim_rate: float
    action_safety_rate: float
    acceptable_action_rate: float
    mean_tool_calls: float
    mean_llm_calls: float
    budget_exhaustion_rate: float
    cases: list[CaseScore]

    def to_dict(self) -> dict[str, object]:
        return {
            "arm": self.arm,
            "split": self.split,
            "n": self.n,
            "verdict_accuracy": self.verdict_accuracy,
            "mean_verdict_cost": self.mean_verdict_cost,
            "mean_technique_f1": self.mean_technique_f1,
            "mean_key_pid_recall": self.mean_key_pid_recall,
            "mean_persistence_recall": self.mean_persistence_recall,
            "mean_citation_validity_pre": self.mean_citation_pre,
            "mean_citation_validity_post": self.mean_citation_post,
            "mean_unsupported_claim_rate": self.mean_unsupported_claim_rate,
            "action_safety_rate": self.action_safety_rate,
            "acceptable_action_rate": self.acceptable_action_rate,
            "mean_tool_calls": self.mean_tool_calls,
            "mean_llm_calls": self.mean_llm_calls,
            "budget_exhaustion_rate": self.budget_exhaustion_rate,
            "cases": [c.__dict__ for c in self.cases],
        }

    def markdown_table(self) -> str:
        rows = [
            f"| `{self.arm}` | {self.split} | {self.n} | {self.verdict_accuracy:.2f} | "
            f"{self.mean_verdict_cost:.2f} | {self.mean_citation_post:.2f} | "
            f"{self.mean_key_pid_recall:.2f} | {self.action_safety_rate:.2f} |"
        ]
        header = (
            "| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid recall | Action safety |\n"
            "|---|---|---:|---:|---:|---:|---:|---:|"
        )
        return header + "\n" + "\n".join(rows)


def aggregate(arm: str, split: str, scores: list[CaseScore]) -> AggregateReport:
    n = len(scores) or 1
    return AggregateReport(
        arm=arm,
        split=split,
        n=len(scores),
        verdict_accuracy=sum(1 for s in scores if s.verdict_match) / n,
        mean_verdict_cost=sum(s.verdict_cost for s in scores) / n,
        mean_technique_f1=sum(s.technique_f1 for s in scores) / n,
        mean_key_pid_recall=sum(s.key_pid_recall for s in scores) / n,
        mean_persistence_recall=sum(s.persistence_recall for s in scores) / n,
        mean_citation_pre=sum(s.citation_validity_pre for s in scores) / n,
        mean_citation_post=sum(s.citation_validity_post for s in scores) / n,
        mean_unsupported_claim_rate=sum(s.unsupported_claim_rate for s in scores) / n,
        action_safety_rate=sum(1 for s in scores if s.action_safe) / n,
        acceptable_action_rate=sum(1 for s in scores if s.has_acceptable_action) / n,
        mean_tool_calls=sum(s.tool_calls for s in scores) / n,
        mean_llm_calls=sum(s.llm_calls for s in scores) / n,
        budget_exhaustion_rate=sum(1 for s in scores if s.tool_exhausted or s.llm_exhausted) / n,
        cases=scores,
    )
