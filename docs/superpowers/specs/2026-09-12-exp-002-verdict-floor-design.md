# EXP-002 verdict floor — design

**Status:** Locked with DR-013. Graph lever only. Not a headline re-measure.  
**Date:** 2026-09-12  
**Decision:** `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`

## Problem

Live `agent-local-7b` (Lightning T4, N=13) never emits `malicious`. Tools run and citation post is 1.0. The write rubric already forbids defaulting to NEE when attack-chain techniques are cited; the 7B ignores it.

## Approaches

**A. Prompt rewrite (rejected as first lever).** Contracts in `tests/agent/test_prompts.py` already lock the rubric. Another paragraph will not bind a 7B that already skipped it.

**B. Deterministic post-verify floor on cited high-sev tactics (chosen).** Same idea as “do not invent ids”: only use techniques and `scope.persistence` that survived the verifier. Knowledge-base tactics decide severity. No gold.

**C. Hydrate techniques from the alert Sigma rule, then floor (rejected).** `get_alert` does not stamp `rule-*` into the ledger. Using the alert rule as a technique would mark every `win_susp_lsass_access` window malicious, including the three gold `likely_benign` LSASS FPs and both NEE twins (same rule as the malicious twin).

**D. LoRA (rejected).** DR-001 / EXP-004 stand. This is a write-policy miss, not a missing weight.

## Unit

`alert2attack.agent.verdict_floor.apply_verdict_floor(case_file, knowledge) -> CaseFile`

- High-sev tactics (hyphen form, as in `attack_techniques.json`): persistence, privilege-escalation, credential-access, defense-evasion, command-and-control, lateral-movement.
- `scope.persistence` nonempty counts as persistence.
- Lift `{not_enough_evidence, suspicious, likely_benign}` → `malicious` when any high-sev tactic is present.
- Leave `malicious` unchanged. Leave NEE/suspicious/likely_benign unchanged when only execution/discovery/initial-access (or unknown ids) are cited.
- Append one open-question note when the verdict changes. Do not rewrite `next_actions`.
- Call site: `InvestigationGraph.verify_node`, only on `verify_done` exits (passed and degraded), after pid hydrate. `pre_repair_case_file` stays the model write.

## Test / protocol

- Unit tests on the pure function; one scripted graph test that the wire exists.
- Dev / scripted only. Do not run official `--split test` after this lands.
- Do not edit `src/alert2attack/eval/metrics.py`.

## Follow-up (not this change)

Technique omission (tech P/R = 0 on 7/8 gold-malicious) needs a later **dev** lever so the writer actually emits techniques from the ledger. That is not this floor, and not LoRA.
