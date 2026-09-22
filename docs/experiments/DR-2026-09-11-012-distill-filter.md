# DR-2026-09-11-012 — Lock teacher-dev distill filter revision

**Status:** Locked (named filter revision). **Not** a launch approval. **Not** training-ready.  
**Owner:** ML Lead  
**Date:** 2026-09-11  
**Related:** `docs/experiments/DATA_CARD-teacher-dev-v0.md`, `docs/experiments/TRACKER.md` EXP-003, `scripts/filter_teacher_dev_distill.py`, `docs/experiments/DR-2026-09-11-011-lora-discuss-gate.md`

## Decision

Replace the EXP-003 keep line (`passed|repaired`, citation_post ≥ 0.9, **not** budget-exhausted) with **DR-012**:

1. Keep `verification_status in {passed, repaired}` even if tool/budget exhausted, when citation ≥ 0.9.
2. Also keep `verification_status == degraded` **only if** citation ≥ 0.9 **and** verdict_match (`case_file.verdict` equals `gold_verdict`).
3. `--prefer-correct-verdict` stays **default on** (drop verdict mismatches for all statuses).
4. Split must be `dev` only; never test. citation ≥ 0.9 from the row field or recompute from `case_file` + ledger evidence (existing script path).
5. Smoke first-draft kill line: filtered **N ≥ 8** clears smoke SFT *discuss*. Full LoRA still needs **N ≥ 12** via a later named re-export (higher repair/tool budget). **Do not claim training-ready for full LoRA at N=9.**

No training code, no GPU, no metric/eval protocol change, no raw scenario edits, no ExpLabs calls. Do not silently loosen beyond this text.

## Evidence (N=20 teacher-dev export after the PLUMB-DISTILL plumbing)

Not a checked-in `reports/` artifact.

- Raw 20/20 nonempty messages; citation_post 1.0.
- Old EXP-003 kept **0** (16 degraded, all repairs=2; 4 passed + tool_exhausted).
- Under DR-012 + prefer-correct: **~N=9** (the 9 degraded with verdict_match). The 4 passed+exhausted are all malicious→NEE, so prefer-correct drops them.

~N=9 would clear smoke SFT discuss (N≥8) and still fail full LoRA (N<12). This card/filter change does **not** produce that filtered file.

## Not in this decision

- No “Approved for launch.”
- No claim that a DR-012 filtered artifact exists in git.
- No EXP-004 / GPU / training job.
- No change to headline eval metrics, scorers, or the runner.
