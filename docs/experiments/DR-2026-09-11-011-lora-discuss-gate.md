# DR-2026-09-11-011 — Lock LoRA/distill discuss gate

**Status:** Locked (Deimos confirmed, ML Lead locked). Discuss cleared on the N=3 slice below. **Not** a launch approval.  
**Owner:** ML Lead  
**Date:** 2026-09-11  
**Related:** `docs/experiments/TRACKER.md`, `README.md` Results, `docs/superpowers/specs/2026-09-10-ml-experiment-strategy-design.md` §3.4, `docs/experiments/DR-2026-09-10-001-reject-lora-until-live-eval.md`

## Decision

Replace the old LoRA *discuss* inequality (“teacher must **beat** B0 on `citation_post` + `key_pid_recall`”) with the gate below. Metric code, scoring, and the eval runner are **unchanged**.

LoRA/distill discuss is cleared when **teacher vs B0** on the official held-out eval:

1. Teacher **≥** B0 on `citation_post` (`mean_citation_validity_post`) **AND** `key_pid_recall` (`mean_key_pid_recall`)
2. Teacher **strictly beats** B0 on **at least one** of:
   - `action_safety` (`action_safety_rate`) higher
   - `mean_cost` (`mean_verdict_cost`) lower
   - `verdict_acc` (`verdict_accuracy`) higher

Ties on citation+key_pid alone are **not** enough. Larger N hoping B0 dips is **not** the plan.

Discuss ≠ launch. **LoRA still not launched** until ML Lead “Approved for launch” + Deimos cost OK. Distill/QLoRA **drafting** is allowed; GPU is not.

## Evidence (N=3 slice — not a full-test result)

Official N=3 test ids at the DR-010 promotion (DR-010 PASS; reports conceptually `2026-09-11` post-pr22). Full held-out test (N=13) was **not** run. `agent-local-7b` was not in this slice.

Alphabetical `--limit 3` on test:

- `otrf_auditpol_system_user_auditpolicy_modification`
- `otrf_cmd_dumping_ntds_dit_file_volume_shadow_copy_benign_lsass`
- `otrf_cmd_mshta_vbscript_execute_psh`

| Arm | N | `verdict_accuracy` | `mean_verdict_cost` | `mean_citation_validity_post` | `mean_key_pid_recall` | `action_safety_rate` |
|---|---:|---:|---:|---:|---:|---:|
| teacher | 3 | 0.67 | 1.67 | 1.0 | 1.0 | 1.0 |
| B0 | 3 | 0.67 | 1.67 | 1.0 | 1.0 | 0.67 |

Per-case teacher: auditpol malicious→likely_benign (safe); benign_lsass likely_benign (safe, 1244); mshta malicious (safe).  
B0: auditpol malicious→likely_benign (**unsafe**); lsass+mshta hits.

Under DR-011 this slice **already clears** via `action_safety` 1.0 > 0.67 (citation+key_pid ≥).

## Not in this decision

- No eval metric change.
- No scoring or runner change.
- No GPU / training job.
- No claim that EXP-001 (full N=13) is done.
