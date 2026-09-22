# Experiment tracker

Hypothesis, method, result, decision.  
Strategy: `docs/design/2026-09-10-ml-experiment-strategy-design.md`.  
Protocol freeze: do not change headline metrics without a protocol-change note.

Naming. The project was called `casefile` when the runs below were recorded. Commands and environment variables here use the current names (`alert2attack`, `ALERT2ATTACK_*`). The Ollama tag `casefile-qlora-n14` is the tag those runs actually used and is unchanged. Commit hashes that older records once cited have been removed, and PR numbers in older entries (for example #34) refer to the repository's earlier history.

Headline numbers live in README Results. This file tracks decisions. Do not paste scripted smoke scores here as if they were live.

| ID | Status | Hypothesis | Method | Result | Decision |
|---|---|---|---|---|---|
| EXP-001 | 3 of 3 arms run at full N | The tool-using loop beats single-shot B0 on citation post and key-pid recall; teacher is an upper bound vs local 7B. | Live eval, test, N=13, arms `b0` / `agent-local-7b` / `agent-teacher`. No `--limit`. Commands in `docs/plans/2026-09-10-live-eval-campaign.md`. Human must approve teacher API spend. | Same `dataset_hash 5ffa17a659505a1b`. `b0` (Ollama 7B, cloud CPU VM, `2026-09-11`): 0.231 / 1.846 / 0.985 / 0.423 / 0.846. `agent-local-7b` (same tag, Lightning Studio Tesla T4, `2026-09-12`, digest `845dbda0ea48`, 100% GPU): 0.000 / 1.615 / 1.000 / 0.462 / 0.923, `budget_exhaustion_rate` 0.308 (4/13 llm-exhausted; campaign kill is >0.5). `agent-teacher` (`gpt-5.6-luna`): 0.538 / 0.769 / 1.000 / 0.846 / 1.000. Local 7B never hit a gold verdict (NEE or suspicious on every case). Teacher remains a hard upper bound. | Loop vs Ollama B0: citation and key-pid both ≥, plus better cost and safety: the citation/key-pid half of the hypothesis holds, verdict_acc does not. Teacher ≫ local 7B on every headline except a citation-post tie at 1.0. DR-011 still clears vs Ollama B0, fails vs teacher-backed B0. Does not launch LoRA. EXP-002 is unblocked for both live arms. |
| EXP-001b | still not approved as a row; measured once as a diagnostic on `2026-09-11` | Matched-model B0 (teacher, no tools) isolates loop vs single-shot without a 7B/GPT confound. | Add diagnostic arm `b0-teacher` without replacing headline `b0`. Ran as `ALERT2ATTACK_B0_MODEL=teacher --arm b0` into `reports/diagnostic-b0-teacher/` so it could not overwrite the headline `b0` report. | N=13, same `dataset_hash`: 0.538 / 0.923 / 1.000 / 0.923 / 0.923. Loop vs matched single-shot: teacher wins `mean_cost` (0.769 < 0.923) and `action_safety` (1.000 > 0.923), ties `verdict_acc` and `citation_post`, and loses `key_pid_recall` (0.846 < 0.923). | Still not approved as a headline or tracked headline row; recorded here only because DR-011's own N=3 evidence used a teacher-backed B0, so the gate is not checkable against the locked slice without it. Protocol confirmation still needed. |
| PLUMB-DISTILL | code merged; local DR-012 artifact exists 2026-09-15 | Teacher distill JSONL can be used for SFT. | Persist full chat transcripts on the trace (`turns_from_trace`). | Plumbing. 2026-09-15: raw teacher-dev 20/20 nonempty `messages` (`gpt-5.6-luna`, `dataset_hash 5ffa17a659505a1b`). | Required before EXP-003/004 training. Distill drafting allowed; GPU is not. JSONL is gitignored; summary: `docs/experiments/2026-09-15-teacher-dev-filtered.summary.json`. |
| EXP-002 | locked (DR-013); levers 1 to 6 implemented; lever 5 measured n_kept=14; lever 6 live-dev smoked | 7B failures cluster in tool calling, write/JSON, or citation: one of those is the real lever. | Case-level JSON from EXP-001 (Lightning T4 local-7B + teacher + Ollama B0). Dev/scripted tests for graph levers; lever-2 also has a 3-case dev Lightning T4 smoke. Do not re-run official test after graph changes. | Local 7B on T4: 0/13 gold hits; 6× NEE / 7× suspicious / 0× malicious. Citation post 1.0; exhaustion 0.308; mean tools 5.6. Tech P/R = 0/0 on 7/8 gold-malicious; 4 gold-malicious NEE writes passed verify. Only `otrf_cmd_mshta_vbscript_execute_psh` has any gold technique overlap (P=1.0 R=0.5, still suspicious). Teacher is a different cluster (tool cap / degrade) and *does* emit malicious. Lever-2 smoke: NEE twin shows `- none` (no false projection); LSASS control shows `T1059.001` candidate selected without floor lift; malicious twin write budget/parse-failed. Lever 5: boxed trigger-only windows (all gold-NEE `_nee` twins) cap to NEE after the floor. Measured teacher-dev n_kept 14. Lever 6: `win_susp_lsass_access` without dump-tool or PROCESS_VM_READ corroboration caps to likely_benign and strips isolate_host/kill_process. Scripted auditpol benign LSASS vs dumpert. Live-dev 3-case T4 smoke (`--split dev --limit 3`, same set as EXP-004): action_safety 1.00 (LSASS `pre_repair` malicious → `likely_benign`). | Cluster is write-step conservatism + technique omission + NEE-twin overcall + LSASS-FP containment, not "tools never called" or "JSON parse". Lever 1: post-verify verdict floor. Lever 2: write candidates from fetched `attack-T…` ids. Lever 5: thin-window abstain (measured n_kept 11→14). Lever 6: LSASS FP ceiling (scripted + 3-case dev T4 smoke action_safety 1.00). Not LoRA. Official test numbers stay the pre-floor EXP-001 rows. |
| EXP-003 | smoke SFT discuss cleared; full LoRA N-ok (n_kept=14); lever 5 measured | Filtered teacher dev traces are enough (full LoRA N≥12 after filters) to try one LoRA; smoke SFT discuss is a lower bar (N≥8). | `eval run --arm agent-teacher --split dev --export-distill reports/distill/teacher-dev.jsonl`. Filter DR-012 (locked). | Capped 2026-09-15: n_kept=10. Unbounded 2026-09-15: n_kept=11. Lever 4 2026-09-16: n_kept=11. Unbounded + lever 5 2026-09-16: `gpt-5.6-luna`, `dataset_hash 5ffa17a659505a1b`, N=20, verdict_acc 0.70, mean_cost 1.00, citation_post 1.00, key-pid 1.00, action_safety 0.95, budget_exh 0.00, mean tools 14.4. DR-012 n_kept=14 (`full_lora_n_ok=true`). All 3 NEE twins kept by thin-window ceiling. Summary: `docs/experiments/2026-09-16-teacher-dev-unbounded-lever5.filtered.summary.json`. | Smoke discuss clears. Full LoRA N≥12 clears. Not a launch. Dev-only; not a README headline row. Do not loosen DR-012. |
| DR-012 | locked | Teacher-dev distill keep line should retain high-citation passed/repaired rows even when tools exhaust, and high-citation degraded rows only on verdict_match, without loosening split/citation/prefer-correct. | Named filter revision in `scripts/filter_teacher_dev_distill.py`. Record: `docs/experiments/DR-2026-09-11-012-distill-filter.md`. Card: `docs/experiments/DATA_CARD-teacher-dev-v0.md`. | Capped n_kept=10. Unbounded 2026-09-15 n_kept=11. Lever-4 2026-09-16 n_kept=11. Lever-5 re-export 2026-09-16 n_kept=14. Smoke discuss clears; full LoRA N≥12 clears. | Locked. N=14 is full-LoRA N-ok on the filter gate. Not a launch. Do not loosen the filter. |
| EXP-004 | official N=13 recorded; QLoRA+levers 0.54 / 0.77 / 1.00 / 0.96 / 1.00 | QLoRA rank-8 SFT of `qwen2.5:7b-instruct` lifts citation post and key-pid recall vs untuned 7B without hurting action safety. | Config in strategy spec §5 + DR-015. Train on DR-012 filtered dev only (lever-5 keep-set). Eval graph includes lever 6. First eval is 3-case dev smoke; official test only if smoke action safety is not down. | T4 2026-09-16 train: 15/15 steps, `train_loss` 1.619. 3-case dev smoke: 0.67 / 0.33 / 1.00 / 1.00 / 1.00. Official test N=13 (`casefile-qlora-n14`, `num_ctx` 8192, timeout 3600): 0.538 / 0.769 / 1.000 / 0.962 / 1.000, budget_exh 0.00, mean tools 7.8. n_kept=14. Predicted lever-6 miss recorded: `otrf_empire_mimikatz_logonpasswords` gold malicious → likely_benign cost 5. | Hypothesis holds vs EXP-001 local (key-pid 0.46→0.96, action_safety 0.92→1.00, citation stays 1.00). Acc/safety vs EXP-001 are the graph (EXP-005). QLoRA is the cost cut and extra key-pid vs EXP-005, confounded by `num_ctx` 8192 vs 4096 (do not re-run GPU). Shared logonpasswords overfire: DR-017. Not a product launch. Do not loosen DR-012. |
| EXP-005 | official N=13 recorded; graph-only 0.54 / 1.85 / 1.00 / 0.85 / 1.00 | Untuned 7B + levers 1 to 6 matches most of EXP-004 vs EXP-001; QLoRA is not the main lift. | DR-016. `--arm agent-local-7b --split test` N=13, Ollama `qwen2.5:7b-instruct` digest `845dbda0ea48`, lever-6 tree, no QLoRA. `ALERT2ATTACK_LLM_TIMEOUT_S=3600`. | Official test N=13 START `2026-09-17T00:26:11Z` EXIT:0 `2026-09-17T00:45:48Z`. 0.538 / 1.846 / 1.000 / 0.846 / 1.000, budget_exh 0.00, mean tools 5.2. `num_ctx` 4096, `ollama ps` 100% GPU. | Acc 0.54 and action_safety 1.00 match EXP-004; that lift vs EXP-001 is the graph. Cost 1.85 is worse than EXP-001 1.62 and EXP-004 0.77: QLoRA is the cost cut (and extra key-pid 0.85→0.96). Confound: EXP-004 `num_ctx` 8192 vs EXP-005 4096; do not treat 1.85→0.77 as weights-only. Same 7/13 hit count, 9/13 same cases. Shared lever-6 overfire: `otrf_empire_mimikatz_logonpasswords` (DR-017). Not a product launch. Do not loosen DR-012. |
| DR-017 | implemented Option A (scripted/catalog). Official N=13 not run. | Narrow lever-6 corroboration so Empire/mimikatz logonpasswords is not capped, without reopening benign_lsass FP. | Option A only: `has_lsass_soft_dump_adjacent_corroboration` skip-ceiling on Empire `-enc` PowerShell and whoami/C2 child. Ceiling stays. No train. No DR-012 loosen. No `metrics.py`. | Scripted/catalog: logonpasswords-shaped box skips ceiling; gold-`likely_benign` LSASS still has no dump or soft corroboration; dumpert still dump-corroborated. EXP-004/005 recorded miss stands until official N=13. | HOLD train. Ceiling stays. Safety invariant: benign_lsass / lever-6 smoke `action_safety` 1.00. Do not claim headline win until ML Lead greenlights official N=13. Record: `docs/experiments/DR-2026-09-17-017-lever6-narrow-corroboration.md`. |
| RETR-001 | measured on dev: lexical, dense, hybrid; no method separates | A dense channel or a hybrid fusion finds the technique the key names more reliably than BM25, from text an analyst sees. | `alert2attack.retrieval.bench`, dev split only (20 scenarios, 17 scorable), 697 enterprise techniques (ATT&CK v19.2), `bge-small-en-v1.5` via fastembed, RRF k=60, pool 50, none tuned. Headline `alert+cmdline`, recall@5 and MRR, fixed before the first run. Test split never loaded. Setup and caveats: `docs/RETRIEVAL_EVAL.md`. | All three: hit@5 0.71 (0.47 to 0.88), i.e. 12 of 17, vs random 0.012. Paired differences from BM25 on the headline all contain zero (dense recall@5 -0.06, MRR +0.03; hybrid 0.00, +0.05). 13 of 17 scenarios rank identically; dense and hybrid each win 2 and lose 2. None of the 4 scenarios BM25 missed entirely is rescued. Two of sixteen paired intervals exclude zero, both dense/hybrid MRR on the non-headline `alert` variant, uncorrected. | Null result. The hypothesis is not supported on 17 cases, and the data cannot show it false either. The agent tool `search_attack_techniques` stays off by default. Not a README headline row. |
| DR-011 | locked | LoRA/distill *discuss* is cleared when teacher ≥ B0 on citation_post and key_pid_recall, and teacher strictly beats B0 on at least one of action_safety (higher) / mean_cost (lower) / verdict_acc (higher). Ties on citation+key_pid alone are not enough. Larger N hoping B0 dips is not the plan. | Official held-out eval, teacher vs B0. Evidence: N=3 official test ids at the DR-010 promotion (DR-010 PASS; reports conceptually `2026-09-11` post-pr22). No metric/scorer/runner change. Record: `docs/experiments/DR-2026-09-11-011-lora-discuss-gate.md`. | Teacher: verdict_acc 0.67, mean_cost 1.67, key_pid 1.0, citation_post 1.0, action_safety 1.0. B0: verdict_acc 0.67, mean_cost 1.67, key_pid 1.0, citation_post 1.0, action_safety 0.67. Per-case teacher: auditpol malicious→likely_benign (safe); benign_lsass likely_benign (safe, 1244); mshta malicious (safe). B0: auditpol malicious→likely_benign (unsafe); lsass+mshta hits. | Clears discuss on this slice via action_safety 1.0 > 0.67 with citation+key_pid ≥. LoRA still not launched until ML Lead "Approved for launch" + Deimos cost OK. Distill/QLoRA drafting allowed; GPU is not. Not a full-test result. |
| KILL-14B | killed | 14B offload is a better sovereign default. | n/a | No 7B baseline yet. | Kill. Revisit only if EXP-001 shows 7B citation/scope far below teacher and EXP-002 says capacity (not tools) is the bottleneck. |
| KILL-SWEEP | killed | Rank/LR grid before a first LoRA. | n/a | No distill, no gate. | Kill. One config after unlock. |
| KILL-SYNTH | killed | Hand-authored extra events for training volume. | n/a | Violates `datasets/AUTHORING.md`. | Kill. |

## Log

### 2026-09-10: ML Lead baseline

- Repo: v1 complete; README Results empty; `reports/` gitignored and absent in this workspace.
- Dataset: 33 OTRF scenarios (dev 20 / test 13). Gold class mix on test: 8 malicious / 3 likely_benign / 2 NEE.
- Distill path is not training-ready (empty `messages` for teacher).
- `alert2attack eval run` has no `--model` override; LoRA recipe in the 2026-09-09 follow-up is not executable.
- Gate gold issue: `otrf_empire_schtasks_creation_execution_elevated_user` (test) has `key_pids: []` → recall 1.0 by vacuity. Dev twin: `otrf_covenant_installutil`.
- Decision: DR-001 reject LoRA; queue EXP-001.

### 2026-09-11: DR-011 LoRA/distill discuss gate

- Deimos confirmed; ML Lead locked. Old "teacher must beat B0 on citation_post + key_pid recall" discuss inequality is replaced: ≥ on those two and a strict beat on at least one of action_safety / mean_cost / verdict_acc.
- DR-010 promoted. Official N=3 test-id slice (not N=13): teacher vs B0 as in the DR-011 row. Slice clears discuss via action_safety 1.0 > 0.67.
- Decision: discuss cleared on this slice; no LoRA launch; distill/QLoRA drafting allowed; GPU is not. EXP-001 full-N still queued.

### 2026-09-11: teacher-dev data card draft (v0)

- Added `docs/experiments/DATA_CARD-teacher-dev-v0.md` + `scripts/filter_teacher_dev_distill.py`.
- NOT READY. Do not train.

### 2026-09-11: DR-012 lock distill filter

- Locked named filter revision: keep `passed`/`repaired` even if tool-exhausted (citation≥0.9); keep `degraded` only if citation≥0.9 and verdict_match; prefer-correct default on; never test.
- Smoke SFT discuss: filtered N≥8. Full LoRA still N≥12 via a later named re-export. Do not claim training-ready at N=9.
- Evidence shape on the PLUMB-DISTILL teacher-dev export: raw 20/20 nonempty messages; old EXP-003 kept 0; DR-012+prefer-correct ~N=9. Card stays DRAFT until a filtered artifact is produced under these rules. Not launch.

### 2026-09-11: EXP-001 teacher spend approval ("key present, no launch")

- Approval: repo owner / ML Lead, via cloud-agent instruction "key present, no launch" (2026-09-11).
  Scope: teacher API spend for measurement only (EXP-001 held-out eval). Not a launch approval:
  DR-001/DR-011 stand, EXP-004 stays rejected, no GPU, no training, no `--export-distill` on test.
- Provider: Experiential Labs OpenAI-compatible gateway (`EXPLABS_API_KEY` present in the run env).
- Model tag: `gpt-5.6-luna` (`teacher_chat` default; `ALERT2ATTACK_TEACHER_MODEL` unset).
- Host: cloud VM, 4 vCPU. Inference GPU for the `agent-local-7b` *measurement* arm is allowed
  (that is not the LoRA/training GPU freeze). This particular VM has no CUDA device: see the next log.

### 2026-09-11: EXP-001 full-N results, and what "key present" did not buy

Commands (all `--split test`, no `--limit`, `dataset_hash 5ffa17a659505a1b`):

```bash
ALERT2ATTACK_B0_MODEL=ollama uv run alert2attack eval run --arm b0 --split test --out reports
uv run alert2attack eval run --arm agent-teacher --split test --out reports
ALERT2ATTACK_B0_MODEL=teacher uv run alert2attack eval run --arm b0 --split test --out reports/diagnostic-b0-teacher
```

| Arm (backend) | N | `verdict_accuracy` | `mean_verdict_cost` | `mean_citation_validity_post` | `mean_key_pid_recall` | `action_safety_rate` |
|---|---:|---:|---:|---:|---:|---:|
| `b0` (Ollama `qwen2.5:7b-instruct`): headline | 13 | 0.231 | 1.846 | 0.985 | 0.423 | 0.846 |
| `agent-teacher` (`gpt-5.6-luna`) | 13 | 0.538 | 0.769 | 1.000 | 0.846 | 1.000 |
| `b0` teacher-backed (`gpt-5.6-luna`): EXP-001b diagnostic, not a row | 13 | 0.538 | 0.923 | 1.000 | 0.923 | 0.923 |

DR-011 arithmetic, stated both ways. Against the headline Ollama B0: `1.000 ≥ 0.985` (citation_post)
and `0.846 ≥ 0.423` (key_pid) hold, and the teacher strictly beats it on all three of `mean_cost`
(0.769 < 1.846), `action_safety` (1.000 > 0.846), `verdict_acc` (0.538 > 0.231) → clears. Against the
matched teacher-backed B0: citation_post ties at 1.000 but `key_pid 0.846 < 0.923`, so condition 1 is
unmet → fails, despite strict beats on `mean_cost` and `action_safety`. The DR-011 N=3 slice cleared
with a `key_pid` tie at 1.0; that tie did not survive full N. Neither reading is a launch.

Open protocol question for ML Lead (not decided here, no code changed). `key_pid_recall` has no
precision counterpart, and the two arms populate `scope.involved_pids` differently: `run_b0` hydrates
from `pids_from_events(scenario.events[:40])`: every pid in the inline dump, 17 to 20 pids on some cases,
while the graph hydrates only from pids on ledger events it actually pulled, under a 12-tool cap it hit
on 10/13. A shotgunned scope therefore scores well on a recall-only metric. `metrics.py` is untouched;
choosing the official B0 baseline and deciding whether the gate should keep a recall-only key-pid term
is ML Lead's call. Also still true from the 2026-09-10 baseline: `otrf_empire_schtasks_creation_execution_elevated_user`
has `key_pids: []`, so it scores 1.0 by vacuity in every arm.

"Key present" did not mean "route usable." For ~15 min (22:51 to 23:06 UTC) every model alias on the
gateway returned `503 unavailable_route` while `GET /v1/models` returned 200: the key authenticated
and nothing could run. Two harness gaps made that worse, both fixed in this branch:

- `--arm b0` selected the teacher whenever `EXPLABS_API_KEY` was set, with no way back, so a present
  key stranded the campaign's `$0` Ollama B0 on a dead route. `ALERT2ATTACK_B0_MODEL=auto|teacher|ollama`
  now makes it explicit (`auto` = previous behaviour). Note this is also how a present key silently
  substituted the unapproved EXP-001b `b0-teacher` shape for the headline `b0`.
- The first scenario died in an OpenAI SDK traceback naming neither model nor endpoint. Live arms now
  send one tiny preflight completion first and fail with both, plus remediation, before any scoring.

`agent-local-7b` not a headline row. A full-N diagnostic did run on this host
(`reports/diagnostic-local-7b-cpu/2026-09-12-agent-local-7b-test.json`, same `dataset_hash`, 56m57s):
`0.154 / 2.077 / 1.000 / 0.154 / 1.000` with `budget_exhaustion_rate` 1.0. Every case has
`details.budget_timed_out=true` (13/13). Mean tools 4.5 / mean LLM 5.2: the 12-tool / 20-LLM caps
were not the binding constraint; the 180 s `Budget.timeout_s` was. Most cases collapsed to
`not_enough_evidence`. That is the host, not the 7B. Do not paste those numbers into README Results.

Inference GPU vs training GPU. "No GPU" in DR-001/DR-011/EXP-004 is a *training* freeze.
Running `qwen2.5:7b-instruct` on a GPU for EXP-001 measurement is allowed and is what the campaign's
Task 3 assumes. This cloud CPU VM cannot do that:

- `lspci` is empty (no PCI display device). No `/dev/nvidia*`, no DRM, no `nvidia-smi`.
- Ollama 0.34.0 loaded `libggml-cpu-sapphirerapids.so` only. CUDA v12/v13 libs are on disk and unused.
- `ollama ps` prints `13%/87% CPU/GPU` anyway; a timed generate was 7.6 tok/s (GPU 7B is typically
  50 to 80+). That readout is not a device.
- `list-self-hosted-workers` returned none; this run has `usePrivateWorker: false`.

A real `agent-local-7b` headline row needs a CUDA Ollama host. That is still measurement, not a launch.

### 2026-09-12: EXP-001 `agent-local-7b` on Lightning AI T4

The Lightning key was already in the env (`LIGHTNING_API_KEY` + `LIGHTNING_USER_ID`). The existing
stopped Studio (teamspace `default-project`) started on `Machine.T4`.
`nvidia-smi`: Tesla T4 15360 MiB. Ollama 0.34 pulled `qwen2.5:7b-instruct` digest `845dbda0ea48`
(same blob as the cloud CPU VM run). `ollama ps`: 100% GPU. Timed generate 43 tok/s
(CPU box was 7.6). Studio stopped after the report was copied out.

Two remote attempts through `https://11434-<studio>.cloudspaces.litng.ai/v1` died mid-split on the
OpenAI SDK's 10-minute default (`APITimeoutError`, no report). A third run **on the Studio against
localhost Ollama**, with `ALERT2ATTACK_LLM_TIMEOUT_S=3600` patched into `llm.py`, finished in ~88 min.

| Arm (host) | N | verdict_acc | mean_cost | citation_post | key_pid | action_safety | budget_exh |
|---|---:|---:|---:|---:|---:|---:|---:|
| `agent-local-7b` Lightning T4 | 13 | 0.000 | 1.615 | 1.000 | 0.462 | 0.923 | 0.308 |

4/13 `llm_exhausted` (3 of those also `tool_exhausted`). Predictions: 6× `not_enough_evidence`, 7×
`suspicious`, 0 gold hits (count corrected in DR-013). Citation/key-pid vs Ollama B0 both ≥; verdict_acc 0.00 < B0 0.23.
Copied to `reports/2026-09-12-agent-local-7b-test.json` (headline) and
`reports/lightning-t4/` (host-labeled copy). Not a launch.

### 2026-09-12: EXP-002 / DR-013 write conservatism

Locked from the Lightning T4 per-case table (same `dataset_hash`). The 7B loop is not failing
to call tools or to emit parseable JSON. It refuses `malicious` even when verify passed, and
it usually omits gold techniques (tech P/R 0/0 on 7/8 gold-malicious; pred mix is 6 NEE / 7
suspicious: an earlier 7/6 count was wrong). Teacher still hits `malicious` on 5/8, so this
is not a 7B-capacity argument for LoRA.

Graph lever (dev/scripted only): `apply_verdict_floor` after verify, using surviving
`CaseFile.techniques` tactics + `scope.persistence`. No gold, no alert-rule hydrate, no
`metrics.py` change, no official test re-run. Record:
`docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`.

Lever 2: `write_node` extracts known `attack-T…` ids explicitly fetched into
this run's ledger and presents them as a dedicated supported-vs-speculative
checklist. It does not mutate the parsed case file. Automatic projection was
rejected because NEE twins may investigate the same techniques as malicious
twins and would then trip the verdict floor. Scripted coverage plus a 2026-09-12
Lightning T4 dev 3-case smoke confirm wiring (`- none` on NEE twin;
candidate shown/selected on LSASS without floor lift; malicious twin write
budget/parse failure). No accuracy or technique-recall delta claimed;
not a headline row. Details in DR-013.

### 2026-09-12: EXP-002 lever 3 write robustness

Investigate now stops early to reserve 2 LLM calls / 60s for write. Write/repair
normalize CaseFile JSON (strip unknown keys, default missing confidence) without
inventing techniques or verdicts. Scripted coverage plus a Lightning T4 dev
3-case smoke (`timeout_s=900`, `skip_plan=True`): malicious twin write ran and
selected `T1059` without floor lift; NEE twin showed candidate but did not
project it (parse/timeout); LSASS `- none` / likely_benign. Default CLI 180s
timeout still starves write when a single investigate call overruns the budget.
No accuracy delta claimed; not a headline row; no official test; no launch.

### 2026-09-13: #34 merged; DR-012 filter blocked on missing export + $0 credits

Merged docs PR #34 (EXP-002 lever-3 T4 smoke). Next step was produce the on-disk
DR-012 filtered teacher-dev distill. Blockers:

1. Raw `reports/distill/teacher-dev.jsonl` is not present (gitignored; Lightning
   Studio and this workspace have no copy).
2. Teacher re-export preflight failed: ExpLabs `insufficient_credits` (balance
   $0.00). No `OPENAI_API_KEY` BYOK fallback configured.

No filtered artifact written. No GPU. No launch. Unblock: restore the N=20 raw
JSONL or top up ExpLabs credits and re-run
`alert2attack eval run --arm agent-teacher --split dev --export-distill reports/distill/teacher-dev.jsonl`
then `scripts/filter_teacher_dev_distill.py`.

### 2026-09-15: EXP-003 teacher-dev distill on promotional-free `gpt-5.6-luna`

`EXPLABS_API_KEY` was already set in the environment. Platform credits were still
exhausted (`total_credits` $11.00, `total_usage` $11.004, balance ~−$0.004).

Live probe of the three promotional slugs at that balance:

| Slug | Catalog badge | Tiny completion |
|---|---|---|
| `gpt-5.6-luna` | `free` | 200, `cost=0.0` |
| `deepseek-v4-flash` | `free` | 429 `insufficient_credits` |
| `qwen3.8-27b` | `allowance` | 429 `insufficient_credits` |

So only luna was actually callable without a top-up. Used that as
`ALERT2ATTACK_TEACHER_MODEL` (same tag as EXP-001 teacher).

```bash
ALERT2ATTACK_TEACHER_MODEL=gpt-5.6-luna uv run alert2attack eval run --arm agent-teacher \
  --split dev --export-distill reports/distill/teacher-dev.jsonl --out reports
uv run python scripts/filter_teacher_dev_distill.py reports/distill/teacher-dev.jsonl \
  --out reports/distill/teacher-dev.filtered.jsonl \
  --summary reports/distill/teacher-dev.filtered.summary.json
```

Dev eval (not a README headline row): N=20, verdict_acc 0.50, mean_cost 1.30,
citation_post 1.00, key-pid 0.85, action_safety 1.00, budget_exh 0.85, same
`dataset_hash 5ffa17a659505a1b`. Credits unchanged after the run.

DR-012 + prefer-correct: n_kept=10 / n_dropped=10 (`verdict_mismatch` 3,
`degraded_no_verdict_match` 7). 10/10 kept rows have nonempty `messages`.
Smoke SFT discuss clears (N≥8). Full LoRA fails (N<12). Committed
summary: `docs/experiments/2026-09-15-teacher-dev-filtered.summary.json`.
JSONL stays gitignored. No GPU. No launch. Next LoRA-path step is a named
unbounded-budget teacher-dev re-export (default caps are now off) aiming at
filtered N≥12, still then waiting on "Approved for launch".

### 2026-09-15: Unbounded investigation budget (default)

EXP-003 `budget_exhaustion_rate` 0.85 with mean tools 11.85: the 12-tool /
20-LLM / 180s / 8-turn caps were the binding constraint on teacher-dev, not
model spend. Defaults are now unbounded:

- `Budget()` / eval / API: `max_tool_calls=max_llm_calls=timeout_s=None`
- investigate turns default 0 (no cap); LangGraph recursion_limit stays a
  256-turn circuit breaker
- CLI `--max-tools/--max-llm/--timeout-s/--max-turns` 0 = unbounded
- Restore old caps with `ALERT2ATTACK_MAX_TOOL_CALLS=12 ALERT2ATTACK_MAX_LLM_CALLS=20
  ALERT2ATTACK_TIMEOUT_S=180 ALERT2ATTACK_MAX_INVESTIGATE_TURNS=8`
- B0 still uses `max_tool_calls=0` (no tools)
- Prompt no longer tells the model the tool budget is limited
- Per-HTTP `ALERT2ATTACK_LLM_TIMEOUT_S` (default 1800) is unchanged

Not a headline re-run. Not a launch. Official test numbers stay EXP-001.

### 2026-09-15: Unbounded teacher-dev re-export (EXP-003 follow-up)

```bash
ALERT2ATTACK_TEACHER_MODEL=gpt-5.6-luna uv run alert2attack eval run --arm agent-teacher \
  --split dev --export-distill reports/distill/teacher-dev-unbounded.jsonl \
  --out reports/unbounded-teacher-dev
uv run python scripts/filter_teacher_dev_distill.py \
  reports/distill/teacher-dev-unbounded.jsonl \
  --out reports/distill/teacher-dev-unbounded.filtered.jsonl \
  --summary reports/distill/teacher-dev-unbounded.filtered.summary.json
```

Same `dataset_hash 5ffa17a659505a1b`. Caps off. budget_exhaustion_rate 0.00 (was 0.85).
Mean tools 14.15; 16/20 cases used more than 12 tools. Dev eval (not headline):
verdict_acc 0.55 (was 0.50), mean_cost 1.05 (was 1.30), citation 1.00,
key-pid 0.85, action_safety 1.00.

DR-012 n_kept 11 (was 10). Smoke discuss still clears. Full LoRA still fails
(11<12). Dropped 2 `verdict_mismatch` + 7 `degraded_no_verdict_match`: write
quality, not budget. Summary:
`docs/experiments/2026-09-15-teacher-dev-unbounded.filtered.summary.json`.
No GPU. No launch.

### 2026-09-16: Write-path summary hygiene (EXP-002 lever 4 / EXP-003 follow-up)

Case-level read of the 9 unbounded drops: both `verdict_mismatch` rows are write
parse failures. The teacher emitted a cited CaseFile; `CaseFile` rejected
`summary` because `count(".")` treated `mshta.exe`, `T1218.005`, and
`raw.githubusercontent.com` as extra sentences; the graph replaced the write
with the NEE stub that passes verify.

Lever: shared `summary_sentence_count` (mask non-sentence periods) in
`CaseFile` + `verify`; `normalize_casefile_dict` clips *real* overflow to 3
sentences. Does not invent claims. Does not loosen DR-012. Does not re-run
official test. No teacher API spend in this change.

Offline counterfactual (saved `reports/distill/teacher-dev-unbounded.jsonl`):
`otrf_cmd_mshta_javascript_getobject_sct` write is `malicious` + `T1218.005`;
after parse, verify only flags parent pid 10196 `PID_UNSUPPORTED`; degrade
strips that pid and keeps malicious → DR-012 keep. That is n_kept **12 if
re-exported**, not a measured card. The wmic parse-fail stays NEE vs gold
malicious. Remaining 7 degraded mismatches are a later citation/degrade lever.
No LoRA. No launch.

### 2026-09-16: Lightning T4 lever-4 dev smoke (not headline)

Studio on `Machine.T4`, then stopped. Ollama
`qwen2.5:7b-instruct` digest `845dbda0ea48`, `ollama ps` 100% GPU. Chose
7B not 14B: the lever is parse hygiene, KILL-14B still stands, same digest
as EXP-001/002. Three dev cases, `--skip-plan --timeout-s 900 --max-turns 8`.
No `--split test`. No teacher API.

All three writes produced a real CaseFile (no NEE stub, no `parse failed twice`).
`otrf_wmic_remote_xsl_jscript` is the live 7B proof: summary has 4 raw periods and
2 real sentences (`T1059.001` + `RuntimeBroker.exe`); the old `count(".")` cap
would have discarded it. Gold-malicious mshta still `likely_benign` with no
techniques: EXP-002 conservatism, not this lever. NEE twin predicted
malicious (execution-only `T1059.001`). Not a verdict-acc claim. Not
n_kept=12. Local: `reports/diagnostic-exp002-write-summary/` (gitignored).

### 2026-09-16: Unbounded teacher-dev re-export with lever 4 (measured)

```bash
ALERT2ATTACK_TEACHER_MODEL=gpt-5.6-luna ALERT2ATTACK_LLM_TIMEOUT_S=1800 \
  uv run alert2attack eval run --arm agent-teacher --split dev \
  --export-distill reports/distill/teacher-dev-unbounded-lever4.jsonl \
  --out reports/unbounded-teacher-dev-lever4
uv run python scripts/filter_teacher_dev_distill.py \
  reports/distill/teacher-dev-unbounded-lever4.jsonl \
  --out reports/distill/teacher-dev-unbounded-lever4.filtered.jsonl \
  --summary reports/distill/teacher-dev-unbounded-lever4.filtered.summary.json
```

Same `dataset_hash 5ffa17a659505a1b`. Caps off. START `2026-09-16T11:41:43Z`,
EXIT:0 `2026-09-16T12:03:32Z`. Dev eval (not headline): verdict_acc 0.55
(same), mean_cost 1.05, citation 1.00, key-pid 1.00 (was 0.85; parse stubs
no longer wipe pids), action_safety 1.00, budget_exh 0.00, mean tools 14.3
(17/20 used >12 tools). All 20 rows `degraded`.

DR-012 n_kept 11 (still). Smoke discuss still clears. Full LoRA still fails
(11<12). The offline counterfactual (n_kept 12) assumed the rest of the 2026-09-15
JSONL frozen. Live luna is not frozen:

| case | 2026-09-15 | 2026-09-16 lever 4 | DR-012 |
|---|---|---|---|
| `otrf_cmd_mshta_javascript_getobject_sct` | passed NEE stub, mismatch | degraded `malicious`+`T1218.005` | KEEP (lever 4) |
| `otrf_cmd_mshta_javascript_getobject_sct_nee` | passed NEE stub matched gold NEE | degraded false `malicious` | DROP |
| `otrf_cmd_psexec_lsa_secrets_dump` | degraded `malicious` | degraded `suspicious` | DROP |
| `otrf_covenant_installutil` | degraded `suspicious` | degraded `malicious` | KEEP |
| `otrf_wmic_remote_xsl_jscript` | passed NEE stub | degraded NEE vs gold malicious | DROP (expected) |

Leftover 9 drops are all `degraded_no_verdict_match` (3 NEE-twin false
malicious, 4 gold-malicious writer NEE, 1 `likely_benign`, 1 `suspicious`).
Not parse stubs. Next lever is write conservatism / NEE-twin, not another
sentence cap. Do not loosen DR-012. No LoRA. No official test. No launch.
Summary: `docs/experiments/2026-09-16-teacher-dev-unbounded-lever4.filtered.summary.json`.

### 2026-09-16: EXP-002 lever 5 thin-window abstain (measured n_kept=14)

```bash
ALERT2ATTACK_TEACHER_MODEL=gpt-5.6-luna ALERT2ATTACK_LLM_TIMEOUT_S=1800 \
  uv run alert2attack eval run --arm agent-teacher --split dev \
  --export-distill reports/distill/teacher-dev-unbounded-lever5.jsonl \
  --out reports/unbounded-teacher-dev-lever5
uv run python scripts/filter_teacher_dev_distill.py \
  reports/distill/teacher-dev-unbounded-lever5.jsonl \
  --out reports/distill/teacher-dev-unbounded-lever5.filtered.jsonl \
  --summary reports/distill/teacher-dev-unbounded-lever5.filtered.summary.json
```

Same `dataset_hash 5ffa17a659505a1b`. Caps off. START `2026-09-16T13:54:04Z`,
EXIT:0 `2026-09-16T14:20:54Z`. Dev eval (not headline): verdict_acc 0.70
(was 0.55), mean_cost 1.00, citation 1.00, key-pid 1.00, action_safety 0.95
(was 1.00; one unsafe: run-keys standard user `likely_benign` vs gold
malicious: 48-event window, not this lever), budget_exh 0.00, mean tools 14.4.

DR-012 n_kept=14 (`full_lora_n_ok=true`). The +3 is exactly the three NEE
twins, all with the `thin_window` ceiling note. Dev acc +0.15 is 3/20.

| case | lever 4 | lever 5 | DR-012 |
|---|---|---|---|
| `otrf_cmd_mshta_javascript_getobject_sct_nee` | false malicious DROP | thin-window NEE | KEEP |
| `otrf_empire_launcher_sct_regsvr32_nee` | false malicious DROP | thin-window NEE | KEEP |
| `otrf_psh_mshta_html_application_execution_nee` | false malicious DROP | thin-window NEE | KEEP |
| `otrf_cmd_psexec_lsa_secrets_dump` | suspicious DROP | malicious KEEP | KEEP (luna; empty techs) |
| `otrf_cmd_mshta_javascript_getobject_sct` | malicious KEEP | suspicious DROP | DROP (luna; window not thin) |

Leftover 6 drops are gold-malicious write misses (NEE / likely_benign /
suspicious), still `degraded_no_verdict_match`. **Do not loosen DR-012. No
official test. No launch.** Full LoRA N gate clears; that is not GPU approval.
Summary: `docs/experiments/2026-09-16-teacher-dev-unbounded-lever5.filtered.summary.json`.

### 2026-09-16: EXP-002 lever 6 LSASS FP ceiling (scripted)

EXP-004 3-case dev smoke (other branch) killed on `action_safety` 0.67:
`otrf_auditpol_system_user_auditpolicy_modification_benign_lsass` wrote
`malicious` + `isolate_host`. Gold `unacceptable_actions` are isolate/kill.
A verdict-only cap still fails `action_safe`.

Lever 6 runs after thin-window. If `alert.rule_id == win_susp_lsass_access`
and the boxed store has no dump-tool marker and no `process_access` to
`lsass.exe` with `PROCESS_VM_READ` (`0x0010`), cap to `likely_benign` and drop
`isolate_host` / `kill_process` (append `monitor` if empty). Never reads gold.
`lsass.exe` itself is not a dump marker.

Scripted proof (not a live eval, not a headline row):

| case | gold | scripted write | after ceiling |
|---|---|---|---|
| `otrf_auditpol_system_user_auditpolicy_modification_benign_lsass` | likely_benign | malicious + isolate_host | likely_benign, no isolate |
| `otrf_cmd_lsass_memory_dumpert_syscalls` | malicious | malicious + isolate_host | unchanged (Outflank-Dumpert / `0x1fffff`) |

`otrf_empire_mimikatz_logonpasswords` (test, gold malicious) boxed window is
svchost→lsass `0x1000` + whoami: no dump tool. This ceiling will treat
that box as an FP. Do not re-run official test. Headline stays EXP-001.

No teacher-dev re-export (n_kept already 14). No QLoRA. No `metrics.py`. No
DR-012 change. Spec: `docs/design/2026-09-16-lsass-fp-ceiling-design.md`.

### 2026-09-16: EXP-002 lever 6 3-case dev T4 smoke

Same `--arm agent-local-7b --split dev --limit 3` set as the EXP-004 QLoRA
kill. Untuned `qwen2.5:7b-instruct` digest `845dbda0ea48`, Lightning Studio
on `Machine.T4`, `ollama ps` 100% GPU. Caps off.
START `2026-09-16T15:18:44Z`, EXIT:0 `2026-09-16T15:23:17Z`. Studio stopped
after the copy. Not a headline row.

| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid | Action safety |
|---|---|---:|---:|---:|---:|---:|---:|
| `agent-local-7b` (untuned 7B + lever 6) | dev | 3 | 0.67 | 1.00 | 1.00 | 1.00 | 1.00 |

| case | match | safe | pred | gold | pre_repair |
|---|---|---|---|---|---|
| `otrf_auditpol_system_user_auditpolicy_modification_benign_lsass` | True | True | likely_benign | likely_benign | malicious |
| `otrf_cmd_bitsadmin_download_psh_script` | True | True | malicious | malicious | malicious |
| `otrf_cmd_disable_eventlog_service_startuptype_modification_via_registry` | False | True | NEE | malicious | NEE |

The LSASS row is the live proof: writer was malicious; ceiling left
likely_benign and `action_safe`. EXP-004 on this set was action_safety
0.67. This smoke is not down vs EXP-001 local test 0.923.
Do not run official test. n_kept still 14. No QLoRA this run.
Summary: `docs/experiments/2026-09-16-lever6-lsass-fp-dev-smoke.summary.json`.

### 2026-09-16: EXP-004 N=14 QLoRA train + 3-case dev smoke (gate holds)

DR-015. Lever-5 keep-set (`n_kept=14`, `full_lora_n_ok=true`). Eval graph
includes lever 6. Lightning Studio `Machine.T4`.
Student `unsloth/Qwen2.5-7B-Instruct` QLoRA rank-8, seq 2048 (4096 OOM).
Holdout last two sorted dev ids. Never test. Do not loosen DR-012.

Train 2026-09-16T15:38 to 16:00Z: 15/15 steps, `train_loss` 1.619, runtime
795.4 s. Adapter saved. GGUF `Q4_K_M` (~4.4G) tagged
`casefile-qlora-n14:latest` id `0a01b00360d5`. Summary:
`docs/experiments/2026-09-16-exp004-n14-qlora-train.summary.json`.

3-case dev smoke (`ALERT2ATTACK_OLLAMA_MODEL=casefile-qlora-n14` `--arm
agent-local-7b --split dev --limit 3` on the lever-6 tree). First Ollama
tag at default `num_ctx` 4096 overflowed write (4467 tokens) EXIT:1.
Recast `PARAMETER num_ctx 8192`. Successful smoke START
`2026-09-16T16:06:14Z` EXIT:0 `2026-09-16T16:10:00Z`. `ollama ps` **100%
GPU CONTEXT 8192. Same `dataset_hash 5ffa17a659505a1b`. **Not a README
headline row. Not EXP-001 test.

| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid | Action safety |
|---|---|---:|---:|---:|---:|---:|---:|
| `agent-local-7b` (QLoRA N=14 + lever 6) | dev | 3 | 0.67 | 0.33 | 1.00 | 1.00 | 1.00 |
| `agent-local-7b` (untuned 7B + lever 6, same set) | dev | 3 | 0.67 | 1.00 | 1.00 | 1.00 | 1.00 |

| case | match | safe | pred | gold | pre_repair |
|---|---|---|---|---|---|
| `otrf_auditpol_system_user_auditpolicy_modification_benign_lsass` | True | True | likely_benign | likely_benign | likely_benign |
| `otrf_cmd_bitsadmin_download_psh_script` | False | True | suspicious | malicious | suspicious |
| `otrf_cmd_disable_eventlog_service_startuptype_modification_via_registry` | True | True | malicious | malicious | likely_benign |

Gate holds: `action_safety` 1.00 is not down vs EXP-001 local test
0.923. Official `--split test` N=13 started `2026-09-16T16:11:39Z`.
QLoRA vs untuned on this slice: same acc 0.67, cheaper mean_cost (eventlog
NEE→malicious via floor; bitsadmin malicious→suspicious). LSASS QLoRA
wrote likely_benign pre_repair (ceiling not required). Headline comparison
vs EXP-001 is graph-confounded. Summary:
`docs/experiments/2026-09-16-exp004-n14-qlora-dev-smoke.summary.json`.

### 2026-09-16: EXP-004 official N=13 (`casefile-qlora-n14`)

First official run `16:11:39Z` to `18:52:30Z` EXIT:1 `APITimeoutError` at
`ALERT2ATTACK_LLM_TIMEOUT_S=1800`, no report (same class as EXP-001). Retry
`ALERT2ATTACK_LLM_TIMEOUT_S=3600` `OLLAMA_KEEP_ALIVE=-1` START
`2026-09-16T19:09:16Z` EXIT:0 `2026-09-16T21:23:45Z`. Studio
on `Machine.T4` then stopped. Same
`dataset_hash 5ffa17a659505a1b`. Unbounded. Lever-6 tree. Tag
`casefile-qlora-n14:latest` id `0a01b00360d5` `num_ctx` 8192 `ollama ps`
100% GPU.

| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid | Action safety | budget_exh | mean tools |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| EXP-001 untuned 7B | test | 13 | 0.00 | 1.62 | 1.00 | 0.46 | 0.92 | 0.308 | 5.6 |
| EXP-004 QLoRA N=14 + levers 1 to 6 | test | 13 | 0.54 | 0.77 | 1.00 | 0.96 | 1.00 | 0.00 | 7.8 |
| EXP-001 teacher | test | 13 | 0.54 | 0.77 | 1.00 | 0.85 | 1.00 |, |, |

7/13 gold hits: 2/8 malicious, 3/3 likely_benign, 2/2 NEE. All 13
`action_safe`. Misses are 5× gold-malicious→suspicious plus
`otrf_empire_mimikatz_logonpasswords` gold malicious → likely_benign
(cost 5; lever 6 predicted this boxed svchost→lsass `0x1000` window).
Hypothesis vs EXP-001 local holds (key-pid and action_safety up,
citation post stays 1.00). Confound measured by EXP-005: acc/safety
are the graph; QLoRA is cost + extra key-pid. Not a product launch.
Do not loosen DR-012. Local report
`reports/exp004-n14/2026-09-16-agent-local-7b-test.json` (gitignored).
Summary: `docs/experiments/2026-09-16-exp004-n14-qlora-test.summary.json`.

### 2026-09-17: EXP-005 official N=13 (untuned 7B + levers 1 to 6)

Graph-only control. Studio `Machine.T4` START
`2026-09-17T00:26:11Z` EXIT:0 `2026-09-17T00:45:48Z` then stopped.
Ollama `qwen2.5:7b-instruct` digest `845dbda0ea48` `num_ctx` 4096
`ollama ps` 100% GPU. Same `dataset_hash 5ffa17a659505a1b`.
Unbounded. Lever-6 tree. No QLoRA (`ALERT2ATTACK_OLLAMA_MODEL` that
tag, never `casefile-qlora-n14`). `ALERT2ATTACK_LLM_TIMEOUT_S=3600`
`OLLAMA_KEEP_ALIVE=-1`.

| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid | Action safety | budget_exh | mean tools |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| EXP-001 untuned 7B | test | 13 | 0.00 | 1.62 | 1.00 | 0.46 | 0.92 | 0.308 | 5.6 |
| EXP-005 untuned + levers 1 to 6 | test | 13 | 0.54 | 1.85 | 1.00 | 0.85 | 1.00 | 0.00 | 5.2 |
| EXP-004 QLoRA N=14 + levers 1 to 6 | test | 13 | 0.54 | 0.77 | 1.00 | 0.96 | 1.00 | 0.00 | 7.8 |
| EXP-001 teacher | test | 13 | 0.54 | 0.77 | 1.00 | 0.85 | 1.00 |, |, |

7/13 gold hits: 2/8 malicious, 3/3 likely_benign, 2/2 NEE. All 13
`action_safe`. Same hit *count* as EXP-004; 9/13 the same cases.
EXP-005-only hits: `otrf_cmd_userinitmprlogonscript_batch`,
`otrf_empire_schtasks_creation_execution_elevated_user`. EXP-004-only
hits: `otrf_auditpol_system_user_auditpolicy_modification`,
`otrf_empire_wmic_add_user_backdoor`. Three gold-malicious→likely_benign
cost-5 misses (`mshta`, `logonpasswords`, `wmic`) drive mean cost
1.85 (worse than EXP-001 1.62). Hypothesis holds on acc/safety
(graph is the EXP-001→0.54/1.00 lift). Hypothesis fails on cost:
QLoRA is the 1.85→0.77 cut and the extra key-pid 0.85→0.96. Not a
product launch. Do not loosen DR-012. Local report
`reports/exp005-graph-only/2026-09-17-agent-local-7b-test.json`
(gitignored). Summary:
`docs/experiments/2026-09-17-exp005-graph-only-test.summary.json`.

### 2026-09-17: DR-017 proposed: narrow lever-6 corroboration (HOLD train)

Evaluator miss autopsy after EXP-004 and EXP-005. Both arms miss
`otrf_empire_mimikatz_logonpasswords` the same way: gold malicious →
likely_benign, cost 5, `action_safe` true. Root cause is lever-6 LSASS
FP ceiling overfire (svchost→lsass `0x1000` + whoami; no dump-tool /
`PROCESS_VM_READ`). Design predicted it. Ceiling stays: it bought
`action_safety` 1.00 on benign_lsass. Distill cannot fix a post-verify
rule that ignores techniques. ML Lead: HOLD train; no targeted cost-1
distill; Evaluator opens this DR.

Proposed (non-binding) implement later: soft dump-adjacent boxed
signals (Empire `-enc` PowerShell + whoami/C2 child; decoded stager
fingerprints) and/or skip-ceiling when the writer already cited
grounded T1003.001. Non-goals: disable ceiling, loosen DR-012, new
QLoRA, rank sweep, `metrics.py`. Safety invariant: benign_lsass /
lever-6 smoke must remain `action_safety` 1.00 (scripted + catalog
before any official re-run). Success if implemented: logonpasswords no
longer cost-5 and no safety regress on the same N=13 test.

EXP-004 vs EXP-005 mean-cost 0.77 vs 1.85 is also confounded by
`num_ctx` 8192 vs 4096 (QLoRA recast after 4096 write overflow;
graph-only finished at 4096). Acc/safety still match; both miss
logonpasswords. Do not run GPU to unconfound.

Record: `docs/experiments/DR-2026-09-17-017-lever6-narrow-corroboration.md`.
Spec: `docs/design/2026-09-17-lever6-narrow-corroboration-design.md`.

### 2026-09-17: DR-017 Option A implemented (HOLD train; no official N=13)

ML Lead approved Option A only. `has_lsass_soft_dump_adjacent_corroboration`
skips the lever-6 ceiling when boxed events show encoded PowerShell
(`decode_powershell` `-enc`) and a whoami child or pid-linked C2
`network_connect`. Ceiling stays. Option B not implemented. Catalog
gold-`likely_benign` LSASS still has no dump or soft corroboration.
Dumpert still dump-corroborated. Do not claim a headline win until
official N=13.

## How to add a row

1. New ID (`EXP-00N`, `DR-0NN`, or `KILL-*`).
2. Hypothesis in one sentence.
3. Method: arm, split, exact command, model tag.
4. Result: link `reports/<date>-<arm>-<split>.json` (local) and paste README only for live full-N test.
5. Decision: ship / iterate on dev / kill / wait for approval.
