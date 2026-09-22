# NEE-twin thin-window abstain: design

Status: Measured 2026-09-16. Lever 5 kept all three NEE twins; DR-012 n_kept 14.  
Date: 2026-09-16  
Related: EXP-002 / DR-013, lever 4 (`docs/design/2026-09-16-write-summary-hygiene-design.md`), DR-012 (locked), `docs/experiments/TRACKER.md`

## Problem

Measured unbounded + lever 4 teacher-dev (N=20, `gpt-5.6-luna`, `dataset_hash 5ffa17a659505a1b`) keeps 11 rows under locked DR-012. The leftover 9 drops are all `degraded_no_verdict_match`. Three of them are NEE twins predicted malicious:

| scenario | gold | pred | boxed window |
|---|---|---|---|
| `otrf_cmd_mshta_javascript_getobject_sct_nee` | NEE | malicious (`T1218.005`) | 1 `process_create` |
| `otrf_empire_launcher_sct_regsvr32_nee` | NEE | malicious (`T1218.010` + `T1059.001`) | 2 `process_create` |
| `otrf_psh_mshta_html_application_execution_nee` | NEE | malicious (`T1218.005` + startup persistence claim) | 1 `process_create` |

Catalog construction (`truncate_to_trigger_context`) boxes NEE twins as trigger ± parent `process_create` only. Gold narrative: follow-on child / network / file / registry evidence is outside the window; the correct write is abstain (`not_enough_evidence`), not `isolate_host` + `malicious`.

The teacher (and the 7B) treat the trigger LOLBin command line as enough for `malicious`. `pre_repair_verdict` is already `malicious` on these three rows: the EXP-002 verdict floor did not cause the mismatch (it never downgrades `malicious`). A T1218-only cap is zero-sum: it would keep the twins and drop the lever-4 mshta gold keep (`T1218.005` only) plus `otrf_covenant_installutil` (`T1218.004`).

Every gold-NEE `_nee` scenario in the catalog is thin (1 to 2 `process_create`, no other kinds). No gold-malicious or `likely_benign` scenario is thin (37 to 48 events).

## Approaches

1. Thin-window abstain ceiling after the verdict floor (chosen). If the boxed case store contains only `process_create` events and at most two of them, cap `{malicious, suspicious, likely_benign}` → `not_enough_evidence`. Never invent evidence. Never read gold. Ceiling wins over the floor so a cited `T1218` cannot lift a truncated twin.
2. Cap defense-evasion proxy (T1218) without persistence/C2/cred (rejected). Distinguishes twins from gold by technique mix, not by window. Drops mshta gold + covenant keeps; net n_kept ~0.
3. Prompt-only "abstain when only the trigger is present" (rejected). EXP-002: the 7B already ignores the write rubric. Teacher still called these three malicious.
4. Skip the floor on NEE-looking writes (rejected). Floor did not fire; `pre_repair` was already malicious.
5. Loosen DR-012 (rejected). Locked.

Write-conservatism on gold-malicious drops (psexec described a secrets dump then wrote `suspicious` with empty techniques; several others wrote NEE with tech P/R 0/0) is out of scope. Thin-window alone is the NEE-twin +1..+3. Revisit psexec only if a measured re-export is still n_kept&lt;12.

## Design

### Predicate

`is_thin_trigger_window(events) -> bool` in `src/alert2attack/agent/thin_window.py`:

- Empty list → `False` (do not cap missing data).
- Any event whose `kind` is not `process_create` → `False`.
- Count of `process_create` in `{1, 2}` → `True`.
- Three or more `process_create` with no other kinds → `False` (not how twins are boxed).

Events come from the boxed case store (`CaseStore.query_events`), not from the run ledger and not from gold. ATT&CK lookup ids in the ledger are irrelevant. Image-loads on the gold mshta twin make that window not thin.

### Ceiling

`apply_thin_window_ceiling(case_file, events) -> CaseFile`:

- If the window is not thin, return the case file unchanged.
- If verdict is already `not_enough_evidence`, unchanged.
- Otherwise set verdict to `not_enough_evidence`, append one stable open-question note. Do not rewrite `techniques`, `next_actions`, `scope`, or `summary`. Never invent ids.

### Call site

`InvestigationGraph.verify_node`, on `verify_done` exits (passed and degraded), after pid hydrate and after `apply_verdict_floor`. Trace note when the verdict changes: `thin_window: <old> → not_enough_evidence`.

### Out of scope

- No `metrics.py` change. No official `--split test`. No DR-012 change.
- No automatic technique projection (lever 2 rejection still stands).
- No GPU / EXP-004. No next_actions rewrite.
- Live teacher-dev re-export 2026-09-16 measured n_kept 14. Do not claim a README headline row.

## Validation

- Unit: thin predicate on 1 to 2 process_creates vs image_load/network; ceiling caps malicious and also caps a floor-lifted NEE+T1218; full windows unchanged.
- Catalog invariant: every `*_nee` gold-NEE scenario is thin; no gold-malicious scenario is thin.
- Scripted graph: load `otrf_cmd_mshta_javascript_getobject_sct_nee`, write malicious+`T1218.005` → final NEE with a `thin_window` note; load the gold mshta twin, same write → stays malicious.
- Existing floor tests on `enc_ps_downloader_001` stay green (that fixture is not thin).
- No `--split test`. No LoRA.

## Offline counterfactual (not a measured card)

Applying the ceiling to the three dropped NEE twins on the saved lever-4 JSONL (catalog windows, not a re-run) would match gold NEE → DR-012 keep. Measured unbounded + lever 5 re-export 2026-09-16: n_kept 14, all three twins kept with the ceiling note. Dev verdict_acc 0.55→0.70. Not a launch.
