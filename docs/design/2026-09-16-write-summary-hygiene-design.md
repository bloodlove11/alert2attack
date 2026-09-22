# Write-path summary hygiene — design

**Status:** Measured 2026-09-16. Lever 4 kept the mshta gold write; DR-012 n_kept stayed **11**.  
**Date:** 2026-09-16  
**Related:** EXP-002 lever 3 (`normalize_casefile_dict`), DR-012 (locked), `docs/experiments/TRACKER.md`

## Problem

Unbounded teacher-dev (N=20, `gpt-5.6-luna`, `dataset_hash 5ffa17a659505a1b`) keeps **11** rows under locked DR-012. The 9 drops are write quality, not budget:

| cluster | n | examples | what happened |
|---|---:|---|---|
| Parse fail → stub NEE that **passes** verify | 2 | `otrf_cmd_mshta_javascript_getobject_sct` (gold malicious), `otrf_wmic_remote_xsl_jscript` (gold malicious) | Writer JSON was otherwise valid. `CaseFile` rejected `summary` because `count(".") > 3`. Graph replaced the write with `_degraded_casefile` (NEE stub). |
| Degraded, verdict mismatch | 7 | 5 gold-malicious NEE after strip; 2 NEE-twins predicted malicious | Writer/repair/degrade path; not this lever. |

The two parse failures are **false sentence counts**, not 4+ real sentences.

Teacher retry summary for the mshta case (2 sentences, **4** raw periods):

> mshta.exe executed inline JavaScript that retrieved and invoked a remote scriptlet, matching T1218.005 proxy execution. The activity occurred on WORKSTATION5 under WORKSTATION5\wardog and used the referenced Atomic Red Team payload.

Periods come from `mshta.exe` + `T1218.005` + two sentence stops. The first attempt also includes `raw.githubusercontent.com` (6 raw periods, still 2 sentences).

Offline counterfactual on the saved unbounded JSONL (gitignored; not a re-run): if that mshta write had parsed, verify fails only `PID_UNSUPPORTED` for parent pid 10196 (no `process_create` in the ledger). `degrade_casefile` strips that pid, keeps `malicious` + `T1218.005`, citation 1.0 → DR-012 **keep**. That is **n_kept 11 → 12** without loosening DR-012. The wmic write is already NEE vs gold malicious, so this lever does not keep it.

Do **not** start LoRA. Do **not** change `metrics.py`. Do **not** re-run official **test**. Do **not** treat n_kept=12 as a measured export until a later named re-export.

### Measured re-export (2026-09-16)

Named unbounded teacher-dev run with this lever in tree (`gpt-5.6-luna`, `dev`, N=20, `dataset_hash 5ffa17a659505a1b`). DR-012 **n_kept=11**. The mshta gold write kept (`malicious`+`T1218.005`). Wmic still drops. Counterfactual +1 did not survive live teacher variance (mshta NEE twin and psexec left the keep set; covenant entered). Key-pid recall 0.85→1.00 because parse stubs no longer wipe pids. Verdict acc stayed 0.55. Summary: `docs/experiments/2026-09-16-teacher-dev-unbounded-lever4.filtered.summary.json`. Still not a launch.

## Approaches

1. **Sentence-aware cap + clip overlong real summaries in the write normalizer (chosen).** Count sentence-ending periods after masking ATT&CK ids, hostnames, dotted versions/IPs, and Windows/script extensions. `CaseFile` / `verify` share that counter. If a write still has >3 *real* sentences, `normalize_casefile_dict` clips to the first 3 so the rest of the CaseFile is not discarded. Never invent verdict, techniques, evidence, or pids.
2. **Raise the period cap to 6–8 (rejected).** Still counts `.exe` as a sentence; just moves the cliff.
3. **Drop the summary cap (rejected).** Design §5.6 keeps `summary` ≤ 3 sentences; `SUMMARY_TOO_LONG` stays a real error for 4+ actual sentences.
4. **Prompt-only “don’t write .exe” (rejected).** Teacher already writes two sentences and still fails the counter. EXP-002 already showed the 7B ignores rubric text.
5. **Loosen DR-012 (rejected).** Locked.

## Design

### Shared counter

`summary_sentence_count(text) -> int` in `src/alert2attack/domain/casefile.py`:

- Mask non-sentence periods, then `count(".")`.
- Masked forms: `T####` / `T####.###`; hostnames (`raw.githubusercontent.com`); dotted versions/IPs (`1.2.3.4`, `7.0`); file/script suffixes (`exe`, `dll`, `sys`, `bat`, `cmd`, `ps1`, `vbs`, `js`, `jse`, `hta`, `sct`, `msi`, `scr`, `lnk`, `inf`). Do **not** treat `.com` as a file suffix (collides with domains).
- Cap remains **3**. `CaseFile._summary_short` and `verify` (`SUMMARY_TOO_LONG`) both use this counter. Four real sentences still fail validation / still flag verify.

### Clip in the existing normalizer

`normalize_casefile_dict` already drops unknown keys and defaults confidence (EXP-002 lever 3). Extend it:

- If `summary` is a non-empty string with more than 3 real sentences, replace it with the prefix through the 3rd sentence-ending period.
- Do not copy clipped text into `open_questions`. Do not invent other fields.

`parse_case_file` (write + repair) therefore keeps cited techniques/verdicts when the only defect is summary length or false periods.

### Out of scope

- No live teacher-dev re-export in this change (counterfactual only).
- No PID hydrate / `PID_UNSUPPORTED` lever (next write-quality candidate after this).
- No automatic technique projection. No verdict-floor change. No GPU. No EXP-004.

## Validation

- Unit: teacher mshta retry string counts as 2 sentences and parses; four real sentences still rejected by `CaseFile` and still `SUMMARY_TOO_LONG`; normalizer clips four real sentences without changing verdict/techniques.
- Scripted graph: a write whose summary has `.exe` + `T1218.005` + two sentences is **kept** (not the NEE stub). A write with four real sentences still produces a CaseFile (clipped), not `parse failed twice`.
- Existing agent/verify/jsonutil tests stay green.
- No `--split test`. No `metrics.py`. No LoRA.
