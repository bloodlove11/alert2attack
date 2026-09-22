# DR-2026-09-12-013: Lock EXP-002: write conservatism, not tools or JSON

Status: Locked (error analysis + graph lever). Not a launch approval. Not a new headline row.  
Owner: ML Lead  
Date: 2026-09-12  
Related: `docs/experiments/TRACKER.md` EXP-002, `docs/design/2026-09-12-exp-002-verdict-floor-design.md`, Lightning T4 report `reports/lightning-t4/2026-09-12-agent-local-7b-test.json` (gitignored)

## Decision

EXP-001 local-7B failures on held-out test cluster in the write step, not in tool calling or JSON parse:

1. Not "tools never called." Mean tools 5.6; `budget_exhaustion_rate` 0.308 (4/13). Campaign kill is >0.5.
2. Not JSON/citation collapse. `mean_citation_validity_post` 1.000. Verification: 6 passed / 3 repaired / 4 degraded.
3. Is verdict conservatism plus technique omission. The 7B never emitted `malicious` or `likely_benign` (6× `not_enough_evidence`, 7× `suspicious`, 0/13 gold hits). On 7/8 gold-malicious cases, technique precision and recall are both 0.0: the writer did not cite gold techniques. Four gold-malicious cases are `not_enough_evidence` with verification passed (auditpol, userinit, launcher_vbs, mimikatz): a valid, fully cited NEE.

Do not start LoRA / QLoRA / EXP-004 to fix a 0.00 accuracy that has a graph lever. Do not change `src/alert2attack/eval/metrics.py`. Do not re-run official test after the lever lands: headline numbers stay the pre-floor EXP-001 rows.

The first lever is a deterministic post-verify verdict floor on *already-cited* high-severity ATT&CK tactics (and surviving `scope.persistence` claims). It does not invent evidence, does not read gold, and does not lift on execution/discovery/initial-access alone. It will not move the 7/8 gold-malicious cases that cited no techniques; that omission is the next write-path lever (dev only), not a reason to train.

## Evidence (local 7B, Lightning T4, N=13, `dataset_hash 5ffa17a659505a1b`)

| scenario | gold | pred | tech P/R | verify | notes |
|---|---|---|---:|---|---|
| `otrf_auditpol_system_user_auditpolicy_modification` | malicious | NEE | 0/0 | passed | tools=6 |
| `otrf_cmd_mshta_vbscript_execute_psh` | malicious | suspicious | 1.00/0.50 | repaired | only gold-malicious case with any technique overlap |
| `otrf_cmd_sharpview_pcre_net` | malicious | suspicious | 0/0 | degraded | |
| `otrf_cmd_userinitmprlogonscript_batch` | malicious | NEE | 0/0 | passed | |
| `otrf_empire_launcher_vbs` | malicious | NEE | 0/0 | passed | llm+tool exhausted |
| `otrf_empire_mimikatz_logonpasswords` | malicious | NEE | 0/0 | passed | llm exhausted |
| `otrf_empire_schtasks_creation_execution_elevated_user` | malicious | suspicious | 0/0 | repaired | `key_pids: []` vacuity |
| `otrf_empire_wmic_add_user_backdoor` | malicious | suspicious | 0/0 | degraded | gold tech is execution-only `T1047` |
| `otrf_cmd_dumping_ntds_dit_file_volume_shadow_copy_benign_lsass` | likely_benign | NEE | 1/1 | passed | empty-empty tech vacuity; exhausted |
| `otrf_empire_dllinjection_loadlibrary_createremotethread_benign_lsass` | likely_benign | NEE | 1/1 | passed | empty-empty; exhausted |
| `otrf_empire_mimikatz_extract_keys_benign_lsass` | likely_benign | suspicious | 1/1 | repaired | unsafe (only 7B safety miss) |
| `otrf_cmd_mshta_vbscript_execute_psh_nee` | NEE | suspicious | 0/0 | degraded | twin of mshta |
| `otrf_empire_launcher_vbs_nee` | NEE | suspicious | 0/0 | degraded | twin of launcher |

Teacher (`gpt-5.6-luna`) is a different cluster: tool cap 12/12 on 10/13, `degraded` on 11/13, but it *does* emit `malicious` (5/8 gold-malicious) and `likely_benign` (2/3). That is not a 7B capacity argument for LoRA.

## Floor (what this decision authorizes)

After verify/repair/degrade, if surviving `CaseFile.techniques` map (via `KnowledgeBase`) to any of:

`persistence`, `privilege-escalation`, `credential-access`, `defense-evasion`, `command-and-control`, `lateral-movement`

or `scope.persistence` is non-empty, lift `not_enough_evidence` / `suspicious` / `likely_benign` → `malicious`. Never downgrade `malicious`. Never invent techniques. Never consult gold. Never lift on `execution` / `discovery` / `initial-access` alone. Do not change `next_actions` in this lever. Do not hydrate techniques from the alert Sigma rule (would fire on LSASS FP and NEE twins that share the malicious twin's rule).

## Lever 2: fetched ATT&CK candidates in the write checklist

The write prompt now receives a compact list of known `attack-T…` evidence ids
that were explicitly fetched in this run. For each candidate, the writer must
include a `TechniqueClaim` only when observed telemetry supports that behavior,
and omit speculative candidates. `rule-*` ids and alert metadata are not
projected.

This is deliberately not deterministic `TechniqueClaim` hydration. An
ATT&CK lookup can be exploratory, and malicious / NEE twins can fetch the same
technique. Automatically converting all lookups into findings could turn an NEE
twin malicious through the verdict floor. The parsed `CaseFile` remains the
writer's selection and the verifier's output.

Lever 2 is implemented with unit and scripted graph coverage. A live-dev
control smoke on Lightning Studio (Machine.T4, Ollama
`qwen2.5:7b-instruct` digest `845dbda0ea48`) checked wiring only: not a
headline row and not a metric claim:

| case | gold | pred | techniques | candidates in write prompt | notes |
|---|---|---|---|---|---|
| `otrf_empire_launcher_sct_regsvr32` | malicious | NEE | `[]` | write never recorded (LLM budget / parse failure after investigate); tool looked up `attack-T1059` | local-7B write failure; floor n/a |
| `otrf_empire_launcher_sct_regsvr32_nee` | NEE | NEE | `[]` | `- none` (no attack lookup) | invalid CaseFile JSON extras; no false projection |
| `otrf_empire_persistence_registry_modification_run_keys_standard_user_benign_lsass` | likely_benign | suspicious | `T1059.001` → `attack-T1059.001` | checklist showed `T1059.001`; Sigma `rule-*` looked up but not projected | writer selected candidate; floor did not fire (execution-only); verify degraded |

Wiring works (candidates when looked up; `- none` when not; rejection path holds;
floor not falsely triggered by execution-only). Live 7B still often fails
CaseFile JSON, so technique-recall / verdict-lift from lever 2 is not a
measured win. Official test remains untouched. Local copies:
`reports/diagnostic-exp002-technique-candidates/` (gitignored).

## Lever 3: write budget reserve + CaseFile JSON normalization

Live-dev smoke showed two write-path failures that prevent levers 1 to 2 from
acting: (1) investigate can consume the whole wall-clock / LLM budget so write
never runs; (2) 7B CaseFile JSON often adds extras (`case_id`, `case_name`) and
omits `confidence`, so both validation attempts fail.

Lever 3:

1. Reserve 2 LLM calls and 60s wall time for write; stop investigate early
   with note `investigate: stop (reserve write budget/time)`.
2. Normalize CaseFile JSON before validate: drop unknown top-level keys,
   alias `description`→`summary` when needed, default missing `confidence` to
   `low` when a verdict is present. Never invent techniques, evidence, or
   verdicts.
3. Short-circuit write when the first response is empty / `BUDGET_EXHAUSTED`.

Implemented with unit + scripted graph coverage. A live-dev control smoke on
Lightning Studio (Machine.T4, Ollama `qwen2.5:7b-instruct`
digest `845dbda0ea48`, `timeout_s=900`, `skip_plan=True`) checked behavior only.
It is not a headline row and not a metric claim:

| case | gold | pred | techniques | notes |
|---|---|---|---|---|
| `otrf_empire_launcher_sct_regsvr32` | malicious | NEE | `T1059` from candidate | write ran (2×); first JSON had extras, second valid; floor did not lift (execution-only) |
| `otrf_empire_launcher_sct_regsvr32_nee` | NEE | NEE | `[]` | candidate `T1059.001` shown; write parse failed then timed out; not projected into final CaseFile |
| `…benign_lsass` | likely_benign | likely_benign | `[]` | candidates `- none`; verify degraded |

With the default CLI `timeout_s=180`, a separate malicious attempt still timed out
mid-investigate and never reached write: reserve cannot save a single investigate
LLM call that overruns the whole budget. Adequate wall time (or shorter
investigate) is required for lever 3 to matter. Official test remains untouched.
Local copies: `reports/diagnostic-exp002-write-robustness/` (gitignored).

## Lever 4: sentence-aware summary cap (teacher-dev parse stubs)

Unbounded teacher-dev error analysis (2026-09-16): both remaining
`verdict_mismatch` rows (`otrf_cmd_mshta_javascript_getobject_sct`,
`otrf_wmic_remote_xsl_jscript`) are write parse failures, not wrong
investigations. The writer JSON was cited; `CaseFile._summary_short` used
`text.count(".") > 3`, so `mshta.exe` + `T1218.005` + two real sentences
failed validation and the graph substituted the NEE stub that passes
verify.

Lever 4:

1. `summary_sentence_count` masks ATT&CK ids, hostnames, dotted versions/IPs,
   and Windows/script extensions, then counts remaining periods. Shared by
   `CaseFile` validation and `verify` (`SUMMARY_TOO_LONG`). Four *real*
   sentences still fail.
2. `normalize_casefile_dict` clips a summary with more than 3 real sentences
   to the first 3 so write/repair does not discard techniques/verdict. Never
   invents claims. Does not copy clipped text into `open_questions`.

Scripted graph + unit coverage. Offline counterfactual on the saved unbounded
JSONL: the mshta write would keep under DR-012 after degrade (parent pid
stripped, `malicious` + `T1218.005` remain) → n_kept 11→12 not measured.
No official test re-run. No teacher-dev API re-export in this change.

A 2026-09-16 Lightning Studio dev smoke (Machine.T4,
Ollama `qwen2.5:7b-instruct` digest `845dbda0ea48`, 100% GPU, `skip_plan`,
`timeout_s=900`) checked write parse only: not a headline row and not a
metric claim. 14B was available; 7B was used because this lever is
sentence counting, KILL-14B still stands, and the digest matches EXP-001/002.

| case | gold | pred | techniques | stub | notes |
|---|---|---|---|---|---|
| `otrf_cmd_mshta_javascript_getobject_sct` | malicious | likely_benign | `[]` | no | 2 write LLM calls (extras/fence, lever 3); conservatism remains; not a parse stub |
| `otrf_cmd_mshta_javascript_getobject_sct_nee` | NEE | malicious | `T1059.001` | no | twin false-malicious; write parsed (`Mshta.exe`, 2 raw periods / 1 sentence) |
| `otrf_wmic_remote_xsl_jscript` | malicious | malicious | `T1059.001` | no | lever 4 hit: 4 raw periods (`T1059.001` + `.exe` + 2 sentences) would fail the old counter; write kept |

Studio stopped after the smoke. Local copies:
`reports/diagnostic-exp002-write-summary/` (gitignored).

## Measured teacher-dev re-export (2026-09-16)

Named unbounded re-export on `gpt-5.6-luna` with lever 4 in tree (`dev`, N=20,
`dataset_hash 5ffa17a659505a1b`, EXIT:0 `2026-09-16T12:03:32Z`).

Dev eval (not headline): verdict_acc 0.55, mean_cost 1.05, citation_post 1.00,
key-pid 1.00 (was 0.85), action_safety 1.00, budget_exh 0.00, mean tools 14.3.
DR-012 n_kept=11 (still). Smoke discuss clears; full LoRA still fails (11<12).

`otrf_cmd_mshta_javascript_getobject_sct` is the live teacher proof: write kept
as degraded `malicious`+`T1218.005` (was a parse-fail NEE stub). Wmic write
parsed too, still NEE vs gold malicious (expected drop). The counterfactual
n_kept 12 did not hold because live luna also flipped the mshta NEE twin
(stub KEEP → false-malicious DROP) and swapped psexec/covenant. Remaining 9
drops are `degraded_no_verdict_match`, not false sentence counts.

Does not loosen DR-012. Does not start LoRA. Does not re-run official test.
Summary: `docs/experiments/2026-09-16-teacher-dev-unbounded-lever4.filtered.summary.json`.

## Lever 5: thin-window abstain (NEE twins)

Catalog NEE twins keep only the alert trigger ± parent `process_create`. Gold
says abstain. Teacher lever-4 still wrote `malicious` (floor did not fire;
`pre_repair` was already malicious). A T1218-only cap would drop the mshta gold
keep.

Lever: `is_thin_trigger_window` / `apply_thin_window_ceiling` after the verdict
floor. Boxed store events only (not gold, not ledger ATT&CK ids). Cap to
`not_enough_evidence`. Leave techniques and `next_actions`. Trace note
`thin_window: …`.

Scripted: `otrf_cmd_mshta_javascript_getobject_sct_nee` malicious+T1218 write →
NEE; gold mshta twin same write stays malicious. Catalog invariant: every gold
NEE is thin; no gold-malicious is.

Measured teacher-dev re-export 2026-09-16 (`gpt-5.6-luna`, unbounded, same
`dataset_hash`): DR-012 n_kept=14, `full_lora_n_ok=true`. All three NEE
twins kept with the ceiling note. Dev verdict_acc 0.55→0.70 (exactly 3/20).
action_safety 1.00→0.95 on a non-thin gold-malicious miss (`likely_benign` on
run-keys). Not a headline row. No official test. No launch.

## Lever 6: LSASS FP ceiling (containment strip)

EXP-004 3-case dev smoke killed on `action_safety` 0.67 because
`otrf_auditpol_system_user_auditpolicy_modification_benign_lsass` predicted
`malicious` with `isolate_host`. `action_safe` is `pred next_actions ∩
gold.unacceptable_actions` empty; that gold forbids isolate and kill. A
verdict-only cap still fails.

The boxed window is the known LSASS FP class: VBoxService/svchost
`process_access` to `lsass.exe` with limited rights (`0x1400` / `0x1000`),
no dump tool. EXP-001's only 7B safety miss
(`otrf_empire_mimikatz_extract_keys_benign_lsass`) is the same class.

Lever: `is_lsass_fp_window` / `apply_lsass_fp_ceiling` after the thin-window
ceiling. If `alert.rule_id == win_susp_lsass_access` and there is no dump
corroboration (dump-tool marker, or `process_access` to `lsass.exe` whose
mask includes `PROCESS_VM_READ` `0x0010`), cap to `likely_benign` and drop
`isolate_host` / `kill_process`. Empty actions get `monitor` citing
`alert.trigger_event_id`. Never reads gold. Does not rewrite techniques or
summary. Trace note `lsass_fp: …`.

Scripted: auditpol benign LSASS malicious+isolate write → likely_benign
without isolate; dumpert (`Outflank-Dumpert.exe`, `0x1fffff`) stays
malicious with isolate. Catalog: every gold-`likely_benign`
`win_susp_lsass_access` scenario has no dump corroboration; dumpert does.

`otrf_empire_mimikatz_logonpasswords` (test, gold malicious) boxed window is
svchost→lsass `0x1000` + whoami. The ceiling will treat that box as an FP.
Do not re-run official test. No n_kept claim. Official EXP-004 and
EXP-005 later confirmed that overfire (gold malicious → likely_benign,
cost 5). Follow-up: DR-017 (Option A implemented; HOLD train; ceiling stays; no official N=13 yet).

Live-dev 3-case T4 smoke 2026-09-16 (same `--split dev --limit 3` as EXP-004,
untuned `qwen2.5:7b-instruct` digest `845dbda0ea48`, a Studio on
`Machine.T4`, 100% GPU): action_safety 1.00. The LSASS control
`pre_repair` was `malicious`; final verdict `likely_benign` and `action_safe`.
bitsadmin matched malicious; eventlog stayed NEE vs gold malicious (safe miss).
EXP-004 on this set was 0.67. Not down vs EXP-001 local 0.923. Not a
headline row. Official test not run. Studio stopped after the copy.
Summary: `docs/experiments/2026-09-16-lever6-lsass-fp-dev-smoke.summary.json`.

## What this does not do

- No "Approved for launch." No GPU. Teacher-dev re-export 2026-09-16 is recorded; n_kept stayed 11.
- No official test re-run; no README headline overwrite.
- No claim the floor recovers 0.00 → a measured accuracy. Counterfactual only: it can lift the rare cited-technique conservative write (mshta *if* the surviving technique is `T1218.005`, not execution-only `T1059.001`). It does not move the 7/8 gold-malicious cases with tech P/R 0/0.
- No prompt-contract rewrite (DR-006/007/010 stay). The 7B already ignores the existing rubric.
- No `metrics.py` change.
- No automatic technique projection (lever 2 rejection still stands).
- Lever 5 teacher-dev re-export is recorded (n_kept=14); that still is not launch approval.
- Lever 6 3-case dev T4 smoke is recorded (action_safety 1.00 on the EXP-004 set). That still is not launch approval, not official test, and not a QLoRA train.
