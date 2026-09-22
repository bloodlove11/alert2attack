# DR-2026-09-17-017: Narrow lever-6 LSASS corroboration (logonpasswords overfire)

Status: Implemented: Option A (soft dump-adjacent skip-ceiling). Not a launch. Official N=13 not run in the implement PR.  
Owner: Evaluator (autopsy), then ML Lead (approved Option A), then implement follow-up  
Date: 2026-09-17  
Related: EXP-004 / DR-015, EXP-005 / DR-016, DR-013 lever 6, `src/alert2attack/agent/lsass_fp.py`, `docs/design/2026-09-16-lsass-fp-ceiling-design.md`, `docs/design/2026-09-17-lever6-narrow-corroboration-design.md`

## Decision

HOLD train. Do not start a targeted cost-1 distill / QLoRA to teach `malicious` on `otrf_empire_mimikatz_logonpasswords`. ML Lead approved Option A only: skip the lever-6 ceiling when boxed events show Empire `-enc` PowerShell and a whoami or C2 child. The ceiling stays. This record does not disable it, loosen DR-012, change `metrics.py`, or authorize GPU. Option B (technique-gated skip) is not implemented.

Implemented in `has_lsass_soft_dump_adjacent_corroboration` (`src/alert2attack/agent/lsass_fp.py`). Do not claim a headline win until ML Lead greenlights official N=13.

## Problem / evidence

Lever 6 (`apply_lsass_fp_ceiling`) caps `win_susp_lsass_access` to `likely_benign` and strips `isolate_host` / `kill_process` unless the boxed store has dump-tool markers or `process_access` to `lsass.exe` whose mask includes `PROCESS_VM_READ` (`0x0010`). Design predicted a miss on the Empire mimikatz logonpasswords test case: the boxed window is svchost→lsass `0x1000` plus `whoami`, not a dump tool. Official N=13 confirmed that overfire on both arms.

| Arm | Scenario | Gold | Pred | Cost | `action_safe` | `pre_repair` |
|---|---|---|---|---:|---|---|
| EXP-004 QLoRA N=14 + levers 1 to 6 (`num_ctx` 8192) | `otrf_empire_mimikatz_logonpasswords` | malicious | likely_benign | 5 | true | suspicious |
| EXP-005 untuned 7B + levers 1 to 6 (`num_ctx` 4096) | `otrf_empire_mimikatz_logonpasswords` | malicious | likely_benign | 5 | true | not_enough_evidence |

Same `dataset_hash 5ffa17a659505a1b`. Summaries: `docs/experiments/2026-09-16-exp004-n14-qlora-test.summary.json`, `docs/experiments/2026-09-17-exp005-graph-only-test.summary.json`. DR-013 / lever-6 design already named this boxed window as an FP under the current predicate.

The ceiling is doing the job it was built for on the benign class. Lever-6 3-case dev T4 smoke (`otrf_auditpol_system_user_auditpolicy_modification_benign_lsass`) held `action_safety` 1.00 after a `pre_repair` malicious write. EXP-004 and EXP-005 both finished official test at `action_safety` 1.00 (3/3 gold `likely_benign` hits, including `otrf_empire_mimikatz_extract_keys_benign_lsass`). Do not throw that away.

EXP-005 also has two other gold-malicious→likely_benign cost-5 misses (`otrf_cmd_mshta_vbscript_execute_psh`, `otrf_empire_wmic_add_user_backdoor`). Those are not this DR. They are not `win_susp_lsass_access` overfire.

## Why distill cannot fix this

The ceiling is a post-verify graph rule. It ignores the writer's verdict and techniques.

1. `has_lsass_dump_corroboration` is a boxed-event predicate (`_DUMP_MARKERS` or LSASS `PROCESS_VM_READ`). It never reads `CaseFile.verdict` or `CaseFile.techniques`.
2. Call site is `InvestigationGraph._apply_verdict_floor` after the verdict floor and thin-window ceiling. Floor can lift a cited T1003.001 write to `malicious`; lever 6 still caps it back to `likely_benign` if the store looks like limited-rights LSASS access.
3. EXP-004 already trained QLoRA on the locked DR-012 keep-set. On this case `pre_repair` was `suspicious`; final was still `likely_benign` cost 5. Teaching the 7B to emit `malicious` + `T1003.001` does not change the store blob, so the ceiling still fires.
4. A targeted cost-1 distill would also train on test shape (this scenario is split `test`) or would chase a graph miss with weights. ML Lead: HOLD train.

## Boxed window (why the current corroboration is empty)

`datasets/scenarios/otrf_empire_mimikatz_logonpasswords/` is `win_susp_lsass_access`, gold `T1003.001`, trigger `ev-0018`.

Present in the box, not dump corroboration today:

- `process_create` `whoami.exe /user` whose parent is `powershell.exe -noP -sta -w 1 -enc <Empire stager>`
- that PowerShell `network_connect` to `10.10.10.5:80`
- svchost → lsass `0x1000` (`ev-0042` / `ev-0043`): the known FP access mask

Absent from the box (and from the decoded `-enc` payload): `mimikatz`, `logonpasswords`, `sekurlsa`, `lsadump`, `PROCESS_VM_READ` to lsass. The decoded stager is AMSI / script-block-logging bypass plus `WebClient.DownloadData(http://10.10.10.5/admin/get.php)` and `IEX`. Adding those dump-tool strings to `_DUMP_MARKERS` does not recover this miss; they are not in the window.

Catalog gold-`likely_benign` `win_susp_lsass_access` scenarios (auditpol, ntds, dllinjection, extract_keys, run-keys, powerview) have no `whoami` / PowerShell `-enc` in the boxed events. Dumpert (`otrf_cmd_lsass_memory_dumpert_syscalls`) already has `Outflank-Dumpert.exe` / `0x1fffff` and is correctly left uncapped.

## Proposed options (hypotheses: non-binding)

Investigate in `src/alert2attack/agent/lsass_fp.py` and the existing LSASS FP design. Pick one narrow predicate in the implement PR after a catalog check. Do not stack all of these.

### Option A: Soft dump-adjacent signals on boxed events (recommended to investigate first)

Extend `has_lsass_dump_corroboration` (or a sibling used only as a *skip-ceiling* gate) so the window is not an FP when it already contains Empire / C2-adjacent process activity next to the LSASS-access alert, for example:

- PowerShell with `-enc` / `-EncodedCommand` and a child `whoami.exe`
- that same encoded PowerShell plus a `network_connect` (C2 child)
- optional: decode `-enc` with the existing deterministic `decode_powershell` and treat Empire stager fingerprints (`/admin/get.php`, AMSI bypass + `DownloadData` + `IEX`) as corroboration

Never read gold. Do not treat `lsass.exe` itself as a marker. Do not rely on literal `mimikatz` / `logonpasswords` cmdline for *this* case (not in the box). Those strings may remain in `_DUMP_MARKERS` for other dumps; they are not the logonpasswords fix.

Why first: this miss is a store-shape problem. A boxed-event predicate matches how lever 6 already works, does not depend on the 7B citing T1003.001, and the current benign_lsass catalog windows lack these signals.

Risk: a future benign LSASS window that also happens to contain encoded PowerShell + whoami would skip the ceiling. Catalog-test that before merge. Keep the predicate conjunctive (encoded PowerShell and whoami/C2), not "any `-enc`".

### Option B: Skip ceiling when the writer already cited grounded T1003.001

Do not apply the ceiling when surviving `CaseFile.techniques` includes `T1003.001` whose evidence ids are in the ledger (same "already cited / grounded" bar as the verdict floor). Never invent the technique. Never hydrate from the Sigma rule (DR-013 rejection still stands).

Why weaker alone: EXP-001 tech P/R on this case was 0/0. EXP-004 `pre_repair` was `suspicious`; EXP-005 `pre_repair` was NEE. If the writer still omits T1003.001, Option B does not fire. If the writer *falsely* cites T1003.001 on a benign_lsass FP, Option B skips the ceiling and can restore the isolate/`action_safety` kill that lever 6 was built to stop. Require grounded evidence ids, and still catalog-test every gold-`likely_benign` LSASS scenario.

### Option C: Combine A as skip-ceiling, keep B out unless A is insufficient

If Option A recovers logonpasswords in scripted tests and leaves benign_lsass capped, stop. Do not add a technique-gated exception unless A fails a real Empire dump path that still lacks `-enc`/whoami/C2 in the box.

## Non-goals

- Disable the LSASS FP ceiling
- Loosen DR-012
- New QLoRA / targeted distill / rank sweep (KILL-SWEEP, KILL-14B)
- Change `src/alert2attack/eval/metrics.py` or headline metric formulas
- Official `--split test` in the implement PR itself (scripted + catalog first; live N=13 only after ML Lead says so)
- Fix EXP-005's mshta / wmic cost-5 misses
- Unconfound EXP-004 vs EXP-005 cost by re-running GPU at matched `num_ctx` (see note below)

## Safety invariant

`action_safety` 1.00 on gold-`likely_benign` `win_susp_lsass_access` must hold:

- Catalog: every gold-`likely_benign` LSASS-access scenario still has no corroboration under the *new* predicate (extend `test_catalog_likely_benign_lsass_alerts_have_no_dump_corroboration`).
- Scripted graph: `test_lsass_fp_write_is_capped_and_containment_stripped` (auditpol benign LSASS malicious+isolate → `likely_benign`, no isolate) stays green. Dumpert stays uncapped.
- Lever-6 3-case dev smoke shape (`--split dev --limit 3`, same set as EXP-004 kill) must remain `action_safety` 1.00 before any official re-run.
- Headline `action_safety` on official N=13 must not go down vs EXP-004 / EXP-005 1.00.

A skip-ceiling path that reintroduces `isolate_host` on `otrf_*_benign_lsass` is a failed implement, even if logonpasswords is no longer cost 5.

## Eval plan (only if later implemented)

Same frozen protocol. No metric formula changes.

| Gate | What | Pass |
|---|---|---|
| Unit + catalog | `tests/agent/test_lsass_fp.py` plus a logonpasswords "soft corroboration present / ceiling skipped" case | green |
| Scripted graph | benign LSASS cap + dumpert keep + logonpasswords not capped when the boxed Empire/whoami tree is present | green |
| Live-dev smoke | same `--split dev --limit 3` as lever-6 / EXP-004 smoke, lever-6 tree | `action_safety` 1.00, LSASS control still safe |
| Official N=13 | same test split, `dataset_hash 5ffa17a659505a1b`, no `--limit` | `otrf_empire_mimikatz_logonpasswords` is not gold malicious → likely_benign cost 5; no regress on benign_lsass safety; headline `action_safety` not down vs 1.00 |

Success is the logonpasswords under-call gone and the safety invariant. Cost may drop because a cost-5 miss left; that is not a reason to retune `metrics.py`. Do not claim a new headline row until that official N=13 exists.

Matched-`num_ctx` EXP-004 vs EXP-005 is out of scope. Do not run GPU for this DR.

## EXP-004 vs EXP-005 cost confound (note only)

EXP-004 official test used Ollama `num_ctx` 8192 (4096 overflowed write on the QLoRA tag). EXP-005 finished at `num_ctx` 4096. Acc/safety still match at 0.54 / 1.00, and both miss logonpasswords the same way, so the overfire is not a context-length artifact. The 1.85 vs 0.77 mean cost comparison is still partly confounded by context size (and by EXP-005's extra mshta/wmic cost-5 misses). Recorded so nobody treats that delta as a pure weights effect. Do not re-run GPU to unconfound it.

## What this does not approve

- Official N=13 live eval / GPU / Ollama in the Option A implement PR
- Training, filter loosen, metric edits, 14B, rank sweep
- Product launch / README headline overwrite before official N=13
- Option B (technique-gated skip)
