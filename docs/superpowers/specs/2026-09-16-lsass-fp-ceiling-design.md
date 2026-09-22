# LSASS false-positive ceiling — design

**Status:** Implemented. Graph lever 6. Live-dev smoked 2026-09-16 (action_safety 1.00 on the EXP-004 3-case **dev** set). Official EXP-004 / EXP-005 confirmed the predicted logonpasswords miss. Narrow corroboration follow-up is **DR-017** (Option A implemented in a follow-up; official N=13 not re-run here).  
**Date:** 2026-09-16  
**Related:** EXP-004 smoke kill (LSASS FP), EXP-001 7B `action_safety` 0.923, lever 5 thin-window, DR-012 (locked), DR-017

## Problem

EXP-004 3-case **dev** smoke killed because `action_safety` 0.67: `otrf_auditpol_system_user_auditpolicy_modification_benign_lsass` predicted `malicious` vs gold `likely_benign`. `action_safe` is `pred next_actions ∩ gold.unacceptable_actions` empty; that gold forbids `isolate_host` and `kill_process`. A verdict-only cap leaves containment in place and still fails the kill.

The boxed window is the known LSASS FP class: `vboxservice.exe` / `svchost.exe` `process_access` to `lsass.exe` with limited rights (`0x1400` / `0x1000`). No dump tool. EXP-001’s only 7B safety miss (`otrf_empire_mimikatz_extract_keys_benign_lsass`, pred `suspicious`) is the same class.

Gold-malicious `otrf_cmd_lsass_memory_dumpert_syscalls` (dev) has `Outflank-Dumpert.exe` and `process_access` to `lsass.exe` with `0x1fffff`. That must **not** cap.

`otrf_empire_mimikatz_logonpasswords` (test) is also `win_susp_lsass_access` but the boxed window is `svchost` → `lsass` `0x1000` plus `whoami` — no dump tool. The ceiling will treat that box as an FP. Official EXP-004 / EXP-005 confirmed gold malicious → likely_benign cost 5. **DR-017** proposes a narrow corroboration follow-up; this spec is unchanged.

n_kept=14 already clears N≥12. This lever is safety, not another filter chase.

## Approaches

1. **LSASS-alert ceiling without dump corroboration, including containment strip (chosen).** If the alert rule is `win_susp_lsass_access` and the boxed store has no dump corroboration, cap `{malicious, suspicious, not_enough_evidence}` → `likely_benign` and drop `isolate_host` / `kill_process`. Never read gold. Never invent techniques.
2. **Verdict-only cap (rejected).** Smoke kill is action_safety; leaving `isolate_host` still fails.
3. **Prompt “don’t isolate LSASS FPs” (rejected).** 7B ignores the write rubric.
4. **Retrain QLoRA on n_kept=14 (rejected as first step).** Smoke died on this FP class; the three NEE-twin traces are a different cluster.
5. **Loosen DR-012 / change `metrics.py` / official test (rejected).**

## Design

### Dump corroboration

`has_lsass_dump_corroboration(events) -> bool` if any boxed event has:

- dump-tool marker in `image` / `target_image` / `target_path` / `command_line` / `details`: `dumpert`, `mimikatz`, `sekurlsa`, `procdump`, `nanodump`, `comsvcs`, `ntdsutil`, `lsassy`, `pypykatz`, `hashdump`, `lsadump`, `minidump`, `outflank` — **not** `lsass.exe` itself
- or `process_access` whose `target_image` ends with `lsass.exe` and `details` parses as a hex access mask that includes `PROCESS_VM_READ` (`0x0010`)

Limited `0x1000` / `0x1400` access from `svchost` / `VBoxService` is **not** corroboration.

### Ceiling

`apply_lsass_fp_ceiling(case_file, events, alert) -> CaseFile`:

- If `alert.rule_id != win_susp_lsass_access`, unchanged.
- If dump corroboration, unchanged.
- Else set verdict to `likely_benign` when it is not already; drop `isolate_host` and `kill_process`; if `next_actions` is then empty, append `monitor` citing `alert.trigger_event_id`. Append one stable open-question note. Do not rewrite techniques, summary, or scope.

### Call site

`InvestigationGraph.verify_node` after the thin-window ceiling (passed and degraded). Trace note `lsass_fp: <old> → likely_benign` when the verdict changes.

### Out of scope

- No `metrics.py`. No official `--split test`. No DR-012 change. No GPU / QLoRA. No teacher-dev re-export required (N already 14).

## Validation

- Unit: FP window caps malicious+isolate → likely_benign without isolate; dumpert 0x1fffff / tool name does not cap; non-LSASS alert unchanged.
- Catalog: every gold-`likely_benign` `win_susp_lsass_access` scenario has no dump corroboration; dumpert does.
- Scripted graph: auditpol benign LSASS write stays `likely_benign` without `isolate_host`; dumpert stays `malicious` with `isolate_host`.
- Existing floor / thin-window tests stay green.
