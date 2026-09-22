# Lever-6 narrow LSASS corroboration — design

**Status:** Implemented. Option A in `src/alert2attack/agent/lsass_fp.py`. Official N=13 not in this change.  
**Date:** 2026-09-17  
**Related:** DR-017, EXP-004, EXP-005, lever-6 design `docs/superpowers/specs/2026-09-16-lsass-fp-ceiling-design.md`, `src/alert2attack/agent/lsass_fp.py`

## Problem

Lever 6 bought `action_safety` 1.00 on benign_lsass by capping `win_susp_lsass_access` without dump-tool / `PROCESS_VM_READ` corroboration. Official N=13 EXP-004 and EXP-005 both miss `otrf_empire_mimikatz_logonpasswords` (gold **malicious** → pred **likely_benign**, cost **5**, `action_safe` true). Design predicted this: the boxed window is svchost→lsass `0x1000` + Empire `-enc` PowerShell + `whoami`, not a dump binary. Distill cannot fix a post-verify ceiling that ignores techniques. HOLD train.

## Approaches

1. **Soft dump-adjacent skip-ceiling on boxed events (recommended to investigate first).** Treat Empire `-enc` PowerShell plus whoami/C2 child (optionally decoded stager fingerprints via existing `decode_powershell`) as corroboration so the ceiling does not fire. Never read gold. Literal `mimikatz` / `logonpasswords` strings are **not** in this box — do not pretend adding them to `_DUMP_MARKERS` recovers the miss.
2. **Skip ceiling when surviving CaseFile already cites grounded T1003.001 (weaker alone).** Floor can already lift that write to malicious; the ceiling then slams it back. Depends on the 7B naming the technique (EXP-001 P/R 0/0; EXP-004 `pre_repair` suspicious). False T1003.001 on benign_lsass would re-open the isolate kill.
3. **Disable ceiling / loosen DR-012 / new QLoRA / rank sweep / `metrics.py` (rejected).** Non-goals. Safety invariant is the point of lever 6.

## Design

Keep `apply_lsass_fp_ceiling` and the containment strip. Option A adds a sibling skip-ceiling gate `has_lsass_soft_dump_adjacent_corroboration`: encoded PowerShell (`decode_powershell`) **and** a whoami child or pid-linked C2 `network_connect`. Never read gold. Literal `mimikatz` / `logonpasswords` strings are not the fix. Catalog: every gold-`likely_benign` `win_susp_lsass_access` scenario still has no dump or soft corroboration. Scripted: auditpol benign LSASS still caps; dumpert still does not; logonpasswords with the boxed Empire/whoami tree does not cap. Live-dev 3-case smoke and official N=13 remain ML Lead gates — this implement does not claim a headline win.

## Out of scope

- Graph code in the DR-017 docs PR
- GPU / QLoRA / teacher-dev re-export
- Matched-`num_ctx` EXP-004 vs EXP-005 re-run (4096 vs 8192 cost compare is confounded; do not unconfound here)
- EXP-005 mshta / wmic cost-5 misses
