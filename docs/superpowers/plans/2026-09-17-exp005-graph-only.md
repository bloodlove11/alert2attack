# EXP-005 graph-only N=13 — implementation plan

**Goal:** Official test of untuned 7B + levers 1–6 so EXP-004 is no longer graph-confounded.

## Global Constraints

- Do not change `src/alert2attack/eval/metrics.py`.
- Do not loosen DR-012.
- Do not train. Do not use `casefile-qlora-n14`.
- KILL-14B. KILL-SWEEP.

---

### Task 1: T4 + Ollama 7B

- [x] Start the Studio on `Machine.T4`
- [x] Install Ollama if needed; pull `qwen2.5:7b-instruct`; confirm digest `845dbda0ea48` and 100% GPU
- [x] Confirm lever-6 eval tree (`lsass_fp.py`)

### Task 2: Official N=13

- [x] `ALERT2ATTACK_LLM_TIMEOUT_S=3600` `OLLAMA_KEEP_ALIVE=-1` `--arm agent-local-7b --split test` no `--limit`
- [x] Recast `num_ctx` 8192 only on context overflow (not needed; finished at 4096)
- [x] Record TRACKER / DR-016 / README; stop Studio (0.54 / 1.85 / 1.00 / 0.85 / 1.00)
