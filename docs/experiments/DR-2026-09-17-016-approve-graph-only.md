# DR-2026-09-17-016: Approve graph-only N=13 control (untuned 7B + levers 1 to 6)

Status: Official N=13 recorded (0.54 / 1.85 / 1.00 / 0.85 / 1.00). No QLoRA. No train.  
Owner: user "go ahead" 2026-09-17 after EXP-004 official N=13 (graph-confounded).  
Related: EXP-005, EXP-004 / DR-015, EXP-001, DR-013 lever 6 3-case dev smoke (`action_safety` 1.00)

## Why

EXP-004 (`casefile-qlora-n14` + levers 1 to 6) is 0.54 / 0.77 / 1.00 / 0.96 / 1.00. EXP-001 untuned on the pre-lever graph is 0.00 / 1.62 / 1.00 / 0.46 / 0.92. Those two rows are not a weights-only delta. The 3-case dev slice already tied QLoRA and untuned+lever 6 on accuracy (0.67). This control isolates the graph.

## Approved for launch

| Knob | Value |
|---|---|
| Student | Ollama `qwen2.5:7b-instruct` digest `845dbda0ea48` (untuned; not `casefile-qlora-n14`) |
| Graph | levers 1 to 6 (same tree as EXP-004 eval) |
| Split | test, N=13, no `--limit` |
| `dataset_hash` | `5ffa17a659505a1b` |
| GPU | Lightning Studio `Machine.T4` |
| HTTP timeout | `ALERT2ATTACK_LLM_TIMEOUT_S=3600` |
| Keep-alive | `OLLAMA_KEEP_ALIVE=-1` |
| Caps | off (unbounded) |
| Kill | `action_safety` down vs EXP-001 local 0.923; context overflow without recast; wall > 4 h with GPU idle |

3-case dev smoke of this exact setup already held `action_safety` 1.00 (2026-09-16 lever-6 T4 smoke). Official test is allowed. Do not train. Do not loosen DR-012. Do not change `metrics.py`. KILL-14B. KILL-SWEEP.

## Measured (2026-09-17)

Official `--split test` N=13, untuned `qwen2.5:7b-instruct` digest `845dbda0ea48`, lever-6 tree, `ALERT2ATTACK_LLM_TIMEOUT_S=3600` `OLLAMA_KEEP_ALIVE=-1`. START `2026-09-17T00:26:11Z` EXIT:0 `2026-09-17T00:45:48Z`. `ollama ps` 100% GPU CONTEXT 4096. Studio Tesla T4 then stopped. Same `dataset_hash 5ffa17a659505a1b`.

| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid | Action safety |
|---|---|---:|---:|---:|---:|---:|---:|
| EXP-001 untuned 7B | test | 13 | 0.00 | 1.62 | 1.00 | 0.46 | 0.92 |
| EXP-005 untuned + levers 1 to 6 | test | 13 | 0.54 | 1.85 | 1.00 | 0.85 | 1.00 |
| EXP-004 QLoRA N=14 + levers 1 to 6 | test | 13 | 0.54 | 0.77 | 1.00 | 0.96 | 1.00 |
| EXP-001 teacher | test | 13 | 0.54 | 0.77 | 1.00 | 0.85 | 1.00 |

7/13 gold hits (2/8 malicious, 3/3 likely_benign, 2/2 NEE). All 13 `action_safe`. Budget exhaustion 0.00, mean tools 5.2. Acc/safety vs EXP-001 are the graph. QLoRA is the cost cut (1.85→0.77) and extra key-pid (0.85→0.96). Same hit count as EXP-004, 9/13 the same cases. Three gold-malicious→likely_benign cost-5 misses (`otrf_cmd_mshta_vbscript_execute_psh`, `otrf_empire_mimikatz_logonpasswords`, `otrf_empire_wmic_add_user_backdoor`). Not a product launch. Summary: `docs/experiments/2026-09-17-exp005-graph-only-test.summary.json`.

## What this does not approve

- Another QLoRA / rank sweep / 14B
- Training on test
- Replacing EXP-001 or EXP-004 rows (this is an added control row)
- A new graph lever
