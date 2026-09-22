# Research status (internal / experiment ops)

Headline numbers and the public loop live in the root [README](../README.md). This note is the demoted ops log: train hold, GPU gates, and host provenance. Do not treat it as a product roadmap.

## Done (v1)

Boxed store and tools, OTRF dataset, investigation graph, citation verifier, eval harness, HTTP API + Prometheus, CI, README results table, graph levers 1–6, one QLoRA, graph-only control, DR-017 Option A on main.

This is a measured prototype, not a shipped product. There is no case UI, no multi-host hunting, no 14B default, and no claim that "the 7B now names every technique." 6 of 13 EXP-004 cases still miss gold.

## Frozen / HOLD train

- HOLD train: no new QLoRA, no targeted distill, no loosening DR-012.
- `metrics.py` stays frozen.
- GPU jobs (train or official live eval) need a human gate (historically: ML Lead plus cost OK). Agents do not launch them.

## Next

- Official N=13 re-measure, pending a human GPU/cost gate, so we can say whether Option A recovered the `otrf_empire_mimikatz_logonpasswords` miss without hurting benign LSASS safety.
- Leftover misses that are not that ceiling: gold-malicious cases that still land on "suspicious" because techniques are omitted.

## Frozen headline host notes

These host names are for reproducing the recorded rows, not for the public one-liner.

| Arm | Host / hardware (as recorded) | When | Notes |
|---|---|---|---|
| `b0` | Cloud Agent CPU, Ollama `qwen2.5:7b-instruct` | 2026-09-11 | No tools |
| EXP-001 | Lightning Studio Tesla T4, same tag, digest `845dbda0ea48`, 100% GPU | 2026-09-12 | Untuned, old graph |
| EXP-005 | Same Studio T4 + digest, `num_ctx` 4096 | 2026-09-17 | Untuned + levers 1–6 |
| EXP-004 | Same Studio T4, `casefile-qlora-n14`, `num_ctx` 8192, id `0a01b00360d5` | 2026-09-16 | QLoRA + levers 1–6 |
| Teacher | `gpt-5.6-luna` | — | Ceiling, not the product |

Dense experiment rows: [`docs/experiments/TRACKER.md`](experiments/TRACKER.md).
