# Phase 6: API, Compose, CI, Run Guide

Goal: Production-shaped shell around the investigation loop: FastAPI jobs, Prometheus metrics, Compose (api + Ollama), GitHub Actions CI, run guide.

Out of scope: auth, durable queue/DB, streaming UI (design §10).

## Delivered

| Piece | Location |
|---|---|
| FastAPI app | `src/alert2attack/api/`: `POST/GET /investigations`, `/health`, `/metrics` |
| In-memory jobs | `jobs.JobStore` (queued → running → succeeded\|failed) |
| Chat factory | `factory.default_chat_factory` (`ollama`/`local-7b`/`openai`/`teacher`) |
| Metrics | Prometheus counters/histograms via `prometheus-client` |
| CLI | `alert2attack serve` |
| Compose | `docker-compose.yml`: api + ollama + ollama-init (pull 7B) |
| CI | `.github/workflows/ci.yml`: uv sync, ruff, mypy, pytest |
| Run guide | `docs/RUN.md` |

## Tests

`tests/api/test_api.py`: health/metrics, sync + async investigate with injected `ScriptedChat`, unknown scenario, list jobs.
