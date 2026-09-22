# Run guide

Local-first EDR investigation agent with CLI, eval, and HTTP API.

## Prerequisites

- Python 3.12+, [`uv`](https://docs.astral.sh/uv/)
- Optional: [Ollama](https://ollama.com) for the default 7B model (`qwen2.5:7b-instruct`)
- Optional: `OPENAI_API_KEY` for the teacher ablation arm

## Install

```bash
uv sync
uv run pytest
uv run ruff check . && uv run mypy
```

QLoRA GPU extras are a separate optional group (not CI, not the API image): `uv sync --group train`. Paths and Lightning env vars: `docs/TRAIN.md`.

## Eval

Offline plumbing smoke (writes `reports/`). Those numbers are never headline metrics:

```bash
./scripts/smoke_eval.sh --split test --limit 1
```

Live arms on a machine with Ollama / `OPENAI_API_KEY`:

```bash
./scripts/smoke_eval.sh --live b0 --split test --limit 3
./scripts/smoke_eval.sh --live local --split test --limit 3
./scripts/smoke_eval.sh --live teacher --split test --limit 3
uv run python scripts/render_eval_table.py reports
```

Live `--live b0` uses the ExpLabs teacher model (`teacher_chat`, e.g. `gpt-5.6-luna` via `ALERT2ATTACK_TEACHER_MODEL`) when `EXPLABS_API_KEY` is set, otherwise Ollama. Scoring protocol and the no-tools B0 path are unchanged.

`ALERT2ATTACK_B0_MODEL` overrides that choice: `auto` (default, the behaviour above), `teacher`, or
`ollama`. Use `ALERT2ATTACK_B0_MODEL=ollama` to run the campaign's `$0` Ollama B0 (Task 2) while a
teacher key is in the environment. A key that is present is not necessarily usable (dead
gateway alias, key scoped to another project), and without the override a present key strands B0 on
an unreachable route. Record which backend produced a B0 row: the per-case `trace.model` in the
report JSON is the source of truth, and Ollama-backed and teacher-backed B0 are different baselines.

`ALERT2ATTACK_OLLAMA_BASE_URL` points `agent-local-7b` (and Ollama-backed `b0`) at a remote Ollama
OpenAI-compatible `/v1`, such as a Lightning Studio GPU or a laptop worker, without changing the arm
name or the `qwen2.5:7b-instruct` tag. Default remains `http://127.0.0.1:11434/v1`. Record the host in
the tracker; do not treat a CPU timeout row as the GPU row.

Live arms (`b0`, `agent-local-7b`, `agent-teacher`) send one tiny preflight completion before the
split is scored, so an unusable endpoint fails immediately, naming the model and base URL, instead
of dying mid-split after partial spend.

Paste the rendered full-N table into the README Results table. Truncated `--limit`
slices are not headline rows. The LoRA/distill discuss gate (DR-011) needs teacher at least equal to
B0 on `citation_post` and `key_pid_recall`, and a strict win over B0 on at least one of
`action_safety` (higher), `mean_cost` (lower) or `verdict_acc` (higher). Ties on citation and
key_pid alone are not enough. Recipe: `docs/plans/2026-09-09-finetune-lora-followup.md`.
Live campaign (EXP-001) and ML Lead freeze: `docs/plans/2026-09-10-live-eval-campaign.md`,
`docs/experiments/TRACKER.md`. Clearing discuss is not a launch. Distill/QLoRA drafting is allowed;
GPU is not. Do not train without an "Approved for launch" note and a Deimos cost OK.

## CLI

```bash
uv run alert2attack scenarios list
uv run alert2attack tool get_alert --scenario otrf_empire_launcher_vbs
uv run alert2attack investigate otrf_empire_launcher_vbs --model ollama
uv run alert2attack eval run --arm agent-local-7b --split test --limit 3
```

Investigation budgets default to unbounded (no 12-tool / 20-LLM / 180s / 8-turn
caps). CLI `0` means unbounded: `--max-tools 0 --max-llm 0 --timeout-s 0 --max-turns 0`.
Restore the old caps with env:

```bash
ALERT2ATTACK_MAX_TOOL_CALLS=12 ALERT2ATTACK_MAX_LLM_CALLS=20 ALERT2ATTACK_TIMEOUT_S=180 \
  ALERT2ATTACK_MAX_INVESTIGATE_TURNS=8 uv run alert2attack eval run --arm agent-teacher --split dev
```

`ALERT2ATTACK_LLM_TIMEOUT_S` (default 1800) is the per-HTTP client timeout, not the
investigation wall-clock budget. B0 still inlines the window with no tools.

Offline / CI scripted investigate:

```bash
uv run alert2attack investigate otrf_empire_launcher_vbs \
  --model scripted --responses-json path/to/responses.json
```

## HTTP API

```bash
uv run uvicorn alert2attack.api.app:app --host 127.0.0.1 --port 8000
```

Without `CONSOLE_PASSWORD_HASH` there is no inbound auth on these endpoints, and the API logs a warning at startup. Set it to require a bearer token on the data routes (see [`web/README.md`](../web/README.md)). Teacher/OpenAI models still need outbound `EXPLABS_API_KEY` or `OPENAI_API_KEY`. Bind loopback for local demos; do not publish the API on a public interface.

- `GET /health`
- `GET /metrics` (Prometheus)
- `POST /investigations`, body `{ "scenario_id": "...", "model": "ollama", "sync": false }`
  - `sync: false` returns `202`, then poll `GET /investigations/{id}`
  - `sync: true` returns `200` with the job and case file (demo)
- `GET /investigations/{id}`
- `GET /investigations`, recent jobs

```bash
uv run alert2attack serve --host 127.0.0.1 --port 8000
```

Example:

```bash
curl -s -X POST localhost:8000/investigations \
  -H 'content-type: application/json' \
  -d '{"scenario_id":"otrf_empire_launcher_vbs","model":"ollama","sync":true}' | jq .
```

## Docker Compose

Pulls `qwen2.5:7b-instruct` on first start (large download). Published ports bind to 127.0.0.1 only (API `8000`, Ollama `11434`). The API has no inbound auth unless `CONSOLE_PASSWORD_HASH` is set, so do not remap these to `0.0.0.0` on a shared host.

```bash
docker compose up --build
```

API: `http://127.0.0.1:8000`. Ollama: `http://127.0.0.1:11434`.

## Teacher (Experiential Labs or OpenAI)

The `teacher` / `agent-teacher` arm uses an OpenAI-compatible API.

Experiential Labs is preferred when `EXPLABS_API_KEY` is set:

```powershell
$env:EXPLABS_API_KEY = "your-explabs-key"
$env:ALERT2ATTACK_TEACHER_MODEL = "gpt-5.6-luna"   # or deepseek-v4-flash / qwen3.8-27b
uv run python scripts/smoke_eval.py --live teacher --split test --limit 3
```

For OpenAI cloud, if you have no ExpLabs key, set `OPENAI_API_KEY` instead.

Optional override: `ALERT2ATTACK_TEACHER_BASE_URL` (default ExpLabs OpenAI-compatible `/v1` endpoint).

A present `EXPLABS_API_KEY` does not imply a positive credit balance. On 2026-09-15, with
platform credits exhausted, `gpt-5.6-luna` still completed at `cost=0.0` (promotional `free`
badge). `deepseek-v4-flash` (`free` badge) and `qwen3.8-27b` (`allowance` badge) returned 429
`insufficient_credits`. Probe the slug before a live arm; do not assume the catalog badge
means the call is free at $0.

## Hardware note

Default model is `qwen2.5:7b-instruct` for ~8 GB VRAM (e.g. RTX 4060 mobile).

## Windows note

Some OTRF scenario files contain real malware-like command lines (e.g. encoded PowerShell /
`regsvr32`). Windows Defender may block reading them (`OSError: [Errno 22]`). Mitigations:

1. Add a Defender exclusion for your clone (e.g. `C:\src\alert2attack`)
2. Or delete / quarantine only the blocked folder under `datasets/scenarios/`
3. Eval loads by split first, so a blocked dev file should not block `--split test`

Prefer cloning to `C:\src\...`, not Desktop/OneDrive.
