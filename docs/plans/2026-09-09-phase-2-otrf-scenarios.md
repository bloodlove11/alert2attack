# Phase 2: OTRF importer, gold scenarios, knowledge expand: Implementation Plan

Goal: Turn real OTRF Sysmon-shaped telemetry into boxed scenarios with gold labels (~24 total: OTRF malicious + authored benign twins + truncated), expand the knowledge base, and ship `alert2attack dataset build` so Phase 3 can investigate real investigation objects.

Architecture: `alert2attack.dataset.otrf` normalizes nxlog-style OTRF JSON lines → `Event`; `alert2attack.dataset.build` downloads (URL+sha256), windows, assigns `ev-NNNN`, writes `manifest.yaml` + `events.jsonl`. Authored scenarios stay hand-written JSONL. Catalog in `datasets/catalog.yaml` lists curated sources. Raw OTRF zips live under `datasets/raw/` (gitignored); committed scenarios hold normalized events plus provenance.

Tech Stack: Python 3.12, `uv`, stdlib (`urllib`, `zipfile`, `hashlib`, `json`), existing Pydantic domain/store/tools, PyYAML, Typer CLI extension.

## Global Constraints

- Python ≥ 3.12, `uv`, `src/` layout, package name `alert2attack`.
- Pydantic v2; `extra="forbid"` on domain/scenario models.
- No network in the default test suite (fixtures under `tests/fixtures/otrf/`).
- Gold never enters `CaseStore`.
- Evidence id grammar unchanged.
- Target ≈24 scenarios; split ≈16 `dev` / ≈8 `test`.
- OTRF origin → gold `malicious`; authored twin → `likely_benign`; truncated → `not_enough_evidence`.

## File structure

| Path | Responsibility |
|---|---|
| `src/alert2attack/dataset/__init__.py` | Public exports |
| `src/alert2attack/dataset/otrf.py` | Map OTRF record → `Event` / `None`; EventID+Channel → `EventKind` |
| `src/alert2attack/dataset/window.py` | Box events to host + time window; assign `ev-NNNN` |
| `src/alert2attack/dataset/build.py` | Download zip, verify sha256, normalize, write scenario skeleton |
| `src/alert2attack/dataset/catalog.py` | Load `datasets/catalog.yaml` |
| `datasets/catalog.yaml` | Curated OTRF entries (id, url, sha256, technique hints, window hints) |
| `datasets/AUTHORING.md` | Rules for authored twins and gold |
| `datasets/scenarios/<id>/` | Normalized scenarios (existing + new) |
| `src/alert2attack/knowledge/data/sigma/*.yaml` | Additional adapted Sigma rules (~6 to 10) |
| `src/alert2attack/cli.py` | Add `dataset build` / `dataset list` |
| `tests/fixtures/otrf/*.jsonl` | Tiny real-shaped OTRF excerpts (no network) |
| `tests/dataset/` | Normalizer, window, build, catalog, split tests |

### Task 1: OTRF to Event normalizer

Files:
- Create: `src/alert2attack/dataset/__init__.py`, `src/alert2attack/dataset/otrf.py`
- Create: `tests/fixtures/otrf/sample_sysmon.jsonl`, `tests/dataset/test_otrf.py`

Interfaces:
- Produces: `normalize_record(raw: dict[str, Any]) -> Event | None`, `EVENT_ID_KIND: mapping`, `parse_otrf_timestamp(value: str) -> datetime`, `host_from_record(raw) -> str`, `pid_int(value) -> int | None`

- [ ] Step 1: Write fixture: 8 to 12 JSONL lines covering Sysmon 1/3/7/10/11/13/22 plus one Security 4698 and one System 7045; include ProcessId as string (OTRF style).

- [ ] Step 2: Write failing tests: process_create maps Image/CommandLine/ParentImage; hashes extract SHA256; unknown EventID returns None; naive UtcTime becomes UTC.

- [ ] Step 3: Implement `otrf.py` and make tests pass.

- [ ] Step 4: Commit `feat(dataset): OTRF nxlog record → Event normalizer`

### Task 2: Window boxing + ev-NNNN assignment

Files:
- Create: `src/alert2attack/dataset/window.py`
- Test: `tests/dataset/test_window.py`

Interfaces:
- Produces: `box_events(events, *, host: str, start: datetime, end: datetime) -> list[Event]` (filter host+window, sort by ts, reassign `event_id` to `ev-0001`…), `assign_evidence_ids(events: list[Event]) -> list[Event]`

- [ ] Step 1: Failing tests: drops other host / out of window; stable sort; ids start at `ev-0001`.

- [ ] Step 2: Implement and commit `feat(dataset): window boxing and stable ev-NNNN assignment`

### Task 3: Catalog + download + `alert2attack dataset build`

Files:
- Create: `src/alert2attack/dataset/catalog.py`, `src/alert2attack/dataset/build.py`, `datasets/catalog.yaml`
- Modify: `src/alert2attack/cli.py`
- Test: `tests/dataset/test_build.py`, `tests/dataset/test_catalog.py`

Interfaces:
- Produces: `CatalogEntry`, `load_catalog(path) -> list[CatalogEntry]`, `download_and_extract(url, sha256, dest_dir) -> Path`, `build_scenario_from_otrf_json(path, *, scenario_id, host, window, alert_seed, out_dir) -> Path`, CLI `alert2attack dataset list`, `alert2attack dataset build <catalog_id> [--out ...]`

- [ ] Step 1: Catalog schema: `id`, `url`, `sha256`, `tactic`, `techniques`, `preferred_host_substring`, `notes`.

- [ ] Step 2: Build from local fixture path in tests (no network). Network download covered by `@pytest.mark.live` or unit-tested with a local zip fixture.

- [ ] Step 3: CLI wires build/list.

- [ ] Step 4: Commit `feat(dataset): catalog, OTRF download+build, CLI dataset commands`

### Task 4: Knowledge expand + AUTHORING.md

Files:
- Create: additional `src/alert2attack/knowledge/data/sigma/*.yaml` (encoded PS already present; add e.g. schtasks, reg run key, certutil download, lsass access, mshta, rundll32: adapted, attributed)
- Ensure `attack_techniques.json` covers all techniques used in gold
- Create: `datasets/AUTHORING.md`
- Test: extend `tests/knowledge/test_base.py`: ≥6 rule slugs; technique set covers catalog techniques

- [ ] Step 1: Add rules + docs + tests; commit `feat(knowledge): more Sigma rules and scenario authoring guide`

### Task 5: Curate ≈24 scenarios with gold + split

Files:
- Create/update: `datasets/scenarios/*/manifest.yaml`, `events.jsonl`
- Modify: `tests/datasets/test_all_scenarios.py`: assert count ≥20, both splits present, provenance fields for `origin: otrf`

Scenario mix (target):
- ~12 malicious (`origin: otrf` preferred; normalized events committed with `source_url` + `source_sha256` in manifest description or new optional `provenance` block: keep YAML compatible: put provenance under `description` / optional free fields only if Scenario allows; prefer `description` text + catalog id in `scenario_id` prefix, or extend Scenario with optional `provenance: {url, sha256, catalog_id}` with `extra` still forbid → add optional `Provenance` model).
- ~8 authored `likely_benign` twins (include Phase 1 SCCM + new)
- ~4 `not_enough_evidence` truncated (include Phase 1)
- Split: mark ~8 as `test`, rest `dev`

Approach: Download curated small OTRF zips from catalog; normalize; choose host with most Sysmon activity; window ± minutes around first suspicious process_create matching technique; write gold from ATT&CK labels; hand-author remaining benign/truncated.

- [ ] Step 1: Extend `Scenario` with optional `Provenance` model (`catalog_id`, `source_url`, `source_sha256`): optional field, default None.

- [ ] Step 2: Build OTRF-derived scenarios; author remaining; assign splits.

- [ ] Step 3: Dataset invariant tests green; commit `data: ~24 gold scenarios (OTRF + authored) with dev/test split`

### Task 6: README Phase 2 status

Files:
- Modify: `README.md`

- [ ] Document `alert2attack dataset list/build`, scenario count, that Phase 2 has no LLM yet.
- [ ] Commit `docs: Phase 2 README: OTRF scenarios and dataset CLI`

## Definition of done

- `uv run pytest` green without network; ruff + mypy clean.
- ≥20 scenarios committed; all three gold verdicts; both splits; OTRF-origin cases present.
- `alert2attack dataset list` works; `dataset build` works offline against a local zip/fixture in tests.
- `AUTHORING.md` exists; ≥6 Sigma rules; ATT&CK covers gold techniques.
- Gold still never enters `CaseStore`.

## What Phase 3 picks up

LangGraph agent (plan → investigate → write), `ChatModel` (Ollama 7B default, teacher, ScriptedChat), budgets, traces, `alert2attack investigate`.
