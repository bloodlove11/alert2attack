# Scenario curation rules

## Goals

Every committed scenario must be investigable with the Phase 1 tool surface, carry honest gold,
and use real public telemetry (OTRF / Security-Datasets). Do not hand-author event rows.

## Origins

| Origin | Gold verdict | How events are produced |
|---|---|---|
| `otrf` | `malicious` | Boxed window from an OTRF host capture (`alert2attack dataset build` / rebuild script). |
| `otrf` | `not_enough_evidence` | Same OTRF capture, truncated to trigger (+ parent when present). Still real events. |
| `otrf` | `likely_benign` | Background slice from an OTRF capture (e.g. `svchost` touching LSASS) with no attacker LOLBINs. |

Record `provenance` (`catalog_id`, `source_url`, `source_sha256`) on every committed scenario.

## Rebuild

1. Download curated zips listed in `datasets/catalog.yaml` (or use `/tmp/otrf-dl*`).
2. Run `uv run python scripts/rebuild_otrf_only_scenarios.py` (or `alert2attack dataset build <id>` for one malicious case).
3. Do not invent JSONL lines. Variants are windows or filters over the same downloaded files.

## Splits

- `dev` for prompt and graph iteration.
- `test` is held out; only `alert2attack eval` touches it. Never tune on test.

## Event hygiene

- Timestamps timezone-aware UTC.
- Stable `ev-NNNN` in timestamp order.
- Alert `trigger_event_id` must exist.
- Prefer ≤48 events per scenario for reviewability.
- Put `GOLD-MARKER-…` in the narrative so tests prove gold never enters SQLite.
