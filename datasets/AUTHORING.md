# Scenario curation rules (Phase 2)

## Goals

Every committed scenario must be investigable with the Phase 1 tool surface, carry honest gold,
and use **real public telemetry** (OTRF / Security-Datasets). Do not hand-author event rows.

## Origins

| Origin | Gold verdict | How events are produced |
|---|---|---|
| `otrf` | `malicious` | Boxed window from an OTRF host capture (`casefile dataset build` / rebuild script). |
| `otrf` | `not_enough_evidence` | Same OTRF capture, truncated to trigger (+ parent when present). Still real events. |
| `otrf` | `likely_benign` | Background slice from an OTRF capture (e.g. `svchost`→LSASS) with no attacker LOLBINs. |

Record `provenance` (`catalog_id`, `source_url`, `source_sha256`) on every committed scenario.

## Rebuild

1. Download curated zips listed in `datasets/catalog.yaml` (or use `/tmp/otrf-dl*`).
2. Run `uv run python scripts/rebuild_otrf_only_scenarios.py` (or `casefile dataset build <id>` for one malicious case).
3. Do not invent JSONL lines. Variants are **windows / filters** over the same downloaded files.

## Splits

- `dev` — prompt/graph iteration.
- `test` — held out; only touched by `casefile eval` (Phase 5). Never tune on test.

## Event hygiene

- Timestamps timezone-aware UTC.
- Stable `ev-NNNN` in timestamp order.
- Alert `trigger_event_id` must exist.
- Prefer ≤48 events per scenario for reviewability.
- Put `GOLD-MARKER-…` in the narrative so tests prove gold never enters SQLite.
