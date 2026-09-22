# EXP-002 technique candidates: design

Status: Approved by "go ahead continue" after EXP-002 lever 2 was proposed.  
Date: 2026-09-12  
Related: `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`

## Problem

The Lightning T4 local-7B run omitted gold techniques on 7/8 gold-malicious
cases. The verdict floor can only act on techniques the writer explicitly
selected and the verifier retained.

## Approaches

1. Dedicated write candidates (chosen). Extract known `attack-T…` ids from
   this run's evidence ledger and render them in a compact write checklist.
   Each id is only a candidate: include it when observed telemetry supports the
   behavior, otherwise omit it.
2. Automatic `TechniqueClaim` projection (rejected). An ATT&CK lookup can be
   speculative. Malicious and NEE twins can look up the same technique, so
   projecting every lookup would convert investigation activity into a finding
   and could trigger the verdict floor incorrectly.
3. Sigma alert-tag projection (rejected). Benign LSASS false positives and
   NEE twins share alert rules with malicious cases. The alert alone is not
   evidence that the ATT&CK behavior occurred.

## Design

Add a pure
`technique_candidates_from_ledger(ledger_ids, knowledge) -> list[str]` helper.
It accepts only ids with the exact `attack-T####[.###]` form, validates them
against the vendored `KnowledgeBase`, deduplicates, and sorts them. Event ids,
Sigma rule ids, malformed ids, and unknown technique ids are excluded.

`InvestigationGraph.write_node` passes the list to `write_user`. The prompt
labels these as candidates, not findings, and requires:

- include a `TechniqueClaim` with its matching `attack-T…` evidence id only
  when telemetry in the tool digest supports the behavior;
- omit speculative candidates;
- never derive a technique from `rule-*` alone.

The model remains responsible for the semantic judgment. The verifier still
checks citations and known technique ids. The existing verdict floor still
sees only techniques the writer selected; this change never mutates a parsed
`CaseFile`.

## Validation and protocol

- Unit-test extraction, sorting, deduplication, unknown ids, and exclusion of
  event/Sigma ids.
- Lock the prompt contract with supported-vs-speculative language.
- Script a graph run that performs an ATT&CK lookup and prove the write call
  receives the candidate.
- Script rejection and prove no automatic claim or verdict lift occurs.
- Run automated tests, Ruff, and mypy.
- Do not spend teacher API budget or run official test for this lever.
  A 2026-09-12 Lightning T4 dev 3-case smoke checked wiring only
  (candidates / `- none` / no false projection / no execution-only floor
  lift). It is not a technique-recall or verdict accuracy claim.
  Record: DR-013.
