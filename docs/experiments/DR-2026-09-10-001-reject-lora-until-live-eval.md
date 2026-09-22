# DR-2026-09-10-001: Reject LoRA until live eval

Status: Rejected (no launch).  
Owner: ML Lead  
Date: 2026-09-10  
Related: `docs/design/2026-09-10-ml-experiment-strategy-design.md`, `docs/experiments/TRACKER.md`

Update 2026-09-11: Launch rejection stands. The *discuss* inequalities in "What would reverse this" item 2 are superseded by DR-011 (`docs/experiments/DR-2026-09-11-011-lora-discuss-gate.md`). Discuss ≠ launch.

## Decision

Do not launch LoRA / QLoRA / any weight-update job. Do not spend teacher API budget until a human approves EXP-001.

The 2026-09-09 follow-up recipe is not "Approved for launch."

## Context

- Design §9 and the follow-up plan already gated training on: Phase 5 green and `agent-teacher` beats `b0` on citation + scope/key-pid recall.
- Phase 5 harness exists. Live Results table is empty. No `reports/*.json` in git (directory gitignored) and none on this workspace.
- Therefore the gate is unmeasured, not passed.

## Evidence against launching now

1. No baseline. Cannot report a LoRA delta vs untuned 7B or vs teacher.
2. Distill is empty of SFT targets for teacher runs. `src/alert2attack/eval/distill.py` `scripted_prompt_messages()` only reads `ScriptedChat.calls`. `src/alert2attack/eval/runner.py` passes that into `distill_record`. Teacher / Ollama clients do not record messages. `LlmCallRecord` stores `prompt_chars` / `response_chars` only (`src/alert2attack/agent/trace.py`). The follow-up text ("each line: chat messages") does not match the code.
3. Eval CLI cannot load a LoRA tag. `alert2attack eval run` has no `--model` (`src/alert2attack/cli.py`). Follow-up step 4 is not executable. Local arm uses `ALERT2ATTACK_OLLAMA_MODEL` only.
4. N is tiny. Dev = 20 investigations; filters (`passed|repaired`, citation_post ≥ 0.9, not exhausted) will cut that. Strategy kill line: do not train if filtered N < 12.
5. Confounded B0 (noted, not changed). Headline `b0` is 7B single-shot. Teacher is a different model with tools. That does not block EXP-001; it blocks over-claiming "the loop works" if only teacher > 7B-B0. Protocol stays frozen.

## What would reverse this

All of:

1. EXP-001 full-N test reports for `b0`, `agent-local-7b`, `agent-teacher` in README (live, not scripted).
2. Gate: teacher citation post and key-pid recall strictly above B0 on that split / `dataset_hash`.
3. PLUMB-DISTILL merged: teacher JSONL contains real tool-call transcripts.
4. Filtered dev N ≥ 12.
5. Human approval of API spend (EXP-003) and of GPU/time (EXP-004).
6. A new decision record with an explicit Approved for launch block: config table, data hash, expected hours, expected cost.

## Not in this decision

- No eval metric change.
- No gold rewrite (empty `key_pids` on one test scenario is logged, not fixed here).
- No training code added.
