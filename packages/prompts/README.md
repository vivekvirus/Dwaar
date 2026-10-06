# packages/prompts: versioned prompts, JSON-schema outputs and evaluation sets (AI-SYS-07)

Everything the AI gateway sends to a model, and everything used to evaluate it, is a file in this repository. Read `docs/adr/0023-ai-gateway-and-guardrails.md` first.

**HONESTY.** No real model has run. The only provider available here is a deterministic SIMULATOR, so nothing in this package measures model
quality. Every report prints: *"Targets are release gates, NOT achieved results."* and *"Simulator provider: no model quality is measured."*

## Layout

```
registry.yaml                     feature -> active version, optional canary version + percent (society bucket = sha256(society_id) mod 100)
<feature>/vN/prompt.md            system prompt (data is always inside <untrusted_data> blocks; the model has no tools, credentials, URLs or SQL)
<feature>/vN/output.schema.json   JSON Schema of the ONLY output the gateway accepts (additionalProperties: false: a model cannot add a command or a target)
<feature>/vN/meta.yaml            feature id, schema version, risk class, tier, status, eval sets, changelog
notification_health/guidance.json deterministic AI-R06 catalogue (manufacturer x issue -> steps, en/hi/mr; hi/mr machine-drafted; NOT verified on devices)
evals/                            held-out, SYNTHETIC evaluation sets (below)
```
Features: translation (AI-R07), poll_wording (AI-C12), notice_drafter (AI-C01), voice_complaint (AI-R02), ticket_triage (AI-F01), shift_handover (AI-G08).

## Changing a prompt or a model (AI-SYS-07)

1. add `vN+1` next to the active version (never edit a released version: its sha256 is in `ai_runs.prompt_version`'s history);
2. `python -m dwaar_ai_gateway.evals.regression --feature AI-R07 --candidate v2` (schema check, access/injection set with the candidate active, PII gate);
3. a reviewer sets `canary: v2` and `canary_percent` in `registry.yaml`; societies are bucketed by a hash of their id;
4. roll back one society or one feature with no deploy: `PUT /v1/ai/controls` (`prompt_version_pin`, `state: disabled`) or the society kill switch.
A real-model change additionally needs a run of the reviewed sets with a real provider; that has not happened.

## Evaluation sets (`evals/`, PRD 11.3). All synthetic. Never edit a frozen set to fit the code under test.

| Set | What exists | PRD minimum / gate | Status |
|---|---|---|---|
| `pii/golden.jsonl` | 500 samples, 563 identifiers, 323 decoys; en/hi/mr, Devanagari digits, spacing, hyphenation; sha256-pinned in `MANIFEST.json`; `golden_unseen_seed20261107.jsonl` is a second sample | 500 samples; recall >= 99% | runnable; measured numbers in the ADR |
| `access_injection/cases.jsonl` | 200 attack cases + 20 benign controls (cross-society/unit/role, lifecycle, malicious documents, confirmation tampering, class X) | 200 cases; zero disclosures or tool executions | runnable in CI with the compromised-model double |
| `classification/cases.json` | 81 tickets (27 per language), emergencies marked | 500 per language; macro-F1 >= 0.90 | scaffold; author-labelled; circular for the simulator |
| `voice/cases.json` | 19 location transcripts against a fixed unit directory | 100 recordings per language; >= 95% critical fields | scaffold; NO recordings, ASR never run |
| `translation/cases.json` | 8 notices | 200 per language pair; >= 95% meaning preservation | scaffold; meaning preservation NOT measured |
| `groundedness`, `ocr`, `matching` | empty placeholders | see file | not M1: not built |

Every set records `annotator_agreement` (`status: not_measured`): real sets need independent annotators and a measured agreement.
Regenerate with `evals/pii/build_golden.py`, `evals/access_injection/build.py`, `evals/build_sets.py` (deterministic seeds; a changed output is a NEW version, never an edit).
Run everything: `python -m dwaar_ai_gateway.evals`.
