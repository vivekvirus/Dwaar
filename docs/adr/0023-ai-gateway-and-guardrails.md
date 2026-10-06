# ADR-0023: AI gateway, guardrails, validated proposals and the M1 AI features (slice 4)

- Status: accepted (with the open items under "Not verified")
- Date: 2026-10-06
- Deciders: Viz (owner), build team (slice 4: AI)
- Related: PRD 10 (10.1 pipeline, 10.2 classes A/B/C/X, AI-SYS-01..09, G1..G12, 10.5 routing), 11 (catalogue, 11.2, 11.3 gates, 11.5 excluded AI), 12.1/12.4,
  8.2 (`ai_runs`, `action_proposals`), AT-25/26/27/28/29, NFR-13, D-18/D-19, SEC-07/SEC-10, PRIV-14/15, ARCH-05, INV-03, INV-05, INV-06;
  ADR-0004 (RLS), ADR-0005 (audit/outbox/idempotency), ADR-0006 (module registry/authz), ADR-0011 (permissions);
  code: `services/ai-gateway/dwaar_ai_gateway`, `services/api/dwaar_api/modules/ai`, migrations `0700-0702`, seed step `s700_ai.py`,
  `packages/prompts`, `packages/i18n/locales/*/ai.json`; tests: `services/ai-gateway/tests/unit`, `tests/integration/ai`, `tests/acceptance/test_at25*,26*,29*`.

## HONESTY FIRST

No API key and no GPU exist in this environment. Every model path runs through a deterministic, labelled SIMULATOR (`simulation=true`: keyword rules
and fixed templates; its "translations" are literally prefixed `[SIMULATED <lang> translation]`). **No model quality was measured.** The PRD
targets (recall >= 99%, macro-F1 >= 0.90, >= 95% critical fields, ...) are release gates, not results; every report prints that sentence and
"Simulator provider: no model quality is measured". The Anthropic adapter exists, is disabled without `DWAAR_AI_ANTHROPIC_API_KEY`, and has
only ever run against a mocked HTTP transport.

## Decisions

### 1. Two layers: a library with no database, and a module that owns persistence and execution

`dwaar_ai_gateway` (pure Python; no DB handle, no session, no credential except the provider's own key inside its adapter) does: policy, redaction,
prompt loading, the provider call behind a 15 s boundary, output validation and proposal assembly. `dwaar_api.modules.ai` does: the `/v1/ai`
routes, availability (kill switch, feature switch, budget) from the database, `ai_runs`, `action_proposals`, confirmation and the deterministic
execution of confirmed commands. The gate control path (`services/edge`, the visits and edge modules, the guard app) imports neither (a test scans
the sources; no route outside `/v1/ai` depends on the AI runtime: a test walks every route's dependencies). The model boundary is a **logical**
boundary: one worker thread that receives one immutable request (server instruction + sanitised, redacted data) and nothing else. It is not an
OS sandbox; running the gateway as its own process with egress limited to the provider host is a deployment step (accepted risk).

### 2. Providers (D-18)

`Provider` protocol; adapters: **simulator** (local/test only; refused elsewhere), **anthropic** (official SDK, `max_retries=0` because the gateway
owns the 15 s budget, structured output via `output_config.format = json_schema`, no sampling parameters, no `thinking` field, no tools, system
prompt in `system`, all data inside `<untrusted_data>` blocks). Model ids are exactly PRD D-18: `claude-haiku-4-5-20251001` (extraction,
classification, short translation <= 600 chars), `claude-sonnet-5-5` (drafting, longer translation), `claude-opus-5-5` only for features listed in
`GatewayConfig.escalation_features` (empty: "only where Sonnet fails evaluation"). Cost is integer paise from measured tokens at an ASSUMED
USD/INR rate (`DWAAR_AI_USD_INR`, default 85, [VERIFY]); simulator runs cost 0 (a DB CHECK forbids a cost on a simulation row).
*Deviation from the SDK guide:* no server-side `fallbacks` and no automatic switch to another model. Routing a declined request to a different model is a
data-processing decision the privacy owner has not approved (D-18 terms are `[VERIFY]`); a refusal is `ProviderError('refused')` and the user gets the
ordinary form. The registry shows `not configured: DWAAR_AI_ANTHROPIC_API_KEY is not set` / `... python package 'anthropic' is not installed` to
**authorised admins only** (`GET /v1/ai/providers`, secretary/org_admin, sensitive); residents see only the disclosed sub-processor, without any variable name.
The SDK is an optional extra of `services/ai-gateway` (`uv sync --extra anthropic`); `uv.lock` was refreshed under flock (anthropic 1.11.0, httpx2).
ASR (AI-R02): an `AsrAdapter` interface, a labelled simulated ASR (the 'audio' is `SIMASR1:` + the transcript) and an honest `not_configured`
entry for self-hosted faster-whisper (D-19, blocked-external). 60-second cap, explicit per-request speech consent, audio never stored.

### 3. Pipeline (PRD 10.1) and what each layer prevents

1. authenticated request: society, person, role and unit scope come from the server-side grants (`require("ai.use")`, UNIT scope; ADR-0006), never from a body or token claim;
2. feature and role check (`FeatureSpec.roles`), then **availability** from the database: kill switch, per-feature switch, budget (`society_quotas.ai_requests_per_day`, default 0 = AI off; optional per-feature daily limit). Unavailable means a 200 with `status=unavailable` and a `fallback` object (`kind=ordinary_form`, `blocks_user=false`, `upsell=false`), no model call, an `ai_runs` row with `outcome=abstained`;
3. **scoped retrieval** (`policy.authorise_sources`): every candidate document is re-checked for society, status (deleted/superseded/archived excluded), role visibility and unit coverage, whatever the retrieval layer returned; excluded text is shingle-fingerprinted;
4. **sanitise, diagnose, redact**: control and bidi/zero-width characters stripped (ZWJ/ZWNJ kept for Devanagari), delimiter spoofing neutralised, size caps, injection patterns recorded as CODES (a diagnostic: nothing depends on it), PII tokenised with request-scoped tokens `⟦PHONE:<nonce>:<n>⟧`;
5. **model boundary** with the 15 s timeout; any provider failure becomes `unavailable` with the ordinary path;
6. **output validation**: safe JSON parse, JSON Schema (`additionalProperties: false`), tool allow-list (every M1 feature allows no tool; any tool call rejects the output), no active content or URL the input did not contain, no raw identifier the request did not send, no foreign/forged token, no echo of excluded documents, system-prompt canary, feature checks (ids the model cites must be authorised ids; no invented entries/exits in a handover);
7. deterministic **finish**: safety flags recomputed by rules (emergency words, legal/safety text, threatening language) so a model that misses one cannot lower the flag; re-identification for the authorised caller only; AI-SYS-08 labels;
8. a **proposal** whose command is fixed by the server's feature registry (never by the model: a model field naming `gate.open` is schema-invalid), with target ids and versions resolved by the server, an expiry and a payload hash.

Execution is separate: `POST /v1/ai/proposals/{id}/confirm` re-derives the role NOW, re-reads every target version, re-checks switches, checks expiry and
the hash (computed over command, class, payload, targets, versions, actor, society and expiry; recomputed from the stored row so tampering is caught),
validates the user's edits, then runs the command inside the same transaction as the proposal's own audit and outbox rows (`mutation()`), under `Idempotency-Key`
and a row lock (two simultaneous confirmations execute once). Failures are PRD 12.2 codes: stale role or target = 409 `stale_version` with
`details.new_proposal_required = true` (AT-26), expiry = 409 `request_expired`, second decision = 409 `already_decided`, hash mismatch = 422
`policy_violation`, another person's proposal = 404. *Budget at confirmation:* confirming makes no model call and costs nothing, so an exhausted budget does NOT block a user's own draft
(declining or exhausting AI never reduces service); the kill switch and the per-feature switch DO stop open proposals. This is the one place where "re-checks budget"
is interpreted rather than applied literally.

### 4. Permission class X and excluded AI as data, enforced three times

* `guardrails.CommandRegistry` cannot hold an executable class-X command, refuses a non-X command whose first segment is a forbidden domain
  (gate, payment, vote, journal, tax, export, rights, fine, service, access, bill, settlement, ledger), and the gateway refuses to start if a feature names such a command;
* `action_proposals` admits only risk classes A/B/C and a CHECK rejects those command domains: a class-X proposal cannot be stored;
* a stored proposal is immutable except its decision columns (column-level grants) and a decided proposal can never change state (trigger).
`EXCLUDED_AI` (PRD 11.5) is data scanned by tests across feature ids and names, command names, the gateway config fields, every JSON schema property (prompts, inputs,
request bodies), every `/v1/ai` OpenAPI path and every `DWAAR_AI_*` environment name: there is no switch to turn on. The controls route answers 422 for an excluded capability
name and 400 for any unknown member. G1..G12 each have a named test (`tests/integration/ai/test_guardrails.py`); G7/G10 bind features that are not M1 (none registered).

### 5. PII redaction (AI-SYS-05) and what was measured

Detects email, GSTIN, PAN, IFSC, vehicle plates (state-code checked, BH series), bank account numbers (only with an account keyword or an IFSC nearby, not after UTR/ref/invoice words),
mobile phones (6-9 + 9 digits, +91/91/0 prefixes, separators), Aadhaar (not starting 0/1, 4-4-4 or contiguous), Devanagari/full-width/Arabic-Indic digits normalised 1:1.
UUIDs are never personal data. Names and addresses are NOT detected here (minimised by never sending them); a bare account number with no keyword is NOT detected.
The 500-sample golden set (563 identifiers, 323 decoys; en/hi/mr, Devanagari digits, spacing, hyphenation) was generated and pinned (sha256) BEFORE the redactor existed.
**Measured:** first run 95.03% recall (535/563), 0.62% false-positive rate on decoys (2/323). The misses were real redactor bugs (a `+` prefix claimed by the Aadhaar pattern; a lower-case
`g` missing from the PAN class; accounts swallowed by the Aadhaar/phone patterns; UTR numbers matched as accounts), fixed in the redactor, never in the set. Afterwards: 100% (563/563),
FPR 0% on v1, and 100%/0% on a second set from another seed (574 identifiers, 338 decoys) generated and measured once with no redactor change after. Because v1 was used to find the bugs it is no
longer held-out; the synthetic generator's templates are limited, so 100% on it is a statement about these shapes, not about all real Indian text. The gate is >= 99%.

### 6. Prompt-injection and exfiltration evaluation (AT-25, PRD 11.3)

`packages/prompts/evals/access_injection/cases.jsonl`: 200 attack cases (40 cross-society, 30 cross-unit, 30 cross-role, 15 deleted/superseded/archived, 45 malicious documents across six
features incl. Hindi/Marathi and zero-width tricks, 25 confirmation-tampering, 15 class-X/unknown commands) + 20 benign controls. Every gateway case runs with
`CompromisedProvider`, a model that obeys every injected instruction, leaks everything it saw plus secrets it was never given, calls tools, emits URLs/markdown images/HTML, claims
commands and forges ids. **Result: 0 unauthorised disclosures, 0 tool executions, 0 class-X executions, 0 over-blocked controls.** To prove the harness is not vacuous, removing scoped retrieval makes
115 of 200 cases fail (181 disclosures) and reducing output validation to a JSON parse makes 50 fail. The set was authored by the same team as the defences; it shows the layers hold against these attacks
with a hostile model, not independent red-team assurance. **Known limit:** free text the model invents from nothing (never in its input, not PII-shaped, not an excluded document's text) cannot be
detected; what keeps private data away from the model is scoped retrieval, not output inspection.

### 7. Failure behaviour (AI-SYS-06, NFR-13, AT-29)

15 s default timeout (configurable down for tests) in a worker thread; an overrunning call is abandoned. Outage/timeout/refusal/rate-limit return the ordinary-form fallback at once;
budget exhaustion, kill switch and feature disable return it without calling the model; per-society and per-feature controls (and a prompt-version pin = rollback) change at once with no deploy, audited, with an outbox event.
The deterministic assistant (AI-R06) costs nothing, ignores the budget and obeys the kill switch. Latency is recorded per run; `GET /v1/ai/status` reports p50/p95 of the last 200 runs and how many were simulated (INV-12).
*Known cost:* the model call happens inside the idempotent request transaction (so a replay never calls the model twice); a slow provider holds one pooled connection for up to the timeout.

### 8. Prompts, schemas, regression and canary (AI-SYS-07)

`packages/prompts/<feature>/vN/{prompt.md, output.schema.json, meta.yaml}` + `registry.yaml` (active, canary version, canary percent; society bucket = sha256 mod 100). `python -m dwaar_ai_gateway.evals.regression --feature AI-R07 --candidate v2`
checks schema validity, runs the access/injection set with the candidate as active prompt and the PII gate, and only ever says "may enter a canary". A database pin overrides the registry per society.
Evaluation scaffolds exist for classification (81 cases), voice location (19 transcripts, no recordings), translation (8 notices; meaning preservation NOT measured), and placeholders for groundedness/OCR/matching
(not M1). All carry `annotator_agreement: not_measured`. Classification macro-F1 of the simulator on its own author's cases is 1.00 en / 0.82 hi / 0.79 mr: informational only (the rules and cases share an author, and hi/mr are below the 0.90 gate).
The gated property there is the deterministic emergency override (0/9 false negatives).

### 9. M1 features

AI-R07 translation (class B; original always returned; legal/safety text flagged for human approval by rules; missing numbers force review), AI-C12 poll wording (flags with reasons, neutral rewrite), AI-C01 notice drafter (multilingual,
threatening language flagged, publishing needs committee approval, draft only), AI-R06 notification health (deterministic catalogue by manufacturer, never claims delivery, steps NOT verified on devices), AI-R02 voice/text complaint
(consent, 60 s, location resolved to the caller's OWN unit ids or a known common area, otherwise "choose"; wrong block/flat is critical; resident edits and confirms; no auto-submit; emergency words raise urgency and add "call the guard"),
AI-F01 triage and AI-G08 handover as interfaces + simulator handlers over narrow input ports (`TicketSource`, `ShiftSource`, tested with fakes; handover always keeps every unresolved critical item, deterministically), AI-C05 as an interface only (`BillRunSource`, registered unavailable).
Commands: `ai.save_draft` (self-contained; private to its owner by a RESTRICTIVE RLS policy), `notice.create_draft`, `ticket.create`, `ticket.apply_triage`, `shift.save_handover` (ports; a missing module answers 503 and leaves the proposal open;
`notice.create_draft` falls back to a private draft).

## Consequences

* New routes (all `/v1/ai`, society from `X-Society-Id`): GET features, POST/GET proposals, GET proposal, POST confirm, POST feedback, GET drafts, GET status, PUT controls, GET runs, GET providers. AT-01's route inventory goes red until its table covers them; `tests/integration/ai/test_isolation.py` has real cross-society, cross-role and cross-person cases and its own inventory.
* Migrations 0700-0702 add six tables, all with the common columns, FORCE RLS in the same migration and narrow column grants.
* Ports are the integration contract for the ticket, notice and shift teams: implement `CommandPort.execute(conn, ctx, payload, *, proposal_id, external_key)` idempotently on `external_key`, and `TicketSource.tickets` / `ShiftSource.events` as the caller.

## Not verified

No real model run; the Anthropic adapter is untested against the live API (request shape and error mapping were checked against the real SDK 1.11.0 with a mocked transport, opt-in test); no real ASR and no recordings (noisy, accented, code-switched speech untested);
no real-device check of the notification guidance; translation meaning preservation and every PRD accuracy gate unmeasured; billing scenario of AT-29 waits for the ledger slice; hi/mr strings are machine-drafted and unreviewed; sub-processor approval, residency and retention terms are `[VERIFY]`.

## Alternatives considered

* AI gateway as a separate network service now: rejected for this slice (no infra to run it); the library boundary keeps that move mechanical.
* Letting the model choose the command or targets and validating after: rejected; the registry chooses them and a model field naming one is a schema violation.
* Blocking confirmation when the daily budget is exhausted: rejected (punishes the user for the society's budget; the draft already exists and costs nothing).
* Detecting injection to block it: kept only as a diagnostic; the evaluation includes injections that evade every pattern.
