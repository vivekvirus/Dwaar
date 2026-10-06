# ADR-0020: Notifications and calling (slice 4)

- Status: accepted
- Date: 2026-10-06
- Deciders: Viz (owner), build team (slice 4, notifications and calling)
- Related: PRD 9.4 (NOTIF-01..NOTIF-09, CALL-01, CALL-02, budget metrics), Appendix C, D-14, D-15, D-21, 16 (AT-11, AT-40), 18.1, OBS-02, IAM-11; INV-01, INV-03,
  INV-05, INV-07; ADR-0004, ADR-0005, ADR-0006, ADR-0013; code: `services/api/dwaar_api/modules/notifications/`, `services/api/migrations/0500_notifications_core.sql`,
  `services/worker/dwaar_worker/notification_jobs.py`, `services/api/dwaar_api/seed/steps/s590_notifications.py`, `packages/i18n/locales/*/notifications.json`;
  tests: `tests/integration/notifications/`, `services/worker/tests/unit/test_notification_jobs.py`, `tests/acceptance/test_at40_cascade.py`,
  `tests/acceptance/test_at11_notification_fallback.py`.

## Context

An approval request (GATE-02) is only useful if the household hears about it, and the PRD is strict about how: a fixed cascade (push, alternate adult, masked
IVR call, WhatsApp / SMS link, then guard-assisted options, never an auto-allow), honest delivery states, no ads on the security channel, masked calls with no
recording, a budget that never costs the society its safety. D-21 leaves the telephony, SMS and WhatsApp vendors `[TBD]` and there is no FCM or APNs account:
nothing in this build can reach a real person. So the module is built to its interfaces, against labelled simulators, and says so everywhere.

## Decisions

1. **The module owns delivery, never the decision.** An approve / deny from a notification (lock-screen action, deep link, IVR keypad) is handed to the visits
   service (`approvals.decide`) as the household member's own act: membership re-checked there, first valid decision wins (compare-and-swap), a late action after
   expiry is 409 `request_expired`, after an earlier decision 409 `already_decided` with the canonical state. Keypad decisions use `channel = 'ivr'` through
   `DecisionIn.model_construct` (the public `DecisionIn` only allows `app`). The planner has no "allow" action at all (INV-03).
2. **The planner is a pure function** (`planner.plan_cascade(timings, household, progress, now)`): no clock, no database. Timings come from the plan stored on the
   approval request (the society policy as it was when the request was raised, from `dwaar_packs`), pulled to the approved bounds (>= 10 s between steps, expiry
   60-180 s). Dedupe keys make it idempotent; past `expires_at` the only action is `expire`; for a request that left `pending` the only action is `cancel`.
   Hypothesis properties (`test_planner_properties.py`): never more than one primary and one alternate call, nothing sent at or after expiry or for a closed request,
   re-planning after issuing is empty, cancellation idempotent, timings always inside the bounds.
3. **Engine and worker.** `engine` (start / advance / issue / close / invalidate) and `runner` (one tick of one society) are plain functions of a connection, a
   clock value and a `ProviderSet`. `services/worker` wraps them (`notification_jobs.notification_tick`, Dramatiq actor `notifications_tick`, `max_retries = 0`,
   scheduled every `DWAAR_WORKER_NOTIFY_INTERVAL_S` = 1 s). Safe under restarts and duplicates: outbox events are handled once per society through a ledger
   (`notification_processed_events`; a cursor on event ids would skip an event whose transaction committed late), every send is deduplicated by a unique key
   written BEFORE the provider is called and the provider call carries the row's deterministic id (an idempotency key for a real adapter), and a per-society
   advisory lock makes two workers take turns. Events consumed: `ApprovalRequested` starts the cascade, `ApprovalDecided` / `ApprovalEscalated` end it,
   `identity.reverification_required` revokes the person's push tokens (IAM-11).
4. **NOTIF-02 states are exactly the PRD's six** (`created, provider_accepted, app_received, displayed, actioned, expired`), each backed by a CHECK that a state needs
   its timestamp. Failure and cancellation are *reasons* (`failure_reason`, `closed_reason`), never a seventh state. `person_reached` needs the app's own receipt
   (or the person's answer); a provider's acceptance is `provider_accepted` and nothing more. States only move forward; `actioned` and `expired` are final; a late
   report after expiry stamps its time but revives nothing. SMS and WhatsApp reach `app_received` only when the recipient opens the deep link (the first
   authenticated fetch is the evidence); a carrier handset report is logged, not promoted.
5. **At most one primary and one alternate call per attempt** is a unique partial index on `notifications` (`channel = 'ivr_call'`, role primary / alternate), shared
   by the cascade IVR and a guard-requested proxy call; a supervisor's `cascade-attempts` starts attempt n+1 (max 5), which resets the slot. The expiry is never
   extended. A policy flag `alternate_call` (off by default) lets a policy ring the alternate after an unanswered primary call (the property tests cover it).
6. **Time, honestly.** The worker takes `now` from an injectable clock (rows are stamped with it); expiry is the visits service's, on the database clock. The
   cascade's `expire` step asks `expire_due_requests` and closes only if the database agrees; tests that need expiry age the request in the database (`shift_request`,
   the same style as AT-04) and say so. Status boards read the database clock.
7. **NOTIF-04 measured (SIMULATION).** `test_worker_jobs.py::test_a_decision_withdraws_the_other_device_within_two_seconds_through_the_real_scheduler_loop`: two
   registered devices, the real scheduler loop at 1 s cadence, StubBroker actor, one process, real PostgreSQL: decision committed to the other device's notification
   `expired` took **0.53 s** (three runs: 0.530, 0.534, 0.535 s). The stale ACTION is refused instantly (the decision is the committed state; no job has to run). This
   says nothing about Redis latency, a real provider's cancel semantics or what a phone shows after a withdrawn push.
8. **Content rules for the clean channels** (NOTIF-01) in three layers: CHECK constraints (`notification_templates`, `notifications`), the validator
   (`categories.validate_template`: class must be transactional, body key in the category's own copy family, no promotional marker in any language, URLs on the
   whitelist) and the last check before a provider (`assert_sendable`). Lock-screen text (NOTIF-09) omits visitor and unit unless the resident opted in; the data
   payload never carries identity either (the app fetches the request, NOTIF-05). SMS (CALL-02): a template without DLT ids is a placeholder and is never sent
   (`dlt_template_not_registered`); the society registers the real ids with `PUT .../notification-templates/{id}/dlt`; links are whitelisted hosts only, https,
   no port, query or fragment.
9. **Budgets** (`budget.py`): per-society monthly caps and counters. Caps bound the spend of finance, service-ticket and digest sends; **security approval and
   emergency are never blocked by a cap**, they are counted and past the cap also counted as `over_budget` (an operations signal). "A high fallback rate is an
   operations problem, not a cost passed to the society" is a field of the metrics answer (`cost_passed_to_society: false`, `ops_attention`).
10. **Providers (D-21).** `Provider` interface (`send` / `cancel` / `drain_events`), four labelled simulators that can fail, delay, drop an acknowledgement, reorder,
    duplicate and report fake device telemetry, and a registry that, outside local/test (or with no `DWAAR_NOTIFICATION_PROVIDERS=simulator`), reports every kind as
    `not configured: <specific missing dependency>` to SECRETARY and ESTATE_MGR only. With no adapter the cascade records `provider_not_configured`, the guard board
    offers the intercom and the office (CALL-01), and nothing is claimed.
11. **Masked calls (CALL-01).** The callee is chosen by the server (`resolve_contact`: role-authorised, primary or alternate of the household), the caller learns a
    masked label (`Household of A-203`), the provider receives an opaque `person:<uuid>` reference (a real adapter resolves the number inside the vault boundary: not
    built), sessions have a TTL (120 s), dial outcome and duration are logged and `recording_enabled` is a column that a CHECK holds at false (a lawful use would need
    its own migration and decision record). Spoken yes/no (NOTIF-08) is M2 and is NOT built: the IVR payload says `speech_input: false`.
12. **Audit and outbox.** API mutations and the cascade's own state changes use the core `mutation` helper (audit + outbox in one transaction). Each dispatch is one
    audit row and one `notification.dispatched` event written in the same transaction as the delivery row (outcome, channel, reason: no text, no name, no number); each
    withdrawal is one `notification.withdrawn` event on its own aggregate (`notification_withdrawal`, versioned 1, 2, ... because `outbox_aggregate_version_uq` forbids
    reusing the request's aggregate versions). The delivery rows and the attempt log are append-style records themselves; per-receipt audit rows were not added (volume).
13. **Permissions** are module-local (PRD 5.2 has no notifications row). Role sets reuse the visits ones (gate operations): household roles for devices, inbox, action
    and settings; gate staff for the status board and calls; GUARD_SUP for new attempts; SECRETARY (and ESTATE_MGR for the provider registry) for templates, budgets and
    providers. Only members who may decide for the unit can change who is notified (a delegated family member yes, a plain one no).

## What is NOT built or NOT verified

Real vendor adapters (FCM, APNs, telephony, SMS gateway, WhatsApp); envelope-encrypted push token storage (the registry keeps a hash and a short reference, so a real
adapter cannot yet send); number resolution for a real call; DLT registration; NOTIF-08 spoken approvals; a provider webhook endpoint (callbacks reach the worker only
through the adapter's `drain_events`); network-cohort measurement (reported `not_observed`); any real device or OS push behaviour (force-stop, Doze, OEM kill, Focus,
permission denial are scripted on the simulator); Redis and a live Dramatiq deployment (StubBroker only); the on-device onboarding diagnostic itself (the API stores its
result and serves the guidance; the app is another slice); the `packages/i18n/src/keys.ts` regeneration (outside this module's paths).

## Consequences

The cascade is deterministic and testable end to end without a provider, and the first real adapter has a clear contract and a clear list of what it must add. The
notification layer can be wrong without being dangerous: it can neither allow nor extend a request, and it cannot claim a delivery it did not observe.
