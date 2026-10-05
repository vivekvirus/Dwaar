// REQ: GATE-03 (409 request_expired / already_decided), INV-07, PRD 12.3 - reducer logic incl. 409 and idempotent retry.
import { ApiError, NetworkError } from "../src/api/errors";
import { IDEMPOTENCY_KEY_PATTERN } from "../src/api/ids";
import type { DecisionCommand } from "../src/api/endpoints";
import { createDecisionCommand, flowReducer, initialFlow, isRetryable, submitDecision, type FlowAction, type FlowState } from "../src/state/approvalFlow";
import { ApprovalRequestSchema, type ApprovalRequest } from "../src/domain/types";
import { recorded } from "./fixtures";

const pending: ApprovalRequest = ApprovalRequestSchema.parse(recorded("approval-request-pending").body);
const canonical = (status: "approved" | "denied" | "expired", version = 2) => ({ request_id: pending.id, status, version, decision_id: status === "expired" ? null : "dec-1", permission_expires_at: status === "approved" ? "2026-10-05T21:00:00Z" : null, entry_observed: false });
const conflict = (code: string, details: Record<string, unknown>) => new ApiError(409, { code, request_id: "req-1", details });

const run = (s: FlowState, ...actions: FlowAction[]) => actions.reduce(flowReducer, s);
const ready = () => run(initialFlow, { type: "loaded", request: pending });
const submitting = () => {
  const command = createDecisionCommand(pending, "soc", "approve");
  return { command, state: run(ready(), { type: "submit", command }) };
};

describe("approval decision flow", () => {
  test("loading -> ready (pending) with the exact backend state", () => {
    const s = ready();
    expect(s.phase).toBe("ready");
    expect(s.request?.entry_observed).toBe(false);
  });

  test("a command is bound to the displayed version and carries fresh keys in the OpenAPI formats", () => {
    const a = createDecisionCommand(pending, "soc", "approve");
    const b = createDecisionCommand(pending, "soc", "approve");
    expect(a.body).toMatchObject({ decision: "approve", expected_version: pending.version, channel: "app" });
    expect(a.idempotencyKey).toMatch(IDEMPOTENCY_KEY_PATTERN);
    expect(a.idempotencyKey).not.toBe(b.idempotencyKey);
    expect(a.body.client_action_id).not.toBe(b.body.client_action_id);
  });

  test("a command for another version than the one shown is ignored (cannot approve what the person did not see)", () => {
    const command = { ...createDecisionCommand(pending, "soc", "approve"), body: { ...createDecisionCommand(pending, "soc", "approve").body, expected_version: pending.version + 1 } };
    expect(run(ready(), { type: "submit", command }).phase).toBe("ready");
  });

  test("200: closed as decided_here with the canonical result; entry stays not observed", () => {
    const { state } = submitting();
    const s = flowReducer(state, { type: "accepted", canonical: canonical("approved") });
    expect(s).toMatchObject({ phase: "closed", how: "decided_here", result: { status: "approved", entry_observed: false } });
  });

  test("409 already_decided: shows the CANONICAL result of the other device, not our own intent", () => {
    const { state } = submitting(); // we tried to approve; the other device denied
    const s = flowReducer(state, { type: "failed", error: conflict("already_decided", { canonical: canonical("denied"), decided_by_role: "family" }) });
    expect(s).toMatchObject({ phase: "closed", how: "decided_elsewhere", decidedByRole: "family", result: { status: "denied", version: 2 } });
  });

  test("409 request_expired: expired, no permission, no entry implied - even if the payload is sloppy", () => {
    const { state } = submitting();
    const s = flowReducer(state, { type: "failed", error: conflict("request_expired", { canonical: { ...canonical("approved"), entry_observed: true } }) });
    expect(s).toMatchObject({ phase: "closed", how: "expired_on_submit", result: { status: "expired", permission_expires_at: null, entry_observed: false } });
  });

  test("409 request_expired without details still ends as expired", () => {
    const { state } = submitting();
    const s = flowReducer(state, { type: "failed", error: conflict("request_expired", {}) });
    expect(s).toMatchObject({ phase: "closed", result: { status: "expired" } });
  });

  test("409 stale_version while still pending: back to ready with a notice (the screen then reloads)", () => {
    const { state } = submitting();
    const s = flowReducer(state, { type: "failed", error: conflict("stale_version", { canonical: { ...canonical("approved"), status: "pending", version: 5, decision_id: null, permission_expires_at: null } }) });
    expect(s).toMatchObject({ phase: "ready", notice: "stale" });
    expect(s.request?.version).toBe(5);
  });

  test("409 stale_version where the request is already closed shows the closed result", () => {
    const { state } = submitting();
    const s = flowReducer(state, { type: "failed", error: conflict("stale_version", { canonical: canonical("denied", 3) }) });
    expect(s).toMatchObject({ phase: "closed", result: { status: "denied" } });
  });

  test("network failure keeps THE SAME command for a retry (same Idempotency-Key and client_action_id)", () => {
    const { command, state } = submitting();
    const failed = flowReducer(state, { type: "failed", error: new NetworkError() });
    expect(failed).toMatchObject({ phase: "send_failed" });
    const again = flowReducer(failed, { type: "submit", command: (failed as Extract<FlowState, { phase: "send_failed" }>).command });
    expect(again.phase).toBe("submitting");
    expect((again as Extract<FlowState, { phase: "submitting" }>).command).toBe(command);
  });

  test("5xx and 429 are retryable with the same command; 4xx other than the handled ones are not", () => {
    expect(isRetryable(new ApiError(503, { code: "dependency_unavailable" }))).toBe(true);
    expect(isRetryable(new ApiError(429, { code: "rate_limited" }))).toBe(true);
    expect(isRetryable(new ApiError(422, { code: "policy_violation" }))).toBe(false);
    expect(isRetryable(new ApiError(400, { code: "invalid_schema" }))).toBe(false);
  });

  test("404/403 on submit -> not_available (fails closed, no hint why)", () => {
    const { state } = submitting();
    expect(flowReducer(state, { type: "failed", error: new ApiError(404, { code: "not_found" }) }).phase).toBe("not_available");
    expect(flowReducer(state, { type: "failed", error: new ApiError(403, { code: "not_authorised" }) }).phase).toBe("not_available");
  });

  test("GATE-03: once closed, a late/stale GET that still says pending cannot reopen the request", () => {
    const { state } = submitting();
    const closed = flowReducer(state, { type: "failed", error: conflict("request_expired", { canonical: canonical("expired") }) });
    const late = flowReducer(closed, { type: "loaded", request: { ...pending, version: 1 } });
    expect(late.phase).toBe("closed");
    expect(late).toBe(closed);
    // and a closed state refuses new commands
    expect(flowReducer(closed, { type: "submit", command: createDecisionCommand(pending, "soc", "approve") }).phase).toBe("closed");
  });

  test("a poll result never replaces the screen while a decision is in flight", () => {
    const { state } = submitting();
    expect(flowReducer(state, { type: "loaded", request: { ...pending, status: "approved", version: 2 } })).toBe(state);
  });

  test("loading an already approved request shows it closed and truthfully 'not entered'", () => {
    const s = run(initialFlow, { type: "loaded", request: { ...pending, status: "approved", version: 2, decision_id: "d", permission_expires_at: "2026-10-05T21:00:00Z", entry_observed: false } });
    expect(s).toMatchObject({ phase: "closed", how: "seen_closed", result: { status: "approved", entry_observed: false } });
  });

  test("load failures: 404 -> not_available; offline on first load -> error; offline while polling keeps the screen", () => {
    expect(run(initialFlow, { type: "load_failed", error: new ApiError(404, { code: "not_found" }) }).phase).toBe("not_available");
    expect(run(initialFlow, { type: "load_failed", error: new NetworkError() }).phase).toBe("error");
    const r = ready();
    expect(flowReducer(r, { type: "load_failed", error: new NetworkError() })).toBe(r);
  });
});

describe("submitDecision orchestration", () => {
  const cmd = (): DecisionCommand => createDecisionCommand(pending, "soc", "approve");
  test("success -> accepted", async () => {
    const decide = jest.fn(async () => canonical("approved"));
    expect(await submitDecision({ decide }, cmd())).toMatchObject({ type: "accepted" });
  });
  test("any throw -> failed (never throws)", async () => {
    const decide = jest.fn(async () => {
      throw conflict("already_decided", {});
    });
    expect(await submitDecision({ decide }, cmd())).toMatchObject({ type: "failed" });
  });
  test("retry re-sends the identical command object", async () => {
    const decide = jest.fn().mockRejectedValueOnce(new NetworkError()).mockResolvedValueOnce(canonical("approved"));
    const c = cmd();
    const first = await submitDecision({ decide }, c);
    expect(first.type).toBe("failed");
    const second = await submitDecision({ decide }, c);
    expect(second.type).toBe("accepted");
    expect(decide.mock.calls[0]![0]).toBe(decide.mock.calls[1]![0]);
  });
});

describe("polling while a send failed", () => {
  test("a reload at the same version keeps the unsent command (retry stays possible)", () => {
    const command = createDecisionCommand(pending, "soc", "approve");
    const failed = run(ready(), { type: "submit", command }, { type: "failed", error: new NetworkError() });
    const after = flowReducer(failed, { type: "loaded", request: pending });
    expect(after.phase).toBe("send_failed");
    expect((after as Extract<FlowState, { phase: "send_failed" }>).command).toBe(command);
  });
  test("a reload that shows a NEWER version drops the stale command (it could not apply anyway)", () => {
    const command = createDecisionCommand(pending, "soc", "approve");
    const failed = run(ready(), { type: "submit", command }, { type: "failed", error: new NetworkError() });
    expect(flowReducer(failed, { type: "loaded", request: { ...pending, version: 3 } }).phase).toBe("ready");
  });
  test("a reload that shows the request closed drops the command and shows the closed result", () => {
    const command = createDecisionCommand(pending, "soc", "approve");
    const failed = run(ready(), { type: "submit", command }, { type: "failed", error: new NetworkError() });
    expect(flowReducer(failed, { type: "loaded", request: { ...pending, status: "denied", version: 2 } })).toMatchObject({ phase: "closed", result: { status: "denied" } });
  });
});
