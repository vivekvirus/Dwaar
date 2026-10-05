// REQ: GATE-03 (a stale mobile approval can never resurrect a denied/expired request), INV-07, PRD 12.2/12.3.
// Pure reducer behind the approval decision screen. Network I/O lives in submitDecision() below so the logic is testable.
import { ApiError, ContractError, NetworkError } from "../api/errors";
import type { Api, DecisionCommand } from "../api/endpoints";
import { newClientActionId, newIdempotencyKey } from "../api/ids";
import type { ApprovalRequest, CanonicalDecision } from "../domain/types";

export type How =
  | "decided_here" // our own decision was accepted (200)
  | "decided_elsewhere" // 409 already_decided: another device/household member won; this is THEIR canonical result
  | "expired_on_submit" // 409 request_expired: no permission was issued
  | "seen_closed"; // the request was already closed when loaded

export type FlowState =
  | { phase: "loading"; request: null }
  | { phase: "ready"; request: ApprovalRequest; notice: "stale" | null }
  | { phase: "submitting"; request: ApprovalRequest; command: DecisionCommand }
  | { phase: "send_failed"; request: ApprovalRequest; command: DecisionCommand; error: unknown }
  | {
      phase: "closed";
      request: ApprovalRequest | null;
      result: CanonicalDecision;
      how: How;
      decidedByRole: string | null;
      command: DecisionCommand | null;
    }
  | { phase: "not_available"; request: null; error: unknown }
  | { phase: "error"; request: ApprovalRequest | null; error: unknown };

export type FlowAction =
  | { type: "loaded"; request: ApprovalRequest }
  | { type: "load_failed"; error: unknown }
  | { type: "submit"; command: DecisionCommand }
  | { type: "accepted"; canonical: CanonicalDecision }
  | { type: "failed"; error: unknown };

export const initialFlow: FlowState = { phase: "loading", request: null };

export function canonicalOf(r: ApprovalRequest): CanonicalDecision {
  return {
    request_id: r.id,
    status: r.status,
    version: r.version,
    decision_id: r.decision_id ?? null,
    permission_expires_at: r.permission_expires_at ?? null,
    entry_observed: r.entry_observed,
  };
}

/** Errors after which the SAME command may be sent again (it cannot apply twice: same Idempotency-Key + client_action_id). */
export function isRetryable(error: unknown): boolean {
  if (error instanceof NetworkError) return true;
  if (error instanceof ApiError) return error.status === 503 || error.status === 429 || error.status >= 500;
  return false;
}

export function flowReducer(state: FlowState, action: FlowAction): FlowState {
  switch (action.type) {
    case "loaded": {
      const r = action.request;
      if (state.phase === "submitting") return state; // never replace the screen under an in-flight decision
      // GATE-03: a late/stale GET that still says "pending" can never reopen a request this screen already saw closed
      if (state.phase === "closed" && r.status === "pending" && r.version <= state.result.version) return state;
      if (state.phase === "send_failed" && r.status === "pending" && r.version === state.command.body.expected_version) {
        return { ...state, request: r }; // same version still pending: the unsent command stays valid for a retry
      }
      if (r.status === "pending") return { phase: "ready", request: r, notice: state.phase === "ready" ? state.notice : null };
      return {
        phase: "closed",
        request: r,
        result: canonicalOf(r),
        how: state.phase === "closed" ? state.how : "seen_closed",
        decidedByRole: r.decision?.by_role ?? (state.phase === "closed" ? state.decidedByRole : null),
        command: state.phase === "closed" ? state.command : null,
      };
    }
    case "load_failed": {
      const e = action.error;
      if (e instanceof ApiError && (e.status === 404 || e.status === 403)) return { phase: "not_available", request: null, error: e };
      if (state.phase === "loading") return { phase: "error", request: null, error: e };
      return state; // keep showing what we know (offline/503 while polling)
    }
    case "submit": {
      if (state.phase !== "ready" && state.phase !== "send_failed") return state;
      // a command is only valid for the version the screen showed
      if (action.command.body.expected_version !== state.request.version) return state;
      return { phase: "submitting", request: state.request, command: action.command };
    }
    case "accepted": {
      if (state.phase !== "submitting") return state;
      return {
        phase: "closed",
        request: state.request,
        result: action.canonical,
        how: "decided_here",
        decidedByRole: null,
        command: state.command,
      };
    }
    case "failed": {
      if (state.phase !== "submitting") return state;
      const e = action.error;
      const req = state.request;
      if (isRetryable(e)) return { phase: "send_failed", request: req, command: state.command, error: e };
      if (e instanceof ContractError) return { phase: "send_failed", request: req, command: state.command, error: e };
      if (e instanceof ApiError) {
        if (e.code === "already_decided" && e.canonical) {
          return { phase: "closed", request: req, result: e.canonical, how: "decided_elsewhere", decidedByRole: e.decidedByRole, command: state.command };
        }
        if (e.code === "request_expired") {
          const base = e.canonical ?? { ...canonicalOf(req), status: "expired" as const };
          // whatever the payload says, an expired answer issues no permission and implies no entry
          return {
            phase: "closed",
            request: req,
            result: { ...base, status: "expired", permission_expires_at: null, entry_observed: false },
            how: "expired_on_submit",
            decidedByRole: null,
            command: state.command,
          };
        }
        if (e.code === "stale_version") {
          const c = e.canonical;
          if (c && c.status !== "pending") {
            return { phase: "closed", request: req, result: c, how: "decided_elsewhere", decidedByRole: e.decidedByRole, command: state.command };
          }
          // still pending at a newer version: show it again with a notice; the screen reloads the fresh request
          return { phase: "ready", request: c ? { ...req, version: c.version } : req, notice: "stale" };
        }
        if (e.status === 404 || e.status === 403) return { phase: "not_available", request: null, error: e };
      }
      return { phase: "error", request: req, error: e };
    }
  }
}

/** A new command per user decision: fresh Idempotency-Key and client_action_id, bound to the version that was displayed. */
export function createDecisionCommand(request: ApprovalRequest, societyId: string, decision: "approve" | "deny"): DecisionCommand {
  return {
    requestId: request.id,
    societyId,
    idempotencyKey: newIdempotencyKey(),
    body: { decision, expected_version: request.version, client_action_id: newClientActionId(), channel: "app" },
  };
}

/** Send a command and translate the outcome into a reducer action. Never throws. */
export async function submitDecision(api: Pick<Api, "decide">, command: DecisionCommand): Promise<FlowAction> {
  try {
    const canonical = await api.decide(command);
    return { type: "accepted", canonical };
  } catch (error) {
    return { type: "failed", error };
  }
}
