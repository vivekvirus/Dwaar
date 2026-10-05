// Display labels for API enum values. Unknown values are shown verbatim (never hidden, never guessed).
import type { MessageKey, TFn } from "@/i18n";

const EXCEPTION_KINDS = ["manual_entry", "emergency_entry", "unauthorised_entry", "exit_unknown", "overstay", "other"] as const;
const EXCEPTION_STATES = ["open", "supervisor_review", "escalated", "resolved"] as const;
const DEVICE_STATES = ["pending_approval", "active", "rejected", "revoked"] as const;
const VISIT_KINDS = ["guest", "delivery", "service", "cab", "staff", "vendor"] as const;
const DEVICE_KINDS = ["terminal", "gateway", "reader", "camera", "relay", "meter_gw"] as const;
const GATE_KINDS = ["vehicle", "pedestrian", "mixed"] as const;
const DIRECTIONS = ["in", "out", "both"] as const;

function pick<T extends readonly string[]>(list: T, value: string, prefix: string, t: TFn): string {
  return (list as readonly string[]).includes(value) ? t(`console.${prefix}.${value}` as MessageKey) : value;
}

export const exceptionKindLabel = (t: TFn, v: string) => pick(EXCEPTION_KINDS, v, "exception_kind", t);
export const exceptionStateLabel = (t: TFn, v: string) => pick(EXCEPTION_STATES, v, "exception_state", t);
export const deviceStateLabel = (t: TFn, v: string) => pick(DEVICE_STATES, v, "device_state", t);
export const visitKindLabel = (t: TFn, v: string) => pick(VISIT_KINDS, v, "visit_kind", t);
export const deviceKindLabel = (t: TFn, v: string) => pick(DEVICE_KINDS, v, "device_kind", t);
export const gateKindLabel = (t: TFn, v: string) => pick(GATE_KINDS, v, "gate_kind", t);
export const directionLabel = (t: TFn, v: string) => pick(DIRECTIONS, v, "direction", t);

export const EXCEPTION_STATE_ORDER = EXCEPTION_STATES;

/** INV-07: submitted / approved / entered / exited are distinct and shown as exactly what the backend recorded. */
export function visitStateLabel(t: TFn, v: { state: string; closed_reason?: string | null }): string {
  switch (v.state) {
    case "requested":
      return t("states.visit.submitted");
    case "authorised":
      return t("states.visit.approved");
    case "inside":
      return t("states.visit.entered");
    case "exited":
      return t("console.visit_state.exited");
    case "expired":
      return t("states.visit.expired");
    case "cancelled":
      return v.closed_reason === "denied" ? t("states.visit.denied") : t("console.visit_state.cancelled");
    default:
      return v.state;
  }
}

export function deviceTone(state: string): "ok" | "warn" | "danger" | "neutral" {
  return state === "active" ? "ok" : state === "pending_approval" ? "warn" : state === "revoked" || state === "rejected" ? "danger" : "neutral";
}
export function exceptionTone(state: string): "ok" | "warn" | "danger" | "info" {
  return state === "resolved" ? "ok" : state === "open" ? "danger" : state === "escalated" ? "warn" : "info";
}
