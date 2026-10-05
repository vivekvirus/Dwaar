// REQ: INV-07 / UX-04: submitted, approved, entered are different facts and are shown with different words. "Approved" is
// never "entered": entry is only claimed when the backend says entry_observed (or visit state "inside").
import type { TKey } from "../i18n";
import type { ApprovalRequest, Visit, Invitation } from "./types";

export type Tone = "neutral" | "info" | "success" | "warning" | "danger";
export interface StatusView {
  key: TKey;
  /** glyph shown next to the words, so state is never carried by colour alone */
  glyph: string;
  tone: Tone;
}

export function requestStatus(r: Pick<ApprovalRequest, "status" | "entry_observed">): StatusView {
  switch (r.status) {
    case "pending":
      return { key: "app.status.pending", glyph: "●", tone: "warning" };
    case "approved":
      return r.entry_observed
        ? { key: "states.visit.entered", glyph: "✓✓", tone: "success" }
        : { key: "states.visit.approved", glyph: "✓", tone: "info" };
    case "denied":
      return { key: "states.visit.denied", glyph: "✕", tone: "danger" };
    case "expired":
      return { key: "states.visit.expired", glyph: "⌛", tone: "danger" };
    case "cancelled":
      return { key: "app.status.cancelled", glyph: "−", tone: "neutral" };
  }
}

export function visitStatus(v: Pick<Visit, "state" | "entry_observed"> & { closed_reason?: string | null }): StatusView {
  switch (v.state) {
    case "requested":
      return { key: "app.status.requested", glyph: "●", tone: "warning" };
    case "authorised":
      return v.entry_observed
        ? { key: "states.visit.entered", glyph: "✓✓", tone: "success" }
        : { key: "states.visit.approved", glyph: "✓", tone: "info" };
    case "inside":
      return { key: "states.visit.entered", glyph: "✓✓", tone: "success" };
    case "exited":
      return { key: "app.status.exited", glyph: "↩", tone: "neutral" };
    case "cancelled":
      // the backend closes a denied visit as "cancelled" with closed_reason "denied": say what happened, not "withdrawn"
      return v.closed_reason === "denied"
        ? { key: "states.visit.denied", glyph: "✕", tone: "danger" }
        : { key: "app.status.cancelled", glyph: "−", tone: "neutral" };
    case "expired":
      return { key: "states.visit.expired", glyph: "⌛", tone: "danger" };
  }
}

export function invitationStatus(i: Pick<Invitation, "state">): StatusView {
  switch (i.state) {
    case "active":
      return { key: "app.status.active", glyph: "✓", tone: "success" };
    case "consumed":
      return { key: "app.status.consumed", glyph: "✓", tone: "neutral" };
    case "expired":
      return { key: "states.visit.expired", glyph: "⌛", tone: "danger" };
    case "revoked":
      return { key: "app.status.revoked", glyph: "✕", tone: "danger" };
    case "draft":
      return { key: "app.status.draft", glyph: "−", tone: "neutral" };
  }
}

/** Entry line of an approval: false is "Not yet at gate / not observed", never an empty value and never "entered". */
export function entryLine(entryObserved: boolean): TKey {
  return entryObserved ? "app.approval.entry_observed" : "app.approval.entry_not_observed";
}
