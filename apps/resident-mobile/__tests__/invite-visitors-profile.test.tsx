// REQ: GATE-01 (invitation + signed QR from the API + revoke), UX-05, UX-06, INV-07, GATE-13.
import React from "react";
import { fireEvent, screen, waitFor, within } from "@testing-library/react-native";
import { ApiError, NetworkError } from "../src/api/errors";
import { InviteNewScreen, buildInvitationBody } from "../src/screens/InviteNewScreen";
import { InviteDetailScreen } from "../src/screens/InviteDetailScreen";
import { VisitorsScreen } from "../src/screens/VisitorsScreen";
import { ProfileScreen } from "../src/screens/ProfileScreen";
import { InvitationSchema, VisitHistorySchema } from "../src/domain/types";
import { createdCodes } from "../src/state/created";
import { makeApi, makeMe, OTHER_UNIT_ID, renderApp, SOCIETY_ID, UNIT_ID } from "./helpers";
import { recorded } from "./fixtures";
import { assertAccessibleControls } from "./a11y";

const nav = (require("expo-router") as any).__router;
const invitation = InvitationSchema.parse(recorded("invitation-created").body);
const visits = VisitHistorySchema.parse(recorded("unit-visits").body);

// the QR text is data from the API; the library only draws it. Capture what it is asked to draw.
const mockQrValues: string[] = [];
jest.mock("react-native-qrcode-svg", () => {
  const { View } = require("react-native");
  return { __esModule: true, default: (props: { value: string }) => { mockQrValues.push(props.value); return <View testID="qr-drawn" />; } };
});

beforeEach(() => {
  jest.clearAllMocks();
  mockQrValues.length = 0;
  createdCodes.clear();
});

describe("invite creation", () => {
  test("buildInvitationBody: purpose, people, one explicit window, optional vehicle, single use", () => {
    const now = new Date("2026-10-05T10:00:00.500Z");
    const body = buildInvitationBody({ unitId: UNIT_ID, purpose: "  Family lunch ", alias: "", people: 3, startOffsetMin: 60, durationMin: 180, plate: " mh12ab1234 ", now });
    expect(body).toEqual({
      unit_id: UNIT_ID,
      kind: "guest",
      purpose: "Family lunch",
      visitor_alias: null,
      people_count: 3,
      windows: [{ start: "2026-10-05T11:00:00.000Z", end: "2026-10-05T14:00:00.000Z" }],
      vehicle_plate: "MH12AB1234",
      max_uses: 1,
      with_code: true,
    });
  });

  test("the purpose is required before anything is sent", async () => {
    const api = makeApi();
    await renderApp(<InviteNewScreen />, api);
    fireEvent.press(await screen.findByRole("button", { name: "Create invitation" }));
    await screen.findByText(/Please enter the purpose of the visit/);
    expect(api.createInvitation).not.toHaveBeenCalled();
  });

  test("creates the invitation for the ACTIVE society/unit with an Idempotency-Key and opens it; the one-time code is kept only in memory", async () => {
    const api = makeApi({ createInvitation: jest.fn(async () => ({ ...invitation, code: "654321" })) });
    await renderApp(<InviteNewScreen />, api);
    fireEvent.changeText(await screen.findByTestId("input-purpose"), "Family lunch");
    fireEvent.changeText(screen.getByTestId("input-plate"), "mh12ab1234");
    fireEvent.press(screen.getByLabelText("More people"));
    fireEvent.press(screen.getByRole("radio", { name: "6 hours" }));
    expect(screen.getByRole("radio", { name: "6 hours" }).props.accessibilityState.selected).toBe(true);
    fireEvent.press(screen.getByRole("button", { name: "Create invitation" }));
    await waitFor(() => expect(nav.replace).toHaveBeenCalledWith(`/invite/${invitation.id}`));
    const [society, body, key] = api.createInvitation.mock.calls[0]!;
    expect(society).toBe(SOCIETY_ID);
    expect(body).toMatchObject({ unit_id: UNIT_ID, purpose: "Family lunch", people_count: 2, vehicle_plate: "MH12AB1234", max_uses: 1 });
    expect(Date.parse(body.windows[0].end) - Date.parse(body.windows[0].start)).toBe(6 * 3600_000);
    expect(key.length).toBeGreaterThanOrEqual(8);
    expect(createdCodes.get(invitation.id)).toBe("654321");
  });

  test("a failed attempt (network) is retried with the SAME key and the SAME frozen body; editing a field starts a new command", async () => {
    const api = makeApi({ createInvitation: jest.fn().mockRejectedValueOnce(new NetworkError()).mockRejectedValueOnce(new NetworkError()).mockResolvedValue({ ...invitation, code: "111111" }) });
    await renderApp(<InviteNewScreen />, api);
    fireEvent.changeText(await screen.findByTestId("input-purpose"), "Delivery");
    fireEvent.press(screen.getByRole("button", { name: "Create invitation" }));
    await screen.findByTestId("invite-error");
    fireEvent.press(screen.getByRole("button", { name: "Create invitation" }));
    await waitFor(() => expect(api.createInvitation).toHaveBeenCalledTimes(2));
    const [, b1, k1] = api.createInvitation.mock.calls[0]!;
    const [, b2, k2] = api.createInvitation.mock.calls[1]!;
    expect(k2).toBe(k1);
    expect(b2).toEqual(b1);
    await screen.findByTestId("invite-error");
    fireEvent.changeText(screen.getByTestId("input-purpose"), "Delivery from Amazon");
    fireEvent.press(screen.getByRole("button", { name: "Create invitation" }));
    await waitFor(() => expect(api.createInvitation).toHaveBeenCalledTimes(3));
    expect(api.createInvitation.mock.calls[2]![2]).not.toBe(k1);
  });

  test("a policy refusal (422) is shown with its i18n message", async () => {
    const api = makeApi({ createInvitation: jest.fn(async () => { throw new ApiError(422, { code: "policy_violation", request_id: "r" }); }) });
    await renderApp(<InviteNewScreen />, api);
    fireEvent.changeText(await screen.findByTestId("input-purpose"), "x");
    fireEvent.press(screen.getByRole("button", { name: "Create invitation" }));
    await screen.findByText("This action is not allowed by the current rules.");
  });

  test("states scope and effect before creating (UX-05); controls are accessible; choices are radios with state", async () => {
    await renderApp(<InviteNewScreen />, makeApi());
    await screen.findByText(/works once, only in the chosen time window/);
    assertAccessibleControls();
    expect(screen.getAllByRole("radio").length).toBe(7);
  });
});

describe("invitation detail", () => {
  test("renders the QR from the API payload verbatim, shows the one-time code, truthful state", async () => {
    createdCodes.set(invitation.id, "654321");
    const api = makeApi({ getInvitation: jest.fn(async () => invitation) });
    await renderApp(<InviteDetailScreen invitationId={invitation.id} />, api);
    await screen.findByTestId("invite-qr");
    expect(mockQrValues).toEqual([invitation.qr]);
    expect(screen.getByLabelText("QR code for the guard to scan")).toBeTruthy();
    expect(screen.getByTestId("invite-code").props.children).toBe("654321");
    expect(screen.getByText(/Shown only now/)).toBeTruthy();
    expect(screen.getByLabelText("Active")).toBeTruthy();
    expect(screen.getByText(/contains no phone number or address/)).toBeTruthy();
    expect(api.getInvitation).toHaveBeenCalledWith(SOCIETY_ID, invitation.id);
  });

  test("without the in-memory code (reopened later) it says the code is not shown again", async () => {
    await renderApp(<InviteDetailScreen invitationId={invitation.id} />, makeApi({ getInvitation: jest.fn(async () => invitation) }));
    await screen.findByText("The code is not shown again.");
  });

  test("revoke: scope and effect first, then a receipt with the revocation version; the QR disappears afterwards", async () => {
    const revoked = { ...invitation, state: "revoked" as const, qr: undefined, version: 2 };
    const get = jest.fn().mockResolvedValueOnce(invitation).mockResolvedValue(revoked);
    const api = makeApi({ getInvitation: get, revokeInvitation: jest.fn(async () => ({ invitation_id: invitation.id, state: "revoked", revoked_version: 7, version: 2 })) });
    await renderApp(<InviteDetailScreen invitationId={invitation.id} />, api);
    fireEvent.press(await screen.findByRole("button", { name: "Revoke invitation" }));
    await screen.findByTestId("revoke-confirm");
    expect(screen.getByText(/Revoking cancels this pass for unit 402/)).toBeTruthy();
    expect(api.revokeInvitation).not.toHaveBeenCalled();
    fireEvent.press(screen.getByRole("button", { name: "Yes, revoke it" }));
    await screen.findByTestId("invite-revoked-receipt");
    expect(api.revokeInvitation).toHaveBeenCalledWith(SOCIETY_ID, invitation.id);
    expect(screen.getByText("Invitation revoked. Receipt: revocation version 7.")).toBeTruthy();
    await waitFor(() => expect(screen.queryByTestId("invite-qr")).toBeNull());
    expect(screen.getByLabelText("Revoked")).toBeTruthy();
    expect(screen.getByTestId("invite-not-active")).toBeTruthy();
  });

  test("a pass of another unit fails closed (error state, no QR)", async () => {
    await renderApp(<InviteDetailScreen invitationId="x" />, makeApi({ getInvitation: jest.fn(async () => ({ ...invitation, unit_id: OTHER_UNIT_ID })) }));
    await screen.findByTestId("state-error");
    expect(screen.queryByTestId("invite-qr")).toBeNull();
    expect(mockQrValues).toEqual([]);
  });
});

describe("Visitors", () => {
  test("own passes and visit history with truthful states; entry not observed is stated", async () => {
    const authorised = { ...visits.items[0]!, id: "v-a", state: "authorised" as const, entry_observed: false, entered_at: null };
    const inside = { ...visits.items[0]!, id: "v-b", state: "inside" as const, entry_observed: true, entered_at: "2026-10-05T09:30:00Z" };
    const api = makeApi({
      listInvitations: jest.fn(async () => ({ items: [invitation] })),
      unitVisits: jest.fn(async () => ({ items: [authorised, inside], next_cursor: null })),
    });
    await renderApp(<VisitorsScreen />, api);
    await screen.findByTestId(`pass-${invitation.id}`);
    await screen.findByTestId("visit-v-a");
    expect(within(screen.getByTestId("visit-v-a")).getByLabelText("Approved; not yet entered")).toBeTruthy();
    expect(within(screen.getByTestId("visit-v-a")).getByText("Entry not observed")).toBeTruthy();
    expect(within(screen.getByTestId("visit-v-b")).getByLabelText("Entered")).toBeTruthy();
    expect(within(screen.getByTestId("visit-v-b")).getByText(/Entered at/)).toBeTruthy();
    expect(api.unitVisits).toHaveBeenCalledWith(SOCIETY_ID, UNIT_ID);
    expect(api.listInvitations).toHaveBeenCalledWith(SOCIETY_ID, UNIT_ID);
  });

  test("empty states", async () => {
    await renderApp(<VisitorsScreen />, makeApi());
    await screen.findByTestId("passes-empty");
    await screen.findByTestId("history-empty");
  });

  test("no infinite feed: more history only on an explicit 'Load more' with the server's cursor", async () => {
    const v = (id: string) => ({ ...visits.items[0]!, id });
    const unitVisits = jest.fn().mockResolvedValueOnce({ items: [v("p1")], next_cursor: "c1" }).mockResolvedValueOnce({ items: [v("p2")], next_cursor: null });
    await renderApp(<VisitorsScreen />, makeApi({ unitVisits }));
    await screen.findByTestId("visit-p1");
    expect(unitVisits).toHaveBeenCalledTimes(1);
    fireEvent.press(screen.getByRole("button", { name: "Load more" }));
    await screen.findByTestId("visit-p2");
    expect(unitVisits).toHaveBeenLastCalledWith(SOCIETY_ID, UNIT_ID, "c1");
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  test("a new-invite button and accessible controls", async () => {
    await renderApp(<VisitorsScreen />, makeApi({ listInvitations: jest.fn(async () => ({ items: [invitation] })) }));
    await screen.findByTestId(`pass-${invitation.id}`);
    fireEvent.press(screen.getByRole("button", { name: "Invite a visitor" }));
    expect(nav.push).toHaveBeenCalledWith("/invite/new");
    assertAccessibleControls();
  });
});

describe("Profile and privacy", () => {
  test("language change is saved server-side (PATCH profile) and re-renders in Hindi", async () => {
    const api = makeApi();
    await renderApp(<ProfileScreen />, api);
    fireEvent.press(await screen.findByRole("radio", { name: "हिन्दी" }));
    await waitFor(() => expect(api.updateProfile).toHaveBeenCalledWith({ preferred_language: "hi" }));
    await screen.findByTestId("lang-saved");
    expect(screen.getByText("आपके खाते में सहेजी जाती है, इसलिए दोबारा इंस्टॉल करने पर भी रहती है।")).toBeTruthy();
    expect(screen.getByRole("radio", { name: "हिन्दी" }).props.accessibilityState.selected).toBe(true);
  });

  test("if the server cannot save it, the UI says it is local only (never claims it was saved)", async () => {
    const api = makeApi({ updateProfile: jest.fn(async () => { throw new NetworkError(); }) });
    await renderApp(<ProfileScreen />, api);
    fireEvent.press(await screen.findByRole("radio", { name: "मराठी" }));
    await screen.findByTestId("lang-local");
    expect(screen.queryByTestId("lang-saved")).toBeNull();
  });

  test("privacy statements, no push claim, active home shown; change-home only offered with several homes", async () => {
    await renderApp(<ProfileScreen />, makeApi());
    await screen.findByTestId("privacy-card");
    expect(screen.getByText(/no advertising and no tracking or analytics tools/)).toBeTruthy();
    expect(screen.getByTestId("alerts-note")).toHaveTextContent(/not pushed to your phone yet/);
    expect(screen.queryByRole("button", { name: "Change home" })).toBeNull();
    expect(screen.getByLabelText(/Unit 402: Sahyadri Residency CHS \(demo\)/)).toBeTruthy();
  });

  test("with several homes the change-home button asks for a fresh choice and goes to the picker", async () => {
    const me = makeMe({}, [
      { role: "owner_occ", unit_id: UNIT_ID, active: true, valid_now: true },
      { role: "tenant", unit_id: OTHER_UNIT_ID, active: true, valid_now: true },
    ]);
    const prefs = new (require("../src/state/prefs").MemoryPrefs)();
    await prefs.setItem("dwaar.context." + me.person.id, JSON.stringify({ societyId: SOCIETY_ID, unitId: UNIT_ID, role: "owner_occ" }));
    await renderApp(<ProfileScreen />, makeApi({ me: jest.fn(async () => me) }), { prefs });
    fireEvent.press(await screen.findByRole("button", { name: "Change home" }));
    expect(nav.replace).toHaveBeenCalledWith("/choose-unit");
  });

  test("controls are accessible", async () => {
    await renderApp(<ProfileScreen />, makeApi());
    await screen.findByTestId("privacy-card");
    assertAccessibleControls();
  });
});
