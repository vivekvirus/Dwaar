// REQ: UX-01 (pending approval pinned at top, quick actions, operational messages separate), PRD 6 states.
import React from "react";
import { fireEvent, screen, within } from "@testing-library/react-native";
import { ApiError, NetworkError } from "../src/api/errors";
import { HomeScreen } from "../src/screens/HomeScreen";
import { ApprovalRequestSchema, VisitHistorySchema } from "../src/domain/types";
import { makeApi, renderApp, SOCIETY_ID, UNIT_ID } from "./helpers";
import { recorded } from "./fixtures";
import { assertAccessibleControls } from "./a11y";

const nav = (require("expo-router") as any).__router;
const pending = ApprovalRequestSchema.parse(recorded("approval-request-pending").body);
const visits = VisitHistorySchema.parse(recorded("unit-visits").body);

beforeEach(() => jest.clearAllMocks());

describe("Home", () => {
  test("pending approval is pinned ABOVE the quick actions and gate updates; the active unit's list is requested", async () => {
    const api = makeApi({ listApprovalRequests: jest.fn(async () => ({ items: [pending], next_cursor: null })), unitVisits: jest.fn(async () => visits) });
    await renderApp(<HomeScreen />, api);
    await screen.findByTestId(`pending-${pending.id}`);
    expect(api.listApprovalRequests).toHaveBeenCalledWith(SOCIETY_ID, UNIT_ID, "pending");
    const headings = screen.getAllByRole("header").map((h) => within(h).queryByText(/./)?.props.children as string);
    expect(headings.slice(0, 3)).toEqual(["Home", "Waiting for your approval", "Fixture Courier is at the gate"]);
    expect(headings.indexOf("Quick actions")).toBeGreaterThan(2);
    expect(headings.indexOf("Gate updates")).toBeGreaterThan(headings.indexOf("Quick actions"));
    expect(screen.getByText("Fixture Courier is at the gate")).toBeTruthy();
  });

  test("quick actions: invite, approve (opens the pending request), view visitors; nothing unreleased", async () => {
    const api = makeApi({ listApprovalRequests: jest.fn(async () => ({ items: [pending], next_cursor: null })) });
    await renderApp(<HomeScreen />, api);
    await screen.findByTestId(`pending-${pending.id}`);
    fireEvent.press(screen.getByRole("button", { name: "Invite" }));
    expect(nav.push).toHaveBeenCalledWith("/invite/new");
    fireEvent.press(screen.getByRole("button", { name: "Approve" }));
    expect(nav.push).toHaveBeenCalledWith(`/approval/${pending.id}`);
    fireEvent.press(screen.getByRole("button", { name: "View visitors" }));
    expect(nav.push).toHaveBeenCalledWith("/visitors");
    // unreleased modules are not shown at all (no empty items)
    for (const hidden of ["Pay dues", "Report an issue", "Community", "Help", "Dues", "Society notices"]) expect(screen.queryByText(hidden)).toBeNull();
  });

  test("nothing pending: says so, and the approve action is disabled with its reason (not a dead button)", async () => {
    await renderApp(<HomeScreen />, makeApi());
    await screen.findByTestId("pending-none");
    const approve = screen.getByRole("button", { name: "Nothing to approve" });
    expect(approve.props.accessibilityState.disabled).toBe(true);
    expect(screen.getByText("No visitor is waiting for you.")).toBeTruthy();
  });

  test("gate updates come from the real visit history with truthful status (authorised is 'Approved; not yet entered')", async () => {
    const authorised = { ...visits.items[0]!, state: "authorised" as const, entry_observed: false, id: "v-1" };
    const api = makeApi({ unitVisits: jest.fn(async () => ({ items: [authorised], next_cursor: null })) });
    await renderApp(<HomeScreen />, api);
    await screen.findByTestId("update-v-1");
    const card = within(screen.getByTestId("update-v-1"));
    expect(card.getByLabelText("Approved; not yet entered")).toBeTruthy();
    expect(card.queryByText("Entered")).toBeNull();
  });

  test("offline with saved data: shows the saved information plus the offline banner; offline with nothing saved says so", async () => {
    const list = jest.fn().mockResolvedValueOnce({ items: [pending], next_cursor: null }).mockRejectedValue(new NetworkError());
    const api = makeApi({ listApprovalRequests: list });
    await renderApp(<HomeScreen />, api);
    await screen.findByTestId(`pending-${pending.id}`);
    // pull-to-refresh fails: data stays, banner appears
    const scroll = screen.getByTestId("screen-home");
    await (scroll.props.refreshControl as any).props.onRefresh();
    await screen.findByTestId("state-offline");
    expect(screen.getByTestId(`pending-${pending.id}`)).toBeTruthy();
    expect(screen.getByText("You are offline. Showing saved information.")).toBeTruthy();
  });

  test("offline on first load with nothing saved: honest message, no 'showing saved information' claim", async () => {
    const api = makeApi({ listApprovalRequests: jest.fn(async () => { throw new NetworkError(); }), unitVisits: jest.fn(async () => { throw new NetworkError(); }) });
    await renderApp(<HomeScreen />, api);
    await screen.findAllByTestId("state-offline-nodata");
    expect(screen.queryByText("You are offline. Showing saved information.")).toBeNull();
    expect(screen.getAllByText(/nothing is saved on this device/).length).toBeGreaterThan(0);
  });

  test("permission denied is shown as such", async () => {
    const api = makeApi({ listApprovalRequests: jest.fn(async () => { throw new ApiError(403, { code: "not_authorised", request_id: "r" }); }) });
    await renderApp(<HomeScreen />, api);
    await screen.findByTestId("state-permission-denied");
    expect(screen.getByText("You do not have permission to see this")).toBeTruthy();
  });

  test("a pending request of another unit in the response is dropped (fail closed)", async () => {
    const foreign = { ...pending, id: "foreign-1", unit_id: "019b76da-a800-739d-a307-bbc68dcdfb1f" };
    await renderApp(<HomeScreen />, makeApi({ listApprovalRequests: jest.fn(async () => ({ items: [foreign], next_cursor: null })) }));
    await screen.findByTestId("pending-none");
    expect(screen.queryByTestId("pending-foreign-1")).toBeNull();
  });

  test("a notification-adapter event only triggers a refresh from the API (state still comes from the API)", async () => {
    let fire: (() => void) | undefined;
    const notifications = { available: true, register: async () => true, subscribe: (fn: (e: any) => void) => { fire = () => fn({ kind: "unknown" }); return () => undefined; } };
    const list = jest.fn().mockResolvedValueOnce({ items: [], next_cursor: null }).mockResolvedValue({ items: [pending], next_cursor: null });
    await renderApp(<HomeScreen />, makeApi({ listApprovalRequests: list }), { notifications });
    await screen.findByTestId("pending-none");
    fire!();
    await screen.findByTestId(`pending-${pending.id}`);
    expect(list).toHaveBeenCalledTimes(2);
  });

  test("the default adapter claims no push", async () => {
    const utils = await renderApp(<HomeScreen />, makeApi());
    expect(utils.services.notifications.available).toBe(false);
  });

  test("controls have roles, names and >= 48 dp targets", async () => {
    await renderApp(<HomeScreen />, makeApi({ listApprovalRequests: jest.fn(async () => ({ items: [pending], next_cursor: null })) }));
    await screen.findByTestId(`pending-${pending.id}`);
    assertAccessibleControls();
  });
});
