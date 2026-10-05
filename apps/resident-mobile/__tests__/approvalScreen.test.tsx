// REQ: GATE-02, GATE-03, INV-07, UX-04, UX-05. Approval decision screen against a fake API that answers like the real one.
import React from "react";
import { fireEvent, screen, waitFor } from "@testing-library/react-native";
import { ApiError, NetworkError } from "../src/api/errors";
import { ApprovalScreen } from "../src/screens/ApprovalScreen";
import { ApprovalRequestSchema } from "../src/domain/types";
import { makeApi, makeMe, OTHER_UNIT_ID, renderApp, SOCIETY_ID, UNIT_ID } from "./helpers";
import { recorded } from "./fixtures";
import { assertAccessibleControls } from "./a11y";

const base = ApprovalRequestSchema.parse(recorded("approval-request-pending").body);
const pendingReq = { ...base, status: "pending" as const, version: 1, expires_in_seconds: 80, decision: null, decision_id: null, permission_expires_at: null, entry_observed: false };
const canonical = (status: "approved" | "denied" | "expired", version = 2) => ({
  request_id: base.id,
  status,
  version,
  decision_id: status === "expired" ? null : "01a10dcd-d0cc-7078-808f-477dec7a94f7",
  permission_expires_at: status === "approved" ? "2026-10-05T09:30:00Z" : null,
  entry_observed: false,
});
const conflict = (code: string, details: Record<string, unknown>) => new ApiError(409, { code, request_id: "req-9", details });

const open = (api = makeApi({ getApprovalRequest: jest.fn(async () => pendingReq) })) => renderApp(<ApprovalScreen requestId={base.id} />, api);
const press = (name: string) => fireEvent.press(screen.getByRole("button", { name }));

describe("approval decision screen", () => {
  test("shows the exact backend state: visitor, pending status, entry not observed, effect and the no-auto-allow note", async () => {
    await open();
    expect(await screen.findByText("Fixture Courier")).toBeTruthy();
    expect(screen.getByLabelText("Waiting for your decision")).toBeTruthy();
    expect(screen.getByLabelText("Entry: Not yet at gate / not observed")).toBeTruthy();
    expect(screen.getByText(/does not mean the visitor has entered/)).toBeTruthy();
    expect(screen.getByText(/not admitted automatically/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Approve" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Deny" })).toBeTruthy();
    expect(screen.queryByText(/^Entered$/)).toBeNull();
  });

  test("approve sends expected_version, a client_action_id and an Idempotency-Key, then shows 'Approved; not yet entered' with a receipt", async () => {
    const api = makeApi({ getApprovalRequest: jest.fn(async () => pendingReq), decide: jest.fn(async () => canonical("approved")) });
    await open(api);
    await screen.findByText("Fixture Courier");
    press("Approve");
    await screen.findByTestId("approval-closed");
    expect(api.decide).toHaveBeenCalledTimes(1);
    const cmd = api.decide.mock.calls[0]![0];
    expect(cmd).toMatchObject({ requestId: base.id, societyId: SOCIETY_ID, body: { decision: "approve", expected_version: 1, channel: "app" } });
    expect(cmd.idempotencyKey.length).toBeGreaterThanOrEqual(8);
    expect(cmd.body.client_action_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(screen.getByLabelText("Approved; not yet entered")).toBeTruthy();
    expect(screen.getByLabelText("Entry: Not yet at gate / not observed")).toBeTruthy();
    expect(screen.getByText("You approved this request")).toBeTruthy();
    expect(screen.getByTestId("approval-receipt")).toBeTruthy();
    expect(screen.getByTestId("approval-permission")).toBeTruthy();
    expect(screen.queryByText("Entered")).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  test("deny shows Denied and no permission", async () => {
    const api = makeApi({ getApprovalRequest: jest.fn(async () => pendingReq), decide: jest.fn(async () => canonical("denied")) });
    await open(api);
    await screen.findByText("Fixture Courier");
    press("Deny");
    await screen.findByTestId("approval-closed");
    expect(screen.getByLabelText("Denied")).toBeTruthy();
    expect(screen.queryByTestId("approval-permission")).toBeNull();
  });

  test("409 already_decided: the canonical result of the OTHER device is shown (denied), not the approval we tried", async () => {
    const api = makeApi({
      getApprovalRequest: jest.fn(async () => pendingReq),
      decide: jest.fn(async () => {
        throw conflict("already_decided", { canonical: canonical("denied"), decided_by_role: "family" });
      }),
    });
    await open(api);
    await screen.findByText("Fixture Courier");
    press("Approve");
    await screen.findByTestId("approval-decided-elsewhere");
    expect(screen.getByLabelText("Denied")).toBeTruthy();
    expect(screen.getByText("Already decided on another device or by another household member")).toBeTruthy();
    expect(screen.getByText("Decided by: Family member")).toBeTruthy();
    expect(screen.queryByText("You approved this request")).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(api.decide).toHaveBeenCalledTimes(1); // no automatic second attempt after a 409
  });

  test("409 request_expired: shows expiry, no permission and no implied entry; approving is no longer possible", async () => {
    const api = makeApi({
      getApprovalRequest: jest.fn(async () => pendingReq),
      decide: jest.fn(async () => {
        throw conflict("request_expired", { canonical: { ...canonical("expired"), status: "expired" } });
      }),
    });
    await open(api);
    await screen.findByText("Fixture Courier");
    press("Approve");
    await screen.findByTestId("state-expired");
    expect(screen.getByText(/No entry was allowed/)).toBeTruthy();
    expect(screen.getByLabelText("Expired")).toBeTruthy();
    expect(screen.getByLabelText("Entry: Not yet at gate / not observed")).toBeTruthy();
    expect(screen.queryByTestId("approval-permission")).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Deny" })).toBeNull();
  });

  test("network failure: nothing is decided; 'Try again' re-sends the SAME Idempotency-Key and client_action_id", async () => {
    const api = makeApi({
      getApprovalRequest: jest.fn(async () => pendingReq),
      decide: jest.fn().mockRejectedValueOnce(new NetworkError()).mockResolvedValueOnce(canonical("approved")),
    });
    await open(api);
    await screen.findByText("Fixture Courier");
    press("Approve");
    await screen.findByTestId("approval-send-failed");
    expect(screen.getByText(/nothing was decided/)).toBeTruthy();
    press("Try again");
    await screen.findByTestId("approval-closed");
    expect(api.decide).toHaveBeenCalledTimes(2);
    const [a, b] = [api.decide.mock.calls[0]![0], api.decide.mock.calls[1]![0]];
    expect(b.idempotencyKey).toBe(a.idempotencyKey);
    expect(b.body.client_action_id).toBe(a.body.client_action_id);
    expect(b.body).toEqual(a.body);
  });

  test("a request that belongs to another unit/society fails closed as 'not available' and offers no controls", async () => {
    const foreign = { ...pendingReq, unit_id: OTHER_UNIT_ID };
    await open(makeApi({ getApprovalRequest: jest.fn(async () => foreign) }));
    await screen.findByTestId("approval-not-available");
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByText("Fixture Courier")).toBeNull();
  });

  test("a 404 from the API looks exactly like a foreign id (no membership disclosure)", async () => {
    await open(makeApi({ getApprovalRequest: jest.fn(async () => { throw new ApiError(404, { code: "not_found", request_id: "r" }); }) }));
    await screen.findByTestId("approval-not-available");
    expect(screen.queryByText(/member/i)).toBeNull();
  });

  test("an already approved request opens as closed: approved but entry NOT observed", async () => {
    await open(makeApi({ getApprovalRequest: jest.fn(async () => ({ ...pendingReq, status: "approved" as const, version: 2, decision_id: "d1", permission_expires_at: "2026-10-05T09:30:00Z" })) }));
    await screen.findByTestId("approval-closed");
    expect(screen.getByLabelText("Approved; not yet entered")).toBeTruthy();
    expect(screen.getByTestId("approval-entry")).toBeTruthy();
  });

  test("an observed entry is the only thing that shows 'Entered'", async () => {
    await open(makeApi({ getApprovalRequest: jest.fn(async () => ({ ...pendingReq, status: "approved" as const, version: 3, decision_id: "d1", entry_observed: true })) }));
    await screen.findByTestId("approval-closed");
    expect(screen.getByLabelText("Entered")).toBeTruthy();
  });

  test("controls have roles, names and >= 48 dp targets", async () => {
    await open();
    await screen.findByText("Fixture Courier");
    const controls = assertAccessibleControls();
    expect(controls.map((c) => c.label)).toEqual(expect.arrayContaining(["Approve", "Deny"]));
  });

  test("Marathi: preferred_language mr renders the screen in Marathi, unit number stays Latin", async () => {
    const api = makeApi({ getApprovalRequest: jest.fn(async () => pendingReq), me: jest.fn(async () => makeMe({ person: { id: "p", display_name: "x", preferred_language: "mr" } })) });
    await open(api);
    await waitFor(() => expect(screen.getByRole("button", { name: "मंजूर करा" })).toBeTruthy());
    expect(screen.getByText(/402/)).toBeTruthy();
    expect(screen.getByText(/अजून गेटवर नाही/)).toBeTruthy();
  });

  test("the screen requests the request from the ACTIVE society only", async () => {
    const api = makeApi({ getApprovalRequest: jest.fn(async () => pendingReq) });
    await open(api);
    await screen.findByText("Fixture Courier");
    expect(api.getApprovalRequest).toHaveBeenCalledWith(SOCIETY_ID, base.id);
    expect(UNIT_ID).toBe(pendingReq.unit_id);
  });
});
