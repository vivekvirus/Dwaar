// REQ: IAM-14 (OTP sign-in), INV-01 (household selector never silently changes; stale ids fail closed), PRD 6 simulator label.
import React from "react";
import { act, fireEvent, screen, waitFor, render } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { Text } from "react-native";
import { ApiError } from "../src/api/errors";
import { AppProvider, useApp, contextKey } from "../src/state/AppProvider";
import { SignInScreen } from "../src/screens/SignInScreen";
import { ChooseHomeScreen } from "../src/screens/ChooseHomeScreen";
import { SimulatorBanner } from "../src/ui/chrome";
import { MemoryPrefs, loadStoredContext, storeContext } from "../src/state/prefs";
import { makeApi, makeMe, makeServices, renderApp, SOCIETY_ID, UNIT_ID, OTHER_UNIT_ID } from "./helpers";
import { assertAccessibleControls } from "./a11y";

const nav = (require("expo-router") as any).__router;
beforeEach(() => jest.clearAllMocks());

const two = [
  { role: "owner_occ", unit_id: UNIT_ID, active: true, valid_now: true },
  { role: "tenant", unit_id: OTHER_UNIT_ID, active: true, valid_now: true },
];

const pair = { token_type: "Bearer", access_token: "access-token-1111", refresh_token: "refresh-token-1111", expires_in: 900, session_id: "s2", simulation: true };

describe("sign-in", () => {
  test("simulator is visibly labelled ('Simulator') on the sign-in flow", async () => {
    const api = makeApi();
    await renderApp(
      <>
        <SimulatorBanner />
        <SignInScreen />
      </>,
      api,
      { signedIn: false, need: "status" },
    );
    await screen.findByTestId("simulator-banner");
    expect(screen.getAllByText(/Simulator/).length).toBeGreaterThan(0);
    expect(screen.getByLabelText(/^Simulator\./)).toBeTruthy();
  });

  test("phone -> code -> verify signs in with device info, tokens come from the API; simulator helper fills the code", async () => {
    const api = makeApi({ otpVerify: jest.fn(async () => pair) });
    await renderApp(<SignInScreen />, api, { signedIn: false, need: "status" });
    fireEvent.changeText(await screen.findByTestId("input-phone"), "+91 99999 01202");
    fireEvent.press(screen.getByRole("button", { name: "Send code" }));
    await screen.findByTestId("input-code");
    expect(api.otpRequest).toHaveBeenCalledWith("+919999901202");
    fireEvent.press(screen.getByRole("button", { name: "Simulator: Fill code from simulator" }));
    await waitFor(() => expect(screen.getByTestId("input-code").props.value).toBe("123456"));
    fireEvent.press(screen.getByRole("button", { name: "Verify and sign in" }));
    await waitFor(() => expect(api.otpVerify).toHaveBeenCalled());
    const [phone, code, device] = api.otpVerify.mock.calls[0]!;
    expect(phone).toBe("+919999901202");
    expect(code).toBe("123456");
    expect(device.device_id).toMatch(/^app-/);
    await waitFor(() => expect(api.me).toHaveBeenCalled());
  });

  test("a wrong code gives ONE generic message (no hint whether the number is registered)", async () => {
    const api = makeApi({ otpVerify: jest.fn(async () => { throw new ApiError(401, { code: "unauthenticated", request_id: "r" }); }) });
    await renderApp(<SignInScreen />, api, { signedIn: false, need: "status" });
    fireEvent.changeText(await screen.findByTestId("input-phone"), "+919999901202");
    fireEvent.press(screen.getByRole("button", { name: "Send code" }));
    fireEvent.changeText(await screen.findByTestId("input-code"), "000000");
    fireEvent.press(screen.getByRole("button", { name: "Verify and sign in" }));
    await screen.findByText("Sign-in did not work. Check the number and code and try again.");
  });

  test("rate limiting shows the retry information", async () => {
    const api = makeApi({ otpRequest: jest.fn(async () => { throw new ApiError(429, { code: "rate_limited", request_id: "r" }, 30); }) });
    await renderApp(<SignInScreen />, api, { signedIn: false, need: "status" });
    fireEvent.changeText(await screen.findByTestId("input-phone"), "+919999901202");
    fireEvent.press(screen.getByRole("button", { name: "Send code" }));
    await screen.findByText(/Too many attempts. Please try again in 30 seconds./);
  });

  test("sign-in controls are accessible (roles, names, 48 dp)", async () => {
    await renderApp(<SignInScreen />, makeApi(), { signedIn: false, need: "status" });
    await screen.findByTestId("input-phone");
    assertAccessibleControls();
    expect(screen.getByLabelText("Mobile number")).toBeTruthy();
  });
});

function Probe() {
  const a = useApp();
  return (
    <>
      <Text testID="probe-active">{a.active ? contextKey(a.active) : "none"}</Text>
      <Text testID="probe-choice">{a.choice ? (a.choice.stale ? "stale" : "choose") : "no"}</Text>
      <Text testID="probe-status">{a.status}</Text>
    </>
  );
}
async function mountProbe(api: ReturnType<typeof makeApi>, prefs: MemoryPrefs) {
  const services = await makeServices(api, { prefs });
  const utils = render(
    <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width: 360, height: 700 }, insets: { top: 0, left: 0, right: 0, bottom: 0 } }}>
      <AppProvider services={services}>
        <Probe />
      </AppProvider>
    </SafeAreaProvider>,
  );
  await waitFor(() => expect(screen.getByTestId("probe-status").props.children).toBe("signedIn"));
  return { ...utils, services };
}

describe("household context (INV-01)", () => {
  const me = makeMe({}, two);
  const key = (unit: string, role: string) => `${SOCIETY_ID}:${unit}:${role}`;

  test("two homes and no stored choice: the person must choose; nothing is picked silently", async () => {
    await mountProbe(makeApi({ me: jest.fn(async () => me) }), new MemoryPrefs());
    expect(screen.getByTestId("probe-active").props.children).toBe("none");
    expect(screen.getByTestId("probe-choice").props.children).toBe("choose");
  });

  test("a stored choice that is no longer offered is dropped with a notice; no other home is substituted", async () => {
    const prefs = new MemoryPrefs();
    await storeContext(prefs, me.person.id, { societyId: "another-society", unitId: "gone-unit", role: "tenant" });
    await mountProbe(makeApi({ me: jest.fn(async () => me) }), prefs);
    expect(screen.getByTestId("probe-active").props.children).toBe("none");
    expect(screen.getByTestId("probe-choice").props.children).toBe("stale");
    expect(await loadStoredContext(prefs, me.person.id)).toBeNull();
  });

  test("a stored choice that is still offered is kept across restarts", async () => {
    const prefs = new MemoryPrefs();
    await storeContext(prefs, me.person.id, { societyId: SOCIETY_ID, unitId: OTHER_UNIT_ID, role: "tenant" });
    await mountProbe(makeApi({ me: jest.fn(async () => me) }), prefs);
    expect(screen.getByTestId("probe-active").props.children).toBe(key(OTHER_UNIT_ID, "tenant"));
  });

  test("exactly one home: it becomes active and is stored", async () => {
    const prefs = new MemoryPrefs();
    await mountProbe(makeApi(), prefs);
    expect(screen.getByTestId("probe-active").props.children).toBe(key(UNIT_ID, "owner_occ"));
    expect(await loadStoredContext(prefs, makeMe().person.id)).toMatchObject({ unitId: UNIT_ID });
  });

  test("the picker lists only offered homes with names from the API; choosing one activates and stores it", async () => {
    const prefs = new MemoryPrefs();
    const api = makeApi({ me: jest.fn(async () => me), unit: jest.fn(async (_s: string, id: string) => ({ id, label: id === UNIT_ID ? "402" : "C-101", block_name: "A" })) });
    await renderApp(<ChooseHomeScreen />, api, { need: "status", prefs });
    const button = await screen.findByRole("button", { name: "Use Sahyadri Residency CHS (demo), unit C-101 (Tenant)" });
    expect(screen.getByRole("button", { name: "Use Sahyadri Residency CHS (demo), unit 402 (Owner, living here)" })).toBeTruthy();
    expect(screen.getAllByRole("button")).toHaveLength(2);
    fireEvent.press(button);
    await waitFor(() => expect(nav.dismissTo).toHaveBeenCalledWith("/"));
    expect(await loadStoredContext(prefs, me.person.id)).toMatchObject({ unitId: OTHER_UNIT_ID, role: "tenant" });
  });

  test("no household role at all: a permission-style message and sign out, never an empty app", async () => {
    const guardOnly = makeMe({}, [{ role: "guard", unit_id: null, active: true, valid_now: true }]);
    await renderApp(<ChooseHomeScreen />, makeApi({ me: jest.fn(async () => guardOnly) }), { need: "status" });
    await screen.findByTestId("screen-no-household");
    expect(screen.getByText("No household access")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeTruthy();
  });

  async function mountGrab(api: ReturnType<typeof makeApi>) {
    const ref: { current?: ReturnType<typeof useApp> } = {};
    function Grab() {
      ref.current = useApp();
      return null;
    }
    const services = await makeServices(api, {});
    render(
      <SafeAreaProvider initialMetrics={{ frame: { x: 0, y: 0, width: 360, height: 700 }, insets: { top: 0, left: 0, right: 0, bottom: 0 } }}>
        <AppProvider services={services}>
          <Grab />
        </AppProvider>
      </SafeAreaProvider>,
    );
    await waitFor(() => expect(ref.current?.status).toBe("signedIn"));
    return { ref, services };
  }

  test("changing home clears cached data (cache keys never mix societies/units) and refuses homes the server did not offer", async () => {
    const { ref } = await mountGrab(makeApi({ me: jest.fn(async () => me) }));
    await waitFor(() => expect(ref.current?.contexts.length).toBe(2));
    await act(async () => ref.current!.selectContext(ref.current!.contexts[0]!));
    expect(ref.current!.active).toMatchObject({ unitId: UNIT_ID });
    ref.current!.cache.set("pending:x", [1]);
    await act(async () => ref.current!.selectContext(ref.current!.contexts[1]!));
    expect(ref.current!.active).toMatchObject({ unitId: OTHER_UNIT_ID });
    expect(ref.current!.cache.get("pending:x")).toBeUndefined();
    await act(async () => ref.current!.selectContext({ societyId: "x", unitId: "y", role: "tenant" }));
    expect(ref.current!.active).toMatchObject({ unitId: OTHER_UNIT_ID }); // unchanged
  });

  test("sign out revokes the session on the server, wipes local tokens and returns to signed-out", async () => {
    const api = makeApi();
    const { ref, services } = await mountGrab(api);
    await act(async () => ref.current!.signOut());
    expect(api.logout).toHaveBeenCalled();
    expect(services.session.signedIn).toBe(false);
    expect(ref.current!.status).toBe("signedOut");
    expect(ref.current!.me).toBeNull();
  });

  test("the session ending (refresh token rejected) returns to sign-in with a notice", async () => {
    const { ref, services } = await mountGrab(makeApi());
    await act(async () => services.session.clear("expired"));
    expect(ref.current!.status).toBe("signedOut");
    expect(ref.current!.sessionEnded).toBe(true);
  });
});
