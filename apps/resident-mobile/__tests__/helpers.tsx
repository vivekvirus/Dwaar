import React from "react";
import { render, waitFor, screen } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { AppProvider, useApp, type AppServices } from "../src/state/AppProvider";
import { SessionManager } from "../src/auth/session";
import { MemoryTokenStore } from "../src/auth/tokenStore";
import { MemoryPrefs } from "../src/state/prefs";
import { NoopNotificationAdapter } from "../src/notifications/adapter";
import type { Api } from "../src/api/endpoints";
import type { Me } from "../src/domain/types";

export const SOCIETY_ID = "019b76da-a800-713c-a879-90fe5f48356e";
export const UNIT_ID = "019b76da-a800-739d-a307-bbc64b8d8f4e";
export const OTHER_UNIT_ID = "019b76da-a800-739d-a307-bbc68dcdfb1f";

export function makeMe(overrides: Partial<Me> = {}, roles?: Me["societies"][number]["roles"]): Me {
  return {
    person: { id: "019b76da-a800-7062-9155-bdc5acb94067", display_name: "Sanjay Deshpande", preferred_language: "en", is_minor: false },
    simulation: true,
    societies: [
      {
        society_id: SOCIETY_ID,
        roles:
          roles ?? [
            { role: "owner_occ", source: "membership", unit_id: UNIT_ID, active: true, valid_now: true, expires_at: null },
            { role: "owner_nr", source: "membership", unit_id: OTHER_UNIT_ID, active: true, valid_now: true, expires_at: null },
          ],
      },
    ],
    ...overrides,
  };
}

export type FakeApi = { [K in keyof Api]: jest.Mock };

export function makeApi(over: Partial<FakeApi> = {}): FakeApi {
  const base: FakeApi = {
    meta: jest.fn(async () => ({ environment: "local", simulation: true, server_time: "2026-10-05T10:00:00Z" })),
    otpRequest: jest.fn(async () => ({ status: "accepted", expires_in_seconds: 300 })),
    otpVerify: jest.fn(),
    devOtp: jest.fn(async () => ({ otp: "123456", simulation: true })),
    logout: jest.fn(async () => undefined),
    me: jest.fn(async () => makeMe()),
    updateProfile: jest.fn(async () => ({ updated: true })),
    society: jest.fn(async (id: string) => ({ id, name: "Sahyadri Residency CHS (demo)" })),
    unit: jest.fn(async (_s: string, id: string) => ({ id, label: "402", block_name: "A" })),
    listApprovalRequests: jest.fn(async () => ({ items: [], next_cursor: null })),
    getApprovalRequest: jest.fn(),
    decide: jest.fn(),
    listInvitations: jest.fn(async () => ({ items: [] })),
    getInvitation: jest.fn(),
    createInvitation: jest.fn(),
    revokeInvitation: jest.fn(),
    unitVisits: jest.fn(async () => ({ items: [], next_cursor: null })),
  };
  return { ...base, ...over };
}

export async function makeServices(api: FakeApi, opts: { signedIn?: boolean; prefs?: MemoryPrefs; notifications?: AppServices["notifications"] } = {}): Promise<AppServices & { prefs: MemoryPrefs }> {
  const store = new MemoryTokenStore();
  if (opts.signedIn !== false) {
    store.value = { accessToken: "access-token-0000", accessExpiresAt: Date.now() + 600_000, refreshToken: "refresh-token-0000", sessionId: "s1" };
  }
  const session = new SessionManager(store, "http://api.test", jest.fn() as unknown as typeof fetch);
  return { api: api as unknown as Api, session, prefs: opts.prefs ?? new MemoryPrefs(), notifications: opts.notifications ?? new NoopNotificationAdapter() };
}

const metrics = { frame: { x: 0, y: 0, width: 360, height: 740 }, insets: { top: 0, left: 0, right: 0, bottom: 0 } };

function Gate({ children, need }: { children: React.ReactNode; need: "active" | "status" }) {
  const app = useApp();
  if (need === "active" ? !app.active : app.status === "booting") return null;
  return <>{children}</>;
}

/** Renders `ui` inside the real AppProvider once boot finished (signed in with an active household). */
export async function renderApp(ui: React.ReactElement, api: FakeApi = makeApi(), opts: { signedIn?: boolean; need?: "active" | "status"; prefs?: MemoryPrefs; notifications?: AppServices["notifications"] } = {}) {
  const services = await makeServices(api, opts);
  const utils = render(
    <SafeAreaProvider initialMetrics={metrics}>
      <AppProvider services={services}>
        <Gate need={opts.need ?? "active"}>{ui}</Gate>
      </AppProvider>
    </SafeAreaProvider>,
  );
  await waitFor(() => expect(screen.toJSON()).not.toBeNull(), { timeout: 3000 });
  return { ...utils, api, services };
}

export function flattenStyle(style: unknown): Record<string, any> {
  if (!style) return {};
  if (Array.isArray(style)) return style.reduce((acc, s) => ({ ...acc, ...flattenStyle(s) }), {});
  return style as Record<string, any>;
}
