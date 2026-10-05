// REQ: PRD 6 / IAM: secure token storage. Native uses expo-secure-store; web uses sessionStorage (tab-scoped).
import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";
import { createTokenStore, type StoredSession } from "../src/auth/tokenStore";

const s: StoredSession = { accessToken: "a".repeat(400), accessExpiresAt: 1_800_000_000_000, refreshToken: "r".repeat(64), sessionId: "sid-1" };

describe("token store", () => {
  const mem = (SecureStore as any).__mem as Map<string, string>;
  beforeEach(() => mem.clear());

  test("native: saved in expo-secure-store under separate keys (no value over 2 KB), never in AsyncStorage", async () => {
    Platform.OS = "android";
    const store = createTokenStore();
    await store.save(s);
    expect(SecureStore.setItemAsync).toHaveBeenCalledTimes(3);
    for (const v of mem.values()) expect(v.length).toBeLessThan(2048);
    expect(await store.load()).toEqual(s);
    await store.clear();
    expect(await store.load()).toBeNull();
    expect(mem.size).toBe(0);
  });

  test("native: partial or corrupt data reads as signed out", async () => {
    Platform.OS = "ios";
    mem.set("dwaar.session.v1.access", "x");
    expect(await createTokenStore().load()).toBeNull();
    mem.set("dwaar.session.v1.refresh", "y");
    mem.set("dwaar.session.v1.meta", "{not json");
    expect(await createTokenStore().load()).toBeNull();
  });

  test("web: sessionStorage only (tab-scoped), localStorage is never used for tokens", async () => {
    Platform.OS = "web";
    const sessionStore = new Map<string, string>();
    const local = jest.fn();
    (globalThis as any).sessionStorage = { getItem: (k: string) => sessionStore.get(k) ?? null, setItem: (k: string, v: string) => void sessionStore.set(k, v), removeItem: (k: string) => void sessionStore.delete(k) };
    (globalThis as any).localStorage = { getItem: local, setItem: local, removeItem: local };
    const store = createTokenStore();
    await store.save(s);
    expect(await store.load()).toEqual(s);
    expect(local).not.toHaveBeenCalled();
    await store.clear();
    expect(await store.load()).toBeNull();
    delete (globalThis as any).sessionStorage;
    delete (globalThis as any).localStorage;
    Platform.OS = "ios";
  });

  test("web: blocked storage does not crash", async () => {
    Platform.OS = "web";
    (globalThis as any).sessionStorage = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => { throw new Error("blocked"); } };
    const store = createTokenStore();
    await expect(store.save(s)).resolves.toBeUndefined();
    await expect(store.load()).resolves.toBeNull();
    delete (globalThis as any).sessionStorage;
    Platform.OS = "ios";
  });
});
