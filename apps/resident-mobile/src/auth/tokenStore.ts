// REQ: PRD 6 / IAM (secure token storage). Native: expo-secure-store (Keychain / Keystore). Web has no secure enclave:
// tokens live in sessionStorage (this tab only), which is documented in the privacy copy and ADR-0015.
import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";

export interface StoredSession {
  accessToken: string;
  /** epoch ms at which the access token expires */
  accessExpiresAt: number;
  refreshToken: string;
  sessionId: string;
}

export interface TokenStore {
  load(): Promise<StoredSession | null>;
  save(session: StoredSession): Promise<void>;
  clear(): Promise<void>;
}

const KEY = "dwaar.session.v1";

function validate(raw: unknown): StoredSession | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (
    typeof r.accessToken === "string" &&
    typeof r.accessExpiresAt === "number" &&
    typeof r.refreshToken === "string" &&
    typeof r.sessionId === "string"
  ) {
    return { accessToken: r.accessToken, accessExpiresAt: r.accessExpiresAt, refreshToken: r.refreshToken, sessionId: r.sessionId };
  }
  return null;
}

class SecureStoreTokenStore implements TokenStore {
  // iOS limits a single value to ~2 KB, so the three secrets are kept under separate keys.
  async load(): Promise<StoredSession | null> {
    try {
      const [access, refresh, meta] = await Promise.all([
        SecureStore.getItemAsync(`${KEY}.access`),
        SecureStore.getItemAsync(`${KEY}.refresh`),
        SecureStore.getItemAsync(`${KEY}.meta`),
      ]);
      if (!access || !refresh || !meta) return null;
      const m = JSON.parse(meta) as { exp?: number; sid?: string };
      return validate({ accessToken: access, refreshToken: refresh, accessExpiresAt: m.exp, sessionId: m.sid });
    } catch {
      return null;
    }
  }
  async save(s: StoredSession): Promise<void> {
    await SecureStore.setItemAsync(`${KEY}.access`, s.accessToken);
    await SecureStore.setItemAsync(`${KEY}.refresh`, s.refreshToken);
    await SecureStore.setItemAsync(`${KEY}.meta`, JSON.stringify({ exp: s.accessExpiresAt, sid: s.sessionId }));
  }
  async clear(): Promise<void> {
    await Promise.all(["access", "refresh", "meta"].map((k) => SecureStore.deleteItemAsync(`${KEY}.${k}`).catch(() => undefined)));
  }
}

class WebSessionTokenStore implements TokenStore {
  async load(): Promise<StoredSession | null> {
    try {
      const raw = globalThis.sessionStorage?.getItem(KEY);
      return raw ? validate(JSON.parse(raw)) : null;
    } catch {
      return null;
    }
  }
  async save(s: StoredSession): Promise<void> {
    try {
      globalThis.sessionStorage?.setItem(KEY, JSON.stringify(s));
    } catch {
      /* storage blocked: the session simply will not survive a reload */
    }
  }
  async clear(): Promise<void> {
    try {
      globalThis.sessionStorage?.removeItem(KEY);
    } catch {
      /* ignore */
    }
  }
}

/** In-memory store for tests and as a fallback. */
export class MemoryTokenStore implements TokenStore {
  value: StoredSession | null = null;
  async load(): Promise<StoredSession | null> {
    return this.value;
  }
  async save(s: StoredSession): Promise<void> {
    this.value = s;
  }
  async clear(): Promise<void> {
    this.value = null;
  }
}

export function createTokenStore(): TokenStore {
  return Platform.OS === "web" ? new WebSessionTokenStore() : new SecureStoreTokenStore();
}
