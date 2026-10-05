// Non-secret local preferences (language, last chosen household, device id). Secrets never go here (see auth/tokenStore.ts).
import AsyncStorage from "@react-native-async-storage/async-storage";
import type { HouseholdContext } from "../domain/household";
import { isHouseholdRole } from "../domain/household";
import { uuidv7 } from "../api/ids";

export interface PrefsStore {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export const asyncPrefs: PrefsStore = {
  async getItem(k) {
    try {
      return await AsyncStorage.getItem(k);
    } catch {
      return null;
    }
  },
  async setItem(k, v) {
    try {
      await AsyncStorage.setItem(k, v);
    } catch {
      /* storage unavailable: preference is session-only */
    }
  },
  async removeItem(k) {
    try {
      await AsyncStorage.removeItem(k);
    } catch {
      /* ignore */
    }
  },
};

export class MemoryPrefs implements PrefsStore {
  data = new Map<string, string>();
  async getItem(k: string) {
    return this.data.get(k) ?? null;
  }
  async setItem(k: string, v: string) {
    this.data.set(k, v);
  }
  async removeItem(k: string) {
    this.data.delete(k);
  }
}

const contextKey = (personId: string) => `dwaar.context.${personId}`;

export async function loadStoredContext(prefs: PrefsStore, personId: string): Promise<HouseholdContext | null> {
  const raw = await prefs.getItem(contextKey(personId));
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as Partial<HouseholdContext>;
    if (typeof v.societyId === "string" && typeof v.unitId === "string" && typeof v.role === "string" && isHouseholdRole(v.role)) {
      return { societyId: v.societyId, unitId: v.unitId, role: v.role };
    }
  } catch {
    /* corrupt value: treated as no stored choice */
  }
  return null;
}

export async function storeContext(prefs: PrefsStore, personId: string, ctx: HouseholdContext | null): Promise<void> {
  if (ctx) await prefs.setItem(contextKey(personId), JSON.stringify(ctx));
  else await prefs.removeItem(contextKey(personId));
}

export async function deviceId(prefs: PrefsStore): Promise<string> {
  const existing = await prefs.getItem("dwaar.device_id");
  if (existing) return existing;
  const id = `app-${uuidv7()}`;
  await prefs.setItem("dwaar.device_id", id);
  return id;
}

export async function loadLocale(prefs: PrefsStore): Promise<string | null> {
  return prefs.getItem("dwaar.locale");
}
export async function storeLocale(prefs: PrefsStore, locale: string): Promise<void> {
  await prefs.setItem("dwaar.locale", locale);
}
