import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
export const APP = resolve(REPO, "apps/admin-web");
export const PG_PORT = Number(process.env.E2E_PG_PORT ?? 55450);
export const API_PORT = Number(process.env.E2E_API_PORT ?? 8150);
export const WEB_PORT = Number(process.env.E2E_WEB_PORT ?? 3150);
export const PG_ROOT = process.env.E2E_PG_ROOT ?? "/tmp/dwaar-admin-e2e-pg";
export const API_URL = `http://127.0.0.1:${API_PORT}`;
export const WEB_URL = `http://localhost:${WEB_PORT}`;
export const STATE_FILE = resolve(APP, "e2e/.state/stack.json");

/** Environment of the private stack: nothing here touches the shared dev database on :55432. */
export function stackEnv(): NodeJS.ProcessEnv {
  const db = (role: string, pw: string) => `postgresql://dwaar_${role}:${pw}@127.0.0.1:${PG_PORT}/dwaar`;
  return {
    ...process.env,
    DWAAR_ENV: "local",
    DWAAR_PG_ROOT: PG_ROOT,
    DWAAR_PG_PORT: String(PG_PORT),
    DWAAR_API_PORT: String(API_PORT),
    DWAAR_DATABASE_OWNER_URL: db("owner", "dwaar-local-owner"),
    DWAAR_DATABASE_URL: db("app", "dwaar-local-app"),
    DWAAR_DATABASE_WORKER_URL: db("worker", "dwaar-local-worker"),
  };
}

export const SEED = {
  mh: { id: "", name: "Sahyadri Residency CHS (demo)" },
  ka: { id: "", name: "Nandana Apartments Owners Association (demo)" },
};

export const PHONES = {
  secretaryMh: "+919999901001", // Anita Kulkarni
  committeeMh: "+919999901003", // Sunita Deshmukh
  guardSupMh: "+919999901008", // Sachin Jadhav
  treasurerMh: "+919999901002", // Rajesh Pawar
  guardMh: "+919999901006", // Ramesh Shinde (no second factor)
  residentMh: "+919999901201", // Neha Patil
  secretaryKa: "+919999901101", // Meera Joshi (secretary of Nandana; given committee in Sahyadri by the fixture)
  estateMgrMh: "+919999901005", // Vinod Gaikwad (UI sign-in test)
  committee2Mh: "+919999901004", // Prakash Joshi (session list test: three sessions)
};
