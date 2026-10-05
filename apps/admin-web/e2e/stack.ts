import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { API_PORT, API_URL, APP, PG_PORT, PG_ROOT, REPO, STATE_FILE, WEB_PORT, stackEnv } from "./env";

type State = { apiPid?: number; webPid?: number };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function save(state: State) {
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state));
}

async function waitFor(url: string, label: string, timeoutMs = 120_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch {
      /* not up yet */
    }
    await sleep(500);
  }
  throw new Error(`${label} did not become ready at ${url}`);
}

function spawnGroup(cmd: string, args: string[], env: NodeJS.ProcessEnv, cwd: string, logName: string): ChildProcess {
  mkdirSync(`${APP}/e2e/.state`, { recursive: true });
  const out = openSync(`${APP}/e2e/.state/${logName}.log`, "w");
  return spawn(cmd, args, { cwd, env, detached: true, stdio: ["ignore", out, out] });
}

function killGroup(pid: number | undefined) {
  if (!pid) return;
  for (const sig of ["SIGTERM", "SIGKILL"] as const) {
    try {
      process.kill(-pid, sig);
    } catch {
      return; // group already gone
    }
    if (sig === "SIGTERM") {
      const t0 = Date.now();
      while (Date.now() - t0 < 5000) {
        try {
          process.kill(-pid, 0);
        } catch {
          return;
        }
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
      }
    }
  }
}

const make = (target: string, env: NodeJS.ProcessEnv) => execFileSync("make", [target], { cwd: REPO, env, stdio: "pipe", timeout: 300_000 }).toString();

/** Brings up Postgres, migrations, the seed, the API and the console, exactly like the README "Local demo" (DWAAR_ENV=local). */
export async function startStack() {
  const env = stackEnv();
  await stopStack(); // never inherit a half-dead stack of an earlier crashed run
  rmSync(PG_ROOT, { recursive: true, force: true });
  const state: State = {};
  try {
    make("db-up", env);
    make("migrate", env);
    make("seed", env);
    const api = spawnGroup("make", ["api"], env, REPO, "api");
    state.apiPid = api.pid;
    save(state);
    await waitFor(`${API_URL}/healthz`, "API");
    const web = spawnGroup("npx", ["next", "start", "-p", String(WEB_PORT)], { ...env, DWAAR_API_URL: API_URL, NODE_ENV: "production" }, APP, "web");
    state.webPid = web.pid;
    save(state);
    await waitFor(`http://localhost:${WEB_PORT}/api/session`, "console");
  } catch (e) {
    await stopStack();
    throw e;
  }
}

export async function stopStack() {
  const env = stackEnv();
  let state: State = {};
  if (existsSync(STATE_FILE)) {
    try {
      state = JSON.parse(readFileSync(STATE_FILE, "utf8")) as State;
    } catch {
      state = {};
    }
  }
  killGroup(state.webPid);
  killGroup(state.apiPid);
  try {
    if (existsSync(PG_ROOT)) make("db-down", env);
  } catch {
    /* already stopped */
  }
  rmSync(PG_ROOT, { recursive: true, force: true });
  rmSync(STATE_FILE, { force: true });
  rmSync(`${APP}/e2e/.state/totp-used.json`, { force: true });
  rmSync(`${APP}/e2e/.state/tokens.json`, { force: true });
}

/** Names of processes that would indicate a leak (used by the teardown assertion). */
export function leftovers(): string[] {
  try {
    const out = execFileSync("pgrep", ["-af", `${PG_ROOT}|-p ${WEB_PORT}|--port ${API_PORT}|port ${API_PORT}`], { encoding: "utf8" });
    return out.split("\n").filter((l) => l && !l.includes("pgrep"));
  } catch {
    return [];
  }
}

export const ports = { PG_PORT, API_PORT, WEB_PORT };
