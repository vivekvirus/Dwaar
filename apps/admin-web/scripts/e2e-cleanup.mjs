// Recovery after a hard-killed e2e run: stops the private stack recorded in e2e/.state/stack.json and removes its database.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(app, "../..");
const stateFile = resolve(app, "e2e/.state/stack.json");
const pgRoot = process.env.E2E_PG_ROOT ?? "/tmp/dwaar-admin-e2e-pg";
const env = { ...process.env, DWAAR_PG_ROOT: pgRoot, DWAAR_PG_PORT: String(process.env.E2E_PG_PORT ?? 55450) };

if (existsSync(stateFile)) {
  const s = JSON.parse(readFileSync(stateFile, "utf8"));
  for (const pid of [s.webPid, s.apiPid]) {
    if (!pid) continue;
    try { process.kill(-pid, "SIGTERM"); } catch { /* gone */ }
  }
}
try { if (existsSync(pgRoot)) execFileSync("make", ["db-down"], { cwd: repo, env, stdio: "inherit" }); } catch { /* already down */ }
rmSync(pgRoot, { recursive: true, force: true });
rmSync(stateFile, { force: true });
console.log("e2e stack stopped and removed");
