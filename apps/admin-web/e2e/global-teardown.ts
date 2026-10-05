import { leftovers, stopStack } from "./stack";

export default async function globalTeardown() {
  if (process.env.E2E_REUSE_STACK === "1" || process.env.E2E_KEEP_STACK === "1") return;
  await stopStack();
  const left = leftovers();
  if (left.length) throw new Error(`leftover processes after teardown:\n${left.join("\n")}`);
}
