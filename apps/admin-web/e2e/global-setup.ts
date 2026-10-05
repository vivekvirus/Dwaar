import { grantCrossSocietyRole } from "./fixtures";
import { startStack } from "./stack";

// E2E_REUSE_STACK=1 (development only): a stack started earlier with E2E_KEEP_STACK=1 is reused as is.
export default async function globalSetup() {
  if (process.env.E2E_REUSE_STACK === "1") return;
  await startStack();
  await grantCrossSocietyRole();
}
