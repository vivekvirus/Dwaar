import type { ReactNode } from "react";
import { Forbidden } from "./blocked";
import { pageAllowed } from "@/server/page-session";

/** Server component: renders its children only when the SERVER-derived capabilities of the selected society allow `path`. */
export async function Guarded({ path, children }: { path: string; children: ReactNode }) {
  if (!(await pageAllowed(path))) return <Forbidden />;
  return <>{children}</>;
}
