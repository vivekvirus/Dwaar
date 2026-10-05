import type { ReactNode } from "react";
import { NoConsoleAccess, SocietyPicker } from "@/components/shell/blocked";
import { Shell } from "@/components/shell/shell";
import { requireSession } from "@/server/page-session";

export const dynamic = "force-dynamic";

export default async function ConsoleLayout({ children }: { children: ReactNode }) {
  const { session } = await requireSession();
  if (!session.societies.some((s) => s.consoleAccess)) return <NoConsoleAccess />;
  if (!session.selectedSocietyId) return <SocietyPicker societies={session.societies} personName={session.person.displayName} />;
  return (
    <Shell
      person={{ displayName: session.person.displayName }}
      simulation={session.simulation}
      societies={session.societies}
      selectedSocietyId={session.selectedSocietyId}
      capabilities={session.capabilities}
      nav={session.nav}
    >
      {children}
    </Shell>
  );
}
