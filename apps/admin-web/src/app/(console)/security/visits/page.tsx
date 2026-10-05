import { Guarded } from "@/components/shell/guarded";
import { VisitsPage } from "@/features/security/visits-page";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.nav.visits");

export default function Page() {
  return (
    <Guarded path="/security/visits">
      <VisitsPage />
    </Guarded>
  );
}
