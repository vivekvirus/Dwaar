import { Guarded } from "@/components/shell/guarded";
import { GatesPage } from "@/features/security/gates-page";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.nav.gates");

export default function Page() {
  return (
    <Guarded path="/security/gates">
      <GatesPage />
    </Guarded>
  );
}
