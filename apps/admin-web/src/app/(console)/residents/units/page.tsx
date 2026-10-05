import { Guarded } from "@/components/shell/guarded";
import { UnitsPage } from "@/features/units/units-page";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.nav.units");

export default function Page() {
  return (
    <Guarded path="/residents/units">
      <UnitsPage />
    </Guarded>
  );
}
