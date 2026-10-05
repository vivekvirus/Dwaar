import { Guarded } from "@/components/shell/guarded";
import { SocietySettingsPage } from "@/features/settings/society-page";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.nav.society");

export default function Page() {
  return (
    <Guarded path="/settings/society">
      <SocietySettingsPage />
    </Guarded>
  );
}
