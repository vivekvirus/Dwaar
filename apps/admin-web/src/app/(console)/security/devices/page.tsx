import { Guarded } from "@/components/shell/guarded";
import { DevicesPage } from "@/features/security/devices-page";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.nav.devices");

export default function Page() {
  return (
    <Guarded path="/security/devices">
      <DevicesPage />
    </Guarded>
  );
}
