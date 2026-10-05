import { Guarded } from "@/components/shell/guarded";
import { ExceptionsPage } from "@/features/security/exceptions-page";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.nav.exceptions");

export default function Page() {
  return (
    <Guarded path="/security/exceptions">
      <ExceptionsPage />
    </Guarded>
  );
}
