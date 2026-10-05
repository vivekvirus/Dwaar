import { Guarded } from "@/components/shell/guarded";
import { Overview } from "@/features/overview/overview";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.nav.overview");

export default function Page() {
  return (
    <Guarded path="/overview">
      <Overview />
    </Guarded>
  );
}
