import { SessionsPage } from "@/features/account/sessions-page";
import { titleOf } from "@/lib/page-title";

export const metadata = titleOf("console.sessions.title");

export default function Page() {
  return <SessionsPage />;
}
