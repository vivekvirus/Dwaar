import { redirect } from "next/navigation";
import { requireSession } from "@/server/page-session";

export default async function SecurityIndex() {
  const { session } = await requireSession();
  const first = session.nav.find((n) => n.href.startsWith("/security/"));
  redirect(first ? first.href : "/overview");
}
