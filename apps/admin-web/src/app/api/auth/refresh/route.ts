import { refreshRedirect } from "@/server/handlers";

export const dynamic = "force-dynamic";
export const GET = (req: Request) => refreshRedirect(req);
