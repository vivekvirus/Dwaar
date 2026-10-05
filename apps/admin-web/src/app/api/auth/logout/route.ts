import { logout } from "@/server/handlers";

export const dynamic = "force-dynamic";
export const POST = (req: Request) => logout(req);
