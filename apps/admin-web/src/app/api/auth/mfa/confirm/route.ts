import { mfaConfirm } from "@/server/handlers";

export const dynamic = "force-dynamic";
export const POST = (req: Request) => mfaConfirm(req);
