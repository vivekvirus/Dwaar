import { selectSociety } from "@/server/handlers";

export const dynamic = "force-dynamic";
export const POST = (req: Request) => selectSociety(req);
