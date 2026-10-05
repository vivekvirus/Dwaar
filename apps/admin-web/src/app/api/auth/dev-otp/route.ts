import { devOtp } from "@/server/handlers";

export const dynamic = "force-dynamic";
export const GET = (req: Request) => devOtp(req);
