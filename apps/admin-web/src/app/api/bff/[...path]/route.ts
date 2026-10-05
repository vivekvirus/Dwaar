import { proxy } from "@/server/handlers";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ path: string[] }> };
const handle = async (req: Request, ctx: Ctx) => proxy(req, (await ctx.params).path);
export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const DELETE = handle;
