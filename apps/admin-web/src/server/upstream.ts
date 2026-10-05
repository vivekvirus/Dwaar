// REQ: INV-01, IAM-08. The only place that talks to the Dwaar API. Tokens are attached here, server-side, never in the browser.
import { upstreamBase } from "./config";

export type UpstreamCall = {
  method: string;
  path: string; // e.g. /v1/me
  token?: string | null;
  society?: string | null; // X-Society-Id
  query?: URLSearchParams | Record<string, string> | null;
  json?: unknown;
  text?: string;
  idempotencyKey?: string | null;
  requestId?: string | null;
};

export type UpstreamResult = { status: number; headers: Headers; body: unknown; text: string };

export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

export async function callUpstream(call: UpstreamCall, fetcher: Fetcher = fetch as Fetcher): Promise<UpstreamResult> {
  const url = new URL(upstreamBase() + call.path);
  if (call.query) {
    const q = call.query instanceof URLSearchParams ? call.query : new URLSearchParams(call.query);
    q.forEach((v, k) => url.searchParams.append(k, v));
  }
  const headers: Record<string, string> = { accept: "application/json" };
  if (call.token) headers.authorization = `Bearer ${call.token}`;
  if (call.society) headers["x-society-id"] = call.society;
  if (call.idempotencyKey) headers["idempotency-key"] = call.idempotencyKey;
  if (call.requestId) headers["x-request-id"] = call.requestId;
  let body: string | undefined;
  if (call.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(call.json);
  } else if (call.text !== undefined) {
    headers["content-type"] = "text/csv";
    body = call.text;
  }
  let res: Response;
  try {
    res = await fetcher(url.toString(), { method: call.method, headers, body, cache: "no-store", redirect: "manual" });
  } catch {
    return {
      status: 503,
      headers: new Headers({ "retry-after": "5" }),
      body: { request_id: call.requestId ?? crypto.randomUUID(), code: "dependency_unavailable", message: "", message_key: "errors.dependency_unavailable", details: {} },
      text: "",
    };
  }
  const text = await res.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }
  return { status: res.status, headers: res.headers, body: parsed, text };
}
