// REQ: IAM-08, IAM-09, INV-05. Server-only configuration of the BFF.
export const COOKIE = {
  access: "dwaar_at",
  refresh: "dwaar_rt",
  society: "dwaar_soc",
  csrf: "dwaar_csrf",
  device: "dwaar_dev",
} as const;

export function upstreamBase(): string {
  return (process.env.DWAAR_API_URL ?? "http://127.0.0.1:8000").replace(/\/+$/, "");
}

/** Secure cookies everywhere except the labelled local environment (plain http on localhost). */
export function cookiesSecure(): boolean {
  const flag = process.env.DWAAR_ADMIN_COOKIE_SECURE;
  if (flag === "true") return true;
  if (flag === "false") return false;
  return process.env.NODE_ENV === "production" && process.env.DWAAR_ENV !== "local";
}

/** Strict allow-list of upstream routes reachable through the generic proxy (the BFF is not an open relay). */
export const PROXY_ALLOW: readonly { method: string; pattern: RegExp }[] = [
  { method: "GET", pattern: /^\/v1\/societies\/[0-9a-f-]{36}\/(units|blocks|gates|gate-policy|devices|exceptions|visits|approval-requests|configuration|feature-flags)$/ },
  { method: "GET", pattern: /^\/v1\/societies\/[0-9a-f-]{36}\/devices\/[0-9a-f-]{36}$/ },
  { method: "GET", pattern: /^\/v1\/societies\/[0-9a-f-]{36}\/gates\/[0-9a-f-]{36}\/lanes$/ },
  { method: "GET", pattern: /^\/v1\/meta$/ },
  { method: "PUT", pattern: /^\/v1\/societies\/[0-9a-f-]{36}\/gate-policy$/ },
  { method: "POST", pattern: /^\/v1\/societies\/[0-9a-f-]{36}\/units:import$/ },
  { method: "POST", pattern: /^\/v1\/societies\/[0-9a-f-]{36}\/devices\/[0-9a-f-]{36}\/(decision|revoke)$/ },
  { method: "POST", pattern: /^\/v1\/exceptions\/[0-9a-f-]{36}\/transition$/ },
  { method: "GET", pattern: /^\/v1\/auth\/sessions$/ },
  { method: "DELETE", pattern: /^\/v1\/auth\/sessions$/ },
  { method: "DELETE", pattern: /^\/v1\/auth\/sessions\/[0-9a-f-]{36}$/ },
];

/** Query parameters the proxy forwards (everything else is dropped; the society is NEVER taken from the client query). */
export const QUERY_ALLOW = new Set([
  "limit", "cursor", "status", "block_id", "floor", "label", "state", "kind", "gate_id", "unit_id", "purpose", "from", "to",
  "dry_run", "create_missing_blocks", "expected_version",
]);
