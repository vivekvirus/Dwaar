// REQ: IAM-14 (short-lived access token, ROTATING refresh token with reuse detection). The refresh token is single-use: the
// new pair is persisted BEFORE the awaiting request is retried, and concurrent 401s share ONE refresh (a second parallel
// refresh with the already-rotated token would look like token reuse and revoke the whole session).
import { ApiError, NetworkError } from "../api/errors";
import { ErrorBodySchema, TokenPairSchema, type TokenPair } from "../domain/types";
import type { StoredSession, TokenStore } from "./tokenStore";

export type SessionEvent = "signed_in" | "signed_out" | "refreshed" | "expired";

/** Refresh when the access token has less than this left. */
export const REFRESH_SKEW_MS = 30_000;

export class SessionManager {
  private current: StoredSession | null = null;
  private inflight: Promise<boolean> | null = null;
  private listeners = new Set<(e: SessionEvent) => void>();

  constructor(
    private readonly store: TokenStore,
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = (...a) => fetch(...a),
    private readonly now: () => number = Date.now,
  ) {}

  subscribe(fn: (e: SessionEvent) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private emit(e: SessionEvent): void {
    this.listeners.forEach((l) => l(e));
  }

  async restore(): Promise<boolean> {
    this.current = await this.store.load();
    return this.current !== null;
  }

  get signedIn(): boolean {
    return this.current !== null;
  }

  get sessionId(): string | null {
    return this.current?.sessionId ?? null;
  }

  /** A valid access token, refreshing first if it is about to expire. Null when signed out. */
  async accessToken(): Promise<string | null> {
    if (!this.current) return null;
    if (this.current.accessExpiresAt - this.now() < REFRESH_SKEW_MS) {
      await this.refresh().catch(() => false);
    }
    return this.current?.accessToken ?? null;
  }

  async adopt(pair: TokenPair): Promise<void> {
    const next: StoredSession = {
      accessToken: pair.access_token,
      accessExpiresAt: this.now() + pair.expires_in * 1000,
      refreshToken: pair.refresh_token,
      sessionId: pair.session_id,
    };
    await this.store.save(next);
    this.current = next;
  }

  async signedInWith(pair: TokenPair): Promise<void> {
    await this.adopt(pair);
    this.emit("signed_in");
  }

  async clear(reason: "signed_out" | "expired" = "signed_out"): Promise<void> {
    this.current = null;
    await this.store.clear();
    this.emit(reason);
  }

  /**
   * Rotate the refresh token. Resolves true when a new pair is stored, false when the session is over (the refresh token was
   * rejected: tokens are wiped and "expired" is emitted). Throws NetworkError when the server could not be reached; the
   * stored tokens are kept so a later attempt can still succeed.
   */
  refresh(): Promise<boolean> {
    if (this.inflight) return this.inflight;
    const used = this.current?.refreshToken;
    if (!used) return Promise.resolve(false);
    this.inflight = this.doRefresh(used).finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async doRefresh(used: string): Promise<boolean> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/v1/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ refresh_token: used }),
      });
    } catch (e) {
      throw new NetworkError(e);
    }
    if (res.ok) {
      const parsed = TokenPairSchema.safeParse(await res.json().catch(() => null));
      if (!parsed.success) {
        await this.clear("expired");
        return false;
      }
      await this.adopt(parsed.data); // persist the rotated pair before anyone retries
      this.emit("refreshed");
      return true;
    }
    if (res.status === 401 || res.status === 403 || res.status === 404) {
      await this.clear("expired");
      return false;
    }
    const body = ErrorBodySchema.safeParse(await res.json().catch(() => null));
    throw new ApiError(res.status, body.success ? body.data : { code: "dependency_unavailable" });
  }
}
