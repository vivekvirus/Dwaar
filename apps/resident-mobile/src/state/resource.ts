// Tiny data hook with an in-memory cache (cleared on sign-out and on any household change: INV-01, cache keys carry the
// society + unit), pull-to-refresh and foreground polling. Nothing here is persisted to disk.
import { useCallback, useEffect, useRef, useState } from "react";
import { AppState as RNAppState } from "react-native";
import { NetworkError } from "../api/errors";

export class DataCache {
  private map = new Map<string, { value: unknown; at: number }>();
  get<T>(key: string): { value: T; at: number } | undefined {
    return this.map.get(key) as { value: T; at: number } | undefined;
  }
  set(key: string, value: unknown): void {
    this.map.set(key, { value, at: Date.now() });
  }
  clear(): void {
    this.map.clear();
  }
}

export interface Resource<T> {
  data: T | undefined;
  error: unknown;
  /** first load with nothing to show */
  loading: boolean;
  refreshing: boolean;
  /** the last attempt could not reach the server; `data` (if any) is older saved information */
  offline: boolean;
  updatedAt: number | null;
  refresh: () => Promise<void>;
}

export function useResource<T>(
  cache: DataCache,
  key: string | null,
  fetcher: () => Promise<T>,
  opts: { pollMs?: number } = {},
): Resource<T> {
  const cached = key ? cache.get<T>(key) : undefined;
  const [data, setData] = useState<T | undefined>(cached?.value);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState<boolean>(key !== null && !cached);
  const [refreshing, setRefreshing] = useState(false);
  const [offline, setOffline] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<number | null>(cached?.at ?? null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const seq = useRef(0);
  const alive = useRef(true);

  const run = useCallback(
    async (manual: boolean) => {
      if (!key) return;
      const mine = ++seq.current;
      if (manual) setRefreshing(true);
      try {
        const value = await fetcherRef.current();
        if (!alive.current || mine !== seq.current) return;
        cache.set(key, value);
        setData(value);
        setError(null);
        setOffline(false);
        setUpdatedAt(Date.now());
      } catch (e) {
        if (!alive.current || mine !== seq.current) return;
        setError(e);
        setOffline(e instanceof NetworkError);
      } finally {
        if (alive.current && mine === seq.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [cache, key],
  );

  useEffect(() => {
    alive.current = true;
    const c = key ? cache.get<T>(key) : undefined;
    setData(c?.value);
    setUpdatedAt(c?.at ?? null);
    setError(null);
    setOffline(false);
    setLoading(key !== null && !c);
    void run(false);
    return () => {
      alive.current = false;
    };
  }, [key, cache, run]);

  useEffect(() => {
    if (!key || !opts.pollMs) return;
    let timer: ReturnType<typeof setInterval> | null = null;
    const start = () => {
      if (!timer) timer = setInterval(() => void run(false), opts.pollMs);
    };
    const stop = () => {
      if (timer) clearInterval(timer);
      timer = null;
    };
    start();
    const sub = RNAppState.addEventListener("change", (s) => (s === "active" ? start() : stop()));
    return () => {
      stop();
      sub.remove();
    };
  }, [key, opts.pollMs, run]);

  const refresh = useCallback(() => run(true), [run]);
  return { data, error, loading, refreshing, offline, updatedAt, refresh };
}
