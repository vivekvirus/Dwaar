"use client";
import { useQuery, type UseQueryOptions } from "@tanstack/react-query";
import { bff, newIdempotencyKey } from "./api-client";
import { useSociety } from "@/components/shell/society-context";

type Q = Record<string, string | number | boolean | null | undefined>;

/** Typed access to the selected society's API through the BFF. Every call carries the selected society; cached results are keyed
 *  by it (INV-01), and the key is the FIRST element so `queryClient.clear()` on switch is belt and braces, not the only guard. */
export function useSocietyApi() {
  const { societyId } = useSociety();
  return {
    societyId,
    get: <T,>(path: string, query?: Q, signal?: AbortSignal) => bff<T>({ kind: "society", path, query, societyId, signal }),
    send: <T,>(method: "POST" | "PUT" | "DELETE", path: string, opts: { json?: unknown; text?: string; query?: Q; idempotencyKey?: string } = {}) =>
      bff<T>({ kind: "society", path, method, societyId, idempotencyKey: opts.idempotencyKey ?? newIdempotencyKey(), ...opts }),
    global: {
      get: <T,>(path: string, query?: Q) => bff<T>({ kind: "v1", path, query, societyId }),
      send: <T,>(method: "POST" | "PUT" | "DELETE", path: string, opts: { json?: unknown; query?: Q; idempotencyKey?: string } = {}) =>
        bff<T>({ kind: "v1", path, method, societyId, idempotencyKey: opts.idempotencyKey ?? newIdempotencyKey(), ...opts }),
    },
  };
}

export function useSocietyQuery<T>(key: unknown[], fn: () => Promise<T>, options: Partial<UseQueryOptions<T>> = {}) {
  const { societyId } = useSociety();
  return useQuery<T>({ queryKey: [societyId, ...key], queryFn: fn, ...options } as UseQueryOptions<T>);
}
