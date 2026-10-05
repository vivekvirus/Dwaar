"use client";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { Page } from "@/api/types";

/** Cursor pagination with Previous/Next (the API cursors are opaque and signed; we keep the stack of cursors we were given).
 *  The cache key always starts with the society id, so a page of one society can never be served for another (INV-01). */
export function useCursorPage<T>(societyId: string, key: unknown[], fetchPage: (cursor: string | null) => Promise<Page<T>>, enabled = true) {
  const [stack, setStack] = useState<(string | null)[]>([null]);
  const cursor = stack[stack.length - 1] ?? null;
  const q = useQuery({
    queryKey: [societyId, ...key, cursor],
    queryFn: () => fetchPage(cursor),
    placeholderData: keepPreviousData,
    enabled,
  });
  return {
    query: q,
    rows: q.data?.items ?? [],
    page: {
      index: stack.length - 1,
      hasPrev: stack.length > 1,
      hasNext: !!q.data?.next_cursor,
      fetching: q.isFetching,
      onPrev: () => setStack((s) => (s.length > 1 ? s.slice(0, -1) : s)),
      onNext: () => setStack((s) => (q.data?.next_cursor ? [...s, q.data.next_cursor] : s)),
    },
    reset: () => setStack([null]),
  };
}
