// API base URL. EXPO_PUBLIC_* values are inlined at bundle time. On an Android emulator use http://10.0.2.2:8000.
export const API_BASE_URL: string = (process.env.EXPO_PUBLIC_API_BASE_URL ?? "http://localhost:8000").replace(/\/+$/, "");

/** Foreground polling cadence for pending approvals (pull-to-refresh is always available). Push arrives in slice 4. */
export const POLL_INTERVAL_MS = 8000;
