import { useRouter } from "expo-router";

/** Thin wrapper so screens (and their tests) depend on a few verbs, not on the router. */
export function useNav() {
  const router = useRouter();
  return {
    push: (path: string) => router.push(path as never),
    replace: (path: string) => router.replace(path as never),
    /** go to a route that may already be on the stack: pops back to it instead of stacking a second copy */
    go: (path: string) => router.dismissTo(path as never),
    back: () => (router.canGoBack() ? router.back() : router.dismissTo("/" as never)),
  };
}
