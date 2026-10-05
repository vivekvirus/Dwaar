import { useEffect, useState } from "react";

/** Seconds left, counted down locally from the server-reported value at `anchor` (a changing number, e.g. fetch time). */
export function useCountdown(serverSeconds: number | null, anchor: number | null): number | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (serverSeconds === null) return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [serverSeconds, anchor]);
  if (serverSeconds === null || anchor === null) return serverSeconds;
  return Math.max(0, serverSeconds - Math.floor((now - anchor) / 1000));
}
