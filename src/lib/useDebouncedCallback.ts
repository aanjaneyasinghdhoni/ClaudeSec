import { useCallback, useEffect, useRef } from 'react';

/**
 * Returns a stable, trailing-debounced wrapper around `callback`.
 *
 * Why: the heavy dashboard tabs (Cost, Heatmap, Orchestration) refetch on every
 * `graph-update` socket event. A single OTLP batch can fan out into many updates,
 * and each refetch triggers a full server-side table scan. Debouncing collapses a
 * burst of updates into ONE trailing refetch, so the UI still refreshes after the
 * burst settles but does not stampede the server while spans are streaming in.
 *
 * The returned function keeps a stable identity across renders so it can be passed
 * straight to `socket.on(...)` / `socket.off(...)` and unbind cleanly. Internally it
 * always invokes the LATEST `callback`, so closures over changing state (e.g. the
 * current view) never go stale.
 *
 * `maxWaitMs` caps how long a caller can be starved. A plain trailing debounce
 * restarts its timer on every call, so against a source that ticks forever — the
 * anomaly sweep emits `sessions-update` every 2.5s whether or not anything changed
 * — a window wider than the tick interval would never fire at all, and the view
 * would silently stop refreshing. With `maxWaitMs` set, bursts still collapse on
 * `delayMs`, but the callback is guaranteed to run at least that often under a
 * continuous stream.
 */
export function useDebouncedCallback<A extends unknown[]>(
  callback: (...args: A) => void,
  delayMs = 700,
  maxWaitMs?: number,
): (...args: A) => void {
  const callbackRef  = useRef(callback);
  const timerRef     = useRef<ReturnType<typeof setTimeout> | null>(null);
  // When the oldest still-unserved call arrived. null when nothing is pending.
  const firstCallRef = useRef<number | null>(null);

  // Always point at the freshest callback so debounced calls never run stale logic.
  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  // Clear any pending invocation when the component unmounts.
  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  return useCallback(
    (...args: A) => {
      const now = Date.now();
      if (firstCallRef.current === null) firstCallRef.current = now;

      // Never push the invocation past maxWait measured from the FIRST pending call.
      const wait = maxWaitMs === undefined
        ? delayMs
        : Math.max(0, Math.min(delayMs, firstCallRef.current + maxWaitMs - now));

      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        firstCallRef.current = null;
        callbackRef.current(...args);
      }, wait);
    },
    [delayMs, maxWaitMs],
  );
}
