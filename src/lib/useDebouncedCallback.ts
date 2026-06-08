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
 */
export function useDebouncedCallback<A extends unknown[]>(
  callback: (...args: A) => void,
  delayMs = 700,
): (...args: A) => void {
  const callbackRef = useRef(callback);
  const timerRef    = useRef<ReturnType<typeof setTimeout> | null>(null);

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
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        callbackRef.current(...args);
      }, delayMs);
    },
    [delayMs],
  );
}
