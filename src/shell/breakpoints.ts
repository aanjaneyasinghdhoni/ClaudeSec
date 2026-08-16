import { useEffect, useState } from 'react';

/**
 * The five layout tiers the shell actually behaves differently at. These are the
 * same numbers as the `--breakpoint-*` values in index.css; they are duplicated
 * here because a couple of decisions (which sidebar state to mount with, whether
 * the detail pane is a sheet or a column) have to be made in JavaScript before
 * first paint and cannot be expressed as a media query.
 *
 *   base  <1024  touch / narrow — rail and list share one off-canvas sheet
 *   lg     1024  icon rail forced, list column appears, detail is an overlay
 *   xl     1280  the 1366 laptop tier: icon rail collapsed by default, compact rows
 *   2xl    1440  rail may expand to 180px, rows relax to 36px
 *   3xl    1920  rail expanded to 224px, detail becomes a persistent column
 */
export type Tier = 'base' | 'lg' | 'xl' | '2xl' | '3xl';

const TIERS: { tier: Tier; min: number }[] = [
  { tier: '3xl', min: 1920 },
  { tier: '2xl', min: 1440 },
  { tier: 'xl',  min: 1280 },
  { tier: 'lg',  min: 1024 },
  { tier: 'base', min: 0 },
];

function measure(): Tier {
  if (typeof window === 'undefined') return 'xl';
  const w = window.innerWidth;
  return TIERS.find(t => w >= t.min)!.tier;
}

/** Re-renders only when the tier changes, not on every resize pixel. */
export function useTier(): Tier {
  const [tier, setTier] = useState<Tier>(measure);
  useEffect(() => {
    const onResize = () => setTier(prev => {
      const next = measure();
      return next === prev ? prev : next;
    });
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);
  return tier;
}

/** True where a span/alert detail pane fits as a persistent third column. */
export function hasDetailColumn(tier: Tier): boolean {
  return tier === '3xl';
}
