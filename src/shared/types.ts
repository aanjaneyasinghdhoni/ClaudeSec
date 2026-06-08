/**
 * src/shared/types.ts — shared type definitions used by both the backend
 * (server/index.ts) and the frontend (src/App.tsx).
 *
 * Pure type-only file: no runtime code, no imports.
 */

/** Threat severity levels used by the detection engine and the UI. */
export type Severity = 'none' | 'low' | 'medium' | 'high';
