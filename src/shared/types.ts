/**
 * src/shared/types.ts — shared type definitions used by both the backend
 * (server/index.ts) and the frontend (src/App.tsx).
 *
 * Pure type-only file: no runtime code, no imports.
 */

/**
 * Threat severity levels used by the detection engine and the UI.
 *
 * `critical` is the highest tier and is reserved for active secret
 * EXFILTRATION — a credential or `.env` being transmitted off the machine
 * (piped/posted/uploaded/scp'd to a network sink). A secret merely *present*
 * in a file stays `high`; transmission is what escalates to `critical`.
 */
export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';
