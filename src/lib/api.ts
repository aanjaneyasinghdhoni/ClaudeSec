// src/lib/api.ts
//
// The dashboard's single door to the backend for anything that CHANGES state.
//
// Mutating `/api` routes sit behind the control token (server/controlToken.ts):
// until the browser has been paired via `claudesec open`, the server answers
// 403 and applies nothing. Reads stay open, so the rest of the UI looks normal.
//
// `fetch` resolves happily on a 403 — it only rejects on a transport failure.
// A call site that writes `await fetch(...)` and then updates its own state has
// therefore just reported success for a request the server refused. In a
// security tool that is worse than a crash: the enforcement badge reads
// `enforce` while the server is still in `monitor`, and the operator believes a
// control is on when it is off.
//
// These helpers reject on every non-2xx, so that failure mode cannot be written
// by accident. Prefer them over bare `fetch` for reads too — `apiJson` gives the
// same status checking for free.

/** A request the server refused, carrying enough detail to explain the refusal. */
export class ApiError extends Error {
  readonly status: number;
  /**
   * The control-token gate refused this request: the browser is not paired.
   * One cause, one fix, so it is worth distinguishing from every other failure.
   */
  readonly needsPairing: boolean;

  constructor(status: number, message: string, needsPairing: boolean) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.needsPairing = needsPairing;
  }
}

/** Full explanation, for the app-level banner. */
export const PAIRING_NOTICE =
  'This browser is not paired with ClaudeSec, so the change was refused and nothing was applied. '
  + 'Run `claudesec open` in a terminal to pair it, then try again.';

/** Short form, for an inline error next to the control that failed. */
const PAIRING_INLINE = 'Not paired — run `claudesec open` to pair this browser.';

// ── App-level failure channel ───────────────────────────────────────────────
// Many mutations are one-click actions with nowhere to put an inline error (a
// bookmark delete, a snooze, an alert dismiss). Rather than grow a per-component
// error slot for each, they report here and App.tsx renders the message in the
// banner strip it already owns. A pairing refusal announces itself without the
// call site having to remember to ask.

type FailureListener = (message: string) => void;
const failureListeners = new Set<FailureListener>();

/** Subscribe to app-level request failures. Returns an unsubscribe function. */
export function onApiFailure(listener: FailureListener): () => void {
  failureListeners.add(listener);
  return () => { failureListeners.delete(listener); };
}

function announce(message: string): void {
  for (const listener of failureListeners) listener(message);
}

/**
 * Surface a failed request in the app-level banner. For call sites with no
 * inline error UI of their own — everything else should render
 * `apiErrorMessage(err, ...)` where the user is already looking.
 *
 * Pairing refusals have already announced themselves, so they are not repeated.
 */
export function reportApiFailure(err: unknown, fallback: string): void {
  if (err instanceof ApiError && err.needsPairing) return;
  announce(apiErrorMessage(err, fallback));
}

/**
 * A message to show the user for a failed request. Transport failures have no
 * server-side explanation, so they fall back to the caller's wording.
 */
export function apiErrorMessage(err: unknown, fallback = 'Request failed'): string {
  return err instanceof ApiError ? err.message : fallback;
}

// ── Requests ────────────────────────────────────────────────────────────────

async function toApiError(res: Response): Promise<ApiError> {
  const body = await res.json().catch(() => ({})) as {
    error?: string; detail?: string; hint?: string;
  };
  // The control-token gate is the only 403 that answers `error: 'forbidden'`;
  // /api/reset and the process routes use their own wording, and those are real
  // refusals with different fixes.
  if (res.status === 403 && body.error === 'forbidden') {
    announce(PAIRING_NOTICE);
    return new ApiError(res.status, PAIRING_INLINE, true);
  }
  // `hint` first: where a route offers one it is the actionable half.
  const detail = body.hint ?? body.error ?? body.detail;
  return new ApiError(res.status, detail ?? `Request failed (HTTP ${res.status})`, false);
}

/** Fetch, rejecting with an ApiError unless the server returned 2xx. */
export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(path, init);
  if (!res.ok) throw await toApiError(res);
  return res;
}

/** Fetch and parse JSON, rejecting with an ApiError unless the server returned 2xx. */
export async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  return readJson<T>(await apiFetch(path, init));
}

type MutateMethod = 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/**
 * Send a mutation and return the server's reply. Rejects with an ApiError
 * unless the server confirmed the change, so the reply is the only thing a
 * caller should update its state from — never the value it just sent.
 */
export async function apiSend<T = unknown>(
  path: string,
  method: MutateMethod,
  body?: unknown,
): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { 'Content-Type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  return readJson<T>(await apiFetch(path, init));
}

/** Some routes confirm with 204 or an empty body; that is still a success. */
async function readJson<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T;
  return await res.json().catch(() => undefined) as T;
}
