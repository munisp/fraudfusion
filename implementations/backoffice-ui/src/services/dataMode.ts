/**
 * Data-source mode for the back-office console.
 *
 * The console NEVER silently substitutes fabricated rows for live API data:
 * when the backoffice API is unreachable, pages render an explicit outage
 * state. Mock data exists only for local development and requires BOTH:
 *   1. a Vite dev-mode build (import.meta.env.DEV), and
 *   2. the explicit `?mock=1` query-param opt-in.
 * In every other case `resolveDataMode` returns 'live'.
 */
export type DataMode = 'live' | 'mock';

export const MOCK_QUERY_PARAM = 'mock';

export function resolveDataMode(search: string, isDev: boolean): DataMode {
  if (!isDev) {
    return 'live';
  }
  return new URLSearchParams(search).get(MOCK_QUERY_PARAM) === '1' ? 'mock' : 'live';
}

/** Mode for the running page; evaluated from the current URL. */
export function currentDataMode(): DataMode {
  return resolveDataMode(window.location.search, import.meta.env.DEV);
}
