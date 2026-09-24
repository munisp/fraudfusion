/** Shared error-message helper for screens (kept out of instrumented screen code). */
export function errorMessage(cause: unknown, fallback: string): string {
  return cause instanceof Error ? cause.message : fallback;
}
