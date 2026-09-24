import React, { useCallback, useState } from 'react';

export function errorMessage(cause: unknown): string {
  if (cause && typeof cause === 'object' && 'response' in cause) {
    const response = (cause as { response?: { data?: { detail?: string; message?: string }; status?: number } }).response;
    const detail = response?.data?.detail ?? response?.data?.message;
    if (detail) return detail;
    if (response?.status) return `Request failed with status ${response.status}.`;
  }
  if (cause instanceof Error) {
    return cause.message === 'Network Error'
      ? 'Cannot reach the KYC API. Confirm the backend is running and retry.'
      : cause.message;
  }
  return 'Unexpected error.';
}

export function ErrorAlert({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div className="alert alert-error" role="alert">
      {message}
    </div>
  );
}

export function ResultBlock({ data }: { data: unknown }) {
  if (data === null || data === undefined) return null;
  return <pre className="result">{JSON.stringify(data, null, 2)}</pre>;
}

export function Badge({ value }: { value: string }) {
  return <span className={`badge badge-${value.toLowerCase()}`}>{value.replace(/_/g, ' ')}</span>;
}

/** Small helper hook: wraps an async action with loading + error state. */
export function useAsyncAction<TArgs extends unknown[], TResult>(
  action: (...args: TArgs) => Promise<TResult>,
) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TResult | null>(null);

  const run = useCallback(
    async (...args: TArgs) => {
      setLoading(true);
      setError(null);
      try {
        const value = await action(...args);
        setResult(value);
        return value;
      } catch (cause) {
        setError(errorMessage(cause));
        return null;
      } finally {
        setLoading(false);
      }
    },
    [action],
  );

  return { loading, error, result, run, setResult };
}
