import React, { useCallback, useEffect, useState } from 'react';
import { OnboardingStatus, onboardingApi } from '../api';
import { ErrorBanner } from '../components/ErrorBanner';

export default function StatusPage() {
  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setStatus(await onboardingApi.getStatus());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to load onboarding status.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section>
      <h2>Onboarding status</h2>
      {error && <ErrorBanner error={error} onRetry={load} />}
      {loading && <p className="muted">Loading status...</p>}
      {status && (
        <div className="card">
          <dl className="status-grid">
            <dt>Tenant</dt>
            <dd>
              <code>{status.tenantId}</code>
            </dd>
            <dt>State</dt>
            <dd>
              <span className={`state state-${status.state}`}>{status.state.replace(/_/g, ' ')}</span>
            </dd>
            <dt>KYC tier</dt>
            <dd>{status.tier ?? 'not selected'}</dd>
            <dt>API key issued</dt>
            <dd>{status.apiKeyIssued ? 'yes' : 'no'}</dd>
            {status.updatedAt && (
              <>
                <dt>Last updated</dt>
                <dd>{new Date(status.updatedAt).toLocaleString()}</dd>
              </>
            )}
          </dl>
          {status.checklist.length > 0 && (
            <p className="muted">
              Checklist: {status.checklist.filter((i) => i.done).length}/{status.checklist.length}{' '}
              complete.
            </p>
          )}
          <button type="button" className="btn btn-secondary" onClick={() => void load()}>
            Refresh
          </button>
        </div>
      )}
    </section>
  );
}
