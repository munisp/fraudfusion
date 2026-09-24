import React, { useCallback, useEffect, useState } from 'react';
import {
  ApiKeyGrant,
  ChecklistItem,
  OnboardingStatus,
  onboardingApi,
} from './api';

type Page = 'api-key' | 'kyc-tier' | 'checklist' | 'status';

const PAGES: { id: Page; label: string }[] = [
  { id: 'api-key', label: 'API Key Request' },
  { id: 'kyc-tier', label: 'KYC Tier Selection' },
  { id: 'checklist', label: 'Integration Checklist' },
  { id: 'status', label: 'Status' },
];

const KYC_TIERS = [
  {
    id: 'basic' as const,
    name: 'Basic',
    description: 'BVN/NIN identity verification and phone/email checks for low-risk retail onboarding.',
  },
  {
    id: 'enhanced' as const,
    name: 'Enhanced',
    description: 'Basic plus PEP and sanctions screening for regulated fintech products.',
  },
  {
    id: 'premium' as const,
    name: 'Premium',
    description: 'Enhanced plus credit-bureau checks, liveness, and document forgery detection.',
  },
];

function ErrorBanner({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="banner banner-error" role="alert">
      <span>{error}</span>
      {onRetry && (
        <button type="button" className="btn btn-secondary" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

function ApiKeyPage() {
  const [form, setForm] = useState({
    organization: '',
    contactEmail: '',
    useCase: '',
    environment: 'sandbox' as 'sandbox' | 'production',
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [grant, setGrant] = useState<ApiKeyGrant | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setGrant(null);
    try {
      setGrant(await onboardingApi.requestApiKey(form));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'API key request failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section>
      <h2>Request an API key</h2>
      <p className="muted">
        Keys are issued per environment. Sandbox keys are approved automatically; production keys go
        through compliance review.
      </p>
      {error && <ErrorBanner error={error} />}
      {grant && (
        <div className="banner banner-success">
          API key request accepted (key id: <code>{grant.keyId}</code>, status: {grant.status}). Store
          the secret shown in your tenant console securely; it is displayed once.
        </div>
      )}
      <form onSubmit={submit} className="card form">
        <label>
          Organization
          <input
            required
            value={form.organization}
            onChange={(e) => setForm({ ...form, organization: e.target.value })}
            placeholder="Acme Fintech Ltd"
          />
        </label>
        <label>
          Contact email
          <input
            required
            type="email"
            value={form.contactEmail}
            onChange={(e) => setForm({ ...form, contactEmail: e.target.value })}
            placeholder="dev@acme.example"
          />
        </label>
        <label>
          Use case
          <textarea
            required
            value={form.useCase}
            onChange={(e) => setForm({ ...form, useCase: e.target.value })}
            placeholder="Describe the journeys you intend to run (KYC, fraud checks, ...)"
          />
        </label>
        <label>
          Environment
          <select
            value={form.environment}
            onChange={(e) => setForm({ ...form, environment: e.target.value as 'sandbox' | 'production' })}
          >
            <option value="sandbox">Sandbox</option>
            <option value="production">Production</option>
          </select>
        </label>
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? 'Submitting...' : 'Request API key'}
        </button>
      </form>
    </section>
  );
}

function KycTierPage() {
  const [tenantId, setTenantId] = useState('');
  const [selected, setSelected] = useState<'basic' | 'enhanced' | 'premium'>('basic');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState<OnboardingStatus | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    setConfirmed(null);
    try {
      setConfirmed(await onboardingApi.selectKycTier({ tenantId, tier: selected }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to save the KYC tier selection.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section>
      <h2>Select your KYC tier</h2>
      <p className="muted">The tier controls which verification checks run for your customers.</p>
      {error && <ErrorBanner error={error} />}
      {confirmed && (
        <div className="banner banner-success">
          Tier saved for tenant <code>{confirmed.tenantId}</code> (state: {confirmed.state}).
        </div>
      )}
      <label className="card form">
        Tenant ID
        <input
          required
          value={tenantId}
          onChange={(e) => setTenantId(e.target.value)}
          placeholder="tenant-..."
        />
      </label>
      <div className="tier-grid">
        {KYC_TIERS.map((tier) => (
          <button
            key={tier.id}
            type="button"
            className={`card tier ${selected === tier.id ? 'tier-selected' : ''}`}
            onClick={() => setSelected(tier.id)}
          >
            <h3>{tier.name}</h3>
            <p>{tier.description}</p>
          </button>
        ))}
      </div>
      <button
        type="button"
        className="btn btn-primary"
        disabled={submitting || !tenantId.trim()}
        onClick={submit}
      >
        {submitting ? 'Saving...' : `Save ${selected} tier`}
      </button>
    </section>
  );
}

function ChecklistPage() {
  const [items, setItems] = useState<ChecklistItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingId, setPendingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await onboardingApi.getChecklist();
      setItems(data.items);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to load the integration checklist.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (item: ChecklistItem) => {
    setPendingId(item.id);
    setError(null);
    try {
      const updated = await onboardingApi.updateChecklistItem(item.id, !item.done);
      setItems((current) => current?.map((it) => (it.id === updated.id ? updated : it)) ?? null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to update the checklist item.');
    } finally {
      setPendingId(null);
    }
  };

  return (
    <section>
      <h2>Integration checklist</h2>
      <p className="muted">Track the steps required before your tenant can go live.</p>
      {error && <ErrorBanner error={error} onRetry={load} />}
      {loading && <p className="muted">Loading checklist...</p>}
      {items && items.length === 0 && <p className="muted">No checklist items yet.</p>}
      {items && (
        <ul className="card checklist">
          {items.map((item) => (
            <li key={item.id}>
              <label>
                <input
                  type="checkbox"
                  checked={item.done}
                  disabled={pendingId === item.id}
                  onChange={() => void toggle(item)}
                />
                <span className={item.done ? 'done' : ''}>
                  {item.label}
                  {item.required && <em className="required">required</em>}
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function StatusPage() {
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

export default function App() {
  const [page, setPage] = useState<Page>('api-key');

  return (
    <div className="app">
      <header className="header">
        <h1>FraudFusion Onboarding Portal</h1>
        <p className="muted">
          Developer and tenant self-service onboarding: API keys, KYC tiers, and go-live tracking.
        </p>
      </header>
      <nav className="tabs" aria-label="Onboarding sections">
        {PAGES.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`tab ${page === p.id ? 'tab-active' : ''}`}
            onClick={() => setPage(p.id)}
          >
            {p.label}
          </button>
        ))}
      </nav>
      <main>
        {page === 'api-key' && <ApiKeyPage />}
        {page === 'kyc-tier' && <KycTierPage />}
        {page === 'checklist' && <ChecklistPage />}
        {page === 'status' && <StatusPage />}
      </main>
      <footer className="footer muted">
        API base URL: <code>{(import.meta.env.VITE_API_BASE_URL as string | undefined) || '(same origin)'}</code>
      </footer>
    </div>
  );
}
