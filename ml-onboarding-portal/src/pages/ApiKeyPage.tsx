import React, { useState } from 'react';
import { ApiKeyGrant, onboardingApi } from '../api';
import { ErrorBanner } from '../components/ErrorBanner';

export default function ApiKeyPage() {
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
