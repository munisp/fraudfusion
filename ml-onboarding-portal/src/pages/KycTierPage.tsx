import React, { useState } from 'react';
import { OnboardingStatus, onboardingApi } from '../api';
import { ErrorBanner } from '../components/ErrorBanner';

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

export default function KycTierPage() {
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
