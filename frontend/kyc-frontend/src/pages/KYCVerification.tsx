import React, { useState } from 'react';
import { kycAPI, KYCResponse } from '../services/api';
import { Badge, ErrorAlert, ResultBlock, errorMessage } from './common';

type Tier = 'basic' | 'enhanced' | 'premium';

const TIER_INFO: Record<Tier, string> = {
  basic: 'BVN/NIN identity verification with phone and email checks.',
  enhanced: 'Basic checks plus PEP and sanctions screening.',
  premium: 'Enhanced checks plus credit bureau lookup.',
};

export default function KYCVerification() {
  const [tier, setTier] = useState<Tier>('basic');
  const [form, setForm] = useState({
    customer_id: '',
    first_name: '',
    last_name: '',
    bvn: '',
    nin: '',
    phone: '',
    email: '',
    date_of_birth: '',
    nationality: 'NG',
    check_pep: true,
    check_sanctions: true,
    check_credit_bureau: false,
    credit_bureau_provider: 'crc',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<KYCResponse | null>(null);

  const [statusId, setStatusId] = useState('');
  const [statusLoading, setStatusLoading] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [statusResult, setStatusResult] = useState<unknown>(null);

  const set = (key: keyof typeof form, value: string | boolean) =>
    setForm((current) => ({ ...current, [key]: value }));

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const base = {
        customer_id: form.customer_id,
        first_name: form.first_name,
        last_name: form.last_name,
        bvn: form.bvn || undefined,
        nin: form.nin || undefined,
        phone: form.phone || undefined,
        email: form.email || undefined,
        date_of_birth: form.date_of_birth || undefined,
      };
      let response: KYCResponse;
      if (tier === 'basic') {
        response = await kycAPI.verifyBasic(base);
      } else if (tier === 'enhanced') {
        response = await kycAPI.verifyEnhanced({
          ...base,
          nationality: form.nationality || undefined,
          check_pep: form.check_pep,
          check_sanctions: form.check_sanctions,
        });
      } else {
        response = await kycAPI.verifyPremium({
          ...base,
          nationality: form.nationality || undefined,
          check_pep: form.check_pep,
          check_sanctions: form.check_sanctions,
          check_credit_bureau: form.check_credit_bureau,
          credit_bureau_provider: form.credit_bureau_provider || undefined,
        });
      }
      setResult(response);
      setStatusId(response.request_id);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setLoading(false);
    }
  };

  const lookupStatus = async () => {
    if (!statusId.trim()) return;
    setStatusLoading(true);
    setStatusError(null);
    setStatusResult(null);
    try {
      setStatusResult(await kycAPI.getStatus(statusId.trim()));
    } catch (cause) {
      setStatusError(errorMessage(cause));
    } finally {
      setStatusLoading(false);
    }
  };

  return (
    <div className="page">
      <h2>KYC Verification</h2>
      <div className="card">
        <div className="btn-row" role="tablist" aria-label="KYC tier">
          {(Object.keys(TIER_INFO) as Tier[]).map((t) => (
            <button
              key={t}
              type="button"
              className={tier === t ? 'btn btn-primary' : 'btn btn-secondary'}
              onClick={() => setTier(t)}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
        <p className="muted">{TIER_INFO[tier]}</p>
        <ErrorAlert message={error} />
        <form onSubmit={submit}>
          <div className="form-grid">
            <label className="field">
              Customer ID *
              <input required value={form.customer_id} onChange={(e) => set('customer_id', e.target.value)} />
            </label>
            <label className="field">
              First name *
              <input required value={form.first_name} onChange={(e) => set('first_name', e.target.value)} />
            </label>
            <label className="field">
              Last name *
              <input required value={form.last_name} onChange={(e) => set('last_name', e.target.value)} />
            </label>
            <label className="field">
              BVN
              <input value={form.bvn} onChange={(e) => set('bvn', e.target.value)} placeholder="11-digit BVN" />
            </label>
            <label className="field">
              NIN
              <input value={form.nin} onChange={(e) => set('nin', e.target.value)} placeholder="11-digit NIN" />
            </label>
            <label className="field">
              Phone
              <input value={form.phone} onChange={(e) => set('phone', e.target.value)} placeholder="+234..." />
            </label>
            <label className="field">
              Email
              <input type="email" value={form.email} onChange={(e) => set('email', e.target.value)} />
            </label>
            <label className="field">
              Date of birth
              <input type="date" value={form.date_of_birth} onChange={(e) => set('date_of_birth', e.target.value)} />
            </label>
            {tier !== 'basic' && (
              <label className="field">
                Nationality
                <input value={form.nationality} onChange={(e) => set('nationality', e.target.value)} />
              </label>
            )}
          </div>
          {tier !== 'basic' && (
            <div className="btn-row">
              <label className="field field-inline">
                <input
                  type="checkbox"
                  checked={form.check_pep}
                  onChange={(e) => set('check_pep', e.target.checked)}
                />
                PEP screening
              </label>
              <label className="field field-inline">
                <input
                  type="checkbox"
                  checked={form.check_sanctions}
                  onChange={(e) => set('check_sanctions', e.target.checked)}
                />
                Sanctions screening
              </label>
              {tier === 'premium' && (
                <>
                  <label className="field field-inline">
                    <input
                      type="checkbox"
                      checked={form.check_credit_bureau}
                      onChange={(e) => set('check_credit_bureau', e.target.checked)}
                    />
                    Credit bureau check
                  </label>
                  <label className="field">
                    Bureau provider
                    <select
                      value={form.credit_bureau_provider}
                      onChange={(e) => set('credit_bureau_provider', e.target.value)}
                    >
                      <option value="crc">CRC Credit Bureau</option>
                      <option value="firstcentral">FirstCentral</option>
                    </select>
                  </label>
                </>
              )}
            </div>
          )}
          <div className="btn-row">
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Verifying...' : `Run ${tier} verification`}
            </button>
          </div>
        </form>
      </div>

      {result && (
        <div className="card">
          <h3>Verification result</h3>
          <p>
            Decision: <Badge value={result.decision} /> Risk: <Badge value={result.risk_level} /> (
            {(result.risk_score * 100).toFixed(0)}%) Level: <Badge value={result.verification_level} />
          </p>
          <p className="muted">
            Request {result.request_id} completed in {result.processing_time_ms} ms at{' '}
            {new Date(result.timestamp).toLocaleString()}.
          </p>
          <ResultBlock data={result.verification_results} />
        </div>
      )}

      <div className="card">
        <h3>Check verification status</h3>
        <ErrorAlert message={statusError} />
        <div className="btn-row">
          <label className="field" style={{ flex: 1 }}>
            Request ID
            <input value={statusId} onChange={(e) => setStatusId(e.target.value)} placeholder="request id" />
          </label>
          <button type="button" className="btn btn-secondary" onClick={lookupStatus} disabled={statusLoading}>
            {statusLoading ? 'Loading...' : 'Lookup'}
          </button>
        </div>
        <ResultBlock data={statusResult} />
      </div>
    </div>
  );
}
