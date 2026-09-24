import React, { useState } from 'react';
import { screeningAPI } from '../services/api';
import { ErrorAlert, ResultBlock, errorMessage } from './common';

export default function Screening() {
  const [form, setForm] = useState({
    full_name: '',
    date_of_birth: '',
    nationality: 'NG',
    passport_number: '',
  });
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<unknown>(null);

  const set = (key: keyof typeof form, value: string) =>
    setForm((current) => ({ ...current, [key]: value }));

  const run = async (key: string, action: () => Promise<unknown>) => {
    setLoading(key);
    setError(null);
    setResult(null);
    try {
      setResult(await action());
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setLoading(null);
    }
  };

  const valid = form.full_name.trim().length > 0;
  const dob = form.date_of_birth || undefined;
  const nationality = form.nationality || undefined;
  const passport = form.passport_number || undefined;

  return (
    <div className="page">
      <h2>PEP &amp; Sanctions Screening</h2>
      <div className="card">
        <ErrorAlert message={error} />
        <div className="form-grid">
          <label className="field">
            Full name *
            <input required value={form.full_name} onChange={(e) => set('full_name', e.target.value)} />
          </label>
          <label className="field">
            Date of birth
            <input type="date" value={form.date_of_birth} onChange={(e) => set('date_of_birth', e.target.value)} />
          </label>
          <label className="field">
            Nationality
            <input value={form.nationality} onChange={(e) => set('nationality', e.target.value)} />
          </label>
          <label className="field">
            Passport number
            <input value={form.passport_number} onChange={(e) => set('passport_number', e.target.value)} />
          </label>
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!valid || loading !== null}
            onClick={() => run('comprehensive', () => screeningAPI.comprehensiveScreening(form.full_name, dob, nationality, passport))}
          >
            {loading === 'comprehensive' ? 'Screening...' : 'Comprehensive screening'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!valid || loading !== null}
            onClick={() => run('pep', () => screeningAPI.screenPEP(form.full_name, dob, nationality))}
          >
            {loading === 'pep' ? 'Screening...' : 'PEP only'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!valid || loading !== null}
            onClick={() => run('sanctions', () => screeningAPI.screenSanctions(form.full_name, dob, nationality, passport))}
          >
            {loading === 'sanctions' ? 'Screening...' : 'Sanctions only'}
          </button>
        </div>
      </div>

      {result !== null && (
        <div className="card">
          <h3>Screening result</h3>
          <ResultBlock data={result} />
        </div>
      )}
    </div>
  );
}
