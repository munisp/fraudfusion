import React, { useState } from 'react';
import { riskAPI, creditBureauAPI } from '../services/api';
import { ErrorAlert, ResultBlock, errorMessage } from './common';

export default function RiskAssessment() {
  const [customerId, setCustomerId] = useState('');
  const [amount, setAmount] = useState('');
  const [channel, setChannel] = useState('card');
  const [behavior, setBehavior] = useState('');

  const [bvn, setBvn] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [provider, setProvider] = useState('crc');

  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<unknown>(null);

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

  const parsedAmount = Number(amount);
  const transactionValid = customerId.trim() !== '' && Number.isFinite(parsedAmount) && parsedAmount > 0;

  const bureauValid = bvn.trim() !== '' && firstName.trim() !== '' && lastName.trim() !== '';

  let parsedBehavior: unknown = null;
  let behaviorError: string | null = null;
  if (behavior.trim()) {
    try {
      parsedBehavior = JSON.parse(behavior);
    } catch {
      behaviorError = 'Behavioral data must be valid JSON.';
    }
  }

  return (
    <div className="page">
      <h2>Risk Assessment</h2>
      <ErrorAlert message={error} />

      <div className="card">
        <h3>Transaction fraud check</h3>
        <div className="form-grid">
          <label className="field">
            Customer ID *
            <input value={customerId} onChange={(e) => setCustomerId(e.target.value)} />
          </label>
          <label className="field">
            Amount (NGN) *
            <input type="number" min="0" value={amount} onChange={(e) => setAmount(e.target.value)} />
          </label>
          <label className="field">
            Channel
            <select value={channel} onChange={(e) => setChannel(e.target.value)}>
              <option value="card">Card</option>
              <option value="transfer">Bank transfer</option>
              <option value="ussd">USSD</option>
              <option value="pos">POS</option>
            </select>
          </label>
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!transactionValid || loading !== null}
            onClick={() =>
              run('fraud', () =>
                riskAPI.checkFraud(customerId, {
                  amount: parsedAmount,
                  currency: 'NGN',
                  channel,
                  timestamp: new Date().toISOString(),
                }),
              )
            }
          >
            {loading === 'fraud' ? 'Checking...' : 'Check fraud'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!transactionValid || loading !== null}
            onClick={() =>
              run('assess', () =>
                riskAPI.assessRisk({
                  customer_id: customerId,
                  transaction_data: { amount: parsedAmount, currency: 'NGN', channel },
                }),
              )
            }
          >
            {loading === 'assess' ? 'Assessing...' : 'Assess risk'}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Behavioral analysis</h3>
        <label className="field">
          Behavioral data (JSON)
          <textarea
            rows={4}
            value={behavior}
            onChange={(e) => setBehavior(e.target.value)}
            placeholder='{"session_duration_seconds": 120, "typing_cadence_ms": 95}'
          />
        </label>
        {behaviorError && <div className="alert alert-error">{behaviorError}</div>}
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={customerId.trim() === '' || !parsedBehavior || loading !== null}
            onClick={() => run('behavior', () => riskAPI.analyzeBehavior(customerId, parsedBehavior))}
          >
            {loading === 'behavior' ? 'Analyzing...' : 'Analyze behavior'}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Credit bureau</h3>
        <div className="form-grid">
          <label className="field">
            BVN *
            <input value={bvn} onChange={(e) => setBvn(e.target.value)} />
          </label>
          <label className="field">
            First name *
            <input value={firstName} onChange={(e) => setFirstName(e.target.value)} />
          </label>
          <label className="field">
            Last name *
            <input value={lastName} onChange={(e) => setLastName(e.target.value)} />
          </label>
          <label className="field">
            Provider
            <select value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="crc">CRC Credit Bureau</option>
              <option value="firstcentral">FirstCentral</option>
            </select>
          </label>
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!bureauValid || loading !== null}
            onClick={() => run('credit', () => creditBureauAPI.checkCredit(bvn, firstName, lastName, provider))}
          >
            {loading === 'credit' ? 'Checking...' : 'Full credit check'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!bureauValid || loading !== null}
            onClick={() => run('score', () => creditBureauAPI.getCreditScore(bvn, firstName, lastName, provider))}
          >
            {loading === 'score' ? 'Fetching...' : 'Score only'}
          </button>
        </div>
      </div>

      {result !== null && (
        <div className="card">
          <h3>Result</h3>
          <ResultBlock data={result} />
        </div>
      )}
    </div>
  );
}
