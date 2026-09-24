import React, { useState } from 'react';
import { biometricAPI } from '../services/api';
import { ErrorAlert, ResultBlock, errorMessage } from './common';

function FileField({
  label,
  file,
  onChange,
}: {
  label: string;
  file: File | null;
  onChange: (file: File | null) => void;
}) {
  return (
    <label className="field">
      {label}
      <input
        type="file"
        accept="image/*"
        onChange={(e) => onChange(e.target.files?.[0] ?? null)}
      />
      {file && <span className="muted">{file.name}</span>}
    </label>
  );
}

export default function BiometricVerification() {
  const [selfie, setSelfie] = useState<File | null>(null);
  const [reference, setReference] = useState<File | null>(null);
  const [checkLiveness, setCheckLiveness] = useState(true);

  const [livenessFile, setLivenessFile] = useState<File | null>(null);
  const [matchA, setMatchA] = useState<File | null>(null);
  const [matchB, setMatchB] = useState<File | null>(null);

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

  return (
    <div className="page">
      <h2>Biometric Verification</h2>
      <ErrorAlert message={error} />

      <div className="card">
        <h3>Selfie verification</h3>
        <p className="muted">
          Upload a live selfie and optionally the reference photo from the customer's ID document.
        </p>
        <div className="form-grid">
          <FileField label="Selfie image *" file={selfie} onChange={setSelfie} />
          <FileField label="Reference image (optional)" file={reference} onChange={setReference} />
        </div>
        <label className="field field-inline mt-4">
          <input
            type="checkbox"
            checked={checkLiveness}
            onChange={(e) => setCheckLiveness(e.target.checked)}
          />
          Run liveness detection
        </label>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!selfie || loading !== null}
            onClick={() =>
              selfie && run('verify', () => biometricAPI.verifyUpload(selfie, reference ?? undefined, checkLiveness))
            }
          >
            {loading === 'verify' ? 'Verifying...' : 'Verify selfie'}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Liveness check</h3>
        <div className="form-grid">
          <FileField label="Image *" file={livenessFile} onChange={setLivenessFile} />
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!livenessFile || loading !== null}
            onClick={() => livenessFile && run('liveness', () => biometricAPI.checkLiveness(livenessFile))}
          >
            {loading === 'liveness' ? 'Checking...' : 'Check liveness'}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Face match</h3>
        <div className="form-grid">
          <FileField label="Image 1 *" file={matchA} onChange={setMatchA} />
          <FileField label="Image 2 *" file={matchB} onChange={setMatchB} />
        </div>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!matchA || !matchB || loading !== null}
            onClick={() => matchA && matchB && run('match', () => biometricAPI.matchFaces(matchA, matchB))}
          >
            {loading === 'match' ? 'Matching...' : 'Match faces'}
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
