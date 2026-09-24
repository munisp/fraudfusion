import React, { useState } from 'react';
import { documentAPI } from '../services/api';
import { ErrorAlert, ResultBlock, errorMessage } from './common';

const DOCUMENT_TYPES = [
  { value: 'national_id', label: 'National ID card' },
  { value: 'drivers_license', label: "Driver's license" },
  { value: 'passport', label: 'International passport' },
  { value: 'bvn_slip', label: 'BVN slip' },
  { value: 'utility_bill', label: 'Utility bill' },
  { value: 'certificate_of_occupancy', label: 'Certificate of Occupancy' },
  { value: 'deed_of_assignment', label: 'Deed of Assignment' },
];

export default function DocumentVerification() {
  const [document, setDocument] = useState<File | null>(null);
  const [documentType, setDocumentType] = useState(DOCUMENT_TYPES[0].value);
  const [checkForgery, setCheckForgery] = useState(true);

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

  const ready = document !== null && loading === null;

  return (
    <div className="page">
      <h2>Document Verification</h2>
      <div className="card">
        <p className="muted">
          Upload an identity or property document to extract its data with OCR, detect forgery, and
          score image quality.
        </p>
        <ErrorAlert message={error} />
        <div className="form-grid">
          <label className="field">
            Document type
            <select value={documentType} onChange={(e) => setDocumentType(e.target.value)}>
              {DOCUMENT_TYPES.map((dt) => (
                <option key={dt.value} value={dt.value}>
                  {dt.label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Document file *
            <input
              type="file"
              accept="image/*,application/pdf"
              onChange={(e) => setDocument(e.target.files?.[0] ?? null)}
            />
            {document && <span className="muted">{document.name}</span>}
          </label>
        </div>
        <label className="field field-inline mt-4">
          <input type="checkbox" checked={checkForgery} onChange={(e) => setCheckForgery(e.target.checked)} />
          Include forgery detection in full verification
        </label>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!ready}
            onClick={() =>
              document && run('verify', () => documentAPI.verify(document, documentType, checkForgery))
            }
          >
            {loading === 'verify' ? 'Verifying...' : 'Full verification'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!ready}
            onClick={() => document && run('ocr', () => documentAPI.extractOCR(document, documentType))}
          >
            {loading === 'ocr' ? 'Extracting...' : 'OCR only'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!ready}
            onClick={() =>
              document && run('forgery', () => documentAPI.checkForgery(document, documentType))
            }
          >
            {loading === 'forgery' ? 'Checking...' : 'Forgery check'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!ready}
            onClick={() => document && run('quality', () => documentAPI.checkQuality(document))}
          >
            {loading === 'quality' ? 'Checking...' : 'Quality check'}
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
