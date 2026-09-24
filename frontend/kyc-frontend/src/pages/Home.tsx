import React from 'react';
import { Link } from 'react-router-dom';

const features = [
  {
    title: 'Tiered KYC verification',
    body: 'Basic (BVN/NIN), Enhanced (PEP + sanctions), and Premium (credit bureau) verification tiers.',
    to: '/kyc',
  },
  {
    title: 'Biometric verification',
    body: 'Selfie capture with liveness detection and face matching against a reference photo.',
    to: '/biometric',
  },
  {
    title: 'Document verification',
    body: 'OCR extraction, forgery detection, and quality checks for identity documents.',
    to: '/document',
  },
  {
    title: 'PEP & sanctions screening',
    body: 'Screen customers against politically-exposed-person and global sanctions lists.',
    to: '/screening',
  },
  {
    title: 'Risk assessment',
    body: 'Transaction fraud checks and behavioral analysis with scored risk decisions.',
    to: '/risk',
  },
];

export default function Home() {
  return (
    <div className="page">
      <div className="card">
        <h2>FraudFusion KYC Verification System</h2>
        <p className="muted">
          Customer onboarding and identity verification for Nigerian fintech: tiered KYC with BVN/NIN
          checks, biometrics, document forensics, screening, and risk scoring.
        </p>
      </div>
      <ul className="feature-list">
        {features.map((feature) => (
          <li key={feature.to}>
            <h3>{feature.title}</h3>
            <p className="muted">{feature.body}</p>
            <Link className="btn btn-secondary" to={feature.to}>
              Open
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
