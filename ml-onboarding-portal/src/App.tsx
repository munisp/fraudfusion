import React, { Suspense, lazy, useState } from 'react';

type Page = 'api-key' | 'kyc-tier' | 'checklist' | 'status';

const PAGES: { id: Page; label: string }[] = [
  { id: 'api-key', label: 'API Key Request' },
  { id: 'kyc-tier', label: 'KYC Tier Selection' },
  { id: 'checklist', label: 'Integration Checklist' },
  { id: 'status', label: 'Status' },
];

// Section-level code splitting: each onboarding step ships as its own chunk.
const ApiKeyPage = lazy(() => import('./pages/ApiKeyPage'));
const KycTierPage = lazy(() => import('./pages/KycTierPage'));
const ChecklistPage = lazy(() => import('./pages/ChecklistPage'));
const StatusPage = lazy(() => import('./pages/StatusPage'));

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
        <Suspense fallback={<p role="status" aria-live="polite" className="muted">Loading section…</p>}>
          {page === 'api-key' && <ApiKeyPage />}
          {page === 'kyc-tier' && <KycTierPage />}
          {page === 'checklist' && <ChecklistPage />}
          {page === 'status' && <StatusPage />}
        </Suspense>
      </main>
      <footer className="footer muted">
        API base URL: <code>{(import.meta.env.VITE_API_BASE_URL as string | undefined) || '(same origin)'}</code>
      </footer>
    </div>
  );
}
