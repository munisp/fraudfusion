import React, { Suspense, lazy, useState } from 'react';

// Section-level code splitting: each back-office page ships as its own chunk.
const Dashboard = lazy(() => import('./pages/Dashboard'));
const FraudAlerts = lazy(() => import('./pages/FraudAlerts'));
const KYCVerifications = lazy(() => import('./pages/KYCVerifications'));

type Page = 'dashboard' | 'fraud-alerts' | 'kyc-verifications';

const PAGES: { id: Page; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'fraud-alerts', label: 'Fraud Alerts' },
  { id: 'kyc-verifications', label: 'KYC Verifications' },
];

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-gray-900">FraudFusion Back Office</h1>
            <p className="text-sm text-gray-500">
              Review queue, KYC overrides, and fraud alert triage
            </p>
          </div>
          <nav className="flex space-x-2" aria-label="Back office sections">
            {PAGES.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setPage(p.id)}
                className={`px-3 py-2 text-sm font-medium rounded-lg ${
                  page === p.id
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                {p.label}
              </button>
            ))}
          </nav>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <Suspense fallback={<p role="status" aria-live="polite" className="text-gray-500">Loading section…</p>}>
          {page === 'dashboard' && <Dashboard />}
          {page === 'fraud-alerts' && <FraudAlerts />}
          {page === 'kyc-verifications' && <KYCVerifications />}
        </Suspense>
      </main>
    </div>
  );
}
