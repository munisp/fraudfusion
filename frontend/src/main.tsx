import React, { Suspense, lazy } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

// Route-level code splitting: the dashboard (and its icon set) is loaded on demand.
const JourneyDashboard = lazy(() => import('./pages/JourneyDashboard'));

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('The application root element is missing.');
}

createRoot(rootElement).render(
  <React.StrictMode>
    <Suspense fallback={<div role="status" aria-live="polite">Loading dashboard…</div>}>
      <JourneyDashboard />
    </Suspense>
  </React.StrictMode>,
);
