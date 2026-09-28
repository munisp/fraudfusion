import React from 'react';
import { AlertTriangle } from 'lucide-react';

/**
 * Permanent red banner rendered for the entire duration of dev-only mock mode
 * (`?mock=1` on a dev build). It must be impossible to mistake mock rows for
 * live data, so this banner is never dismissible.
 */
const MockDataBanner: React.FC = () => (
  <div
    role="alert"
    data-testid="mock-data-banner"
    className="w-full rounded-lg border-2 border-red-600 bg-red-600 px-4 py-3 flex items-center"
  >
    <AlertTriangle className="w-5 h-5 text-white mr-3 flex-shrink-0" />
    <p className="text-sm font-bold text-white tracking-wide">
      MOCK DATA — everything on this page is fabricated sample content from the dev-only
      ?mock=1 mode. Nothing here is live, and changes are not persisted.
    </p>
  </div>
);

export default MockDataBanner;
