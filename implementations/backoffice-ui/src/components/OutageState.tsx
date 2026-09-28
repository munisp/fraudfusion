import React from 'react';
import { RefreshCw, ServerCrash } from 'lucide-react';

interface OutageStateProps {
  /** Base URL the console tried to reach, shown so operators can verify config. */
  apiBaseUrl: string;
  onRetry: () => void;
  retrying: boolean;
}

/**
 * Full-width outage state shown when the backoffice API is unreachable.
 * This replaces any fabricated/sample content: no rows are rendered while
 * the backend is down.
 */
const OutageState: React.FC<OutageStateProps> = ({ apiBaseUrl, onRetry, retrying }) => (
  <div
    role="alert"
    data-testid="outage-state"
    className="w-full rounded-lg border-2 border-red-300 bg-red-50 p-8 text-center"
  >
    <ServerCrash className="mx-auto h-10 w-10 text-red-600" />
    <h2 className="mt-4 text-lg font-semibold text-red-800">Live data unavailable</h2>
    <p className="mt-2 text-sm text-red-700">
      Backend unreachable at <code className="font-mono font-semibold">{apiBaseUrl}</code>.
    </p>
    <p className="mt-1 text-sm text-red-600">
      No data is being displayed. Check that the backoffice-api service is running and that
      VITE_BACKOFFICE_API_URL points at it, then retry.
    </p>
    <button
      onClick={onRetry}
      disabled={retrying}
      className="mt-4 inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 disabled:opacity-50"
    >
      <RefreshCw className={`w-4 h-4 mr-2 ${retrying ? 'animate-spin' : ''}`} />
      Retry
    </button>
  </div>
);

export default OutageState;
