import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';
import type { FraudAlert, FraudAlertAction } from '../types';
import {
  Search,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  AlertCircle,
  CheckCircle,
  XCircle,
  Clock,
  Eye,
  User,
  CreditCard,
  MapPin,
  Calendar,
  DollarSign,
  Shield,
  TrendingUp,
} from 'lucide-react';

/**
 * Built-in sample alerts, used only as a documented offline fallback when the
 * backoffice API (`GET /backoffice/fraud/alerts`) is unreachable. Status actions
 * taken against the fallback are applied locally and are not persisted.
 */
const mockAlerts: FraudAlert[] = [
  {
    id: 'alert-001',
    alertType: 'transaction',
    severity: 'critical',
    status: 'open',
    customerId: 'cust-001',
    customerName: 'Adebayo Ogundimu',
    description: 'Unusual high-value transaction detected outside normal pattern',
    amount: 5000000,
    currency: 'NGN',
    location: 'Lagos, Nigeria',
    detectedAt: new Date().toISOString(),
    riskScore: 0.92,
    indicators: ['Velocity anomaly', 'New device', 'Unusual amount', 'Off-hours transaction'],
    relatedTransactions: 3,
  },
  {
    id: 'alert-002',
    alertType: 'identity',
    severity: 'high',
    status: 'investigating',
    customerId: 'cust-002',
    customerName: 'Chukwuemeka Okonkwo',
    description: 'Multiple failed biometric verification attempts',
    detectedAt: new Date(Date.now() - 3600000).toISOString(),
    assignedTo: 'Analyst A',
    riskScore: 0.78,
    indicators: ['Biometric mismatch', 'Multiple attempts', 'Device fingerprint change'],
  },
  {
    id: 'alert-003',
    alertType: 'account_takeover',
    severity: 'critical',
    status: 'open',
    customerId: 'cust-003',
    customerName: 'Fatima Ibrahim',
    description: 'Suspicious login from new location with password change attempt',
    location: 'Unknown VPN',
    detectedAt: new Date(Date.now() - 7200000).toISOString(),
    riskScore: 0.95,
    indicators: ['New IP address', 'VPN detected', 'Password change', 'Email change attempt'],
  },
  {
    id: 'alert-004',
    alertType: 'document_fraud',
    severity: 'medium',
    status: 'resolved',
    customerId: 'cust-004',
    customerName: 'Emeka Nwosu',
    description: 'Potential document manipulation detected in submitted ID',
    detectedAt: new Date(Date.now() - 86400000).toISOString(),
    assignedTo: 'Analyst B',
    riskScore: 0.55,
    indicators: ['ELA anomaly', 'Font inconsistency', 'Metadata tampering'],
  },
  {
    id: 'alert-005',
    alertType: 'money_laundering',
    severity: 'high',
    status: 'investigating',
    customerId: 'cust-005',
    customerName: 'Globex Industries Ltd',
    description: 'Structured transactions pattern detected - possible smurfing',
    amount: 9500000,
    currency: 'NGN',
    detectedAt: new Date(Date.now() - 43200000).toISOString(),
    assignedTo: 'Analyst C',
    riskScore: 0.82,
    indicators: ['Structured deposits', 'Multiple accounts', 'Round amounts', 'Rapid movement'],
    relatedTransactions: 12,
  },
];

const SeverityBadge: React.FC<{ severity: FraudAlert['severity'] }> = ({ severity }) => {
  const styles = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full border ${styles[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
};

const StatusBadge: React.FC<{ status: FraudAlert['status'] }> = ({ status }) => {
  const styles = {
    open: 'bg-red-100 text-red-800',
    investigating: 'bg-blue-100 text-blue-800',
    resolved: 'bg-green-100 text-green-800',
    false_positive: 'bg-gray-100 text-gray-800',
  };

  const labels = {
    open: 'Open',
    investigating: 'Investigating',
    resolved: 'Resolved',
    false_positive: 'False Positive',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${styles[status]}`}>
      {labels[status]}
    </span>
  );
};

const AlertTypeIcon: React.FC<{ type: FraudAlert['alertType'] }> = ({ type }) => {
  const icons = {
    transaction: <CreditCard className="w-5 h-5" />,
    identity: <User className="w-5 h-5" />,
    account_takeover: <Shield className="w-5 h-5" />,
    document_fraud: <AlertCircle className="w-5 h-5" />,
    money_laundering: <DollarSign className="w-5 h-5" />,
  };

  const colors = {
    transaction: 'text-blue-600 bg-blue-100',
    identity: 'text-purple-600 bg-purple-100',
    account_takeover: 'text-red-600 bg-red-100',
    document_fraud: 'text-orange-600 bg-orange-100',
    money_laundering: 'text-yellow-600 bg-yellow-100',
  };

  return <div className={`p-2 rounded-lg ${colors[type]}`}>{icons[type]}</div>;
};

const ACTION_STATUS: Record<FraudAlertAction, FraudAlert['status']> = {
  investigate: 'investigating',
  resolve: 'resolved',
  false_positive: 'false_positive',
};

const FraudAlerts: React.FC = () => {
  const [selectedAlert, setSelectedAlert] = useState<FraudAlert | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionPending, setActionPending] = useState(false);
  // Local overrides hold optimistic updates and fallback-mode edits.
  const [localAlerts, setLocalAlerts] = useState<FraudAlert[] | null>(null);

  const {
    data: apiAlerts,
    isError: apiUnreachable,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ['fraudAlerts'],
    queryFn: () => api.getFraudAlerts(),
    retry: false,
  });

  // Live API data wins; documented mock fallback when the API is unreachable.
  const alerts = localAlerts ?? apiAlerts ?? mockAlerts;

  const applyAction = async (alert: FraudAlert, action: FraudAlertAction) => {
    setActionError(null);
    setActionPending(true);
    const previous = alerts;
    const optimistic = previous.map((a) =>
      a.id === alert.id ? { ...a, status: ACTION_STATUS[action] } : a,
    );
    setLocalAlerts(optimistic);
    setSelectedAlert((current) =>
      current && current.id === alert.id
        ? { ...current, status: ACTION_STATUS[action] }
        : current,
    );
    try {
      const updated = await api.updateFraudAlertStatus(alert.id, { action });
      setLocalAlerts(optimistic.map((a) => (a.id === alert.id ? { ...a, ...updated } : a)));
      setSelectedAlert((current) =>
        current && current.id === alert.id ? { ...current, ...updated } : current,
      );
    } catch (cause) {
      // Roll back the optimistic update.
      if (apiUnreachable) {
        // Fallback mode: keep the local edit, it is the best we can do offline.
        setActionError(
          'Backoffice API unreachable — status change applied to local sample data only and will not persist.',
        );
      } else {
        setLocalAlerts(previous);
        setSelectedAlert(alert);
        setActionError(
          cause instanceof Error ? cause.message : 'Failed to update the alert status.',
        );
      }
    } finally {
      setActionPending(false);
    }
  };

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter && alert.severity !== severityFilter) return false;
    if (statusFilter && alert.status !== statusFilter) return false;
    if (typeFilter && alert.alertType !== typeFilter) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        alert.customerName.toLowerCase().includes(query) ||
        alert.description.toLowerCase().includes(query) ||
        alert.id.toLowerCase().includes(query)
      );
    }
    return true;
  });

  const stats = {
    total: alerts.length,
    critical: alerts.filter((a) => a.severity === 'critical').length,
    open: alerts.filter((a) => a.status === 'open').length,
    resolved: alerts.filter((a) => a.status === 'resolved').length,
  };

  return (
    <div className="space-y-6">
      {apiUnreachable && (
        <div className="rounded-lg border border-yellow-300 bg-yellow-50 p-3 text-sm text-yellow-800">
          Backoffice API unreachable — showing built-in sample data. Status changes will be applied
          locally only.
        </div>
      )}
      {actionError && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800" role="alert">
          {actionError}
        </div>
      )}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Fraud Alerts</h1>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => {
              setLocalAlerts(null);
              void refetch();
            }}
            disabled={isFetching}
            className="flex items-center px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center px-3 py-2 text-sm font-medium rounded-lg border ${
              showFilters
                ? 'text-blue-700 bg-blue-50 border-blue-300'
                : 'text-gray-700 bg-white border-gray-300 hover:bg-gray-50'
            }`}
          >
            <Filter className="w-4 h-4 mr-2" />
            Filters
          </button>
        </div>
      </div>

      {showFilters && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="">All Statuses</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Alert Type</label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
              >
                <option value="">All Types</option>
                <option value="transaction">Transaction</option>
                <option value="identity">Identity</option>
                <option value="account_takeover">Account Takeover</option>
                <option value="document_fraud">Document Fraud</option>
                <option value="money_laundering">Money Laundering</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search alerts..."
                  className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Alerts</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Critical</p>
              <p className="text-2xl font-bold text-red-600">{stats.critical}</p>
            </div>
            <div className="p-3 bg-red-100 rounded-lg">
              <AlertCircle className="w-6 h-6 text-red-600" />
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Open</p>
              <p className="text-2xl font-bold text-orange-600">{stats.open}</p>
            </div>
            <div className="p-3 bg-orange-100 rounded-lg">
              <Clock className="w-6 h-6 text-orange-600" />
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Resolved</p>
              <p className="text-2xl font-bold text-green-600">{stats.resolved}</p>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {filteredAlerts.map((alert) => (
          <div
            key={alert.id}
            className={`bg-white rounded-lg shadow-sm border-l-4 p-4 ${
              alert.severity === 'critical'
                ? 'border-l-red-500'
                : alert.severity === 'high'
                ? 'border-l-orange-500'
                : alert.severity === 'medium'
                ? 'border-l-yellow-500'
                : 'border-l-blue-500'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start space-x-4">
                <AlertTypeIcon type={alert.alertType} />
                <div>
                  <div className="flex items-center space-x-2 mb-1">
                    <h3 className="font-medium text-gray-900">{alert.id}</h3>
                    <SeverityBadge severity={alert.severity} />
                    <StatusBadge status={alert.status} />
                  </div>
                  <p className="text-gray-600 mb-2">{alert.description}</p>
                  <div className="flex items-center space-x-4 text-sm text-gray-500">
                    <div className="flex items-center">
                      <User className="w-4 h-4 mr-1" />
                      {alert.customerName}
                    </div>
                    {alert.amount && (
                      <div className="flex items-center">
                        <DollarSign className="w-4 h-4 mr-1" />
                        {alert.currency} {alert.amount.toLocaleString()}
                      </div>
                    )}
                    {alert.location && (
                      <div className="flex items-center">
                        <MapPin className="w-4 h-4 mr-1" />
                        {alert.location}
                      </div>
                    )}
                    <div className="flex items-center">
                      <Calendar className="w-4 h-4 mr-1" />
                      {new Date(alert.detectedAt).toLocaleString()}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {alert.indicators.map((indicator, index) => (
                      <span
                        key={index}
                        className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded"
                      >
                        {indicator}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <div className="text-right mr-4">
                  <p className="text-sm text-gray-500">Risk Score</p>
                  <p
                    className={`text-lg font-bold ${
                      alert.riskScore > 0.8
                        ? 'text-red-600'
                        : alert.riskScore > 0.5
                        ? 'text-orange-600'
                        : 'text-yellow-600'
                    }`}
                  >
                    {(alert.riskScore * 100).toFixed(0)}%
                  </p>
                </div>
                <button
                  onClick={() => setSelectedAlert(alert)}
                  className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg"
                >
                  <Eye className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">
          Showing {filteredAlerts.length} of {alerts.length} alerts
        </p>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setPage(Math.max(1, page - 1))}
            disabled={page === 1}
            className="p-2 text-gray-600 hover:bg-gray-100 rounded-lg disabled:opacity-50"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>
          <span className="text-sm text-gray-700">Page {page} of 1</span>
          <button
            onClick={() => setPage(page + 1)}
            disabled={true}
            className="p-2 text-gray-600 hover:bg-gray-100 rounded-lg disabled:opacity-50"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>
      </div>

      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          pending={actionPending}
          onAction={(action) => void applyAction(selectedAlert, action)}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  );
};

interface AlertDetailModalProps {
  alert: FraudAlert;
  pending: boolean;
  onAction: (action: FraudAlertAction) => void;
  onClose: () => void;
}

const AlertDetailModal: React.FC<AlertDetailModalProps> = ({ alert, pending, onAction, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <div className="flex items-center space-x-3">
            <AlertTypeIcon type={alert.alertType} />
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Alert {alert.id}</h2>
              <div className="flex items-center space-x-2 mt-1">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-gray-600 rounded-lg">
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
          <div className="space-y-6">
            <div>
              <h3 className="font-medium text-gray-900 mb-2">Description</h3>
              <p className="text-gray-600">{alert.description}</p>
            </div>

            <div className="grid grid-cols-2 gap-6">
              <div>
                <h3 className="font-medium text-gray-900 mb-2">Customer Information</h3>
                <dl className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <dt className="text-gray-500">Name:</dt>
                    <dd className="text-gray-900">{alert.customerName}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-gray-500">Customer ID:</dt>
                    <dd className="text-gray-900">{alert.customerId}</dd>
                  </div>
                  {alert.location && (
                    <div className="flex justify-between">
                      <dt className="text-gray-500">Location:</dt>
                      <dd className="text-gray-900">{alert.location}</dd>
                    </div>
                  )}
                </dl>
              </div>

              <div>
                <h3 className="font-medium text-gray-900 mb-2">Alert Details</h3>
                <dl className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <dt className="text-gray-500">Type:</dt>
                    <dd className="text-gray-900 capitalize">{alert.alertType.replace('_', ' ')}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-gray-500">Risk Score:</dt>
                    <dd
                      className={`font-semibold ${
                        alert.riskScore > 0.8
                          ? 'text-red-600'
                          : alert.riskScore > 0.5
                          ? 'text-orange-600'
                          : 'text-yellow-600'
                      }`}
                    >
                      {(alert.riskScore * 100).toFixed(0)}%
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-gray-500">Detected:</dt>
                    <dd className="text-gray-900">{new Date(alert.detectedAt).toLocaleString()}</dd>
                  </div>
                  {alert.assignedTo && (
                    <div className="flex justify-between">
                      <dt className="text-gray-500">Assigned To:</dt>
                      <dd className="text-gray-900">{alert.assignedTo}</dd>
                    </div>
                  )}
                </dl>
              </div>
            </div>

            {alert.amount && (
              <div>
                <h3 className="font-medium text-gray-900 mb-2">Transaction Details</h3>
                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Amount:</span>
                    <span className="text-xl font-bold text-gray-900">
                      {alert.currency} {alert.amount.toLocaleString()}
                    </span>
                  </div>
                  {alert.relatedTransactions && (
                    <div className="flex items-center justify-between mt-2">
                      <span className="text-gray-500">Related Transactions:</span>
                      <span className="text-gray-900">{alert.relatedTransactions}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            <div>
              <h3 className="font-medium text-gray-900 mb-2">Risk Indicators</h3>
              <div className="flex flex-wrap gap-2">
                {alert.indicators.map((indicator, index) => (
                  <span
                    key={index}
                    className="px-3 py-1 text-sm bg-red-50 text-red-700 rounded-lg border border-red-200"
                  >
                    <AlertTriangle className="w-3 h-3 inline mr-1" />
                    {indicator}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end space-x-3 p-4 border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            Close
          </button>
          <button
            onClick={() => onAction('investigate')}
            disabled={pending || alert.status === 'investigating'}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            Investigate
          </button>
          <button
            onClick={() => onAction('resolve')}
            disabled={pending || alert.status === 'resolved'}
            className="px-4 py-2 text-sm font-medium text-white bg-green-600 rounded-lg hover:bg-green-700 disabled:opacity-50"
          >
            Mark Resolved
          </button>
          <button
            onClick={() => onAction('false_positive')}
            disabled={pending || alert.status === 'false_positive'}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 disabled:opacity-50"
          >
            False Positive
          </button>
        </div>
      </div>
    </div>
  );
};

export default FraudAlerts;
