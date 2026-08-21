import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Search,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  User,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Eye,
  FileText,
  Camera,
  Fingerprint,
  MapPin,
  Building,
  Phone,
} from 'lucide-react';

interface KYCVerification {
  id: string;
  customerId: string;
  customerName: string;
  email: string;
  phone: string;
  status: 'pending' | 'in_progress' | 'approved' | 'rejected' | 'requires_review';
  submittedAt: string;
  completedAt?: string;
  verificationType: 'individual' | 'business';
  riskScore: number;
  verificationSteps: {
    bvn: 'pending' | 'verified' | 'failed';
    nin: 'pending' | 'verified' | 'failed';
    address: 'pending' | 'verified' | 'failed';
    biometric: 'pending' | 'verified' | 'failed';
    document: 'pending' | 'verified' | 'failed';
  };
  documents: {
    type: string;
    status: 'pending' | 'verified' | 'rejected';
  }[];
}

const mockVerifications: KYCVerification[] = [
  {
    id: 'kyc-001',
    customerId: 'cust-001',
    customerName: 'Adebayo Ogundimu',
    email: 'adebayo.o@email.com',
    phone: '+234 801 234 5678',
    status: 'pending',
    submittedAt: new Date().toISOString(),
    verificationType: 'individual',
    riskScore: 0.25,
    verificationSteps: {
      bvn: 'verified',
      nin: 'verified',
      address: 'pending',
      biometric: 'pending',
      document: 'verified',
    },
    documents: [
      { type: 'National ID', status: 'verified' },
      { type: 'Utility Bill', status: 'pending' },
    ],
  },
  {
    id: 'kyc-002',
    customerId: 'cust-002',
    customerName: 'Chukwuemeka Okonkwo',
    email: 'c.okonkwo@business.ng',
    phone: '+234 802 345 6789',
    status: 'requires_review',
    submittedAt: new Date(Date.now() - 3600000).toISOString(),
    verificationType: 'individual',
    riskScore: 0.72,
    verificationSteps: {
      bvn: 'verified',
      nin: 'failed',
      address: 'verified',
      biometric: 'verified',
      document: 'failed',
    },
    documents: [
      { type: 'Passport', status: 'rejected' },
      { type: 'Bank Statement', status: 'verified' },
    ],
  },
  {
    id: 'kyc-003',
    customerId: 'cust-003',
    customerName: 'Fatima Ibrahim',
    email: 'fatima.i@company.com',
    phone: '+234 803 456 7890',
    status: 'approved',
    submittedAt: new Date(Date.now() - 86400000).toISOString(),
    completedAt: new Date(Date.now() - 43200000).toISOString(),
    verificationType: 'individual',
    riskScore: 0.08,
    verificationSteps: {
      bvn: 'verified',
      nin: 'verified',
      address: 'verified',
      biometric: 'verified',
      document: 'verified',
    },
    documents: [
      { type: "Driver's License", status: 'verified' },
      { type: 'Utility Bill', status: 'verified' },
    ],
  },
  {
    id: 'kyc-004',
    customerId: 'cust-004',
    customerName: 'Globex Industries Ltd',
    email: 'compliance@globex.ng',
    phone: '+234 1 234 5678',
    status: 'in_progress',
    submittedAt: new Date(Date.now() - 7200000).toISOString(),
    verificationType: 'business',
    riskScore: 0.45,
    verificationSteps: {
      bvn: 'verified',
      nin: 'pending',
      address: 'verified',
      biometric: 'pending',
      document: 'pending',
    },
    documents: [
      { type: 'CAC Certificate', status: 'verified' },
      { type: 'Tax Clearance', status: 'pending' },
      { type: 'Board Resolution', status: 'pending' },
    ],
  },
];

const StatusBadge: React.FC<{ status: KYCVerification['status'] }> = ({ status }) => {
  const styles = {
    pending: 'bg-yellow-100 text-yellow-800',
    in_progress: 'bg-blue-100 text-blue-800',
    approved: 'bg-green-100 text-green-800',
    rejected: 'bg-red-100 text-red-800',
    requires_review: 'bg-orange-100 text-orange-800',
  };

  const labels = {
    pending: 'Pending',
    in_progress: 'In Progress',
    approved: 'Approved',
    rejected: 'Rejected',
    requires_review: 'Requires Review',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${styles[status]}`}>
      {labels[status]}
    </span>
  );
};

const StepIndicator: React.FC<{ status: 'pending' | 'verified' | 'failed'; label: string; icon: React.ReactNode }> = ({
  status,
  label,
  icon,
}) => {
  const colors = {
    pending: 'text-gray-400 bg-gray-100',
    verified: 'text-green-600 bg-green-100',
    failed: 'text-red-600 bg-red-100',
  };

  return (
    <div className="flex flex-col items-center">
      <div className={`p-2 rounded-full ${colors[status]}`}>{icon}</div>
      <span className="text-xs mt-1 text-gray-600">{label}</span>
      {status === 'verified' && <CheckCircle className="w-3 h-3 text-green-500 mt-0.5" />}
      {status === 'failed' && <XCircle className="w-3 h-3 text-red-500 mt-0.5" />}
      {status === 'pending' && <Clock className="w-3 h-3 text-gray-400 mt-0.5" />}
    </div>
  );
};

const KYCVerifications: React.FC = () => {
  const [selectedVerification, setSelectedVerification] = useState<KYCVerification | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);

  const filteredVerifications = mockVerifications.filter((v) => {
    if (statusFilter && v.status !== statusFilter) return false;
    if (typeFilter && v.verificationType !== typeFilter) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        v.customerName.toLowerCase().includes(query) ||
        v.email.toLowerCase().includes(query) ||
        v.customerId.toLowerCase().includes(query)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">KYC Verifications</h1>
        <div className="flex items-center space-x-3">
          <button className="flex items-center px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
            <RefreshCw className="w-4 h-4 mr-2" />
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
              <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="">All Statuses</option>
                <option value="pending">Pending</option>
                <option value="in_progress">In Progress</option>
                <option value="approved">Approved</option>
                <option value="rejected">Rejected</option>
                <option value="requires_review">Requires Review</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
              >
                <option value="">All Types</option>
                <option value="individual">Individual</option>
                <option value="business">Business</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by name, email, or ID..."
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
              <p className="text-sm text-gray-500">Total Verifications</p>
              <p className="text-2xl font-bold text-gray-900">{mockVerifications.length}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-lg">
              <User className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Pending Review</p>
              <p className="text-2xl font-bold text-yellow-600">
                {mockVerifications.filter((v) => v.status === 'pending' || v.status === 'requires_review').length}
              </p>
            </div>
            <div className="p-3 bg-yellow-100 rounded-lg">
              <Clock className="w-6 h-6 text-yellow-600" />
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Approved</p>
              <p className="text-2xl font-bold text-green-600">
                {mockVerifications.filter((v) => v.status === 'approved').length}
              </p>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">High Risk</p>
              <p className="text-2xl font-bold text-red-600">
                {mockVerifications.filter((v) => v.riskScore > 0.7).length}
              </p>
            </div>
            <div className="p-3 bg-red-100 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-red-600" />
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Customer
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Risk Score
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Verification Progress
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Submitted
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredVerifications.map((verification) => (
              <tr key={verification.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 h-10 w-10 bg-blue-100 rounded-full flex items-center justify-center">
                      {verification.verificationType === 'business' ? (
                        <Building className="w-5 h-5 text-blue-600" />
                      ) : (
                        <User className="w-5 h-5 text-blue-600" />
                      )}
                    </div>
                    <div className="ml-4">
                      <div className="text-sm font-medium text-gray-900">{verification.customerName}</div>
                      <div className="text-sm text-gray-500">{verification.email}</div>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="capitalize text-sm text-gray-700">{verification.verificationType}</span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <StatusBadge status={verification.status} />
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden mr-2">
                      <div
                        className={`h-full rounded-full ${
                          verification.riskScore > 0.7
                            ? 'bg-red-500'
                            : verification.riskScore > 0.4
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                        }`}
                        style={{ width: `${verification.riskScore * 100}%` }}
                      />
                    </div>
                    <span
                      className={`text-sm font-medium ${
                        verification.riskScore > 0.7
                          ? 'text-red-600'
                          : verification.riskScore > 0.4
                          ? 'text-yellow-600'
                          : 'text-green-600'
                      }`}
                    >
                      {(verification.riskScore * 100).toFixed(0)}%
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex space-x-2">
                    <StepIndicator
                      status={verification.verificationSteps.bvn}
                      label="BVN"
                      icon={<Fingerprint className="w-4 h-4" />}
                    />
                    <StepIndicator
                      status={verification.verificationSteps.nin}
                      label="NIN"
                      icon={<FileText className="w-4 h-4" />}
                    />
                    <StepIndicator
                      status={verification.verificationSteps.address}
                      label="Addr"
                      icon={<MapPin className="w-4 h-4" />}
                    />
                    <StepIndicator
                      status={verification.verificationSteps.biometric}
                      label="Bio"
                      icon={<Camera className="w-4 h-4" />}
                    />
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {new Date(verification.submittedAt).toLocaleDateString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <button
                    onClick={() => setSelectedVerification(verification)}
                    className="text-blue-600 hover:text-blue-900"
                  >
                    <Eye className="w-5 h-5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">
          Showing {filteredVerifications.length} of {mockVerifications.length} verifications
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

      {selectedVerification && (
        <KYCDetailModal
          verification={selectedVerification}
          onClose={() => setSelectedVerification(null)}
        />
      )}
    </div>
  );
};

interface KYCDetailModalProps {
  verification: KYCVerification;
  onClose: () => void;
}

const KYCDetailModal: React.FC<KYCDetailModalProps> = ({ verification, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">KYC Verification Details</h2>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-gray-600 rounded-lg">
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
          <div className="grid grid-cols-2 gap-6">
            <div>
              <h3 className="font-medium text-gray-900 mb-3">Customer Information</h3>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <dt className="text-gray-500">Name:</dt>
                  <dd className="text-gray-900 font-medium">{verification.customerName}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Email:</dt>
                  <dd className="text-gray-900">{verification.email}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Phone:</dt>
                  <dd className="text-gray-900">{verification.phone}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Customer ID:</dt>
                  <dd className="text-gray-900">{verification.customerId}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Type:</dt>
                  <dd className="text-gray-900 capitalize">{verification.verificationType}</dd>
                </div>
              </dl>
            </div>

            <div>
              <h3 className="font-medium text-gray-900 mb-3">Verification Status</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-gray-500">Overall Status:</span>
                  <StatusBadge status={verification.status} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-500">Risk Score:</span>
                  <span
                    className={`font-semibold ${
                      verification.riskScore > 0.7
                        ? 'text-red-600'
                        : verification.riskScore > 0.4
                        ? 'text-yellow-600'
                        : 'text-green-600'
                    }`}
                  >
                    {(verification.riskScore * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-500">Submitted:</span>
                  <span className="text-gray-900">
                    {new Date(verification.submittedAt).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6">
            <h3 className="font-medium text-gray-900 mb-3">Verification Steps</h3>
            <div className="grid grid-cols-5 gap-4">
              <StepIndicator
                status={verification.verificationSteps.bvn}
                label="BVN Verification"
                icon={<Fingerprint className="w-5 h-5" />}
              />
              <StepIndicator
                status={verification.verificationSteps.nin}
                label="NIN Verification"
                icon={<FileText className="w-5 h-5" />}
              />
              <StepIndicator
                status={verification.verificationSteps.address}
                label="Address Verification"
                icon={<MapPin className="w-5 h-5" />}
              />
              <StepIndicator
                status={verification.verificationSteps.biometric}
                label="Biometric Check"
                icon={<Camera className="w-5 h-5" />}
              />
              <StepIndicator
                status={verification.verificationSteps.document}
                label="Document Check"
                icon={<FileText className="w-5 h-5" />}
              />
            </div>
          </div>

          <div className="mt-6">
            <h3 className="font-medium text-gray-900 mb-3">Documents</h3>
            <div className="space-y-2">
              {verification.documents.map((doc, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                >
                  <div className="flex items-center space-x-3">
                    <FileText className="w-5 h-5 text-gray-400" />
                    <span className="text-gray-900">{doc.type}</span>
                  </div>
                  <span
                    className={`px-2 py-1 text-xs font-medium rounded-full ${
                      doc.status === 'verified'
                        ? 'bg-green-100 text-green-800'
                        : doc.status === 'rejected'
                        ? 'bg-red-100 text-red-800'
                        : 'bg-yellow-100 text-yellow-800'
                    }`}
                  >
                    {doc.status}
                  </span>
                </div>
              ))}
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
          <button className="px-4 py-2 text-sm font-medium text-white bg-green-600 rounded-lg hover:bg-green-700">
            Approve
          </button>
          <button className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700">
            Reject
          </button>
        </div>
      </div>
    </div>
  );
};

export default KYCVerifications;
