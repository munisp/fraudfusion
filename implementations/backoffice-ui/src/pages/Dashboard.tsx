import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';
import {
  FileCheck,
  FileX,
  Clock,
  AlertTriangle,
  TrendingUp,
  Users,
  Activity,
  Shield,
} from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
  icon: React.ReactNode;
  color: string;
}

const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  change,
  changeType,
  icon,
  color,
}) => (
  <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-gray-500">{title}</p>
        <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
        {change && (
          <p
            className={`text-sm mt-1 ${
              changeType === 'positive'
                ? 'text-green-600'
                : changeType === 'negative'
                ? 'text-red-600'
                : 'text-gray-500'
            }`}
          >
            {change}
          </p>
        )}
      </div>
      <div className={`p-3 rounded-lg ${color}`}>{icon}</div>
    </div>
  </div>
);

const Dashboard: React.FC = () => {
  const { data: stats, isLoading, isError } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: () => api.getDashboardStats(),
    refetchInterval: 30000,
    retry: false,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (isError || !stats) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-6 text-red-800">
        Dashboard metrics are unavailable. Confirm that the authenticated backoffice API is reachable and retry.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <div className="text-sm text-gray-500">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Verifications"
          value={stats.totalVerifications.toLocaleString()}
          change="+12% from last month"
          changeType="positive"
          icon={<Users className="w-6 h-6 text-blue-600" />}
          color="bg-blue-100"
        />
        <StatCard
          title="Pending Reviews"
          value={stats.pendingReviews}
          change={stats.pendingReviews > 100 ? 'High volume' : 'Normal'}
          changeType={stats.pendingReviews > 100 ? 'negative' : 'neutral'}
          icon={<Clock className="w-6 h-6 text-yellow-600" />}
          color="bg-yellow-100"
        />
        <StatCard
          title="Approved Today"
          value={stats.approvedToday}
          change="+8% from yesterday"
          changeType="positive"
          icon={<FileCheck className="w-6 h-6 text-green-600" />}
          color="bg-green-100"
        />
        <StatCard
          title="Rejected Today"
          value={stats.rejectedToday}
          change="-3% from yesterday"
          changeType="positive"
          icon={<FileX className="w-6 h-6 text-red-600" />}
          color="bg-red-100"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Fraud Detection Metrics
          </h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Shield className="w-5 h-5 text-blue-600" />
                <span className="text-gray-700">Detection Rate</span>
              </div>
              <span className="font-semibold text-gray-900">
                {(stats.fraudDetectionRate * 100).toFixed(2)}%
              </span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Activity className="w-5 h-5 text-green-600" />
                <span className="text-gray-700">Avg Processing Time</span>
              </div>
              <span className="font-semibold text-gray-900">
                {stats.averageProcessingTime}s
              </span>
            </div>

          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Fraud Types Detected
          </h2>
          <div className="space-y-3">
            {Object.entries(stats.fraudByType).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className="w-4 h-4 text-orange-500" />
                  <span className="text-gray-700 capitalize">
                    {type.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="font-semibold text-gray-900">{count}</span>
                  <div className="w-24 h-2 bg-gray-200 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-orange-500 rounded-full"
                      style={{
                        width: `${(count / Math.max(...Object.values(stats.fraudByType))) * 100}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">
          Verifications by Type
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Object.entries(stats.verificationsByType).map(([type, count]) => (
            <div
              key={type}
              className="text-center p-4 bg-gray-50 rounded-lg"
            >
              <p className="text-2xl font-bold text-gray-900">
                {count.toLocaleString()}
              </p>
              <p className="text-sm text-gray-500 capitalize mt-1">{type}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
