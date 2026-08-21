import React from 'react';
import { fireEvent, render, waitFor } from '@testing-library/react-native';
import { MobileApi } from '../services/MobileApi';
import SplashScreen from './SplashScreen';
import RegisterScreen from './RegisterScreen';
import DashboardScreen from './DashboardScreen';
import KYCStartScreen from './KYCStartScreen';
import KYCDocumentScreen from './KYCDocumentScreen';
import KYCBiometricScreen from './KYCBiometricScreen';
import KYCStatusScreen from './KYCStatusScreen';
import DocumentUploadScreen from './DocumentUploadScreen';
import DocumentListScreen from './DocumentListScreen';
import ProfileScreen from './ProfileScreen';
import SettingsScreen from './SettingsScreen';
import NotificationsScreen from './NotificationsScreen';
import VideoKYCScreen from './VideoKYCScreen';
import FraudAlertsScreen from './FraudAlertsScreen';

jest.mock('../services/MobileApi', () => ({
  MobileApi: {
    profile: jest.fn(), dashboard: jest.fn(), documents: jest.fn(), notifications: jest.fn(), alerts: jest.fn(), createKycSession: jest.fn(),
  },
}));

const api = MobileApi as jest.Mocked<typeof MobileApi>;
const serverResponses = {
  profile: { id: 'user-1', notificationEnabled: true, biometricEnabled: true },
  dashboard: { openCases: 1, pendingKyc: 1, unreadNotifications: 2, riskLevel: 'low' as const },
  documents: [{ id: 'doc-1', name: 'passport', type: 'passport', status: 'verified' as const, createdAt: '2026-08-21T00:00:00Z' }],
  notifications: [{ id: 'notice-1', title: 'Notice', body: 'Server event', createdAt: '2026-08-21T00:00:00Z' }],
  alerts: [{ id: 'alert-1', title: 'Alert', severity: 'high' as const, status: 'open', createdAt: '2026-08-21T00:00:00Z' }],
  createKycSession: { id: 'kyc-1', status: 'created' as const, updatedAt: '2026-08-21T00:00:00Z' },
};

beforeEach(() => {
  jest.clearAllMocks();
  api.profile.mockResolvedValue(serverResponses.profile);
  api.dashboard.mockResolvedValue(serverResponses.dashboard);
  api.documents.mockResolvedValue(serverResponses.documents);
  api.notifications.mockResolvedValue(serverResponses.notifications);
  api.alerts.mockResolvedValue(serverResponses.alerts);
  api.createKycSession.mockResolvedValue(serverResponses.createKycSession);
});

type Method = 'profile' | 'dashboard' | 'documents' | 'notifications' | 'alerts';
type ScreenCase = { name: string; Component: React.ComponentType; method: Method };
const cases: ScreenCase[] = [
  { name: 'Splash', Component: SplashScreen, method: 'profile' },
  { name: 'Register', Component: RegisterScreen, method: 'profile' },
  { name: 'Dashboard', Component: DashboardScreen, method: 'dashboard' },
  { name: 'KYC start', Component: KYCStartScreen, method: 'dashboard' },
  { name: 'KYC document', Component: KYCDocumentScreen, method: 'documents' },
  { name: 'KYC biometric', Component: KYCBiometricScreen, method: 'profile' },
  { name: 'KYC status', Component: KYCStatusScreen, method: 'dashboard' },
  { name: 'Document upload', Component: DocumentUploadScreen, method: 'documents' },
  { name: 'Document list', Component: DocumentListScreen, method: 'documents' },
  { name: 'Profile', Component: ProfileScreen, method: 'profile' },
  { name: 'Settings', Component: SettingsScreen, method: 'profile' },
  { name: 'Notifications', Component: NotificationsScreen, method: 'notifications' },
  { name: 'Video KYC', Component: VideoKYCScreen, method: 'profile' },
  { name: 'Fraud alerts', Component: FraudAlertsScreen, method: 'alerts' },
];

describe('mobile server-state screens', () => {
  it.each(cases)('$name loads real API-backed state', async ({ Component, method }) => {
    await render(<Component />);
    await waitFor(() => expect(api[method]).toHaveBeenCalledTimes(1));
  });

  it('renders an API error instead of substituting local operational data', async () => {
    api.dashboard.mockRejectedValueOnce(new Error('backend unavailable'));
    const view = await render(<DashboardScreen />);
    await waitFor(() => expect(view.getByText('backend unavailable')).toBeTruthy());
  });
});


describe('KYC session initiation', () => {
  it('creates a persisted KYC session before refreshing the dashboard', async () => {
    const view = await render(<KYCStartScreen />);
    await waitFor(() => expect(api.dashboard).toHaveBeenCalledTimes(1));
    api.dashboard.mockClear();
    fireEvent.press(view.getByText('Start KYC session'));
    await waitFor(() => expect(api.createKycSession).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(api.dashboard).toHaveBeenCalledTimes(1));
    expect(api.createKycSession.mock.invocationCallOrder[0]).toBeLessThan(api.dashboard.mock.invocationCallOrder[0]);
  });
});
