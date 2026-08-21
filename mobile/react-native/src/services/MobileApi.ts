import axios, { AxiosHeaders, InternalAxiosRequestConfig } from 'axios';
import { AuthService } from './AuthService';

export interface DashboardSummary { openCases: number; pendingKyc: number; unreadNotifications: number; riskLevel: 'low' | 'medium' | 'high'; }
export interface KycSession { id: string; status: 'created' | 'documents_required' | 'biometric_required' | 'video_required' | 'under_review' | 'approved' | 'rejected'; updatedAt: string; decisionReason?: string; }
export interface DocumentRecord { id: string; name: string; type: string; status: 'uploaded' | 'verified' | 'rejected'; createdAt: string; }
export interface NotificationRecord { id: string; title: string; body: string; readAt?: string; createdAt: string; }
export interface FraudAlert { id: string; title: string; severity: 'low' | 'medium' | 'high' | 'critical'; status: string; createdAt: string; }
export interface Profile { id: string; email?: string; name?: string; notificationEnabled: boolean; biometricEnabled: boolean; }

function apiBaseUrl(): string {
  const runtime = globalThis as typeof globalThis & { __FRAUDFUSION_API_CONFIG__?: { baseUrl: string } };
  const baseUrl = runtime.__FRAUDFUSION_API_CONFIG__?.baseUrl;
  if (!baseUrl) throw new Error('Mobile API base URL is required');
  return baseUrl.replace(/\/$/, '');
}

const client = axios.create({ timeout: 15_000 });
client.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  const session = await AuthService.restoreSession();
  if (!session) throw new Error('Authenticated session required');
  config.baseURL = apiBaseUrl();
  config.headers = AxiosHeaders.from(config.headers);
  config.headers.set('Authorization', `Bearer ${session.accessToken}`);
  config.headers.set('Accept', 'application/json');
  return config;
});

export const MobileApi = {
  dashboard: async (): Promise<DashboardSummary> => (await client.get('/mobile/dashboard')).data,
  profile: async (): Promise<Profile> => (await client.get('/auth/me')).data,
  updateProfile: async (payload: Partial<Profile>): Promise<Profile> => (await client.patch('/mobile/profile', payload)).data,
  notifications: async (): Promise<NotificationRecord[]> => (await client.get('/notifications')).data,
  markNotificationRead: async (id: string): Promise<void> => { await client.post(`/notifications/${id}/read`); },
  alerts: async (): Promise<FraudAlert[]> => (await client.get('/mobile/fraud-alerts')).data,
  documents: async (): Promise<DocumentRecord[]> => (await client.get('/documents')).data,
  createKycSession: async (): Promise<KycSession> => (await client.post('/kyc/sessions')).data,
  kycSession: async (id: string): Promise<KycSession> => (await client.get(`/kyc/sessions/${id}`)).data,
  beginDocumentUpload: async (sessionId: string, documentType: string, name: string): Promise<{ uploadUrl: string; documentId: string }> => (await client.post(`/kyc/sessions/${sessionId}/documents`, { documentType, name })).data,
  completeDocumentUpload: async (sessionId: string, documentId: string): Promise<KycSession> => (await client.post(`/kyc/sessions/${sessionId}/documents/${documentId}/complete`)).data,
  biometricChallenge: async (sessionId: string): Promise<{ challengeId: string; prompt: string }> => (await client.post(`/kyc/sessions/${sessionId}/biometric-challenge`)).data,
  submitBiometric: async (sessionId: string, challengeId: string): Promise<KycSession> => (await client.post(`/kyc/sessions/${sessionId}/biometric-challenge/${challengeId}/complete`)).data,
  submitVideoKyc: async (sessionId: string, videoReference: string): Promise<KycSession> => (await client.post(`/kyc/sessions/${sessionId}/video`, { videoReference })).data,
};
