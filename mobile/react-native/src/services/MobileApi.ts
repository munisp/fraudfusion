import axios, { AxiosHeaders, InternalAxiosRequestConfig } from 'axios';
import { AuthService } from './AuthService';
import { logger } from './logger';
import type { TamperReport } from './TamperService';

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

// Per-class timeouts: reads fail fast, mutations get room, uploads get the most.
const GET_TIMEOUT_MS = 10_000;
const MUTATION_TIMEOUT_MS = 15_000;
const UPLOAD_TIMEOUT_MS = 60_000;
// Bounded retry for idempotent GETs only (exponential backoff: 250ms, 500ms).
const MAX_GET_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 250;

const client = axios.create({ timeout: GET_TIMEOUT_MS });
client.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  // Session is served from an in-memory cache (no Keychain bridge call per
  // request) and proactively refreshed before expiry.
  const session = await AuthService.getValidSession();
  if (!session) throw new Error('Authenticated session required');
  config.baseURL = apiBaseUrl();
  config.headers = AxiosHeaders.from(config.headers);
  config.headers.set('Authorization', `Bearer ${session.accessToken}`);
  config.headers.set('Accept', 'application/json');
  return config;
});

// In-flight GET dedup: rapid tab switches re-mount screens that fire identical
// GETs; concurrent callers share a single network request.
const inFlightGets = new Map<string, Promise<unknown>>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryable(error: unknown): boolean {
  if (!axios.isAxiosError(error)) return false;
  // Network failure / timeout, or a transient server error.
  if (!error.response) return true;
  return error.response.status >= 500;
}

async function get<T>(path: string, timeoutMs: number = GET_TIMEOUT_MS): Promise<T> {
  const key = `GET ${path}`;
  const existing = inFlightGets.get(key);
  if (existing) return existing as Promise<T>;

  const request = (async (): Promise<T> => {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return (await client.get(path, { timeout: timeoutMs })).data as T;
      } catch (error) {
        if (attempt >= MAX_GET_ATTEMPTS || !isRetryable(error)) throw error;
        const delayMs = RETRY_BASE_DELAY_MS * 2 ** (attempt - 1);
        logger.warn('api.get_retry_scheduled', { path, attempt, delayMs });
        await sleep(delayMs);
      }
    }
  })();

  inFlightGets.set(key, request);
  try {
    return await request;
  } finally {
    inFlightGets.delete(key);
  }
}

async function send<T>(method: 'post' | 'patch', path: string, body?: unknown, timeoutMs: number = MUTATION_TIMEOUT_MS): Promise<T> {
  // Mutations are never auto-retried (not idempotent) and never deduped.
  return (await client[method](path, body, { timeout: timeoutMs })).data as T;
}

export const MobileApi = {
  dashboard: (): Promise<DashboardSummary> => get('/mobile/dashboard'),
  profile: (): Promise<Profile> => get('/auth/me'),
  updateProfile: (payload: Partial<Profile>): Promise<Profile> => send('patch', '/mobile/profile', payload),
  notifications: (): Promise<NotificationRecord[]> => get('/notifications'),
  markNotificationRead: async (id: string): Promise<void> => { await send('post', `/notifications/${id}/read`); },
  alerts: (): Promise<FraudAlert[]> => get('/mobile/fraud-alerts'),
  documents: (): Promise<DocumentRecord[]> => get('/documents'),
  createKycSession: (): Promise<KycSession> => send('post', '/kyc/sessions'),
  kycSession: (id: string): Promise<KycSession> => get(`/kyc/sessions/${id}`),
  beginDocumentUpload: (sessionId: string, documentType: string, name: string): Promise<{ uploadUrl: string; documentId: string }> => send('post', `/kyc/sessions/${sessionId}/documents`, { documentType, name }, UPLOAD_TIMEOUT_MS),
  completeDocumentUpload: (sessionId: string, documentId: string): Promise<KycSession> => send('post', `/kyc/sessions/${sessionId}/documents/${documentId}/complete`, undefined, UPLOAD_TIMEOUT_MS),
  biometricChallenge: (sessionId: string): Promise<{ challengeId: string; prompt: string }> => send('post', `/kyc/sessions/${sessionId}/biometric-challenge`),
  submitBiometric: (sessionId: string, challengeId: string): Promise<KycSession> => send('post', `/kyc/sessions/${sessionId}/biometric-challenge/${challengeId}/complete`),
  submitVideoKyc: (sessionId: string, videoReference: string): Promise<KycSession> => send('post', `/kyc/sessions/${sessionId}/video`, { videoReference }, UPLOAD_TIMEOUT_MS),
  // Device-tamper report (TamperService wiring). Best-effort: failures are
  // logged, never thrown — the local session wipe must not be masked by a
  // reporting outage.
  reportDeviceTamper: async (report: TamperReport): Promise<void> => {
    try {
      await send('post', '/api/v1/security/device-tamper', report);
    } catch (error) {
      logger.warn('security.device_tamper_report_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
    }
  },
};
