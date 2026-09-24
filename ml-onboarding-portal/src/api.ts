const API_BASE_URL = ((import.meta.env.VITE_API_BASE_URL as string | undefined) || '').replace(/\/$/, '');

export interface ApiKeyRequest {
  organization: string;
  contactEmail: string;
  useCase: string;
  environment: 'sandbox' | 'production';
}

export interface ApiKeyGrant {
  keyId: string;
  apiKey?: string;
  environment: string;
  status: string;
}

export interface KycTierSelection {
  tenantId: string;
  tier: 'basic' | 'enhanced' | 'premium';
}

export interface ChecklistItem {
  id: string;
  label: string;
  done: boolean;
  required: boolean;
}

export interface OnboardingStatus {
  tenantId: string;
  tier?: string;
  apiKeyIssued: boolean;
  checklist: ChecklistItem[];
  state: 'not_started' | 'in_progress' | 'pending_review' | 'active' | 'suspended';
  updatedAt?: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      credentials: 'include',
      ...init,
    });
  } catch {
    throw new ApiError('Cannot reach the FraudFusion API. Check your network connection and try again.');
  }
  if (!response.ok) {
    let detail = `Request failed with status ${response.status}.`;
    try {
      const body = (await response.json()) as { detail?: string; message?: string };
      detail = body.detail ?? body.message ?? detail;
    } catch {
      // keep default detail
    }
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

/**
 * Backend routes consumed by this portal (documented in docs/ONBOARDING.md):
 *   POST /api/v1/onboarding/api-keys          -> request an API key
 *   POST /api/v1/onboarding/kyc-tier          -> select the tenant KYC tier
 *   GET  /api/v1/onboarding/checklist         -> integration checklist state
 *   POST /api/v1/onboarding/checklist/:id     -> toggle a checklist item
 *   GET  /api/v1/onboarding/status            -> overall onboarding status
 */
export const onboardingApi = {
  requestApiKey: (payload: ApiKeyRequest) =>
    request<ApiKeyGrant>('/api/v1/onboarding/api-keys', { method: 'POST', body: JSON.stringify(payload) }),
  selectKycTier: (payload: KycTierSelection) =>
    request<OnboardingStatus>('/api/v1/onboarding/kyc-tier', { method: 'POST', body: JSON.stringify(payload) }),
  getChecklist: () => request<{ items: ChecklistItem[] }>('/api/v1/onboarding/checklist'),
  updateChecklistItem: (id: string, done: boolean) =>
    request<ChecklistItem>(`/api/v1/onboarding/checklist/${encodeURIComponent(id)}`, {
      method: 'POST',
      body: JSON.stringify({ done }),
    }),
  getStatus: () => request<OnboardingStatus>('/api/v1/onboarding/status'),
};
