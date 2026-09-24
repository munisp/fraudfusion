import axios, { AxiosInstance } from 'axios';
import {
  DocumentReview,
  KYCVerification,
  FraudAlert,
  FraudAlertUpdate,
  JourneyExecution,
  AuditLogEntry,
  DashboardStats,
  ReviewAction,
  FilterOptions,
  PaginationParams,
  PaginatedResponse,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.client.interceptors.request.use((config) => {
      const token = localStorage.getItem('auth_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('auth_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.client.get('/backoffice/dashboard/stats');
    return response.data;
  }

  async getDocumentReviews(
    filters: FilterOptions,
    pagination: PaginationParams
  ): Promise<PaginatedResponse<DocumentReview>> {
    const response = await this.client.get('/backoffice/documents/reviews', {
      params: { ...filters, ...pagination },
    });
    return response.data;
  }

  async getDocumentReview(id: string): Promise<DocumentReview> {
    const response = await this.client.get(`/backoffice/documents/reviews/${id}`);
    return response.data;
  }

  async getDocumentImage(documentId: string): Promise<string> {
    const response = await this.client.get(`/backoffice/documents/${documentId}/image`, {
      responseType: 'blob',
    });
    return URL.createObjectURL(response.data);
  }

  async submitReviewDecision(action: ReviewAction): Promise<DocumentReview> {
    const response = await this.client.post('/backoffice/documents/reviews/decision', action);
    return response.data;
  }

  async assignReview(reviewId: string, reviewerId: string): Promise<DocumentReview> {
    const response = await this.client.post(`/backoffice/documents/reviews/${reviewId}/assign`, {
      reviewerId,
    });
    return response.data;
  }

  async getKYCVerifications(
    filters: FilterOptions,
    pagination: PaginationParams
  ): Promise<PaginatedResponse<KYCVerification>> {
    const response = await this.client.get('/backoffice/kyc/verifications', {
      params: { ...filters, ...pagination },
    });
    return response.data;
  }

  async getKYCVerification(id: string): Promise<KYCVerification> {
    const response = await this.client.get(`/backoffice/kyc/verifications/${id}`);
    return response.data;
  }

  async overrideKYCDecision(
    verificationId: string,
    decision: string,
    reason: string
  ): Promise<KYCVerification> {
    const response = await this.client.post(`/backoffice/kyc/verifications/${verificationId}/override`, {
      decision,
      reason,
    });
    return response.data;
  }

  async getFraudAlerts(): Promise<FraudAlert[]> {
    const response = await this.client.get('/backoffice/fraud/alerts');
    return response.data;
  }

  async updateFraudAlertStatus(alertId: string, update: FraudAlertUpdate): Promise<FraudAlert> {
    const response = await this.client.post(`/backoffice/fraud/alerts/${alertId}/status`, update);
    return response.data;
  }

  async getJourneyExecutions(
    filters: FilterOptions,
    pagination: PaginationParams
  ): Promise<PaginatedResponse<JourneyExecution>> {
    const response = await this.client.get('/backoffice/journeys/executions', {
      params: { ...filters, ...pagination },
    });
    return response.data;
  }

  async getJourneyExecution(id: string): Promise<JourneyExecution> {
    const response = await this.client.get(`/backoffice/journeys/executions/${id}`);
    return response.data;
  }

  async retryJourneyStep(executionId: string, stepNumber: number): Promise<JourneyExecution> {
    const response = await this.client.post(`/backoffice/journeys/executions/${executionId}/retry`, {
      stepNumber,
    });
    return response.data;
  }

  async cancelJourney(executionId: string, reason: string): Promise<JourneyExecution> {
    const response = await this.client.post(`/backoffice/journeys/executions/${executionId}/cancel`, {
      reason,
    });
    return response.data;
  }

  async getAuditLogs(
    filters: FilterOptions,
    pagination: PaginationParams
  ): Promise<PaginatedResponse<AuditLogEntry>> {
    const response = await this.client.get('/backoffice/audit/logs', {
      params: { ...filters, ...pagination },
    });
    return response.data;
  }

  async exportAuditLogs(filters: FilterOptions): Promise<Blob> {
    const response = await this.client.get('/backoffice/audit/logs/export', {
      params: filters,
      responseType: 'blob',
    });
    return response.data;
  }

  async login(email: string, password: string): Promise<{ token: string; user: any }> {
    const response = await this.client.post('/auth/login', { email, password });
    return response.data;
  }

  async logout(): Promise<void> {
    await this.client.post('/auth/logout');
    localStorage.removeItem('auth_token');
  }

  async getCurrentUser(): Promise<any> {
    const response = await this.client.get('/auth/me');
    return response.data;
  }
}

export const api = new ApiService();
