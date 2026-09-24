export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'reviewer' | 'analyst' | 'viewer';
  permissions: string[];
  createdAt: string;
  lastLogin: string;
}

export interface DocumentReview {
  id: string;
  documentId: string;
  documentType: DocumentType;
  status: ReviewStatus;
  submittedAt: string;
  reviewedAt?: string;
  reviewerId?: string;

  customerName: string;
  customerId: string;
  tenantId: string;

  ocrResult?: OCRResult;
  fraudIndicators: FraudIndicator[];
  riskScore: number;

  decision?: ReviewDecision;
  decisionReason?: string;
  notes?: string;
}

export type DocumentType =
  | 'national_id'
  | 'drivers_license'
  | 'passport'
  | 'bvn_slip'
  | 'utility_bill'
  | 'bank_statement'
  | 'certificate_of_occupancy'
  | 'survey_plan'
  | 'deed_of_assignment'
  | 'cac_certificate'
  | 'degree_certificate'
  | 'nysc_certificate';

export type ReviewStatus =
  | 'pending'
  | 'in_review'
  | 'approved'
  | 'rejected'
  | 'escalated'
  | 'needs_info';

export type ReviewDecision =
  | 'approve'
  | 'reject'
  | 'escalate'
  | 'request_info';

export interface OCRResult {
  extractedText: string;
  confidence: number;
  fields: Record<string, string>;
  processingTime: number;
  engine: string;
}

export interface FraudIndicator {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  confidence: number;
  evidence?: string;
}

export interface KYCVerification {
  id: string;
  customerId: string;
  customerName: string;
  verificationType: 'bvn' | 'nin' | 'phone' | 'address' | 'employment';
  status: 'pending' | 'verified' | 'failed' | 'manual_review';
  submittedAt: string;
  completedAt?: string;

  verificationData: Record<string, any>;
  matchScore?: number;
  discrepancies?: string[];

  reviewerId?: string;
  decision?: string;
  notes?: string;
}

export interface FraudAlert {
  id: string;
  alertType: 'transaction' | 'identity' | 'account_takeover' | 'document_fraud' | 'money_laundering';
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  customerId: string;
  customerName: string;
  description: string;
  amount?: number;
  currency?: string;
  location?: string;
  detectedAt: string;
  assignedTo?: string;
  riskScore: number;
  indicators: string[];
  relatedTransactions?: number;
}

export type FraudAlertAction = 'investigate' | 'resolve' | 'false_positive';

export interface FraudAlertUpdate {
  action: FraudAlertAction;
  note?: string;
}

export interface JourneyExecution {
  id: string;
  journeyId: number;
  journeyName: string;
  tenantId: string;
  customerId: string;

  status: 'running' | 'completed' | 'failed' | 'paused' | 'cancelled';
  startedAt: string;
  completedAt?: string;

  currentStep: number;
  totalSteps: number;
  steps: JourneyStep[];

  finalDecision?: string;
  riskScore?: number;
}

export interface JourneyStep {
  stepNumber: number;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startedAt?: string;
  completedAt?: string;
  result?: Record<string, any>;
  error?: string;
}

export interface AuditLogEntry {
  id: string;
  eventType: string;
  severity: 'info' | 'warning' | 'critical';
  timestamp: string;

  actorId?: string;
  actorType?: string;
  actorIp?: string;

  resourceType: string;
  resourceId: string;
  action: string;
  outcome: string;

  details: Record<string, any>;
}

export interface DashboardStats {
  totalVerifications: number;
  pendingReviews: number;
  approvedToday: number;
  rejectedToday: number;

  fraudDetectionRate: number;
  averageProcessingTime: number;

  verificationsByType: Record<string, number>;
  fraudByType: Record<string, number>;

  recentActivity: ActivityItem[];
}

export interface ActivityItem {
  id: string;
  type: string;
  description: string;
  timestamp: string;
  userId?: string;
  resourceId?: string;
}

export interface ReviewAction {
  documentId: string;
  decision: ReviewDecision;
  reason: string;
  notes?: string;
}

export interface FilterOptions {
  status?: ReviewStatus[];
  documentType?: DocumentType[];
  dateFrom?: string;
  dateTo?: string;
  riskScoreMin?: number;
  riskScoreMax?: number;
  tenantId?: string;
  searchQuery?: string;
}

export interface PaginationParams {
  page: number;
  pageSize: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}
