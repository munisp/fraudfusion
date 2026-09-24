import axios from 'axios';

// API Base URL - set VITE_API_BASE_URL to your backend URL (standardized across all web apps)
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Types
export interface BasicKYCRequest {
  customer_id: string;
  bvn?: string;
  nin?: string;
  phone?: string;
  email?: string;
  first_name: string;
  last_name: string;
  date_of_birth?: string;
}

export interface EnhancedKYCRequest extends BasicKYCRequest {
  check_pep?: boolean;
  check_sanctions?: boolean;
  nationality?: string;
}

export interface PremiumKYCRequest extends EnhancedKYCRequest {
  check_credit_bureau?: boolean;
  credit_bureau_provider?: string;
}

export interface KYCResponse {
  request_id: string;
  customer_id: string;
  status: string;
  verification_level: string;
  risk_score: number;
  risk_level: string;
  decision: string;
  verification_results: any;
  timestamp: string;
  processing_time_ms: number;
}

// KYC Verification APIs
export const kycAPI = {
  verifyBasic: async (data: BasicKYCRequest): Promise<KYCResponse> => {
    const response = await api.post('/api/v1/kyc/verify/basic', data);
    return response.data;
  },

  verifyEnhanced: async (data: EnhancedKYCRequest): Promise<KYCResponse> => {
    const response = await api.post('/api/v1/kyc/verify/enhanced', data);
    return response.data;
  },

  verifyPremium: async (data: PremiumKYCRequest): Promise<KYCResponse> => {
    const response = await api.post('/api/v1/kyc/verify/premium', data);
    return response.data;
  },

  getStatus: async (requestId: string) => {
    const response = await api.get(`/api/v1/kyc/status/${requestId}`);
    return response.data;
  },
};

// Biometric APIs
export const biometricAPI = {
  verify: async (selfieBase64: string, referenceBase64?: string, checkLiveness: boolean = true) => {
    const response = await api.post('/api/v1/biometric/verify', {
      selfie_image_base64: selfieBase64,
      reference_image_base64: referenceBase64,
      check_liveness: checkLiveness,
    });
    return response.data;
  },

  verifyUpload: async (selfie: File, reference?: File, checkLiveness: boolean = true) => {
    const formData = new FormData();
    formData.append('selfie', selfie);
    if (reference) {
      formData.append('reference', reference);
    }
    formData.append('check_liveness', String(checkLiveness));

    const response = await api.post('/api/v1/biometric/verify/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  checkLiveness: async (image: File) => {
    const formData = new FormData();
    formData.append('image', image);

    const response = await api.post('/api/v1/biometric/liveness', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  matchFaces: async (image1: File, image2: File) => {
    const formData = new FormData();
    formData.append('image1', image1);
    formData.append('image2', image2);

    const response = await api.post('/api/v1/biometric/face-match', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
};

// Document APIs
export const documentAPI = {
  verify: async (document: File, documentType: string, checkForgery: boolean = true) => {
    const formData = new FormData();
    formData.append('document', document);
    formData.append('document_type', documentType);
    formData.append('check_forgery', String(checkForgery));

    const response = await api.post('/api/v1/document/verify', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  extractOCR: async (document: File, documentType: string) => {
    const formData = new FormData();
    formData.append('document', document);
    formData.append('document_type', documentType);

    const response = await api.post('/api/v1/document/ocr', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  checkForgery: async (document: File, documentType: string) => {
    const formData = new FormData();
    formData.append('document', document);
    formData.append('document_type', documentType);

    const response = await api.post('/api/v1/document/forgery-check', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  checkQuality: async (document: File) => {
    const formData = new FormData();
    formData.append('document', document);

    const response = await api.post('/api/v1/document/quality-check', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
};

// Screening APIs
export const screeningAPI = {
  screenPEP: async (fullName: string, dateOfBirth?: string, nationality?: string) => {
    const response = await api.post('/api/v1/screening/pep', {
      full_name: fullName,
      date_of_birth: dateOfBirth,
      nationality: nationality,
    });
    return response.data;
  },

  screenSanctions: async (fullName: string, dateOfBirth?: string, nationality?: string, passportNumber?: string) => {
    const response = await api.post('/api/v1/screening/sanctions', {
      full_name: fullName,
      date_of_birth: dateOfBirth,
      nationality: nationality,
      passport_number: passportNumber,
    });
    return response.data;
  },

  comprehensiveScreening: async (fullName: string, dateOfBirth?: string, nationality?: string, passportNumber?: string) => {
    const response = await api.post('/api/v1/screening/comprehensive', {
      full_name: fullName,
      date_of_birth: dateOfBirth,
      nationality: nationality,
      passport_number: passportNumber,
    });
    return response.data;
  },
};

// Credit Bureau APIs
export const creditBureauAPI = {
  checkCredit: async (bvn: string, firstName: string, lastName: string, provider: string = 'crc') => {
    const response = await api.post('/api/v1/credit-bureau/check', {
      bvn,
      first_name: firstName,
      last_name: lastName,
      provider,
    });
    return response.data;
  },

  getCreditScore: async (bvn: string, firstName: string, lastName: string, provider: string = 'crc') => {
    const response = await api.post('/api/v1/credit-bureau/score-only', {
      bvn,
      first_name: firstName,
      last_name: lastName,
      provider,
    });
    return response.data;
  },
};

// Risk Assessment APIs
export const riskAPI = {
  assessRisk: async (data: any) => {
    const response = await api.post('/api/v1/risk/assess', data);
    return response.data;
  },

  checkFraud: async (customerId: string, transactionData: any, historicalData?: any[]) => {
    const response = await api.post('/api/v1/risk/fraud-check', {
      customer_id: customerId,
      transaction_data: transactionData,
      historical_data: historicalData,
    });
    return response.data;
  },

  analyzeBehavior: async (customerId: string, behavioralData: any) => {
    const response = await api.post('/api/v1/risk/behavioral-analysis', {
      customer_id: customerId,
      behavioral_data: behavioralData,
    });
    return response.data;
  },
};

export default api;
