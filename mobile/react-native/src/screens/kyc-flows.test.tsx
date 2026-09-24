import React from 'react';
import { fireEvent, render, waitFor } from '@testing-library/react-native';
import { KycSession, MobileApi } from '../services/MobileApi';
import { BiometricService } from '../services/BiometricService';
import KYCBiometricScreen from './KYCBiometricScreen';
import DocumentUploadScreen from './DocumentUploadScreen';
import VideoKYCScreen from './VideoKYCScreen';

jest.mock('../services/MobileApi', () => ({
  MobileApi: {
    profile: jest.fn(),
    documents: jest.fn(),
    createKycSession: jest.fn(),
    beginDocumentUpload: jest.fn(),
    completeDocumentUpload: jest.fn(),
    biometricChallenge: jest.fn(),
    submitBiometric: jest.fn(),
    submitVideoKyc: jest.fn(),
  },
}));

jest.mock('../services/BiometricService', () => ({
  BiometricService: {
    isAvailable: jest.fn(),
    authenticate: jest.fn(),
  },
}));

const api = MobileApi as jest.Mocked<typeof MobileApi>;
const biometrics = BiometricService as jest.Mocked<typeof BiometricService>;

const profile = { id: 'user-1', notificationEnabled: true, biometricEnabled: true };
const session = { id: 'kyc-1', status: 'created' as const, updatedAt: '2026-08-21T00:00:00Z' };

beforeEach(() => {
  jest.clearAllMocks();
  api.profile.mockResolvedValue(profile);
  api.documents.mockResolvedValue([
    { id: 'doc-1', name: 'passport', type: 'passport', status: 'verified', createdAt: '2026-08-21T00:00:00Z' },
  ]);
  api.createKycSession.mockResolvedValue(session);
  api.beginDocumentUpload.mockResolvedValue({ uploadUrl: 'https://uploads.local/doc-2', documentId: 'doc-2' });
  api.completeDocumentUpload.mockResolvedValue({ ...session, status: 'documents_required' });
  api.biometricChallenge.mockResolvedValue({ challengeId: 'ch-1', prompt: 'Scan fingerprint' });
  api.submitBiometric.mockResolvedValue({ ...session, status: 'biometric_required' });
  api.submitVideoKyc.mockResolvedValue({ ...session, status: 'under_review' });
  biometrics.isAvailable.mockResolvedValue(true);
  biometrics.authenticate.mockResolvedValue(undefined);
});

describe('KYCBiometricScreen enrollment flow', () => {
  it('enrolls biometrics end-to-end via device scan and server challenge', async () => {
    let resolveSubmit: (value: KycSession) => void = () => {};
    api.submitBiometric.mockImplementation(
      () => new Promise((resolve) => { resolveSubmit = resolve; }),
    );
    const view = await render(<KYCBiometricScreen />);
    await waitFor(() => expect(api.profile).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(view.getByText(/Biometric login on this account: enabled/)).toBeTruthy());
    expect(view.getByText('Enrollment status: idle')).toBeTruthy();

    fireEvent.press(view.getByText('Start biometric enrollment'));
    await waitFor(() => expect(view.getByText('Scanning...')).toBeTruthy());
    expect(view.getByText('Enrollment status: scanning')).toBeTruthy();

    resolveSubmit({ ...session, status: 'biometric_required' });
    await waitFor(() => expect(view.getByText('Enrollment status: success')).toBeTruthy());
    expect(biometrics.authenticate).toHaveBeenCalledTimes(1);
    expect(api.createKycSession).toHaveBeenCalledTimes(1);
    expect(api.biometricChallenge).toHaveBeenCalledWith('kyc-1');
    expect(api.submitBiometric).toHaveBeenCalledWith('kyc-1', 'ch-1');
  });

  it('reports failure when the device has no biometric sensor', async () => {
    biometrics.isAvailable.mockResolvedValue(false);
    const view = await render(<KYCBiometricScreen />);
    await waitFor(() => expect(view.getByText('Start biometric enrollment')).toBeTruthy());
    fireEvent.press(view.getByText('Start biometric enrollment'));
    await waitFor(() => expect(view.getByText('Enrollment status: failure')).toBeTruthy());
    expect(view.getByText('Biometric sensor is not available on this device')).toBeTruthy();
    expect(api.createKycSession).not.toHaveBeenCalled();
  });

  it('falls back to a safe message when the server rejects biometric submission', async () => {
    api.submitBiometric.mockRejectedValue('unexpected');
    const view = await render(<KYCBiometricScreen />);
    await waitFor(() => expect(view.getByText('Start biometric enrollment')).toBeTruthy());
    fireEvent.press(view.getByText('Start biometric enrollment'));
    await waitFor(() => expect(view.getByText('Enrollment status: failure')).toBeTruthy());
    expect(view.getByText('Biometric enrollment failed')).toBeTruthy();
  });

  it('shows an error instead of profile state when the profile load fails', async () => {
    api.profile.mockRejectedValue(new Error('backend unavailable'));
    const view = await render(<KYCBiometricScreen />);
    await waitFor(() => expect(view.getByText('backend unavailable')).toBeTruthy());
    expect(view.queryByText(/Biometric login on this account/)).toBeNull();
  });

  it('renders biometric login as disabled when the profile says so', async () => {
    api.profile.mockResolvedValue({ ...profile, biometricEnabled: false });
    const view = await render(<KYCBiometricScreen />);
    await waitFor(() =>
      expect(view.getByText(/Biometric login on this account: disabled/)).toBeTruthy(),
    );
  });
});

describe('DocumentUploadScreen upload flow', () => {
  it('uploads a document through begin/complete and refreshes the list', async () => {
    let resolveComplete: (value: KycSession) => void = () => {};
    api.completeDocumentUpload.mockImplementation(
      () => new Promise((resolve) => { resolveComplete = resolve; }),
    );
    const view = await render(<DocumentUploadScreen />);
    await waitFor(() => expect(api.documents).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(view.getByText(/doc-1/)).toBeTruthy());

    fireEvent.press(view.getByText('Upload passport'));
    await waitFor(() => expect(view.getByText('Uploading...')).toBeTruthy());

    resolveComplete({ ...session, status: 'documents_required' });
    await waitFor(() => expect(api.completeDocumentUpload).toHaveBeenCalledWith('kyc-1', 'doc-2'));
    expect(api.beginDocumentUpload).toHaveBeenCalledWith('kyc-1', 'passport', 'passport.png');
    await waitFor(() => expect(api.documents).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(view.getByText('Upload passport')).toBeTruthy());
  });

  it('renders an upload error when the begin call fails', async () => {
    api.beginDocumentUpload.mockRejectedValue(new Error('storage rejected'));
    const view = await render(<DocumentUploadScreen />);
    await waitFor(() => expect(view.getByText('Upload passport')).toBeTruthy());
    fireEvent.press(view.getByText('Upload passport'));
    await waitFor(() => expect(view.getByText('storage rejected')).toBeTruthy());
    expect(api.completeDocumentUpload).not.toHaveBeenCalled();
  });

  it('uses the safe fallback when the document list load rejects a non-Error', async () => {
    api.documents.mockRejectedValue('unexpected');
    const view = await render(<DocumentUploadScreen />);
    await waitFor(() => expect(view.getByText('Request failed')).toBeTruthy());
  });
});

describe('VideoKYCScreen submission flow', () => {
  it('creates a KYC session and submits the recorded video', async () => {
    let resolveSubmit: (value: KycSession) => void = () => {};
    api.submitVideoKyc.mockImplementation(
      () => new Promise((resolve) => { resolveSubmit = resolve; }),
    );
    const view = await render(<VideoKYCScreen />);
    await waitFor(() => expect(api.profile).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(view.getByText(/account user-1/)).toBeTruthy());

    fireEvent.press(view.getByText('Submit recorded video session'));
    await waitFor(() => expect(view.getByText('Submitting...')).toBeTruthy());

    resolveSubmit({ ...session, status: 'under_review' });
    await waitFor(() => expect(view.getByText('KYC session kyc-1: under_review')).toBeTruthy());
    expect(api.submitVideoKyc).toHaveBeenCalledWith('kyc-1', 'recording-kyc-1');
  });

  it('uses the safe fallback when video submission rejects a non-Error', async () => {
    api.submitVideoKyc.mockRejectedValue('unexpected');
    const view = await render(<VideoKYCScreen />);
    await waitFor(() => expect(view.getByText('Submit recorded video session')).toBeTruthy());
    fireEvent.press(view.getByText('Submit recorded video session'));
    await waitFor(() => expect(view.getByText('Video KYC submission failed')).toBeTruthy());
  });

  it('shows an error instead of profile state when the profile load fails', async () => {
    api.profile.mockRejectedValue(new Error('backend unavailable'));
    const view = await render(<VideoKYCScreen />);
    await waitFor(() => expect(view.getByText('backend unavailable')).toBeTruthy());
    expect(view.queryByText(/Video identification for account/)).toBeNull();
  });
});
