export type RootStackParamList = {
  Splash: undefined;
  Login: undefined;
  Register: undefined;
  Dashboard: undefined;
  KYCStart: undefined;
  KYCDocument: { sessionId: string };
  KYCStatus: { sessionId: string };
  DocumentUpload: { sessionId: string; documentType: string };
  KYCVideo: { sessionId: string };
  KYCBiometric: { sessionId: string; challengeId: string };
  FraudAlerts: undefined;
  Notifications: undefined;
  Profile: undefined;
  Settings: undefined;
};
