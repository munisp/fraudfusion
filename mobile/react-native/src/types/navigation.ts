export type RootStackParamList = {
  Splash: undefined;
  Login: undefined;
  Register: undefined;
  Main: undefined;
  KYCDocument: { sessionId: string };
  KYCBiometric: { sessionId: string; challengeId: string };
  KYCStatus: { sessionId: string };
  DocumentUpload: { sessionId: string; documentType: string };
  VideoKYC: { sessionId: string };
  Notifications: undefined;
  Settings: undefined;
};

export type MainTabParamList = {
  Dashboard: undefined;
  KYC: undefined;
  Documents: undefined;
  Alerts: undefined;
  Profile: undefined;
};
