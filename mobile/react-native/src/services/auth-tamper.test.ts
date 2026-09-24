/**
 * AuthService <-> TamperService wiring tests.
 *
 * Proves: tamper checks run on login and foreground; a critical verdict under
 * 'block' enforcement wipes the Keychain session + in-memory cache and blocks
 * sign-in; 'warn' enforcement reports but does not block.
 */

const mockReportDeviceTamper = jest.fn().mockResolvedValue(undefined);

jest.mock('react-native-keychain', () => ({
  ACCESSIBLE: { WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WHEN_UNLOCKED_THIS_DEVICE_ONLY' },
  ACCESS_CONTROL: { BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE: 'BIOMETRY' },
  SECURITY_LEVEL: { SECURE_HARDWARE: 'SECURE_HARDWARE' },
  setGenericPassword: jest.fn().mockResolvedValue(true),
  getGenericPassword: jest.fn().mockResolvedValue(false),
  resetGenericPassword: jest.fn().mockResolvedValue(true),
  getSecurityLevel: jest.fn(),
}));

jest.mock('react-native-app-auth', () => ({
  authorize: jest.fn(),
  refresh: jest.fn(),
  revoke: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('./MobileApi', () => ({
  MobileApi: { reportDeviceTamper: (...args: unknown[]) => mockReportDeviceTamper(...args) },
}));

const KEYCHAIN_SERVICE = 'com.fraudfusion.mobile.session';

function fakeJwt(sub = 'user-1'): string {
  const json = JSON.stringify({ sub, email: 'u@example.com', realm_access: { roles: ['user'] } });
  const payload = btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `hdr.${payload}.sig`;
}

function oidcResult() {
  return {
    accessToken: fakeJwt(),
    refreshToken: 'refresh-token',
    accessTokenExpirationDate: new Date(Date.now() + 3600_000).toISOString(),
  };
}

describe('AuthService tamper wiring', () => {
  let AuthService: typeof import('./AuthService').AuthService;
  let __setTamperService: typeof import('./AuthService').__setTamperService;
  // jest.resetModules() gives the service-under-test FRESH mock module
  // instances, so mock implementations must be attached to the re-required
  // mocks (not the top-level imports) inside beforeEach.
  let Keychain: jest.Mocked<typeof import('react-native-keychain')>;
  let authorize: jest.Mock;

  beforeEach(() => {
    jest.resetModules();
    Keychain = require('react-native-keychain');
    ({ authorize } = require('react-native-app-auth'));
    mockReportDeviceTamper.mockClear();
    mockReportDeviceTamper.mockResolvedValue(undefined);
    (globalThis as { __FRAUDFUSION_AUTH_CONFIG__?: unknown }).__FRAUDFUSION_AUTH_CONFIG__ = {
      issuer: 'https://idp.example/realms/fraudfusion',
      clientId: 'mobile',
      redirectUrl: 'fraudfusion://callback',
    };
    delete (globalThis as { __TAMPER_ENFORCEMENT__?: string }).__TAMPER_ENFORCEMENT__;
    ({ AuthService, __setTamperService } = require('./AuthService'));
  });

  afterEach(() => {
    __setTamperService(null);
  });

  it('sign-in succeeds on a trusted device and persists the session', async () => {
    (Keychain.getSecurityLevel as jest.Mock).mockResolvedValue('SECURE_ENCLAVE');
    authorize.mockResolvedValue(oidcResult());

    const session = await AuthService.signIn();

    expect(session.user.id).toBe('user-1');
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(Keychain.setGenericPassword).toHaveBeenCalledWith(
      'session',
      expect.stringContaining('"accessToken"'),
      expect.objectContaining({ service: KEYCHAIN_SERVICE }),
    );
    expect(mockReportDeviceTamper).not.toHaveBeenCalled();
  });

  it('critical verdict on login wipes the session and blocks before authorize', async () => {
    // SOFTWARE security level => enclave_unavailable => untrusted verdict.
    (Keychain.getSecurityLevel as jest.Mock).mockResolvedValue('SOFTWARE');

    await expect(AuthService.signIn()).rejects.toThrow('device integrity');

    expect(authorize).not.toHaveBeenCalled();
    expect(Keychain.resetGenericPassword).toHaveBeenCalledWith({ service: KEYCHAIN_SERVICE });
    expect(mockReportDeviceTamper).toHaveBeenCalledWith(
      expect.objectContaining({ signals: expect.arrayContaining(['enclave_unavailable']) }),
    );
    // No session is retrievable after the wipe.
    expect(await AuthService.restoreSession()).toBeNull();
  });

  it('foreground re-check wipes an existing session on a critical verdict', async () => {
    (Keychain.getSecurityLevel as jest.Mock).mockResolvedValue('SECURE_ENCLAVE');
    authorize.mockResolvedValue(oidcResult());
    await AuthService.signIn();
    expect(await AuthService.restoreSession()).not.toBeNull();

    // Device becomes compromised while the app is backgrounded.
    (Keychain.getSecurityLevel as jest.Mock).mockResolvedValue('SOFTWARE');
    const trusted = await AuthService.verifyDeviceIntegrity('foreground');

    expect(trusted).toBe(false);
    expect(Keychain.resetGenericPassword).toHaveBeenCalledWith({ service: KEYCHAIN_SERVICE });
    expect(await AuthService.restoreSession()).toBeNull();
  });

  it('foreground re-check on a trusted device keeps the session', async () => {
    (Keychain.getSecurityLevel as jest.Mock).mockResolvedValue('SECURE_ENCLAVE');
    authorize.mockResolvedValue(oidcResult());
    await AuthService.signIn();

    expect(await AuthService.verifyDeviceIntegrity('foreground')).toBe(true);
    expect(await AuthService.restoreSession()).not.toBeNull();
  });

  it("warn enforcement reports the verdict but does not block sign-in", async () => {
    (globalThis as { __TAMPER_ENFORCEMENT__?: string }).__TAMPER_ENFORCEMENT__ = 'warn';
    (Keychain.getSecurityLevel as jest.Mock).mockResolvedValue('SOFTWARE');
    authorize.mockResolvedValue(oidcResult());

    const session = await AuthService.signIn();

    expect(session.user.id).toBe('user-1');
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(mockReportDeviceTamper).toHaveBeenCalled();
  });
});
