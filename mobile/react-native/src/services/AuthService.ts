import * as Keychain from 'react-native-keychain';
import { authorize, refresh, revoke, AuthorizeResult, AuthConfiguration, RefreshResult } from 'react-native-app-auth';
import { logger } from './logger';

export interface AuthenticatedUser {
  id: string;
  email?: string;
  name?: string;
  roles: string[];
}

export interface Session {
  accessToken: string;
  refreshToken?: string;
  accessTokenExpirationDate?: string;
  user: AuthenticatedUser;
}

type IdentityConfig = AuthConfiguration & { issuer: string; clientId: string; redirectUrl: string };

const keychainService = 'com.fraudfusion.mobile.session';

// In-memory session cache: avoids a native Keychain bridge round-trip on every
// API call. `undefined` means "not yet read from secure storage this launch".
let cachedSession: Session | null | undefined;
// Single-flight refresh so concurrent requests share one token refresh.
let refreshInFlight: Promise<Session> | null = null;

// Refresh access tokens this far ahead of expiry instead of failing at 401.
const REFRESH_MARGIN_MS = 60_000;

function isExpiringSoon(session: Session): boolean {
  if (!session.accessTokenExpirationDate) return false;
  const expiresAt = Date.parse(session.accessTokenExpirationDate);
  return Number.isFinite(expiresAt) && expiresAt - Date.now() <= REFRESH_MARGIN_MS;
}

function requiredConfig(): IdentityConfig {
  const runtime = globalThis as typeof globalThis & { __FRAUDFUSION_AUTH_CONFIG__?: IdentityConfig };
  const config = runtime.__FRAUDFUSION_AUTH_CONFIG__;
  if (!config?.issuer || !config.clientId || !config.redirectUrl) {
    throw new Error('Mobile OIDC configuration is required before authentication can start');
  }
  return {
    ...config,
    scopes: config.scopes ?? ['openid', 'profile', 'email', 'offline_access'],
    usePKCE: true,
  };
}

function decodePayload(token: string): Record<string, unknown> {
  const [, payload] = token.split('.');
  if (!payload) {
    throw new Error('Identity provider returned a malformed access token');
  }
  const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
  const decoder = (globalThis as typeof globalThis & { atob?: (encoded: string) => string }).atob;
  if (!decoder) {
    throw new Error('The native runtime does not provide base64 token decoding');
  }
  const json = decoder(normalized);
  return JSON.parse(json) as Record<string, unknown>;
}

function userFromToken(accessToken: string): AuthenticatedUser {
  const claims = decodePayload(accessToken);
  const subject = claims.sub;
  if (typeof subject !== 'string' || subject.length === 0) {
    throw new Error('Identity provider token contains no subject');
  }
  const realmRoles = (claims.realm_access as { roles?: unknown } | undefined)?.roles;
  return {
    id: subject,
    email: typeof claims.email === 'string' ? claims.email : undefined,
    name: typeof claims.name === 'string' ? claims.name : undefined,
    roles: Array.isArray(realmRoles) ? realmRoles.filter((role): role is string => typeof role === 'string') : [],
  };
}

async function persistSession(result: AuthorizeResult | RefreshResult): Promise<Session> {
  const session: Session = {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken ?? undefined,
    accessTokenExpirationDate: result.accessTokenExpirationDate,
    user: userFromToken(result.accessToken),
  };
  await Keychain.setGenericPassword('session', JSON.stringify(session), {
    service: keychainService,
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  cachedSession = session;
  return session;
}

export const AuthService = {
  async signIn(): Promise<Session> {
    const result = await authorize(requiredConfig());
    const session = await persistSession(result);
    logger.info('auth.oidc_sign_in_succeeded', { userId: session.user.id });
    return session;
  },

  async restoreSession(): Promise<Session | null> {
    // Serve from memory after the first restore; Keychain is only touched once
    // per launch (and again after sign-in/sign-out/refresh mutates the cache).
    if (cachedSession !== undefined) return cachedSession;
    const stored = await Keychain.getGenericPassword({ service: keychainService });
    if (!stored) {
      cachedSession = null;
      return null;
    }
    try {
      cachedSession = JSON.parse(stored.password) as Session;
      return cachedSession;
    } catch {
      await Keychain.resetGenericPassword({ service: keychainService });
      cachedSession = null;
      logger.warn('auth.invalid_secure_session_removed');
      return null;
    }
  },

  /**
   * Returns the cached session, proactively refreshing the access token when it
   * expires within REFRESH_MARGIN_MS. Concurrent callers share one refresh.
   * Falls back to the stored (stale) session if the refresh fails, letting the
   * server's 401 drive re-authentication.
   */
  async getValidSession(): Promise<Session | null> {
    const session = await this.restoreSession();
    if (!session || !isExpiringSoon(session)) return session;
    if (!session.refreshToken) return session;
    if (!refreshInFlight) {
      refreshInFlight = this.refreshSession(session).finally(() => {
        refreshInFlight = null;
      });
    }
    try {
      return await refreshInFlight;
    } catch (error) {
      logger.warn('auth.proactive_refresh_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
      return session;
    }
  },

  async refreshSession(session: Session): Promise<Session> {
    if (!session.refreshToken) {
      throw new Error('Session cannot be refreshed because no refresh token is available');
    }
    const result = await refresh(requiredConfig(), { refreshToken: session.refreshToken });
    return persistSession({ ...result, refreshToken: result.refreshToken ?? session.refreshToken });
  },

  async signOut(): Promise<void> {
    const session = await this.restoreSession();
    if (session?.accessToken) {
      try {
        await revoke(requiredConfig(), { tokenToRevoke: session.refreshToken ?? session.accessToken, sendClientId: true });
      } catch (error) {
        logger.warn('auth.oidc_revocation_failed', { reason: error instanceof Error ? error.message : 'unknown_error' });
      }
    }
    await Keychain.resetGenericPassword({ service: keychainService });
    cachedSession = null;
    logger.info('auth.sign_out_completed');
  },
};

declare global {
  var __FRAUDFUSION_AUTH_CONFIG__: IdentityConfig | undefined;
}
