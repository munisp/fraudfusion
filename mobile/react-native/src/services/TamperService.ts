/**
 * TamperService — device integrity + offline-queue integrity (lane B3 / P2-2, P2-3)
 *
 * ADDITIVE module: intentionally not wired into any existing file. Integration
 * points (for the mobile lane to wire):
 *   - call `TamperService.enforceDeviceIntegrity()` before login in
 *     AuthService; on failure it wipes the Keychain session via
 *     `Keychain.resetGenericPassword({ service })` and reports a
 *     SECURITY_EVENT to the server.
 *   - use `TamperService.sealQueueEntry` / `verifyQueueEntry` around the
 *     OFFLINE_QUEUE entries in src/store/state-management-fixes.ts.
 *
 * REQUIRED NATIVE DEPENDENCIES (documented, NOT added to package.json here —
 * the mobile lane owns dependency changes):
 *   - `jail-monkey` (>= 2.8.0): jailbreak/root detection, hook detection,
 *     debug detection, mock-location. Android equivalent coverage of
 *     rootbeer-style checks.
 *   - `react-native-keychain` (>= 8.2.0, ALREADY PRESENT): secure enclave /
 *     Android Keystore backed storage; used for the offline-queue HMAC key.
 *   - `react-native-device-info` (>= 10.0.0, ALREADY common): emulator checks.
 *
 * Server-side contract: a device flagged by `reportTamper()` is treated as
 * read-only by the backend, and no mobile client scope may ever hold the
 * `storage_deleter` / `storage_admin` role (enforced in Keycloak client
 * scopes — see deploy/kubernetes/keycloak.yaml owned by the platform lane).
 */

import { Platform } from 'react-native';
import * as Keychain from 'react-native-keychain';

// ---------------------------------------------------------------------------
// Native module interfaces (structural typing so this file compiles standalone
// before the dependencies are added to package.json)
// ---------------------------------------------------------------------------

interface JailMonkeyLike {
  isJailBroken(): boolean;
  hookDetected(): boolean;
  canMockLocation(): boolean;
  isOnExternalStorage?(): boolean;
  isDebuggedMode?(): Promise<boolean> | boolean;
  isDevSettings?(): Promise<boolean> | boolean;
}

interface DeviceInfoLike {
  isEmulator(): Promise<boolean>;
}

/** Injected by the wiring layer once `jail-monkey` is a real dependency. */
let jailMonkey: JailMonkeyLike | null = null;
let deviceInfo: DeviceInfoLike | null = null;

export function __bindNativeModules(opts: {
  jailMonkey?: JailMonkeyLike;
  deviceInfo?: DeviceInfoLike;
}): void {
  jailMonkey = opts.jailMonkey ?? null;
  deviceInfo = opts.deviceInfo ?? null;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TamperSignal =
  | 'jailbreak_or_root'
  | 'hook_framework'
  | 'debugger_attached'
  | 'dev_settings'
  | 'emulator'
  | 'enclave_unavailable'
  | 'queue_integrity_failure';

export interface TamperReport {
  deviceId: string;
  signals: TamperSignal[];
  platform: string;
  detectedAt: string;
}

export interface TamperVerdict {
  trusted: boolean;
  signals: TamperSignal[];
}

export interface QueueEntrySeal {
  /** HMAC-SHA256 hex over canonical(entry payload + seq + enqueuedAt) */
  hmac: string;
  seq: number;
  enqueuedAt: string;
}

export type TamperEventReporter = (report: TamperReport) => Promise<void>;
export type SessionWiper = () => Promise<void>;

const QUEUE_KEY_KEYCHAIN_SERVICE = 'com.fraudfusion.mobile.offlineQueueKey';
const DEFAULT_SESSION_SERVICE = 'com.fraudfusion.mobile.session';

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class TamperService {
  constructor(
    private readonly reporter?: TamperEventReporter,
    private readonly sessionWiper?: SessionWiper,
    private readonly enforcement: 'block' | 'warn' =
      (globalThis as { __TAMPER_ENFORCEMENT__?: 'block' | 'warn' }).__TAMPER_ENFORCEMENT__ ?? 'block',
  ) {}

  // -- Jailbreak / root / debugger / emulator detection ---------------------

  async detectTampering(): Promise<TamperVerdict> {
    const signals: TamperSignal[] = [];

    if (jailMonkey) {
      try {
        if (jailMonkey.isJailBroken()) signals.push('jailbreak_or_root');
      } catch { /* fail open on individual probe, verdict below */ }
      try {
        if (jailMonkey.hookDetected()) signals.push('hook_framework');
      } catch { /* ignore */ }
      try {
        const debugged = await jailMonkey.isDebuggedMode?.();
        if (debugged) signals.push('debugger_attached');
      } catch { /* ignore */ }
      try {
        const dev = await jailMonkey.isDevSettings?.();
        if (dev) signals.push('dev_settings');
      } catch { /* ignore */ }
    }

    if (deviceInfo) {
      try {
        if (await deviceInfo.isEmulator()) signals.push('emulator');
      } catch { /* ignore */ }
    }

    if (!(await this.hasSecureEnclave())) signals.push('enclave_unavailable');

    return { trusted: signals.length === 0, signals };
  }

  /** Debugger detection fallback when jail-monkey is absent: the synchronous
   *  `debugger` statement timing side-channel. Cheap heuristic, iOS/Android. */
  debuggerTimingAnomaly(budgetMs = 50): boolean {
    const start = Date.now();
    // eslint-disable-next-line no-debugger
    debugger;
    return Date.now() - start > budgetMs;
  }

  /** Verify the platform secure enclave / Keystore actually protects keys. */
  async hasSecureEnclave(): Promise<boolean> {
    try {
      const level = await Keychain.getSecurityLevel();
      if (!level) return false;
      // STRONGBOX/SECURE_ENCLAVE/SECURE_HARDWARE acceptable; SOFTWARE is not
      // for the offline-queue key on regulated devices.
      return String(level) !== 'SOFTWARE';
    } catch {
      return false;
    }
  }

  /**
   * Enforce device integrity at login/launch. On detection (and
   * enforcement='block'): wipe the Keychain session and report a
   * SECURITY_EVENT to the server. Returns the verdict; callers must refuse
   * login when `trusted === false` and enforcement is 'block'.
   */
  async enforceDeviceIntegrity(deviceId: string): Promise<TamperVerdict> {
    const verdict = await this.detectTampering();
    if (!verdict.trusted) {
      await this.reportTamper(deviceId, verdict.signals);
      if (this.enforcement === 'block') {
        await this.wipeLocalSession();
      }
    }
    return verdict;
  }

  async wipeLocalSession(): Promise<void> {
    if (this.sessionWiper) {
      await this.sessionWiper();
      return;
    }
    // Default: wipe the AuthService session entry (device-resident user data
    // ONLY — server-side fraud/KYC/AML evidence is never erasable by any
    // mobile API).
    await Keychain.resetGenericPassword({ service: DEFAULT_SESSION_SERVICE });
  }

  async reportTamper(deviceId: string, signals: TamperSignal[]): Promise<void> {
    const report: TamperReport = {
      deviceId,
      signals,
      platform: Platform.OS,
      detectedAt: new Date().toISOString(),
    };
    if (this.reporter) {
      await this.reporter(report); // POST /api/v1/security/device-tamper
    }
  }

  // -- Offline-queue integrity (HMAC) ----------------------------------------

  /**
   * Queue entries are HMAC-SHA256 tagged so an attacker editing the plaintext
   * AsyncStorage queue (or a tamper-wipe replaying stale entries) is detected
   * on dequeue. The HMAC key lives in the Keychain/Keystore, never in
   * AsyncStorage.
   *
   * NOTE: pure-TS HMAC-SHA256 below exists so integrity works before a native
   * crypto module is wired; the wiring layer SHOULD replace `_hmacSha256Hex`
   * with react-native-quick-crypto / expo-crypto for production throughput.
   */
  async getOrCreateQueueKey(): Promise<string> {
    const existing = await Keychain.getGenericPassword({ service: QUEUE_KEY_KEYCHAIN_SERVICE });
    if (existing && existing.password) return existing.password;
    const key = generateRandomHex(32);
    await Keychain.setGenericPassword('offline-queue-hmac', key, {
      service: QUEUE_KEY_KEYCHAIN_SERVICE,
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      accessControl:
        Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE,
      securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
    });
    return key;
  }

  async sealQueueEntry(
    payload: unknown,
    seq: number,
    enqueuedAt: string,
  ): Promise<QueueEntrySeal> {
    const key = await this.getOrCreateQueueKey();
    const canonical = canonicalize({ payload, seq, enqueuedAt });
    return { hmac: hmacSha256Hex(key, canonical), seq, enqueuedAt };
  }

  async verifyQueueEntry(
    payload: unknown,
    seal: QueueEntrySeal,
  ): Promise<boolean> {
    const key = await this.getOrCreateQueueKey();
    const canonical = canonicalize({ payload, seq: seal.seq, enqueuedAt: seal.enqueuedAt });
    const expected = hmacSha256Hex(key, canonical);
    return constantTimeEqual(expected, seal.hmac);
  }
}

// ---------------------------------------------------------------------------
// Pure-TS helpers (no native deps)
// ---------------------------------------------------------------------------

function generateRandomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  const cryptoApi = (globalThis as { crypto?: { getRandomValues(a: Uint8Array): void } }).crypto;
  if (cryptoApi?.getRandomValues) {
    cryptoApi.getRandomValues(arr);
  } else {
    // Last-resort fallback (Hermes without crypto polyfill): not ideal, logged
    // by callers via enclave_unavailable signal.
    for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// --- minimal HMAC-SHA256 (FIPS 180-4 + RFC 2104), pure TS -------------------

const K: number[] = (() => {
  // round constants generated from cube roots of the first 64 primes
  const primes: number[] = [];
  let candidate = 2;
  while (primes.length < 64) {
    if (isPrime(candidate)) primes.push(candidate);
    candidate++;
  }
  return primes.map((p) => Math.floor(frac(Math.cbrt(p)) * 2 ** 32) >>> 0);
  function isPrime(n: number): boolean {
    for (let i = 2; i * i <= n; i++) if (n % i === 0) return false;
    return n > 1;
  }
  function frac(x: number): number {
    return x - Math.floor(x);
  }
})();

const H0: number[] = [2, 3, 5, 7, 11, 13, 17, 19].map(
  (p) => Math.floor((Math.sqrt(p) - Math.floor(Math.sqrt(p))) * 2 ** 32) >>> 0,
);

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha256Hex(message: Uint8Array): string {
  const bitLen = message.length * 8;
  const paddedLen = (((message.length + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(paddedLen);
  buf.set(message);
  buf[message.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(paddedLen - 4, bitLen >>> 0);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 2 ** 32));

  const h = H0.slice();
  const w = new Array<number>(64);
  for (let block = 0; block < paddedLen; block += 64) {
    for (let t = 0; t < 16; t++) w[t] = view.getUint32(block + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0; h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return h.map((x) => x.toString(16).padStart(8, '0')).join('');
}

function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function hmacSha256Hex(keyHex: string, message: string): string {
  const keyBytes = new Uint8Array(keyHex.match(/../g)!.map((b) => parseInt(b, 16)));
  const blockSize = 64;
  const key = keyBytes.length > blockSize
    ? new Uint8Array(sha256Hex(keyBytes).match(/../g)!.map((b) => parseInt(b, 16)))
    : keyBytes;
  const ipad = new Uint8Array(blockSize).fill(0x36);
  const opad = new Uint8Array(blockSize).fill(0x5c);
  for (let i = 0; i < key.length; i++) {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }
  const inner = sha256Hex(concat(ipad, utf8Bytes(message)));
  const innerBytes = new Uint8Array(inner.match(/../g)!.map((b) => parseInt(b, 16)));
  return sha256Hex(concat(opad, innerBytes));
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

export const __testing = { hmacSha256Hex, sha256Hex, canonicalize, constantTimeEqual };

export default TamperService;
