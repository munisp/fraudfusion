import { describe, expect, it } from 'vitest';
import { resolveDataMode } from './dataMode';
import { API_BASE_URL } from './api';

/**
 * Regression tests for the mock-substitution audit finding: the console must
 * never silently render fabricated rows when the API is down. Mock data is
 * reachable only via an explicit dev-mode `?mock=1` opt-in.
 */
describe('resolveDataMode', () => {
  it('returns live by default in dev (no query param)', () => {
    expect(resolveDataMode('', true)).toBe('live');
    expect(resolveDataMode('?page=2', true)).toBe('live');
  });

  it('returns mock only for the explicit ?mock=1 opt-in on a dev build', () => {
    expect(resolveDataMode('?mock=1', true)).toBe('mock');
    expect(resolveDataMode('?foo=bar&mock=1', true)).toBe('mock');
  });

  it('ignores mock=1 on production builds', () => {
    expect(resolveDataMode('?mock=1', false)).toBe('live');
  });

  it('does not treat other mock values as opt-in', () => {
    expect(resolveDataMode('?mock=true', true)).toBe('live');
    expect(resolveDataMode('?mock=0', true)).toBe('live');
    expect(resolveDataMode('?mock=', true)).toBe('live');
  });
});

describe('API_BASE_URL', () => {
  it('defaults to the in-cluster backoffice-api Service when env is unset', () => {
    // VITE_BACKOFFICE_API_URL / VITE_API_BASE_URL are not set under test.
    expect(API_BASE_URL).toBe('http://backoffice-api:8087');
  });
});
