// k6: cached auth-check latency against any authenticated endpoint.
// Budget: p50 < 2ms server-side middleware overhead; client-observed p95 < 50ms.
// Usage: k6 run -e BASE_URL=http://crypto-fraud-detector:8082 -e TOKEN=$TOKEN perf/k6/auth-check.js
import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

const latency = new Trend('auth_check_latency', true);

export const options = {
  scenarios: {
    warmup: { executor: 'constant-vus', vus: 5, duration: '60s', tags: { phase: 'warmup' } },
    baseline: { executor: 'constant-vus', vus: 20, duration: '5m', startTime: '60s' },
  },
  thresholds: {
    'http_req_duration{phase:!warmup}': ['p(95)<50', 'p(99)<100'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const res = http.get(`${__ENV.BASE_URL}/api/v1/crypto-fraud/reports/daily`, {
    headers: { Authorization: `Bearer ${__ENV.TOKEN}` },
    tags: { phase: 'baseline' },
  });
  latency.add(res.timings.duration);
  check(res, { 'not 401/403': (r) => r.status !== 401 && r.status !== 403 });
}
