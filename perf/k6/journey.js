// k6: journey execute accept latency (202 pattern) + result polling.
// Budget: accept p50 < 50ms, p95 < 150ms, p99 < 400ms; poll p95 < 20ms.
// Usage: k6 run -e BASE_URL=http://orchestrator:8000 -e TOKEN=$TOKEN perf/k6/journey.js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    warmup: { executor: 'constant-vus', vus: 5, duration: '60s', tags: { phase: 'warmup' } },
    target: { executor: 'constant-vus', vus: 20, duration: '10m', startTime: '60s' },
  },
  thresholds: {
    'http_req_duration{endpoint:execute}': ['p(95)<150', 'p(99)<400'],
    'http_req_duration{endpoint:poll}': ['p(95)<20'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${__ENV.TOKEN}` };
  const res = http.post(
    `${__ENV.BASE_URL}/api/v1/journey/execute`,
    JSON.stringify({
      journey_id: 'journey-34',
      tenant_id: __ENV.TENANT || 'tenant-1',
      data: { bvn: '12345678901', amount: 5000 },
    }),
    { headers, tags: { endpoint: 'execute' } },
  );
  check(res, { 'accepted': (r) => r.status === 202 || r.status === 200 });
  if (res.status === 202) {
    const id = res.json('execution_id');
    const poll = http.get(`${__ENV.BASE_URL}/api/v1/journey/executions/${id}`, {
      headers, tags: { endpoint: 'poll' },
    });
    check(poll, { 'poll ok': (r) => r.status === 200 || r.status === 202 });
  }
}
