// k6: ledger journal post latency.
// Budget: p50 < 30ms, p95 < 100ms, p99 < 250ms.
// Usage: k6 run -e BASE_URL=http://ledger-command:8098 -e TOKEN=$TOKEN \
//   -e DEBIT=<uuid> -e CREDIT=<uuid> perf/k6/ledger-post.js
import http from 'k6/http';
import { check } from 'k6';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

export const options = {
  scenarios: {
    warmup: { executor: 'constant-vus', vus: 5, duration: '60s', tags: { phase: 'warmup' } },
    target: { executor: 'constant-vus', vus: 25, duration: '10m', startTime: '60s' },
    // 10% duplicate idempotency keys: exercises the ON CONFLICT fast path.
  },
  thresholds: {
    'http_req_duration{phase:!warmup}': ['p(95)<100', 'p(99)<250'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const idem = __ITER % 10 === 0 ? `k6-dup-${__VU}-${Math.floor(__ITER / 10)}` : uuidv4();
  const res = http.post(
    `${__ENV.BASE_URL}/api/v1/ledger/journals`,
    JSON.stringify({
      idempotency_key: idem,
      journal_type: 'capture',
      debit_account_id: __ENV.DEBIT,
      credit_account_id: __ENV.CREDIT,
      amount: '10.00',
      currency: 'NGN',
    }),
    { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${__ENV.TOKEN}` } },
  );
  check(res, { 'posted': (r) => r.status === 201 || r.status === 200 });
}
