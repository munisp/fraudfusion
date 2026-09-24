// k6: fraud-score latency (rules-based detector + ONNX ML service).
// Budgets: detector p95 < 50ms; ML p95 < 50ms; batch(100) p95 < 2s.
// Usage:
//   k6 run -e BASE_URL=http://crypto-fraud-detector:8082 -e TOKEN=$TOKEN perf/k6/fraud-score.js
//   k6 run -e BASE_URL=http://aml-service:8100 -e ML=1 perf/k6/fraud-score.js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    warmup: { executor: 'constant-vus', vus: 10, duration: '60s', tags: { phase: 'warmup' } },
    target: { executor: 'constant-vus', vus: 50, duration: '10m', startTime: '60s' },
  },
  thresholds: {
    'http_req_duration{endpoint:single}': ['p(95)<50', 'p(99)<100'],
    'http_req_duration{endpoint:batch}': ['p(95)<2000'],
    http_req_failed: ['rate<0.01'],
  },
};

const txn = (i) => JSON.stringify({
  id: `k6-${__VU}-${__ITER}-${i}`,
  user_id: `user-${__VU}`,
  wallet_address: `0x${(__VU * 1000 + i).toString(16).padStart(40, '0')}`,
  cryptocurrency: 'BTC',
  amount: 500 + (i % 50) * 100,
  transaction_type: 'send',
  counterparty: 'counterparty-x',
  platform: 'binance',
  timestamp: new Date().toISOString(),
});

export default function () {
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${__ENV.TOKEN || ''}` };
  const res = http.post(`${__ENV.BASE_URL}/api/v1/crypto-fraud/transactions/analyze`, txn(0), {
    headers, tags: { endpoint: 'single' },
  });
  check(res, { 'scored': (r) => r.status === 200 });

  if (__ITER % 20 === 0) {
    const batch = JSON.stringify({ transactions: Array.from({ length: 100 }, (_, i) => JSON.parse(txn(i))) });
    const bres = http.post(`${__ENV.BASE_URL}/api/v1/crypto-fraud/transactions/batch-analyze`, batch, {
      headers, tags: { endpoint: 'batch' },
    });
    check(bres, { 'batch ok': (r) => r.status === 200 });
  }
}
