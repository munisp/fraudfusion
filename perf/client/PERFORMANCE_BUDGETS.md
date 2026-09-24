# Client Performance Budgets — Web Frontends & Mobile

Scope: `frontend/`, `frontend/kyc-frontend/`, `implementations/backoffice-ui/`,
`ml-onboarding-portal/` (Vite/React SPAs) and `mobile/react-native/`
(React Native 0.83). Budgets are enforced in CI; a regression >20% vs `main`
fails the PR (see audit `lane-B2-performance.md` §9-10).

## 1. Web bundle budgets

| Budget | Limit | Rationale |
|---|---|---|
| Initial JS (gzip) per app | **< 250 KB** | TTI < 2s on 4G cold (audit §9) |
| Initial JS (gzip), target | < 150 KB | react-vendor (~43-46 KB gz) + app entry |
| Per-route / per-section chunk (gzip) | **< 100 KB** | route-level code splitting keeps navigation instant |
| CSS (gzip) per app | < 30 KB | `cssCodeSplit: true`, per-route CSS |
| Sourcemaps | `hidden` only | never serve `.map` to users; upload to error tracker |

Current post-fix measurements (see `output/fixes2/P4-frontend-mobile-perf.md`
for full chunk tables):

| App | Initial JS gzip (before → after) |
|---|---|
| frontend | 49.9 KB single bundle → ~44.9 KB entry+vendor, dashboard lazy (3.4 KB) |
| kyc-frontend | 77.8 KB single bundle → ~55.6 KB entry+vendor+router, 5 route chunks lazy |
| backoffice-ui | 87.2 KB single bundle → ~60.9 KB entry+vendor+query, 3 section chunks lazy |
| ml-onboarding-portal | 48.6 KB single bundle → ~47.5 KB entry+vendor, 4 section chunks lazy |

### Measuring bundles

```bash
# Per app
npm ci && npm run build          # vite prints the gzip chunk table (CI gate input)
npx source-map-explorer 'dist/assets/*.js'   # treemap of what ships (hidden maps are still emitted)
# or: npx vite-bundle-visualizer
```

CI gate sketch: parse `vite build` output (or `dist/assets` sizes via
`gzip -c`), fail if entry chunk + eager vendor > 250 KB gzip or any lazy route
chunk > 100 KB gzip. Lighthouse CI (`@lhci/cli`) enforces TTI on 4G throttling.

## 2. Web runtime budgets

| Metric | Budget |
|---|---|
| TTI cold (4G, mid-tier) | < 2s p50 / < 3s p95 |
| API fetch timeout | 10s client-side (`AbortSignal.timeout`), abort on unmount |
| Route-to-route navigation | < 200ms (chunk prefetched or < 100 KB gz) |

Static serving: use the nginx snippet in `perf/client/nginx-static.conf`
(gzip/brotli, immutable caching for hashed assets, `no-cache` for index.html).

## 3. Mobile budgets

| Metric | Budget | Mechanism |
|---|---|---|
| Cold start → interactive | **< 2s** (low-end Android, API 29) | no artificial splash delay; splash gates on `initializeApp` + session restore only; push/biometric init deferred via `InteractionManager` |
| List scrolling | **60fps** (≤ 1 dropped frame/sustained scroll) | FlatList windowing (`windowSize=7`, `initialNumToRender=12`, `removeClippedSubviews`), memoized rows |
| API call (client-observed) | < 300ms p50 / < 800ms p95 / < 2s p99 | in-memory session cache (no Keychain bridge per request), proactive token refresh 60s pre-expiry, GET in-flight dedup, 10s GET timeout, 3-attempt backoff (250/500ms) on network/5xx |
| Hermes | enabled in release | see `mobile/react-native/README.md` (native dirs not committed — verify at build time) |

### Measuring mobile

- **Startup**: [Flashlight](https://docs.flashlight.dev/) or Detox +
  `react-native-performance` (`mark`/`measure` from app start to first
  interactive frame; gate: `TimeToInteractive < 2000ms` on a low-end device).
- **JS/frame perf**: Flipper (debug builds) or `react-native-performance`
  + `PerformanceObserver` for render marks; FlatList scroll fps via
  Flashlight's `@perf` profiler on a 500-row alerts list.
- **Network**: axios timing interceptor or Charles/Flipper network plugin;
  assert dashboard/alerts GET p95 < 800ms on staging.

## 4. API p95 targets referenced by clients

From the platform latency budget (audit §9): mobile-observed GETs
(dashboard/alerts/documents) p95 < 800ms incl. network; fraud scoring
p95 < 50ms server-side; ledger reads p95 < 30ms. Client retry/dedup config in
`mobile/react-native/src/services/MobileApi.ts` is sized to these targets.

## 5. Regression gates (CI)

1. `vite build` chunk-size gate per §1 for all 4 web apps.
2. Lighthouse CI: TTI/LCP on `/` of each app, 4G throttle, budgets above.
3. Mobile: `npm test` (jest, 100% coverage on `src/screens/**`), plus a
   Flashlight cold-start measurement on release APK in nightly CI.
4. Fail the pipeline if any budget regresses >20% vs the `main` baseline.
