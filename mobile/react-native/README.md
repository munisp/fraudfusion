# FraudFusion Mobile (React Native)

## Performance configuration

### Hermes engine

React Native 0.83 enables **Hermes and the New Architecture by default** for new
projects. This repository ships the JS/TS application code only — the native
`android/` and `ios/` projects are generated at build/provisioning time and are
**not committed**, so Hermes enablement cannot be verified from source here.
When the native projects are generated (or restored), verify explicitly:

- `android/gradle.properties`: `hermesEnabled=true` (default in RN 0.83 templates)
- `android/app/build.gradle`: `enableSeparateBuildPerCPUArchitecture=true` and
  `def enableProguardInReleaseBuilds = true`, and ship an **AAB** (`bundletool` /
  `./gradlew bundleRelease`) so Play delivers per-ABI splits.
- iOS: `hermes_enabled => true` in the `Podfile` (RN 0.83 default), release
  scheme builds with `Release` configuration.

Cold-start weight is dominated by bridge-heavy dependencies
(`@react-native-firebase/*`, `@notifee/react-native`, `react-native-keychain`,
`react-native-biometrics`, `react-native-vector-icons`). To keep startup under
the 2s budget:

- Firebase Messaging is **lazy-initialized** (`src/services/NotificationService.ts`
  creates the messaging client on first use, not at module load).
- Non-critical startup work (push registration, biometric capability probe) is
  deferred via `InteractionManager.runAfterInteractions` in `src/App.tsx` —
  the splash screen gates only on real initialization and session restore,
  with **no artificial delay**.
- `react-native-vector-icons`: strip unused icon fonts from the native build
  (only `MaterialCommunityIcons` is used). On Android keep only that font in
  `android/app/src/main/assets/fonts`; on iOS remove unused fonts from the
  Xcode target / `UIAppFonts`.

### Remote debugging / dev tooling in production

Remote JS debugging is only available in `__DEV__` builds; release builds never
expose the Chrome debugger, and Hermes bytecode ships without source. Do not
ship `react-native` dev settings or `__DEV__` overrides in release configs.
Release builds should also keep `android:usesCleartextTraffic="false"` and must
not enable `networkSecurityConfig` debug overrides. Flipper/perf tooling is
debug-only by default in the RN 0.83 template — do not add it to release
build variants.

### Runtime configuration

The app requires runtime config globals before startup (validated in
`initializeApp`):

- `__FRAUDFUSION_AUTH_CONFIG__` — OIDC issuer/clientId/redirectUrl
- `__FRAUDFUSION_API_CONFIG__` — `{ baseUrl }`

### Client-side performance measures (see perf/client/PERFORMANCE_BUDGETS.md)

- Session tokens are cached in memory after the first Keychain read
  (`AuthService.getValidSession`), with single-flight proactive refresh 60s
  before expiry — no native bridge call per API request.
- `MobileApi` GETs: 10s timeout, bounded retry (3 attempts, 250/500ms backoff,
  network/5xx only) and in-flight request dedup; mutations are never retried
  (not idempotent) and time out at 15s; upload-adjacent calls at 60s.
- List screens (`FraudAlertsScreen`, `NotificationsScreen`,
  `DocumentListScreen`) render through a virtualized `FlatList`
  (`initialNumToRender=12`, `windowSize=7`, `removeClippedSubviews`) with
  `React.memo` row components instead of stringified JSON blobs.

### Tests

```
npm install
npm test          # jest, 100% coverage threshold on src/screens/**
npm run typecheck
```
