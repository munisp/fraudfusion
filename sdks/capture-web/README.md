# @fraudfusion/capture-web

Zero-dependency browser capture widget for FraudFusion KYC — the web half of
the "mobile capture SDK" gap. Two mounts:

- **Document capture** — camera preview with real-time quality feedback
  (blur / glare / texture, computed client-side with the same thresholds as
  the server-side cv2 engine) and auto-capture once quality is stable.
- **Liveness capture** — fetches a signed challenge from kyc-api
  (`/api/v1/biometric/liveness/challenge`), guides the user through the
  still/move phases, captures the frame sequence, and submits it to
  `/api/v1/biometric/liveness/verify-frames`. The server verdict is
  authoritative; the client shows an advisory pre-check.

## Quickstart

```html
<script src="capture-core.js"></script>
<script src="capture-widget.js"></script>
<div id="doc"></div>
<script>
  FraudFusionCapture.mountDocumentCapture(document.getElementById("doc"), {
    onCapture: async (blob) => {
      const form = new FormData();
      form.append("document", blob, "id.jpg");
      form.append("document_type", "nin_slip");
      await fetch("https://api.example.com/api/v1/document/verify", {
        method: "POST",
        headers: { "X-API-Key": "ffk_live_…" },
        body: form,
      });
    },
  });
</script>
```

Liveness:

```js
const liv = FraudFusionCapture.mountLivenessCapture(el, {
  apiBase: "https://api.example.com",
  apiKey: "ffk_live_…",
  onResult: (verdict) => console.log(verdict.verdict), // live|spoof|inconclusive
});
await liv.run();
```

Against the developer sandbox, use `apiBase: "http://localhost:8091"` and any
`ffk_test_…` key.

## Architecture & verification

- `capture-core.js` — **pure logic, DOM-free**: luma conversion, Laplacian
  blur, glare (with whiteout guard), luminance-bucket texture, inter-frame
  motion, challenge-phase evaluation. Fully covered by `npm test`
  (`node --test`, 11 tests, no dependencies, no network).
- `capture-widget.js` — **thin DOM shell**: getUserMedia, canvas, FormData
  upload. Not unit-testable in node; every decision branch delegates to the
  tested core. Browser-verified only — that limitation is stated honestly
  here rather than papered over with mocks.

## Honest limitations

- **Native SDKs (React Native / Flutter / iOS / Android) are roadmap**, not
  built. The widget works in mobile browsers, which covers many Nigerian
  fintech PWAs, but Smile-ID-style native capture UX is future work.
- Client-side quality checks are advisory UX; the server-side cv2 engine
  re-analyzes every upload and is authoritative.
- Requires a secure context (https or localhost) for getUserMedia.
