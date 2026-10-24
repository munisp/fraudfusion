/**
 * @fraudfusion/capture-web — browser widget (thin DOM shell over
 * capture-core.js). All quality logic lives in the pure core; this file only
 * wires camera/canvas/upload. It is intentionally NOT unit-tested in node —
 * browser-verified only (see README "Verification" section); every branch
 * that makes a decision delegates to the tested core.
 *
 * Usage (see README for full quickstart):
 *   const cap = FraudFusionCapture.mountDocumentCapture(el, {
 *     onCapture: (blob) => sdk.documentVerify(blob, "nin_slip"),
 *   });
 *   const liv = FraudFusionCapture.mountLivenessCapture(el, {
 *     apiBase, apiKey, onResult: (verdict) => {...},
 *   });
 */

"use strict";

(function (global) {
  const core = global.FraudFusionCaptureCore
    || (typeof require === "function" ? require("./capture-core.js") : null);
  if (!core) throw new Error("capture-core.js must be loaded first");

  const FRAME_W = 320;
  const FRAME_H = 240;

  async function startCamera(video) {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { width: { ideal: 1280 }, facingMode: "environment" },
      audio: false,
    });
    video.srcObject = stream;
    await video.play();
    return stream;
  }

  function grabGray(video) {
    const canvas = document.createElement("canvas");
    canvas.width = FRAME_W;
    canvas.height = FRAME_H;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(video, 0, 0, FRAME_W, FRAME_H);
    const data = ctx.getImageData(0, 0, FRAME_W, FRAME_H).data;
    return core.rgbaToGray(data, FRAME_W, FRAME_H);
  }

  function captureBlob(video) {
    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext("2d").drawImage(video, 0, 0);
    return new Promise((resolve) =>
      canvas.toBlob(resolve, "image/jpeg", 0.92));
  }

  /**
   * Document capture: live quality meter + auto-capture when quality is
   * "good" for `stableFrames` consecutive frames.
   */
  function mountDocumentCapture(el, opts) {
    const video = document.createElement("video");
    video.muted = true;
    video.playsInline = true;
    const status = document.createElement("div");
    status.className = "ff-capture-status";
    el.appendChild(video);
    el.appendChild(status);

    let stream = null;
    let timer = null;
    let stable = 0;
    let done = false;
    const stableFrames = (opts && opts.stableFrames) || 3;

    async function tick() {
      if (done) return;
      const gray = grabGray(video);
      const scores = {
        blur: core.blurScore(gray, FRAME_W, FRAME_H),
        glare: core.glareScore(gray),
        buckets: core.luminanceBuckets(gray),
      };
      const label = core.qualityLabel(scores);
      status.textContent = `quality: ${label} (blur ${scores.blur.toFixed(0)})`;
      stable = label === "good" ? stable + 1 : 0;
      if (opts && opts.onQuality) opts.onQuality({ label, scores });
      if (stable >= stableFrames) {
        done = true;
        const blob = await captureBlob(video);
        stop();
        if (opts && opts.onCapture) opts.onCapture(blob, { label, scores });
        return;
      }
      timer = setTimeout(tick, 250);
    }

    function stop() {
      if (timer) clearTimeout(timer);
      if (stream) stream.getTracks().forEach((t) => t.stop());
    }

    return startCamera(video).then((s) => {
      stream = s;
      tick();
      return { stop };
    });
  }

  /**
   * Liveness capture: fetches a signed challenge from kyc-api, guides the
   * user through the phases, captures frames, submits to verify-frames.
   */
  function mountLivenessCapture(el, opts) {
    const video = document.createElement("video");
    video.muted = true;
    video.playsInline = true;
    const status = document.createElement("div");
    status.className = "ff-liveness-status";
    el.appendChild(video);
    el.appendChild(status);

    let stream = null;

    async function run() {
      stream = await startCamera(video);
      const chResp = await fetch(
        `${opts.apiBase}/api/v1/biometric/liveness/challenge`,
        { method: "POST", headers: { "X-API-Key": opts.apiKey } });
      if (!chResp.ok) throw new Error(`challenge failed: ${chResp.status}`);
      const challenge = await chResp.json();

      const frames = [];
      const grays = [];
      const FRAMES_PER_PHASE = 4;
      for (const phase of challenge.phases) {
        status.textContent = phase === "still"
          ? "Hold still…" : "Move your head slowly…";
        for (let i = 0; i < FRAMES_PER_PHASE; i++) {
          await new Promise((r) => setTimeout(r, 350));
          grays.push(grabGray(video));
          frames.push(await captureBlob(video));
        }
      }
      // client-side pre-check (advisory; server verdict is authoritative)
      const motions = [];
      for (let i = 1; i < grays.length; i++) {
        const a = core.downscale(grays[i - 1], FRAME_W, FRAME_H);
        const b = core.downscale(grays[i], FRAME_W, FRAME_H);
        motions.push(core.frameMotion(a.gray, b.gray));
      }
      const precheck = core.evaluateChallenge(motions, challenge.phases);
      if (opts.onPrecheck) opts.onPrecheck(precheck);

      const form = new FormData();
      form.append("challenge_id", challenge.challenge_id);
      form.append("phases", challenge.phases.join(","));
      form.append("expires_at", String(challenge.expires_at));
      form.append("signature", challenge.signature);
      frames.forEach((blob, i) =>
        form.append("frames", blob, `frame${i}.jpg`));
      const vResp = await fetch(
        `${opts.apiBase}/api/v1/biometric/liveness/verify-frames`,
        { method: "POST", headers: { "X-API-Key": opts.apiKey },
          body: form });
      const verdict = await vResp.json();
      if (opts.onResult) opts.onResult(verdict, precheck);
      return verdict;
    }

    function stop() {
      if (stream) stream.getTracks().forEach((t) => t.stop());
    }

    return { run: () => run().finally(stop), stop };
  }

  global.FraudFusionCapture = { mountDocumentCapture, mountLivenessCapture };
})(typeof window !== "undefined" ? window : globalThis);
