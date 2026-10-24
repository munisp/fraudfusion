/** Browser capture widget (DOM shell; browser-verified, not unit-tested). */
export interface DocumentCaptureOptions {
  stableFrames?: number;
  onQuality?: (q: { label: string; scores: unknown }) => void;
  onCapture?: (blob: Blob, quality: { label: string; scores: unknown }) => void;
}
export interface LivenessCaptureOptions {
  apiBase: string;
  apiKey: string;
  onPrecheck?: (result: unknown) => void;
  onResult?: (verdict: unknown, precheck: unknown) => void;
}
export function mountDocumentCapture(
  el: HTMLElement, opts: DocumentCaptureOptions): Promise<{ stop(): void }>;
export function mountLivenessCapture(
  el: HTMLElement,
  opts: LivenessCaptureOptions): { run(): Promise<unknown>; stop(): void };
