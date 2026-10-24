/** Pure capture-quality core (DOM-free). */
export function rgbaToGray(
  rgba: Uint8ClampedArray, width: number, height: number): Float64Array;
export function blurScore(
  gray: ArrayLike<number>, width: number, height: number): number;
/** Returns glare fraction, or -1 when whiteout makes it unmeasurable. */
export function glareScore(
  gray: ArrayLike<number>, saturatedThreshold?: number,
  whiteoutFraction?: number): number;
export function luminanceBuckets(
  gray: ArrayLike<number>, bucketWidth?: number): number;
export interface QualityScores { blur: number; glare: number; buckets: number }
export function qualityLabel(s: QualityScores): "poor" | "acceptable" | "good";
export function frameMotion(
  a: ArrayLike<number>, b: ArrayLike<number>): number;
export interface ChallengeMismatch { phase: number; expected: string; mean: number }
export interface ChallengeResult {
  checked: boolean;
  passed: boolean | null;
  reason?: string;
  mismatches?: ChallengeMismatch[];
  segmentMeans?: number[];
}
export function evaluateChallenge(
  motions: number[], phases: string[]): ChallengeResult;
export function downscale(
  gray: ArrayLike<number>, width: number, height: number,
  maxDim?: number): { gray: Float64Array; width: number; height: number };
export const MOTION_STILL_MAX: number;
export const MOTION_MOVE_MIN: number;
