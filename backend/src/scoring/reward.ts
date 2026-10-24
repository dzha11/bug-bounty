/**
 * Severity assessment and reward recommendation.
 *
 *  - Baseline  (comparison condition): tier and amount derived from the CVSS v3.1
 *    base score only — the dominant practice on commercial bug bounty platforms.
 *  - Multi-factor model (proposed): CVSS + operator-confirmed real impact +
 *    exploitability evidence + scale of exposure + asset criticality, with report
 *    quality adjusting the amount inside the published band.
 *
 * Both models are deterministic and bounded by the published reward matrix, so the
 * researcher can see min/max before testing (transparency requirement).
 * Weights are INITIAL expert-set values; calibrating them is part of the study.
 */
import { severityOf } from './cvss31.js';

export type Tier = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'EXCEPTIONAL';
export type RewardMatrix = Record<Tier, { min: number; max: number }>;

export const REAL_IMPACT = { NONE: 0, LIMITED: 0.35, SIGNIFICANT: 0.7, SEVERE: 1 } as const;
export const EXPLOITABILITY = {
  THEORETICAL: 0.2,
  CONDITIONAL_POC: 0.5,
  RELIABLE_POC: 0.8,
  TRIVIAL_AUTOMATABLE: 1,
} as const;
export const SCALE = { SINGLE_USER: 0.2, USER_SUBSET: 0.5, ALL_USERS: 0.8, CROSS_SYSTEM: 1 } as const;
export const ASSET_CRITICALITY = { LOW: 0.25, MEDIUM: 0.5, HIGH: 0.75, CRITICAL: 1 } as const;

export const WEIGHTS = { cvss: 0.4, impact: 0.2, exploitability: 0.15, scale: 0.15, asset: 0.1 };

export interface QualityChecklist {
  reproducible: boolean; // operator reproduced the issue
  clearSteps: boolean;
  workingPoc: boolean;
  impactExplained: boolean;
  remediationAdvice: boolean;
}

export function qualityScore(q: QualityChecklist): number {
  const s =
    0.3 * +q.reproducible +
    0.25 * +q.clearSteps +
    0.2 * +q.workingPoc +
    0.15 * +q.impactExplained +
    0.1 * +q.remediationAdvice;
  return Math.round(s * 1000) / 1000;
}

const BANDS: Record<Tier, [number, number]> = {
  LOW: [0.1, 4],
  MEDIUM: [4, 7],
  HIGH: [7, 9],
  CRITICAL: [9, 9.5],
  EXCEPTIONAL: [9.5, 10],
};

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));
const round1000 = (x: number) => Math.round(x / 1000) * 1000;

function position(score: number, [lo, hi]: [number, number]) {
  return clamp01((score - lo) / (hi - lo));
}

export interface BaselineResult {
  tier: Tier | 'NONE';
  reward: number;
}

/** CVSS-only baseline. */
export function baselineReward(cvssScore: number, matrix: RewardMatrix): BaselineResult {
  const sev = severityOf(cvssScore);
  if (sev === 'NONE') return { tier: 'NONE', reward: 0 };
  const tier = sev as Tier;
  const band: [number, number] = tier === 'CRITICAL' ? [9, 10] : BANDS[tier];
  const { min, max } = matrix[tier];
  return { tier, reward: round1000(min + (max - min) * position(cvssScore, band)) };
}

export interface MultiFactorInput {
  cvssScore: number;
  realImpact: keyof typeof REAL_IMPACT;
  exploitability: keyof typeof EXPLOITABILITY;
  scale: keyof typeof SCALE;
  assetCriticality: keyof typeof ASSET_CRITICALITY;
  quality: number; // 0..1
}

export interface MultiFactorResult {
  score: number;
  tier: Tier | 'NONE';
  reward: number;
  contributions: Record<string, number>;
}

export function multiFactorScore(i: Omit<MultiFactorInput, 'quality'>) {
  const contributions = {
    cvss: 10 * WEIGHTS.cvss * (i.cvssScore / 10),
    impact: 10 * WEIGHTS.impact * REAL_IMPACT[i.realImpact],
    exploitability: 10 * WEIGHTS.exploitability * EXPLOITABILITY[i.exploitability],
    scale: 10 * WEIGHTS.scale * SCALE[i.scale],
    asset: 10 * WEIGHTS.asset * ASSET_CRITICALITY[i.assetCriticality],
  };
  const score = Math.round(Object.values(contributions).reduce((a, b) => a + b, 0) * 100) / 100;
  for (const k of Object.keys(contributions) as (keyof typeof contributions)[]) {
    contributions[k] = Math.round(contributions[k] * 100) / 100;
  }
  return { score, contributions };
}

export function tierOf(score: number): Tier {
  if (score >= 9.5) return 'EXCEPTIONAL';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

export function multiFactorReward(i: MultiFactorInput, matrix: RewardMatrix): MultiFactorResult {
  const { score, contributions } = multiFactorScore(i);
  // A finding with no confirmed real impact and no CVSS impact is not rewardable.
  if (i.cvssScore === 0 || (i.realImpact === 'NONE' && i.cvssScore < 4)) {
    return { score, tier: 'NONE', reward: 0, contributions };
  }
  const tier = tierOf(score);
  const { min, max } = matrix[tier];
  const pos = clamp01(0.7 * position(score, BANDS[tier]) + 0.3 * clamp01(i.quality));
  return { score, tier, reward: round1000(min + (max - min) * pos), contributions };
}

/** Amount for an operator-confirmed (possibly overridden) tier: band midpoint adjusted by quality. */
export function rewardForTier(tier: Tier, quality: number, matrix: RewardMatrix): number {
  const { min, max } = matrix[tier];
  return round1000(min + (max - min) * clamp01(0.5 * 0.7 + 0.3 * quality));
}

export const DEFAULT_MATRIX: RewardMatrix = {
  LOW: { min: 50_000, max: 150_000 },
  MEDIUM: { min: 150_000, max: 500_000 },
  HIGH: { min: 500_000, max: 1_500_000 },
  CRITICAL: { min: 1_500_000, max: 3_000_000 },
  EXCEPTIONAL: { min: 3_000_000, max: 5_000_000 },
};
