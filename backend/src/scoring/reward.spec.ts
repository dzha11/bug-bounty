import {
  baselineReward,
  DEFAULT_MATRIX,
  multiFactorReward,
  multiFactorScore,
  qualityScore,
  tierOf,
  WEIGHTS,
} from './reward.js';

const FULL_Q = { reproducible: true, clearSteps: true, workingPoc: true, impactExplained: true, remediationAdvice: true };
const NO_Q = { reproducible: false, clearSteps: false, workingPoc: false, impactExplained: false, remediationAdvice: false };

describe('reward models', () => {
  it('weights sum to 1', () => {
    expect(Object.values(WEIGHTS).reduce((a, b) => a + b, 0)).toBeCloseTo(1, 10);
  });

  it('quality score is in [0,1]', () => {
    expect(qualityScore(FULL_Q)).toBe(1);
    expect(qualityScore(NO_Q)).toBe(0);
  });

  it('baseline depends on CVSS only and stays inside the published band', () => {
    for (const s of [0.1, 3.9, 4, 6.5, 7, 8.8, 9, 10]) {
      const r = baselineReward(s, DEFAULT_MATRIX);
      const band = DEFAULT_MATRIX[r.tier as keyof typeof DEFAULT_MATRIX];
      expect(r.reward).toBeGreaterThanOrEqual(band.min);
      expect(r.reward).toBeLessThanOrEqual(band.max);
    }
    expect(baselineReward(0, DEFAULT_MATRIX)).toEqual({ tier: 'NONE', reward: 0 });
  });

  it('multi-factor score is bounded in [0,10]', () => {
    const max = multiFactorScore({ cvssScore: 10, realImpact: 'SEVERE', exploitability: 'TRIVIAL_AUTOMATABLE', scale: 'CROSS_SYSTEM', assetCriticality: 'CRITICAL' });
    const min = multiFactorScore({ cvssScore: 0, realImpact: 'NONE', exploitability: 'THEORETICAL', scale: 'SINGLE_USER', assetCriticality: 'LOW' });
    expect(max.score).toBe(10);
    expect(min.score).toBeGreaterThanOrEqual(0);
  });

  it('is monotonic: raising any factor never lowers the score', () => {
    const base = { cvssScore: 6.5, realImpact: 'LIMITED', exploitability: 'CONDITIONAL_POC', scale: 'USER_SUBSET', assetCriticality: 'MEDIUM' } as const;
    const s0 = multiFactorScore(base).score;
    expect(multiFactorScore({ ...base, realImpact: 'SEVERE' }).score).toBeGreaterThan(s0);
    expect(multiFactorScore({ ...base, scale: 'ALL_USERS' }).score).toBeGreaterThan(s0);
    expect(multiFactorScore({ ...base, assetCriticality: 'CRITICAL' }).score).toBeGreaterThan(s0);
    expect(multiFactorScore({ ...base, cvssScore: 7.5 }).score).toBeGreaterThan(s0);
  });

  it('distinguishes findings that CVSS-only scoring cannot (same vector, different context)', () => {
    // Same CVSS 6.5 IDOR: one exposes a single test profile, the other all citizens' records on a critical portal.
    const low = multiFactorReward({ cvssScore: 6.5, realImpact: 'LIMITED', exploitability: 'CONDITIONAL_POC', scale: 'SINGLE_USER', assetCriticality: 'MEDIUM', quality: 0.55 }, DEFAULT_MATRIX);
    const high = multiFactorReward({ cvssScore: 6.5, realImpact: 'SEVERE', exploitability: 'TRIVIAL_AUTOMATABLE', scale: 'ALL_USERS', assetCriticality: 'CRITICAL', quality: 1 }, DEFAULT_MATRIX);
    expect(baselineReward(6.5, DEFAULT_MATRIX)).toEqual(baselineReward(6.5, DEFAULT_MATRIX));
    expect(high.tier).not.toBe(low.tier);
    expect(high.reward).toBeGreaterThan(low.reward);
  });

  it('quality moves the amount inside the band but never across tiers', () => {
    const i = { cvssScore: 8.1, realImpact: 'SIGNIFICANT', exploitability: 'RELIABLE_POC', scale: 'ALL_USERS', assetCriticality: 'HIGH' } as const;
    const poor = multiFactorReward({ ...i, quality: 0 }, DEFAULT_MATRIX);
    const good = multiFactorReward({ ...i, quality: 1 }, DEFAULT_MATRIX);
    expect(poor.tier).toBe(good.tier);
    expect(good.reward).toBeGreaterThan(poor.reward);
    expect(good.reward).toBeLessThanOrEqual(DEFAULT_MATRIX[good.tier as 'HIGH'].max);
  });

  it('a finding without impact is not rewardable', () => {
    const r = multiFactorReward({ cvssScore: 3.1, realImpact: 'NONE', exploitability: 'THEORETICAL', scale: 'SINGLE_USER', assetCriticality: 'LOW', quality: 1 }, DEFAULT_MATRIX);
    expect(r.tier).toBe('NONE');
    expect(r.reward).toBe(0);
  });

  it('tier thresholds', () => {
    expect([3.99, 4, 6.99, 7, 8.99, 9, 9.49, 9.5].map(tierOf)).toEqual([
      'LOW', 'MEDIUM', 'MEDIUM', 'HIGH', 'HIGH', 'CRITICAL', 'CRITICAL', 'EXCEPTIONAL',
    ]);
  });
});
