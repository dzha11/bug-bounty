/**
 * Experiment E1 — discrimination of the CVSS-only baseline vs the multi-factor model.
 *
 * Design: full-factorial scenario grid. Each REFERENCE CVSS vector is combined with every
 * level of real impact x exploitability x scale x asset criticality (4x4x4x4 = 256 contexts).
 * Report quality is fixed at 1.0 to isolate the effect of the context factors.
 * The grid is SYNTHETIC by design: it tests a property of the models (can they
 * tell apart contexts that CVSS treats as identical?), it is not real report data.
 *
 * Output: experiments/out/e1_reward_sensitivity.json and .csv
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { baseScore } from '../src/scoring/cvss31.js';
import {
  ASSET_CRITICALITY,
  baselineReward,
  DEFAULT_MATRIX,
  EXPLOITABILITY,
  multiFactorReward,
  REAL_IMPACT,
  SCALE,
} from '../src/scoring/reward.js';

const VECTORS: Record<string, string> = {
  'Reflected XSS': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  'Authenticated IDOR (read)': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  'Unauth. info disclosure': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  'High-complexity RCE': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
  'Unauth. RCE': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
};
const ORDER = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'EXCEPTIONAL'];

const rows: any[] = [];
const summary: any[] = [];
for (const [name, vector] of Object.entries(VECTORS)) {
  const cvss = baseScore(vector);
  const base = baselineReward(cvss, DEFAULT_MATRIX);
  const local: any[] = [];
  for (const realImpact of Object.keys(REAL_IMPACT) as (keyof typeof REAL_IMPACT)[])
    for (const exploitability of Object.keys(EXPLOITABILITY) as (keyof typeof EXPLOITABILITY)[])
      for (const scale of Object.keys(SCALE) as (keyof typeof SCALE)[])
        for (const assetCriticality of Object.keys(ASSET_CRITICALITY) as (keyof typeof ASSET_CRITICALITY)[]) {
          const mf = multiFactorReward({ cvssScore: cvss, realImpact, exploitability, scale, assetCriticality, quality: 1 }, DEFAULT_MATRIX);
          const r = { finding: name, vector, cvss, realImpact, exploitability, scale, assetCriticality,
            baselineTier: base.tier, baselineReward: base.reward, mfScore: mf.score, mfTier: mf.tier, mfReward: mf.reward,
            tierShift: ORDER.indexOf(mf.tier) - ORDER.indexOf(base.tier) };
          rows.push(r);
          local.push(r);
        }
  const rewards = local.map((r) => r.mfReward);
  const tiers = new Set(local.map((r) => r.mfTier));
  summary.push({
    finding: name,
    cvss,
    baselineTier: base.tier,
    baselineReward: base.reward,
    baselineDistinctOutputs: 1,
    mfDistinctTiers: tiers.size,
    mfTiers: ORDER.filter((t) => tiers.has(t)).join('/'),
    mfDistinctRewards: new Set(rewards).size,
    mfMinReward: Math.min(...rewards),
    mfMaxReward: Math.max(...rewards),
    pctSameTier: Math.round((100 * local.filter((r) => r.tierShift === 0).length) / local.length),
    pctUpgraded: Math.round((100 * local.filter((r) => r.tierShift > 0).length) / local.length),
    pctDowngraded: Math.round((100 * local.filter((r) => r.tierShift < 0).length) / local.length),
  });
}

mkdirSync(new URL('./out/', import.meta.url), { recursive: true });
writeFileSync(new URL('./out/e1_reward_sensitivity.json', import.meta.url), JSON.stringify({ summary, n: rows.length }, null, 2));
const cols = Object.keys(rows[0]);
writeFileSync(new URL('./out/e1_reward_sensitivity.csv', import.meta.url), [cols.join(','), ...rows.map((r) => cols.map((c) => r[c]).join(','))].join('\n'));
console.log(`E1: ${rows.length} scenario evaluations (${Object.keys(VECTORS).length} vectors x 256 contexts)`);
console.table(summary);
