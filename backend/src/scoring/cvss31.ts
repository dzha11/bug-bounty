/**
 * CVSS v3.1 base-score calculator, implemented from the FIRST specification
 * (CVSS v3.1 Specification Document, Section 7 and Appendix A "Roundup").
 */
export type CvssMetrics = {
  AV: 'N' | 'A' | 'L' | 'P';
  AC: 'L' | 'H';
  PR: 'N' | 'L' | 'H';
  UI: 'N' | 'R';
  S: 'U' | 'C';
  C: 'H' | 'L' | 'N';
  I: 'H' | 'L' | 'N';
  A: 'H' | 'L' | 'N';
};

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

const ALLOWED: Record<keyof CvssMetrics, string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
};

export class CvssError extends Error {}

export function parseVector(vector: string): CvssMetrics {
  const parts = vector.trim().split('/');
  if (parts[0] !== 'CVSS:3.1' && parts[0] !== 'CVSS:3.0') {
    throw new CvssError('Vector must start with CVSS:3.1/');
  }
  const m: Partial<Record<string, string>> = {};
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(':');
    if (!(k in ALLOWED)) throw new CvssError(`Unknown metric ${k}`);
    if (m[k] !== undefined) throw new CvssError(`Duplicate metric ${k}`);
    if (!ALLOWED[k as keyof CvssMetrics].includes(v)) throw new CvssError(`Bad value ${k}:${v}`);
    m[k] = v;
  }
  for (const k of Object.keys(ALLOWED)) {
    if (m[k] === undefined) throw new CvssError(`Missing metric ${k}`);
  }
  return m as CvssMetrics;
}

/** Appendix A roundup: smallest number, to 1 decimal, >= input (float-safe). */
export function roundup(x: number): number {
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

export function baseScore(vector: string): number {
  const m = parseVector(vector);
  const changed = m.S === 'C';
  const pr = m.PR === 'N' ? 0.85 : m.PR === 'L' ? (changed ? 0.68 : 0.62) : changed ? 0.5 : 0.27;
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  if (impact <= 0) return 0;
  return changed
    ? roundup(Math.min(1.08 * (impact + exploitability), 10))
    : roundup(Math.min(impact + exploitability, 10));
}

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export function severityOf(score: number): Severity {
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}
