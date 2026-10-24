import { baseScore, CvssError, parseVector, roundup, severityOf } from './cvss31.js';

// Reference vectors with base scores as published by the FIRST CVSS v3.1
// calculator / NVD for well-known CVEs (see report, Appendix C).
const REFERENCE: [string, number, string][] = [
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'unauthenticated RCE (e.g. CVE-2021-44228 class, scope unchanged)'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'CVE-2021-44228 Log4Shell'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5, 'CVE-2014-0160 Heartbleed (v3 rescoring)'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'typical reflected XSS'],
  ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8, 'local privilege escalation'],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5, 'authenticated IDOR read'],
  ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.1, 'high-complexity network RCE'],
  ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6, 'minimal physical info leak'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, 'no impact'],
];

describe('CVSS v3.1 base score', () => {
  it.each(REFERENCE)('%s -> %d (%s)', (vector, expected) => {
    expect(baseScore(vector)).toBe(expected);
  });

  it('implements the v3.1 floating-point-safe Roundup', () => {
    expect(roundup(4.02)).toBe(4.1);
    expect(roundup(4.0)).toBe(4.0);
    expect(roundup(4.000001)).toBe(4.0); // v3.0 naive ceil would give 4.1
  });

  it('maps scores to qualitative severity', () => {
    expect([0, 3.9, 4, 6.9, 7, 8.9, 9, 10].map(severityOf)).toEqual([
      'NONE', 'LOW', 'MEDIUM', 'MEDIUM', 'HIGH', 'HIGH', 'CRITICAL', 'CRITICAL',
    ]);
  });

  it('rejects malformed vectors', () => {
    expect(() => parseVector('AV:N/AC:L')).toThrow(CvssError);
    expect(() => baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toThrow(/Missing metric A/);
    expect(() => baseScore('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/Bad value/);
    expect(() => baseScore('CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/Duplicate/);
  });
});
