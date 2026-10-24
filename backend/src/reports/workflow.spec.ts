import type { Role } from '../common/security.js';
import { canTransition, STATUSES, TERMINAL, TRANSITIONS } from './workflow.js';
import { inScope } from './scope.js';

const ROLES: Role[] = ['RESEARCHER', 'OPERATOR', 'AGENCY', 'ADMIN'];

describe('report workflow state machine', () => {
  it('happy path follows the specification order', () => {
    const path: [string, string, Role][] = [
      ['SUBMITTED', 'TRIAGE', 'OPERATOR'],
      ['TRIAGE', 'VALIDATED', 'OPERATOR'],
      ['VALIDATED', 'ACCEPTED', 'OPERATOR'],
      ['ACCEPTED', 'SEVERITY_ASSIGNED', 'OPERATOR'],
      ['SEVERITY_ASSIGNED', 'REWARD_APPROVED', 'ADMIN'],
      ['REWARD_APPROVED', 'PAID', 'ADMIN'],
      ['PAID', 'REMEDIATION', 'AGENCY'],
      ['REMEDIATION', 'RETEST', 'AGENCY'],
      ['RETEST', 'CLOSED', 'OPERATOR'],
    ];
    for (const [f, t, r] of path) expect(canTransition(f as any, t as any, r)).toEqual({ ok: true });
  });

  it('researcher can never move a report (no self-approval)', () => {
    for (const from of STATUSES) for (const to of STATUSES) {
      expect(canTransition(from, to, 'RESEARCHER').ok).toBe(false);
    }
  });

  it('payment cannot be skipped or done before severity assignment', () => {
    expect(canTransition('ACCEPTED', 'PAID', 'ADMIN')).toEqual({ ok: false, reason: 'INVALID_TRANSITION' });
    expect(canTransition('SUBMITTED', 'PAID', 'ADMIN')).toEqual({ ok: false, reason: 'INVALID_TRANSITION' });
  });

  it('reward does not depend on remediation: PAID precedes REMEDIATION', () => {
    const order = STATUSES as readonly string[];
    expect(order.indexOf('PAID')).toBeLessThan(order.indexOf('REMEDIATION'));
  });

  it('terminal states have no outgoing transitions', () => {
    for (const s of TERMINAL) for (const r of ROLES) for (const to of STATUSES) {
      expect(canTransition(s, to, r).ok).toBe(false);
    }
  });

  it('wrong role on a valid edge is FORBIDDEN_ROLE, not INVALID_TRANSITION', () => {
    expect(canTransition('SEVERITY_ASSIGNED', 'REWARD_APPROVED', 'OPERATOR')).toEqual({ ok: false, reason: 'FORBIDDEN_ROLE' });
  });

  it('every status is reachable from SUBMITTED', () => {
    const seen = new Set<string>(['SUBMITTED']);
    const queue = ['SUBMITTED'];
    while (queue.length) {
      const s = queue.shift()!;
      for (const r of TRANSITIONS[s as keyof typeof TRANSITIONS]) if (!seen.has(r.to)) { seen.add(r.to); queue.push(r.to); }
    }
    expect([...seen].sort()).toEqual([...STATUSES].sort());
  });
});

describe('scope matching', () => {
  const inS = ['portal.agency-a.test', '*.portal.agency-a.test', 'api.agency-a.test/v1'];
  const outS = ['status.portal.agency-a.test'];
  it.each([
    ['https://portal.agency-a.test/login', true],
    ['https://eservices.portal.agency-a.test/form?id=1', true],
    ['api.agency-a.test/v1/users/42', true],
    ['https://api.agency-a.test/v2/users', false],
    ['https://status.portal.agency-a.test/', false],
    ['https://portal.agency-a.test.evil.example/', false],
  ])('%s -> %s', (target, expected) => {
    expect(inScope(target, inS, outS)).toBe(expected);
  });
});
