import type { Role } from '../common/security.js';

/** Report lifecycle (from the CyberHunt KZ specification). */
export const STATUSES = [
  'SUBMITTED',
  'TRIAGE',
  'VALIDATED',
  'REJECTED', // out of scope / not reproducible / invalid
  'DUPLICATE',
  'ACCEPTED',
  'SEVERITY_ASSIGNED',
  'REWARD_APPROVED',
  'PAID',
  'REMEDIATION',
  'RETEST',
  'CLOSED',
] as const;
export type Status = (typeof STATUSES)[number];

interface Rule {
  to: Status;
  roles: Role[];
}

/**
 * Allowed transitions and who may perform them. Anything not listed is rejected.
 * Payment happens BEFORE remediation so the reward never depends on when the
 * asset owner fixes the problem (specification requirement).
 */
export const TRANSITIONS: Record<Status, Rule[]> = {
  SUBMITTED: [{ to: 'TRIAGE', roles: ['OPERATOR'] }],
  TRIAGE: [
    { to: 'VALIDATED', roles: ['OPERATOR'] },
    { to: 'REJECTED', roles: ['OPERATOR'] },
  ],
  VALIDATED: [
    { to: 'ACCEPTED', roles: ['OPERATOR'] },
    { to: 'DUPLICATE', roles: ['OPERATOR'] },
  ],
  ACCEPTED: [{ to: 'SEVERITY_ASSIGNED', roles: ['OPERATOR'] }],
  SEVERITY_ASSIGNED: [{ to: 'REWARD_APPROVED', roles: ['ADMIN'] }],
  REWARD_APPROVED: [{ to: 'PAID', roles: ['ADMIN'] }],
  PAID: [{ to: 'REMEDIATION', roles: ['AGENCY'] }],
  REMEDIATION: [{ to: 'RETEST', roles: ['AGENCY'] }],
  RETEST: [
    { to: 'CLOSED', roles: ['OPERATOR'] },
    { to: 'REMEDIATION', roles: ['OPERATOR'] }, // fix did not hold
  ],
  REJECTED: [],
  DUPLICATE: [],
  CLOSED: [],
};

export type TransitionCheck = { ok: true } | { ok: false; reason: 'INVALID_TRANSITION' | 'FORBIDDEN_ROLE' };

export function canTransition(from: Status, to: Status, role: Role): TransitionCheck {
  const rule = TRANSITIONS[from]?.find((r) => r.to === to);
  if (!rule) return { ok: false, reason: 'INVALID_TRANSITION' };
  if (!rule.roles.includes(role)) return { ok: false, reason: 'FORBIDDEN_ROLE' };
  return { ok: true };
}

export const TERMINAL: Status[] = ['REJECTED', 'DUPLICATE', 'CLOSED'];
