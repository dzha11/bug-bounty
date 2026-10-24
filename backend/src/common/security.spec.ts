import { createHmac } from 'node:crypto';
import { canonical, entryHash, GENESIS } from '../audit/audit.service.js';
import { CryptoService } from './crypto.service.js';
import { hashPassword, signToken, verifyPassword, verifyToken } from './security.js';

describe('field encryption (AES-256-GCM)', () => {
  const c = new CryptoService();
  it('round-trips and never stores plaintext', () => {
    const blob = c.encrypt('SELECT * FROM citizens -- PoC', 'report:CHR-1:poc');
    expect(blob).not.toContain('citizens');
    expect(c.decrypt(blob, 'report:CHR-1:poc')).toBe('SELECT * FROM citizens -- PoC');
  });
  it('uses a fresh IV: same plaintext gives different ciphertext', () => {
    expect(c.encrypt('x', 'a')).not.toBe(c.encrypt('x', 'a'));
  });
  it('detects tampering and ciphertext swapping between records (AAD)', () => {
    const blob = c.encrypt('secret', 'report:CHR-1:poc');
    expect(() => c.decrypt(blob, 'report:CHR-2:poc')).toThrow();
    const parts = blob.split('.');
    const ct = Buffer.from(parts[3], 'base64');
    ct[0] ^= 1;
    parts[3] = ct.toString('base64');
    expect(() => c.decrypt(parts.join('.'), 'report:CHR-1:poc')).toThrow();
  });
});

describe('passwords and tokens', () => {
  it('scrypt hashes verify only the right password', () => {
    const h = hashPassword('correct horse battery');
    expect(verifyPassword('correct horse battery', h)).toBe(true);
    expect(verifyPassword('wrong', h)).toBe(false);
  });
  it('tokens: valid, tampered, expired, alg=none', () => {
    const t = signToken({ sub: 1, role: 'RESEARCHER' }, 'k', 60);
    expect(verifyToken(t, 'k')?.sub).toBe(1);
    expect(verifyToken(t, 'other')).toBeNull();
    const [h, , s] = t.split('.');
    const forged = Buffer.from(JSON.stringify({ sub: 1, role: 'ADMIN', iat: 0, exp: 9e9 })).toString('base64url');
    expect(verifyToken(`${h}.${forged}.${s}`, 'k')).toBeNull();
    expect(verifyToken(signToken({ sub: 1, role: 'RESEARCHER' }, 'k', -1), 'k')).toBeNull();
    const none = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    expect(verifyToken(`${none}.${forged}.`, 'k')).toBeNull();
    // even a correct HMAC with a non-HS256 header is rejected
    const hs512h = Buffer.from(JSON.stringify({ alg: 'HS512' })).toString('base64url');
    const sig = createHmac('sha256', 'k').update(`${hs512h}.${forged}`).digest('base64url');
    expect(verifyToken(`${hs512h}.${forged}.${sig}`, 'k')).toBeNull();
  });
});

describe('audit hash chain', () => {
  it('canonical JSON is key-order independent', () => {
    expect(canonical({ b: 1, a: { d: 2, c: 3 } })).toBe(canonical({ a: { c: 3, d: 2 }, b: 1 }));
  });
  it('changing any field changes the hash', () => {
    const row = { at: '2026-10-24T10:00:00.000Z', actor_id: 1, actor_role: 'OPERATOR', action: 'X', entity: 'report', entity_id: 'CHR-1', details: { to: 'PAID' } };
    const h = entryHash(GENESIS, row);
    expect(entryHash(GENESIS, { ...row, details: { to: 'CLOSED' } })).not.toBe(h);
    expect(entryHash('f'.repeat(64), row)).not.toBe(h);
  });
});
