import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

// ---------- password hashing (scrypt, N=16384, r=8, p=1) ----------
export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32);
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [alg, saltB, hashB] = stored.split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(hashB, 'base64');
  const actual = scryptSync(password, Buffer.from(saltB, 'base64'), expected.length);
  return timingSafeEqual(expected, actual);
}

// ---------- minimal HS256 JWT ----------
export type Role = 'RESEARCHER' | 'OPERATOR' | 'AGENCY' | 'ADMIN';
export interface TokenPayload {
  sub: number;
  role: Role;
  org?: number | null;
  iat: number;
  exp: number;
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');

export function signToken(p: Omit<TokenPayload, 'iat' | 'exp'>, secret: string, ttl: number): string {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ ...p, iat: now, exp: now + ttl }));
  const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

export function verifyToken(token: string, secret: string): TokenPayload | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  let header: any;
  try {
    header = JSON.parse(Buffer.from(h, 'base64url').toString());
  } catch {
    return null;
  }
  if (header.alg !== 'HS256') return null; // rejects alg=none / algorithm confusion
  const expected = createHmac('sha256', secret).update(`${h}.${b}`).digest();
  const got = Buffer.from(s, 'base64url');
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString()) as TokenPayload;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}
