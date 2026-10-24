import { randomBytes } from 'node:crypto';

function required(name: string, devDefault?: string): string {
  const v = process.env[name];
  if (v && v.length > 0) return v;
  if (process.env.NODE_ENV === 'production' || devDefault === undefined) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return devDefault;
}

// Development defaults exist ONLY so the prototype runs out of the box.
// In production every secret must come from the environment / a secret store.
export const config = {
  port: Number(process.env.PORT ?? 3001),
  databaseUrl: required(
    'DATABASE_URL',
    'postgresql://cyberhunt:cyberhunt_dev@localhost:5432/cyberhunt',
  ),
  // 32-byte keys, base64
  fieldEncKey: required('FIELD_ENC_KEY', Buffer.alloc(32, 7).toString('base64')),
  hmacKey: required('HMAC_KEY', Buffer.alloc(32, 9).toString('base64')),
  jwtSecret: required('JWT_SECRET', randomBytes(32).toString('base64')),
  jwtTtlSeconds: Number(process.env.JWT_TTL_SECONDS ?? 3600),
  corsOrigin: process.env.CORS_ORIGIN ?? 'http://localhost:3000',
};
