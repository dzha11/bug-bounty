import {
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Ip,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { AuditService } from '../audit/audit.service.js';
import { CryptoService } from '../common/crypto.service.js';
import { hashPassword, signToken, verifyPassword } from '../common/security.js';
import type { TokenPayload } from '../common/security.js';
import { parse } from '../common/validation.js';
import { config } from '../config.js';
import { DatabaseService } from '../db/database.service.js';
import { CurrentUser, Public } from './auth.guard.js';

const RegisterSchema = z.object({
  email: z.string().email().max(200),
  fullName: z.string().min(2).max(200),
  password: z.string().min(10).max(200),
  iin: z.string().regex(/^\d{12}$/, 'IIN must be 12 digits'),
  phone: z.string().regex(/^\+?\d{10,15}$/).optional(),
  acceptNda: z.literal(true),
  acceptRulesOfEngagement: z.literal(true),
});

const LoginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

/** Simple fixed-window limiter for login attempts (per IP + email). */
const attempts = new Map<string, { count: number; resetAt: number }>();
export const LOGIN_LIMIT = 5;
const WINDOW_MS = 15 * 60 * 1000;
export function resetLoginLimiter() {
  attempts.clear();
}

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(DatabaseService) private readonly db: DatabaseService,
    @Inject(CryptoService) private readonly crypto: CryptoService,
    @Inject(AuditService) private readonly audit: AuditService,
  ) {}

  @Public()
  @Post('register')
  async register(@Body() body: unknown) {
    const b = parse(RegisterSchema, body);
    const iinHmac = this.crypto.hmac(b.iin);
    const exists = await this.db.one('SELECT 1 FROM users WHERE email=$1 OR iin_hmac=$2', [b.email.toLowerCase(), iinHmac]);
    if (exists) throw new ConflictException('Account already exists');
    const researcherId = `CH-${randomBytes(3).toString('hex').toUpperCase()}`;
    const user = await this.db.one(
      `INSERT INTO users (email, full_name, password_hash, role, iin_hmac, phone_enc, researcher_id)
       VALUES ($1,$2,$3,'RESEARCHER',$4,$5,$6) RETURNING id, researcher_id, level`,
      [
        b.email.toLowerCase(),
        b.fullName,
        hashPassword(b.password),
        iinHmac,
        b.phone ? this.crypto.encrypt(b.phone, `user:phone:${b.email.toLowerCase()}`) : null,
        researcherId,
      ],
    );
    await this.audit.log({
      actorId: user.id,
      actorRole: 'RESEARCHER',
      action: 'USER_REGISTERED',
      entity: 'user',
      entityId: user.id,
      details: { researcherId, ndaAccepted: true, roeAccepted: true },
    });
    return { id: user.id, researcherId: user.researcher_id, level: user.level };
  }

  @Public()
  @Post('login')
  @HttpCode(200)
  async login(@Body() body: unknown, @Ip() ip: string) {
    const b = parse(LoginSchema, body);
    const key = `${ip}|${b.email.toLowerCase()}`;
    const now = Date.now();
    const a = attempts.get(key);
    if (a && a.resetAt > now && a.count >= LOGIN_LIMIT) {
      throw new HttpException('Too many login attempts, try later', HttpStatus.TOO_MANY_REQUESTS);
    }
    const user = await this.db.one('SELECT * FROM users WHERE email=$1', [b.email.toLowerCase()]);
    if (!user || !verifyPassword(b.password, user.password_hash)) {
      const cur = a && a.resetAt > now ? a : { count: 0, resetAt: now + WINDOW_MS };
      cur.count++;
      attempts.set(key, cur);
      await this.audit.log({
        actorId: user?.id ?? null,
        actorRole: null,
        action: 'LOGIN_FAILED',
        entity: 'user',
        entityId: user?.id ?? null,
        details: { ip },
      });
      throw new UnauthorizedException('Invalid credentials'); // same message: no user enumeration
    }
    attempts.delete(key);
    const token = signToken(
      { sub: user.id, role: user.role, org: user.organization_id },
      config.jwtSecret,
      config.jwtTtlSeconds,
    );
    await this.audit.log({ actorId: user.id, actorRole: user.role, action: 'LOGIN', entity: 'user', entityId: user.id });
    return { token, role: user.role, fullName: user.full_name };
  }

  @Get('me')
  async me(@CurrentUser() u: TokenPayload) {
    return this.db.one(
      'SELECT id, email, full_name, role, researcher_id, level, points, organization_id FROM users WHERE id=$1',
      [u.sub],
    );
  }
}
