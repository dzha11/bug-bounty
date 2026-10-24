import { Controller, ForbiddenException, Get, Inject, NotFoundException, Param, ParseIntPipe, Post } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import { CurrentUser, Public, Roles } from '../auth/auth.guard.js';
import type { TokenPayload } from '../common/security.js';
import { DatabaseService } from '../db/database.service.js';

@Controller('programs')
export class ProgramsController {
  constructor(
    @Inject(DatabaseService) private readonly db: DatabaseService,
    @Inject(AuditService) private readonly audit: AuditService,
  ) {}

  /** Public catalog: scope, rules and the reward matrix are visible before testing. */
  @Public()
  @Get()
  async list() {
    const r = await this.db.query(
      `SELECT p.id, p.name, o.name AS organization, p.asset_type, p.asset_criticality, p.in_scope, p.out_of_scope,
              p.allowed_methods, p.forbidden_methods, p.reward_matrix, p.rules_version, p.starts_at, p.ends_at
         FROM programs p JOIN organizations o ON o.id = p.organization_id
        WHERE p.is_private = false ORDER BY p.id`,
    );
    return r.rows;
  }

  @Public()
  @Get(':id')
  async get(@Param('id', ParseIntPipe) id: number) {
    const p = await this.db.one(
      `SELECT p.*, o.name AS organization FROM programs p JOIN organizations o ON o.id=p.organization_id
        WHERE p.id=$1 AND p.is_private=false`,
      [id],
    );
    if (!p) throw new NotFoundException();
    return p;
  }

  /** Safe Harbor: record rules version, timestamp and researcher before any testing. */
  @Roles('RESEARCHER')
  @Post(':id/safe-harbor')
  async acceptSafeHarbor(@Param('id', ParseIntPipe) id: number, @CurrentUser() u: TokenPayload) {
    const p = await this.db.one('SELECT id, rules_version, ends_at FROM programs WHERE id=$1', [id]);
    if (!p) throw new NotFoundException();
    if (new Date(p.ends_at) < new Date()) throw new ForbiddenException('Program has ended');
    const row = await this.db.one(
      `INSERT INTO safe_harbor_acceptances (user_id, program_id, rules_version) VALUES ($1,$2,$3)
       ON CONFLICT (user_id, program_id, rules_version) DO UPDATE SET rules_version = EXCLUDED.rules_version
       RETURNING id, rules_version, accepted_at`,
      [u.sub, id, p.rules_version],
    );
    await this.audit.log({
      actorId: u.sub,
      actorRole: u.role,
      action: 'SAFE_HARBOR_ACCEPTED',
      entity: 'program',
      entityId: id,
      details: { rulesVersion: p.rules_version },
    });
    return row;
  }
}
