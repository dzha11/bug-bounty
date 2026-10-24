import { Inject, Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type pg from 'pg';
import { DatabaseService } from '../db/database.service.js';

export const GENESIS = '0'.repeat(64);

export interface AuditEntry {
  actorId: number | null;
  actorRole: string | null;
  action: string;
  entity: string;
  entityId?: string | number | null;
  details?: Record<string, unknown>;
}

/** Deterministic JSON (sorted keys) so the hash can be recomputed exactly. */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
    .join(',')}}`;
}

export function entryHash(prevHash: string, row: {
  at: string;
  actor_id: number | null;
  actor_role: string | null;
  action: string;
  entity: string;
  entity_id: string | null;
  details: unknown;
}): string {
  const body = canonical({
    at: row.at,
    actor_id: row.actor_id,
    actor_role: row.actor_role,
    action: row.action,
    entity: row.entity,
    entity_id: row.entity_id,
    details: row.details,
  });
  return createHash('sha256').update(prevHash + body).digest('hex');
}

/**
 * Hash-chained, append-only audit log. Each entry stores the hash of the previous
 * entry; changing or removing any row breaks every later hash. The table also has
 * a database trigger that rejects UPDATE and DELETE.
 */
@Injectable()
export class AuditService {
  constructor(@Inject(DatabaseService) private readonly db: DatabaseService) {}

  async log(e: AuditEntry, client?: pg.PoolClient): Promise<void> {
    const run = async (c: pg.PoolClient) => {
      // serialise writers so the chain is linear
      await c.query('SELECT pg_advisory_xact_lock(424242)');
      const prev = await c.query<{ hash: string }>('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1');
      const prevHash = prev.rows[0]?.hash ?? GENESIS;
      const row = {
        at: new Date().toISOString(),
        actor_id: e.actorId,
        actor_role: e.actorRole,
        action: e.action,
        entity: e.entity,
        entity_id: e.entityId == null ? null : String(e.entityId),
        details: e.details ?? {},
      };
      const hash = entryHash(prevHash, row);
      await c.query(
        `INSERT INTO audit_log (at, actor_id, actor_role, action, entity, entity_id, details, prev_hash, hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [row.at, row.actor_id, row.actor_role, row.action, row.entity, row.entity_id, row.details, prevHash, hash],
      );
    };
    if (client) return run(client);
    await this.db.tx(run);
  }

  async verify(): Promise<{ valid: boolean; entries: number; brokenAt: number | null }> {
    const r = await this.db.query(
      `SELECT id, to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS at,
              actor_id, actor_role, action, entity, entity_id, details, prev_hash, hash
         FROM audit_log ORDER BY id`,
    );
    let prev = GENESIS;
    for (const row of r.rows) {
      if (row.prev_hash !== prev || entryHash(prev, row) !== row.hash) {
        return { valid: false, entries: r.rowCount ?? 0, brokenAt: Number(row.id) };
      }
      prev = row.hash;
    }
    return { valid: true, entries: r.rowCount ?? 0, brokenAt: null };
  }

  async list(limit = 100) {
    const r = await this.db.query(
      `SELECT id, at, actor_id, actor_role, action, entity, entity_id, details, hash
         FROM audit_log ORDER BY id DESC LIMIT $1`,
      [limit],
    );
    return r.rows;
  }
}
