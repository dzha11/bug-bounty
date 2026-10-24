import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { config } from '../config.js';

const here = dirname(fileURLToPath(import.meta.url));

@Injectable()
export class DatabaseService implements OnModuleDestroy {
  readonly pool = new pg.Pool({ connectionString: config.databaseUrl, max: 10 });

  async query<T extends pg.QueryResultRow = any>(text: string, params: unknown[] = []) {
    return this.pool.query<T>(text, params);
  }

  async one<T extends pg.QueryResultRow = any>(text: string, params: unknown[] = []) {
    const r = await this.pool.query<T>(text, params);
    return r.rows[0] as T | undefined;
  }

  /** Runs fn inside a single transaction. */
  async tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async migrate(): Promise<void> {
    // schema.sql lives next to the source file (copied to dist by nest-cli assets)
    const candidates = [join(here, 'schema.sql'), join(here, '../../src/db/schema.sql')];
    for (const p of candidates) {
      try {
        await this.pool.query(readFileSync(p, 'utf8'));
        return;
      } catch (e: any) {
        if (e.code !== 'ENOENT') throw e;
      }
    }
    throw new Error('schema.sql not found');
  }

  async onModuleDestroy() {
    await this.pool.end();
  }
}
