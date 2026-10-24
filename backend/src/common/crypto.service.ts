import { Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { config } from '../config.js';

/**
 * Field-level encryption for confidential vulnerability material.
 * AES-256-GCM with a random 96-bit IV per value. The associated data (AAD)
 * binds a ciphertext to its record and column, so ciphertexts cannot be
 * swapped between reports or fields without failing authentication.
 * Format: v1.<iv b64>.<tag b64>.<ciphertext b64>
 */
@Injectable()
export class CryptoService {
  private readonly key = Buffer.from(config.fieldEncKey, 'base64');
  private readonly hmacKey = Buffer.from(config.hmacKey, 'base64');

  constructor() {
    if (this.key.length !== 32) throw new Error('FIELD_ENC_KEY must be 32 bytes (base64)');
  }

  encrypt(plaintext: string, aad: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    c.setAAD(Buffer.from(aad, 'utf8'));
    const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
    const tag = c.getAuthTag();
    return ['v1', iv.toString('base64'), tag.toString('base64'), ct.toString('base64')].join('.');
  }

  decrypt(blob: string, aad: string): string {
    const [v, ivB, tagB, ctB] = blob.split('.');
    if (v !== 'v1') throw new Error('Unsupported ciphertext version');
    const d = createDecipheriv('aes-256-gcm', this.key, Buffer.from(ivB, 'base64'));
    d.setAAD(Buffer.from(aad, 'utf8'));
    d.setAuthTag(Buffer.from(tagB, 'base64'));
    return Buffer.concat([d.update(Buffer.from(ctB, 'base64')), d.final()]).toString('utf8');
  }

  /** Keyed hash for values that must be compared but never stored in clear (IIN, target). */
  hmac(value: string): string {
    return createHmac('sha256', this.hmacKey).update(value).digest('hex');
  }
}
