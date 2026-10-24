import { targetKey } from '../scoring/dedup.js';

/** Very small wildcard matcher for scope entries such as "*.egov.kz" or "api.example.kz/v1". */
export function inScope(target: string, inScopeList: string[], outOfScope: string[]): boolean {
  const key = targetKey(target);
  const match = (pattern: string) => {
    const p = pattern.toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
    const re = new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '(/.*)?$');
    return re.test(key);
  };
  return inScopeList.some(match) && !outOfScope.some(match);
}
