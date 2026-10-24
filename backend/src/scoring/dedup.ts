/**
 * Automatic duplicate check: TF-IDF vectors + cosine similarity over the
 * normalised text of a report (title, target, description, steps).
 * Combined with an exact-match signal on the HMAC fingerprint of the target
 * (host + path), computed elsewhere.
 */
export interface DocInput {
  id: number;
  text: string;
}

const STOP = new Set(
  'the a an and or of to in on for is are was were be by with this that it as at from can via into user users page'.split(
    ' ',
  ),
);

export function normalise(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/https?:\/\/[^\s/]+/g, ' ') // host is covered by the fingerprint signal
    .replace(/[0-9a-f]{8,}/g, ' ') // ids / hashes
    .replace(/[^\p{L}\p{N}_/.-]+/gu, ' ')
    .split(/\s+/)
    .map((t) => t.replace(/^[./-]+|[./-]+$/g, ''))
    .filter((t) => t.length > 1 && !STOP.has(t));
}

function tf(tokens: string[]) {
  const m = new Map<string, number>();
  for (const t of tokens) m.set(t, (m.get(t) ?? 0) + 1);
  for (const [k, v] of m) m.set(k, v / tokens.length);
  return m;
}

export function similarity(query: DocInput, corpus: DocInput[]): { id: number; score: number }[] {
  const docs = [query, ...corpus].map((d) => normalise(d.text));
  const N = docs.length;
  const df = new Map<string, number>();
  for (const d of docs) for (const t of new Set(d)) df.set(t, (df.get(t) ?? 0) + 1);
  const idf = (t: string) => Math.log((N + 1) / ((df.get(t) ?? 0) + 1)) + 1; // smoothed
  const vec = (tokens: string[]) => {
    const v = new Map<string, number>();
    for (const [t, f] of tf(tokens)) v.set(t, f * idf(t));
    return v;
  };
  const norm = (v: Map<string, number>) => Math.sqrt([...v.values()].reduce((a, b) => a + b * b, 0));
  const q = vec(docs[0]);
  const qn = norm(q) || 1;
  return corpus
    .map((d, i) => {
      const v = vec(docs[i + 1]);
      let dot = 0;
      for (const [t, w] of q) dot += w * (v.get(t) ?? 0);
      return { id: d.id, score: Math.round((dot / (qn * (norm(v) || 1))) * 1000) / 1000 };
    })
    .sort((a, b) => b.score - a.score);
}

export const DUPLICATE_THRESHOLD = 0.35;

/** Combined decision used at submission: text similarity, boosted by identical target. */
export function combinedScore(textScore: number, sameTarget: boolean): number {
  return Math.min(1, Math.round((textScore + (sameTarget ? 0.15 : 0)) * 1000) / 1000);
}

export function targetKey(target: string): string {
  try {
    const u = new URL(target.includes('://') ? target : `https://${target}`);
    return `${u.hostname.toLowerCase()}${u.pathname.replace(/\/+$/, '').toLowerCase()}`;
  } catch {
    return target.trim().toLowerCase();
  }
}
