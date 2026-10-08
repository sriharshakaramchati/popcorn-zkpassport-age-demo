import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
export const hexNonce = () => randomBytes(32).toString('hex');
export function bindingContext(sessionId, nonce) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(sessionId) || !/^[a-f0-9]{64}$/.test(nonce)) throw new Error('Invalid session binding');
  return createHash('sha256').update(`popcorn-zkpassport-age-v1\0${sessionId}\0${nonce}`).digest('hex');
}
export function signCredential(payload, key) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = createHmac('sha256', key).update(body).digest('base64url');
  return `${body}.${mac}`;
}
export function verifyCredential(token, key, sessionId, nonce, now = Date.now(), mode = 'popcorn-attested') {
  if (typeof token !== 'string') return null;
  const [body, sig, extra] = token.split('.');
  if (!body || !sig || extra) return null;
  const expected = createHmac('sha256', key).update(body).digest();
  let given;
  try { given = Buffer.from(sig, 'base64url'); } catch { return null; }
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString());
    return claims.v === 1 && claims.aud === 'popcorn-zkpassport-age-demo' && claims.ageOver18 === true &&
      claims.sessionId === sessionId && claims.nonce === nonce && claims.exp > now && claims.iat <= now &&
      claims.mode === mode && ['passport-only','popcorn-connected','popcorn-attested'].includes(mode) ? claims : null;
  } catch { return null; }
}
export function requireExactProofQuery(query, binding) {
  if (!query || typeof query !== 'object' || Array.isArray(query)) throw new Error('Missing query');
  const keys = Object.keys(query).sort();
  if (keys.join(',') !== 'age,bind' || !query.age || Object.keys(query.age).join(',') !== 'gte' || query.age.gte !== 18 || !query.bind || Object.keys(query.bind).join(',') !== 'custom_data' || query.bind.custom_data !== binding) throw new Error('Query must be exactly age >=18 and this session binding');
}
