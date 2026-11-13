/**
 * 管理员会话 token（§9）：
 * - 登录走统一账号中心 OAuth（routes/oauth.ts）；通过邮箱白名单后，
 *   本模块签发平台自己的 HMAC 签名 token（exp = now + 8h）
 * - token 走 WS 首帧 / Authorization 头，绝不出现在任何 URL
 */
import { ADMIN_TOKEN_TTL_MS } from "@dida/shared";
import { bytesToB64, b64ToBytes } from "@dida/shared";

export interface TokenClaims {
  sub: "admin";
  exp: number; // ms
}

const te = new TextEncoder();
const td = new TextDecoder();

export const b64Url = (b: Uint8Array) =>
  bytesToB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const fromB64Url = (s: string) => {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return b64ToBytes(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
};

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- HMAC token ----------

export async function hmacSha256(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

export async function signToken(
  signingKey: Uint8Array,
  claims: TokenClaims,
): Promise<string> {
  const header = b64Url(te.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = b64Url(te.encode(JSON.stringify(claims)));
  const mac = await hmacSha256(signingKey, te.encode(`${header}.${payload}`));
  return `${header}.${payload}.${b64Url(mac)}`;
}

export async function verifyToken(
  signingKey: Uint8Array,
  token: string,
  now = Date.now(),
): Promise<TokenClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const mac = await hmacSha256(signingKey, te.encode(`${h}.${p}`));
  const provided = fromB64Url(s);
  if (!constantTimeEqual(mac, provided)) return null;
  try {
    const claims = JSON.parse(td.decode(fromB64Url(p))) as TokenClaims;
    if (claims.sub !== "admin") return null;
    if (typeof claims.exp !== "number" || claims.exp <= now) return null;
    return claims;
  } catch {
    return null;
  }
}

/** 签发 8h 管理员 token（§9） */
export function newAdminToken(signingKey: Uint8Array): Promise<string> {
  return signToken(signingKey, {
    sub: "admin",
    exp: Date.now() + ADMIN_TOKEN_TTL_MS,
  });
}
