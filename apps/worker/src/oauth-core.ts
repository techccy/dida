/**
 * 账号中心 OAuth 核心逻辑（纯函数，无 IO/路由依赖，可单测）：
 * - state 签发/校验：HMAC 签名的无状态 anti-CSRF 令牌（10 分钟有效），
 *   无需服务端存储，由 TOKEN_SIGNING_KEY 保证不可伪造
 * - 账号中心 access_token 本地验签：HS256 JWT，密钥 = client_secret
 *   （校验 iss / aud / exp / email，零网络开销）
 * - 管理员邮箱白名单：解析本地文件内容（一行一个邮箱，# 注释，大小写不敏感）
 */
import { b64Url, constantTimeEqual, fromB64Url, hmacSha256 } from "./admin";

/** 账号中心认证站（统一账号中心） */
export const ACCOUNT_CENTER_BASE = "https://account.techccy.com";

/** state 有效期：10 分钟（覆盖跳转 + 账号中心认证 + 回调全程；授权码本身亦 10 分钟有效） */
export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

const te = new TextEncoder();
const td = new TextDecoder();

// ---------- anti-CSRF state（无状态 HMAC 签名方案） ----------

/**
 * 签发 OAuth state：`<blob-b64url>.<sig-b64url>`。
 * blob = b64url(JSON{n, exp})；sig = HMAC(signingKey, "oauth-state." + blob)。
 */
export async function signState(
  signingKey: Uint8Array,
  now = Date.now(),
): Promise<string> {
  const n = b64Url(crypto.getRandomValues(new Uint8Array(16)));
  const blob = b64Url(
    te.encode(JSON.stringify({ n, exp: now + OAUTH_STATE_TTL_MS })),
  );
  const sig = await hmacSha256(signingKey, te.encode(`oauth-state.${blob}`));
  return `${blob}.${b64Url(sig)}`;
}

/** 校验回调 state：签名 + 有效期；任何畸形输入一律 false */
export async function verifyState(
  signingKey: Uint8Array,
  state: string,
  now = Date.now(),
): Promise<boolean> {
  const parts = state.split(".");
  if (parts.length !== 2) return false;
  const [blob, sig] = parts;
  const expected = await hmacSha256(
    signingKey,
    te.encode(`oauth-state.${blob}`),
  );
  let provided: Uint8Array;
  try {
    provided = fromB64Url(sig);
  } catch {
    return false;
  }
  if (!constantTimeEqual(provided, expected)) return false;
  try {
    const claims = JSON.parse(td.decode(fromB64Url(blob))) as {
      n?: unknown;
      exp?: unknown;
    };
    if (typeof claims.n !== "string" || claims.n.length === 0) return false;
    if (typeof claims.exp !== "number" || claims.exp <= now) return false;
    return true;
  } catch {
    return false;
  }
}

// ---------- 账号中心 access_token 验签（HS256 JWT） ----------

export interface AccountCenterClaims {
  /** 账号中心用户唯一 ID（sub，全平台一致；不要用 email 做 ID） */
  sub: string;
  email: string;
  exp: number;
  [key: string]: unknown;
}

/**
 * 本地验签账号中心 access_token：HS256，密钥 = client_secret。
 * 校验 exp / iss / aud，并要求 email 为非空字符串。
 * 验签失败（签名/exp/iss/aud/形状不符）返回 null。
 */
export async function verifyAccessToken(
  clientSecret: string,
  token: string,
  opts: { issuer: string; audience: string },
  now = Date.now(),
): Promise<AccountCenterClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const expected = await hmacSha256(te.encode(clientSecret), te.encode(`${h}.${p}`));
  let provided: Uint8Array;
  try {
    provided = fromB64Url(s);
  } catch {
    return null;
  }
  if (!constantTimeEqual(provided, expected)) return null;
  try {
    const claims = JSON.parse(td.decode(fromB64Url(p))) as Record<string, unknown>;
    if (claims.iss !== opts.issuer) return null;
    if (claims.aud !== opts.audience) return null;
    // JWT NumericDate（Unix 秒，见账号中心文档 §4 payload 示例）
    if (typeof claims.exp !== "number" || claims.exp <= Math.floor(now / 1000))
      return null;
    if (typeof claims.sub !== "string" || claims.sub.length === 0) return null;
    if (typeof claims.email !== "string" || claims.email.length === 0)
      return null;
    return claims as unknown as AccountCenterClaims;
  } catch {
    return null;
  }
}

// ---------- 管理员邮箱白名单（本地文件） ----------

/**
 * 解析白名单文件内容：一行一个邮箱；`#` 起注释；忽略空行；大小写不敏感。
 */
export function parseWhitelist(txt: string): Set<string> {
  const out = new Set<string>();
  for (const line of txt.split(/\r?\n/)) {
    const s = line.split("#")[0].trim().toLowerCase();
    if (s) out.add(s);
  }
  return out;
}

/** 邮箱是否在白名单内（大小写不敏感，容忍首尾空白） */
export function isWhitelisted(set: Set<string>, email: string): boolean {
  return set.has(email.trim().toLowerCase());
}
