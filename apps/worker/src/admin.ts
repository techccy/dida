/**
 * 管理员认证（§9）：
 * - ADMIN_PASS_HASH（Worker Secret）：PBKDF2-SHA256 口令哈希，格式
 *   `pbkdf2-sha256$<iter>$<salt-b64>$<hash-b64>`
 * - 登录成功签发 HMAC 签名 token（exp = now + 8h）
 * - token 走 WS 首帧 / Authorization 头，绝不出现在任何 URL
 *
 * 本地开发（wrangler dev，无 Secrets）：若配置了 DEV_ADMIN_PASSWORD，
 * 则对口令即时做比较（仅本地，README 要求生产必须设置 Secrets）。
 */
import {
  ADMIN_TOKEN_TTL_MS,
  PBKDF2_ITERATIONS,
  PBKDF2_KEY_BYTES,
} from "@dida/shared";
import { bytesToB64, b64ToBytes } from "@dida/shared";

export interface TokenClaims {
  sub: "admin";
  exp: number; // ms
}

const te = new TextEncoder();
const td = new TextDecoder();

const b64Url = (b: Uint8Array) =>
  bytesToB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64Url = (s: string) => {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return b64ToBytes(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
};

// ---------- PBKDF2 ----------

export async function pbkdf2Hash(
  password: string,
  salt: Uint8Array,
  iterations = PBKDF2_ITERATIONS,
  keyLength = PBKDF2_KEY_BYTES,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    te.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    keyLength * 8,
  );
  return new Uint8Array(bits);
}

/** 生成可存入 Worker Secret 的口令哈希字符串（部署工具用） */
export async function computeAdminPassHash(
  password: string,
  iterations = PBKDF2_ITERATIONS,
): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2Hash(password, salt, iterations);
  return `pbkdf2-sha256$${iterations}$${bytesToB64(salt)}$${bytesToB64(hash)}`;
}

/** 校验口令与存储的哈希（timing-safe 比较） */
export async function verifyAdminPass(
  password: string,
  stored: string,
): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100_000) return false;
  const salt = b64ToBytes(parts[2]);
  const expected = b64ToBytes(parts[3]);
  const actual = await pbkdf2Hash(password, salt, iterations, expected.length);
  return constantTimeEqual(actual, expected);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
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

// ---------- 登录编排 ----------

export interface LoginCheck {
  ok: boolean;
  /** 本地开发模式（无 ADMIN_PASS_HASH secret） */
  local?: boolean;
  reason?: "bad-password" | "not-configured";
}

/**
 * 校验管理员口令。
 * 生产：Secret 里的 PBKDF2 哈希（timing-safe，§9）。
 * 本地开发：DEV_ADMIN_PASSWORD 即时比较（仅 wrangler dev）。
 */
export async function checkAdminPassword(
  password: string,
  storedHash: string | undefined,
  devPassword: string | undefined,
): Promise<LoginCheck> {
  if (storedHash) {
    const ok = await verifyAdminPass(password, storedHash);
    return ok ? { ok: true } : { ok: false, reason: "bad-password" };
  }
  if (devPassword) {
    const ok = constantTimeEqual(te.encode(password), te.encode(devPassword));
    return ok
      ? { ok: true, local: true }
      : { ok: false, reason: "bad-password", local: true };
  }
  return { ok: false, reason: "not-configured" };
}
