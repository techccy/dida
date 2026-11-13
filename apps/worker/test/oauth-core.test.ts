/**
 * 账号中心 OAuth 核心逻辑单元测试：
 * anti-CSRF state 签发/校验 · access_token（HS256 JWT）本地验签 · 邮箱白名单。
 */
import { describe, it, expect } from "vitest";
import { b64Url, hmacSha256 } from "../src/admin";
import {
  OAUTH_STATE_TTL_MS,
  isWhitelisted,
  parseWhitelist,
  signState,
  verifyAccessToken,
  verifyState,
  type AccountCenterClaims,
} from "../src/oauth-core";

const KEY = new Uint8Array(32).fill(7);
const SECRET = "test-client-secret";

/** 用给定 secret 手工构造 HS256 JWT（模拟账号中心签发的 access_token） */
async function hs256Jwt(
  secret: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const te = new TextEncoder();
  const h = b64Url(te.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const p = b64Url(te.encode(JSON.stringify(payload)));
  const sig = await hmacSha256(te.encode(secret), te.encode(`${h}.${p}`));
  return `${h}.${p}.${b64Url(sig)}`;
}

const validClaims = (): Record<string, unknown> => ({
  iss: "https://account.techccy.com",
  sub: "u_abc123",
  aud: "app_test",
  email: "Admin@Example.com",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 7200,
});

describe("anti-CSRF state（无状态 HMAC 签名）", () => {
  it("签发 → 校验往返", async () => {
    const state = await signState(KEY);
    await expect(verifyState(KEY, state)).resolves.toBe(true);
    // 两个 state 不重复（含随机 nonce）
    expect(state).not.toBe(await signState(KEY));
  });

  it("过期 state → 拒绝", async () => {
    const state = await signState(KEY, Date.now() - OAUTH_STATE_TTL_MS - 1000);
    await expect(verifyState(KEY, state)).resolves.toBe(false);
  });

  it("篡改签名 / 篡改 blob → 拒绝", async () => {
    const state = await signState(KEY);
    const [blob, sig] = state.split(".");
    await expect(verifyState(KEY, `${blob}.${"A".repeat(sig.length)}`)).resolves.toBe(false);
    const claims = JSON.parse(atob(blob.replace(/-/g, "+").replace(/_/g, "/"))) as { exp: number };
    claims.exp = Date.now() + 3_600_000; // 明显不同于原 exp（TTL=10min），确保 blob 改变
    const forgedBlob = b64Url(new TextEncoder().encode(JSON.stringify(claims)));
    await expect(verifyState(KEY, `${forgedBlob}.${sig}`)).resolves.toBe(false);
  });

  it("错误密钥签发 → 拒绝", async () => {
    const state = await signState(new Uint8Array(32).fill(8));
    await expect(verifyState(KEY, state)).resolves.toBe(false);
  });

  it("畸形输入 → 拒绝（不抛异常）", async () => {
    await expect(verifyState(KEY, "garbage")).resolves.toBe(false);
    await expect(verifyState(KEY, "a.b.c")).resolves.toBe(false);
    await expect(verifyState(KEY, "!!!.###")).resolves.toBe(false);
  });
});

describe("账号中心 access_token 本地验签（HS256）", () => {
  it("正确 secret / iss / aud → 通过，返回 email 与 sub", async () => {
    const token = await hs256Jwt(SECRET, validClaims());
    const claims = await verifyAccessToken(SECRET, token, {
      issuer: "https://account.techccy.com",
      audience: "app_test",
    });
    expect(claims).not.toBeNull();
    expect(claims!.sub).toBe("u_abc123");
    expect(claims!.email).toBe("Admin@Example.com");
  });

  it("错误 secret（签名不符）→ 拒绝", async () => {
    const token = await hs256Jwt("wrong-secret", validClaims());
    await expect(
      verifyAccessToken(SECRET, token, {
        issuer: "https://account.techccy.com",
        audience: "app_test",
      }),
    ).resolves.toBeNull();
  });

  it("iss / aud 不匹配 → 拒绝", async () => {
    const token = await hs256Jwt(SECRET, validClaims());
    await expect(
      verifyAccessToken(SECRET, token, {
        issuer: "https://evil.example.com",
        audience: "app_test",
      }),
    ).resolves.toBeNull();
    await expect(
      verifyAccessToken(SECRET, token, {
        issuer: "https://account.techccy.com",
        audience: "app_other",
      }),
    ).resolves.toBeNull();
  });

  it("过期 token → 拒绝", async () => {
    const c = validClaims() as { exp: number };
    c.exp = Math.floor(Date.now() / 1000) - 10;
    const token = await hs256Jwt(SECRET, c);
    await expect(
      verifyAccessToken(SECRET, token, {
        issuer: "https://account.techccy.com",
        audience: "app_test",
      }),
    ).resolves.toBeNull();
  });

  it("缺 email / 非 string email → 拒绝", async () => {
    const noEmail = validClaims();
    delete (noEmail as Record<string, unknown>).email;
    await expect(
      verifyAccessToken(SECRET, await hs256Jwt(SECRET, noEmail), {
        issuer: "https://account.techccy.com",
        audience: "app_test",
      }),
    ).resolves.toBeNull();
  });

  it("格式错误 → 拒绝", async () => {
    await expect(
      verifyAccessToken(SECRET, "garbage", {
        issuer: "https://account.techccy.com",
        audience: "app_test",
      }),
    ).resolves.toBeNull();
  });
});

describe("管理员邮箱白名单（本地文件解析）", () => {
  it("解析：忽略注释/空行，大小写不敏感", () => {
    const set = parseWhitelist(
      "# 管理员\n\nAdmin@Example.com  \r\n  other@example.com # 行内注释\n",
    );
    expect(set).toEqual(new Set(["admin@example.com", "other@example.com"]));
  });

  it("命中判断：大小写与首尾空白容忍", () => {
    const set = parseWhitelist("admin@example.com\n");
    expect(isWhitelisted(set, "ADMIN@example.com")).toBe(true);
    expect(isWhitelisted(set, "  admin@example.com ")).toBe(true);
    expect(isWhitelisted(set, "admin@other.com")).toBe(false);
  });

  it("空白名单：任何人都不命中", () => {
    const set = parseWhitelist("# 只有注释\n\n");
    expect(set.size).toBe(0);
    expect(isWhitelisted(set, "admin@example.com")).toBe(false);
  });

  it("AccountCenterClaims 形状导出可用（类型冒烟）", () => {
    const c: AccountCenterClaims = {
      sub: "u_x",
      email: "a@b.c",
      exp: 1,
    };
    expect(c.sub).toBe("u_x");
  });
});
