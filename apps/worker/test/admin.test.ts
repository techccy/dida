/**
 * 管理员认证单元测试（§9）：
 * PBKDF2 口令哈希 + HMAC token 签发/校验。
 * Node 22 自带 WebCrypto（crypto.subtle），vitest node 环境即可运行。
 */
import { describe, it, expect } from "vitest";
import {
  pbkdf2Hash,
  computeAdminPassHash,
  verifyAdminPass,
  signToken,
  verifyToken,
  newAdminToken,
  checkAdminPassword,
  type TokenClaims,
} from "../src/admin";
import { PBKDF2_ITERATIONS, ADMIN_TOKEN_TTL_MS } from "@dida/shared";

const KEY = new Uint8Array(32).fill(7);

describe("PBKDF2 口令哈希", () => {
  it("相同输入 → 相同输出（确定性）", async () => {
    const salt = new Uint8Array(16).fill(1);
    const a = await pbkdf2Hash("correct horse battery staple", salt, 100_000);
    const b = await pbkdf2Hash("correct horse battery staple", salt, 100_000);
    expect(a).toEqual(b);
    expect(a).toHaveLength(32);
  });

  it("不同口令 → 不同输出", async () => {
    const salt = new Uint8Array(16).fill(1);
    const a = await pbkdf2Hash("password-a", salt, 100_000);
    const b = await pbkdf2Hash("password-b", salt, 100_000);
    expect(a).not.toEqual(b);
  });

  it("computeAdminPassHash 格式：pbkdf2-sha256$iter$saltB64$hashB64", async () => {
    const stored = await computeAdminPassHash("s3cret");
    const parts = stored.split("$");
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe("pbkdf2-sha256");
    expect(Number(parts[1])).toBe(PBKDF2_ITERATIONS);
    expect(Buffer.from(parts[2], "base64").length).toBe(16);
    expect(Buffer.from(parts[3], "base64").length).toBe(32);
  });

  it("verifyAdminPass：正确口令通过，错误口令拒绝", async () => {
    const stored = await computeAdminPassHash("s3cret");
    await expect(verifyAdminPass("s3cret", stored)).resolves.toBe(true);
    await expect(verifyAdminPass("wrong", stored)).resolves.toBe(false);
  });

  it("verifyAdminPass：畸形/低迭代数存储串一律拒绝", async () => {
    await expect(verifyAdminPass("x", "not-a-hash")).resolves.toBe(false);
    await expect(verifyAdminPass("x", "pbkdf2-sha256$50000$AAAA$BBBB")).resolves.toBe(
      false,
    );
    await expect(verifyAdminPass("x", "")).resolves.toBe(false);
  });
});

describe("HMAC token（§9：8h 过期，签名校验）", () => {
  it("签发 → 校验往返", async () => {
    const token = await newAdminToken(KEY);
    const claims = await verifyToken(KEY, token);
    expect(claims).not.toBeNull();
    expect(claims!.sub).toBe("admin");
    // exp ≈ now + 8h
    const delta = claims!.exp - Date.now();
    expect(delta).toBeGreaterThan(ADMIN_TOKEN_TTL_MS - 5000);
    expect(delta).toBeLessThanOrEqual(ADMIN_TOKEN_TTL_MS);
  });

  it("篡改 payload → 拒绝", async () => {
    const token = await newAdminToken(KEY);
    const [h, p, s] = token.split(".");
    const forged = Buffer.from(
      JSON.stringify({ sub: "admin", exp: Date.now() + 99_000_000 }),
    ).toString("base64url");
    await expect(verifyToken(KEY, `${h}.${forged}.${s}`)).resolves.toBeNull();
  });

  it("错误密钥 → 拒绝", async () => {
    const token = await newAdminToken(KEY);
    const other = new Uint8Array(32).fill(8);
    await expect(verifyToken(other, token)).resolves.toBeNull();
  });

  it("过期 token → 拒绝", async () => {
    const expired: TokenClaims = { sub: "admin", exp: Date.now() - 1000 };
    const token = await signToken(KEY, expired);
    await expect(verifyToken(KEY, token)).resolves.toBeNull();
  });

  it("sub 非 admin → 拒绝", async () => {
    const claims = { sub: "user" as string, exp: Date.now() + 3600_000 };
    const token = await signToken(KEY, claims as unknown as TokenClaims);
    await expect(verifyToken(KEY, token)).resolves.toBeNull();
  });

  it("格式错误 → 拒绝", async () => {
    await expect(verifyToken(KEY, "garbage")).resolves.toBeNull();
    await expect(verifyToken(KEY, "a.b")).resolves.toBeNull();
  });
});

describe("checkAdminPassword（生产 secret / 本地 dev / 未配置）", () => {
  it("有 ADMIN_PASS_HASH：按 PBKDF2 校验", async () => {
    const stored = await computeAdminPassHash("prod-pass");
    await expect(
      checkAdminPassword("prod-pass", stored, undefined),
    ).resolves.toEqual({ ok: true });
    await expect(
      checkAdminPassword("nope", stored, undefined),
    ).resolves.toEqual({ ok: false, reason: "bad-password" });
  });

  it("无 secret 但有 DEV_ADMIN_PASSWORD：本地开发兜底", async () => {
    await expect(
      checkAdminPassword("dida-local-pass", undefined, "dida-local-pass"),
    ).resolves.toEqual({ ok: true, local: true });
    await expect(
      checkAdminPassword("x", undefined, "dida-local-pass"),
    ).resolves.toEqual({ ok: false, reason: "bad-password", local: true });
  });

  it("两者皆无：not-configured", async () => {
    await expect(checkAdminPassword("x", undefined, undefined)).resolves.toEqual(
      { ok: false, reason: "not-configured" },
    );
  });
});
