/**
 * 管理员会话 token 单元测试（§9）：HMAC 签发/校验。
 * Node 22 自带 WebCrypto（crypto.subtle），vitest node 环境即可运行。
 */
import { describe, it, expect } from "vitest";
import {
  signToken,
  verifyToken,
  newAdminToken,
  type TokenClaims,
} from "../src/admin";
import { ADMIN_TOKEN_TTL_MS } from "@dida/shared";

const KEY = new Uint8Array(32).fill(7);

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
