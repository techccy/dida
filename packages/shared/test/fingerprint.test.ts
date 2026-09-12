import { describe, it, expect } from "vitest";
import { computeFingerprint } from "../src/fingerprint";

const A = new Uint8Array(32).fill(1);
const B = new Uint8Array(32).fill(2);
const SALT = new Uint8Array(32).fill(3);

describe("computeFingerprint", () => {
  it("格式 XXXX-XXXX-XXXX-XXXX（16 位 Crockford）", async () => {
    const fp = await computeFingerprint(A, B, SALT);
    expect(fp).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(fp.replace(/-/g, "")).toHaveLength(16);
  });

  it("双方输入顺序固定（admin 在前）→ 一致", async () => {
    const f1 = await computeFingerprint(A, B, SALT);
    const f2 = await computeFingerprint(A, B, SALT);
    expect(f1).toBe(f2);
  });

  it("交换公钥顺序 → 不同指纹（顺序敏感）", async () => {
    const f1 = await computeFingerprint(A, B, SALT);
    const f2 = await computeFingerprint(B, A, SALT);
    expect(f1).not.toBe(f2);
  });

  it("MITM 模拟：A 看到假 B'，B 看到假 A' → 双方指纹不同", async () => {
    const fakeB = new Uint8Array(32).fill(9);
    const fakeA = new Uint8Array(32).fill(9);
    const fpA = await computeFingerprint(A, fakeB, SALT); // A 端：真实 A 公钥 + 被篡改的 B 公钥
    const fpB = await computeFingerprint(fakeA, B, SALT); // B 端：被篡改的 A 公钥 + 真实 B 公钥
    expect(fpA).not.toBe(fpB);
  });

  it("salt 不同 → 指纹不同", async () => {
    const salt2 = new Uint8Array(32).fill(4);
    const f1 = await computeFingerprint(A, B, SALT);
    const f2 = await computeFingerprint(A, B, salt2);
    expect(f1).not.toBe(f2);
  });

  it("长度校验", async () => {
    await expect(computeFingerprint(new Uint8Array(31), B, SALT)).rejects.toThrow();
    await expect(computeFingerprint(A, new Uint8Array(33), SALT)).rejects.toThrow();
    await expect(computeFingerprint(A, B, new Uint8Array(1))).rejects.toThrow();
  });
});
