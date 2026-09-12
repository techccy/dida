import { describe, it, expect, beforeAll } from "vitest";
import {
  generateKeyPair,
  deriveDirectionKeys,
  encryptMsg,
  decryptMsg,
  DecryptError,
  MsgTooLargeError,
  type KeyPair,
} from "../src/crypto/crypto";
import { bytesToB64, b64ToBytes } from "@dida/shared";

let admin: KeyPair;
let part: KeyPair;
const SALT = crypto.getRandomValues(new Uint8Array(32));

beforeAll(async () => {
  admin = await generateKeyPair();
  part = await generateKeyPair();
});

describe("deriveDirectionKeys", () => {
  it("双方共享秘密一致（X25519 ECDH 对称性）", async () => {
    const aSide = await deriveDirectionKeys(
      admin.privateKey,
      part.publicKey,
      SALT,
      "admin",
    );
    const bSide = await deriveDirectionKeys(
      part.privateKey,
      admin.publicKey,
      SALT,
      "participant",
    );
    expect(aSide.sharedSecret).toEqual(bSide.sharedSecret);
    expect(aSide.sharedSecret).toHaveLength(32);
  });

  it("方向性密钥：admin 的 encKey 能被 participant 的 decKey 解密（反之亦然）", async () => {
    const aSide = await deriveDirectionKeys(
      admin.privateKey,
      part.publicKey,
      SALT,
      "admin",
    );
    const bSide = await deriveDirectionKeys(
      part.privateKey,
      admin.publicKey,
      SALT,
      "participant",
    );
    // 密钥本身不可导出（extractable=false）；用加解密行为验证方向对应
    const { nonce: n1, ct: c1 } = await encryptMsg(aSide.encKey, { text: "a→b", ts: 1 }, "admin");
    expect(await decryptMsg(bSide.decKey, "admin", n1, c1)).toEqual({ text: "a→b", ts: 1 });
    const { nonce: n2, ct: c2 } = await encryptMsg(bSide.encKey, { text: "b→a", ts: 2 }, "participant");
    expect(await decryptMsg(aSide.decKey, "participant", n2, c2)).toEqual({ text: "b→a", ts: 2 });
  });

  it("salt 不同 → 密钥不同", async () => {
    const s2 = crypto.getRandomValues(new Uint8Array(32));
    const k1 = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const k2 = await deriveDirectionKeys(admin.privateKey, part.publicKey, s2, "admin");
    // 用 k1 加密，k2 解密 → 应失败
    const { nonce, ct } = await encryptMsg(k1.encKey, { text: "x", ts: 1 }, "admin");
    await expect(decryptMsg(k2.decKey, "admin", nonce, ct)).rejects.toThrow(
      DecryptError,
    );
  });
});

describe("encryptMsg / decryptMsg", () => {
  it("完整往返：admin 加密 → participant 解密", async () => {
    const aSide = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const bSide = await deriveDirectionKeys(part.privateKey, admin.publicKey, SALT, "participant");
    const msg = { text: "你好，dida", ts: 1757596800000 };
    const { nonce, ct } = await encryptMsg(aSide.encKey, msg, "admin");
    expect(nonce).toBeTruthy();
    const out = await decryptMsg(bSide.decKey, "admin", nonce, ct);
    expect(out).toEqual(msg);
  });

  it("用错方向的密钥解密 → 失败（方向性密钥）", async () => {
    const aSide = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const msg = { text: "hi", ts: 1 };
    const { nonce, ct } = await encryptMsg(aSide.encKey, msg, "admin");
    // 管理员自己的 decKey 解密自己发出的 admin 方向消息 → AAD 不匹配
    await expect(
      decryptMsg(aSide.decKey, "admin", nonce, ct),
    ).rejects.toThrow(DecryptError);
  });

  it("跨方向重放：B→A 密文被重放到 A→B 方向 → AAD 拒", async () => {
    const aSide = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const bSide = await deriveDirectionKeys(part.privateKey, admin.publicKey, SALT, "participant");
    // participant 发给 admin 的消息
    const { nonce, ct } = await encryptMsg(bSide.encKey, { text: "x", ts: 2 }, "participant");
    // 攻击者把这条消息当作 admin 发出的重放给 participant → 方向密钥不匹配（且 AAD 不匹配）
    await expect(
      decryptMsg(bSide.decKey, "admin", nonce, ct),
    ).rejects.toThrow(DecryptError);
  });

  it("篡改密文 → 失败", async () => {
    const aSide = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const bSide = await deriveDirectionKeys(part.privateKey, admin.publicKey, SALT, "participant");
    const { nonce, ct } = await encryptMsg(aSide.encKey, { text: "y", ts: 3 }, "admin");
    const ctBytes = b64ToBytes(ct);
    ctBytes[0] ^= 0x01;
    await expect(
      decryptMsg(bSide.decKey, "admin", nonce, bytesToB64(ctBytes)),
    ).rejects.toThrow(DecryptError);
  });

  it("超过 8KB → 拒发（MsgTooLargeError）", async () => {
    const aSide = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const big = { text: "a".repeat(8 * 1024), ts: 4 };
    await expect(
      encryptMsg(aSide.encKey, big, "admin"),
    ).rejects.toThrow(MsgTooLargeError);
  });

  it("8KB 内的长消息可正常加解密", async () => {
    const aSide = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const bSide = await deriveDirectionKeys(part.privateKey, admin.publicKey, SALT, "participant");
    const text = "汉".repeat(4000); // 4000 * 3 bytes ≈ 12KB？超限。用 2000
    const msg = { text: "汉".repeat(2500), ts: 5 };
    const plainBytes = new TextEncoder().encode(JSON.stringify(msg));
    expect(plainBytes.length).toBeLessThanOrEqual(8192);
    const { nonce, ct } = await encryptMsg(aSide.encKey, msg, "admin");
    const out = await decryptMsg(bSide.decKey, "admin", nonce, ct);
    expect(out).toEqual(msg);
    void text;
  });

  it("nonce 每次随机（两次加密结果不同）", async () => {
    const aSide = await deriveDirectionKeys(admin.privateKey, part.publicKey, SALT, "admin");
    const msg = { text: "same", ts: 6 };
    const e1 = await encryptMsg(aSide.encKey, msg, "admin");
    const e2 = await encryptMsg(aSide.encKey, msg, "admin");
    expect(e1.nonce).not.toBe(e2.nonce);
    expect(e1.ct).not.toBe(e2.ct);
  });
});
