/**
 * 安全指纹派生（§5.4）—— 纯函数，仅前端使用，DO 不参与计算。
 *
 *   fingerprint = CrockfordBase32( SHA-256( pubAdmin ‖ pubParticipant ‖ salt )[0:10] )
 *   → 16 字符，格式化 XXXX-XXXX-XXXX-XXXX
 *
 * 输入顺序固定（admin 公钥在前），双方各自本地算出同一值。
 * 若 DO 主动 MITM（给双方不同的假公钥），双方算出不同指纹，OOB 核对即可发现。
 */
import {
  FINGERPRINT_PREFIX_BYTES,
} from "./constants";
import { crockfordEncode, sha256 } from "./code";

const PUB_BYTES = 32;

export async function computeFingerprint(
  pubAdmin: Uint8Array,
  pubParticipant: Uint8Array,
  salt: Uint8Array,
): Promise<string> {
  if (pubAdmin.length !== PUB_BYTES) throw new Error("pubAdmin 必须 32 字节");
  if (pubParticipant.length !== PUB_BYTES)
    throw new Error("pubParticipant 必须 32 字节");
  if (salt.length !== PUB_BYTES) throw new Error("salt 必须 32 字节");

  const concat = new Uint8Array(PUB_BYTES * 3);
  concat.set(pubAdmin, 0);
  concat.set(pubParticipant, PUB_BYTES);
  concat.set(salt, PUB_BYTES * 2);

  const digest = await sha256(concat);
  const prefix = digest.slice(0, FINGERPRINT_PREFIX_BYTES); // 10 字节 = 80 bit = 16 字符
  const raw = crockfordEncode(prefix);
  return raw.replace(/(.{4})(?=.)/g, "$1-");
}
