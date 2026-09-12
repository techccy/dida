/**
 * 邀请码与哈希工具（§8）
 * - 12 位 Crockford Base32（≈60 bit 熵）
 * - 码的明文从不上盘：DO 只存 SHA-256 哈希
 */
import { CROCKFORD_ALPHABET, CODE_LENGTH } from "./constants";

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** 将字节数组编码为 Crockford Base32（要求长度是 5 bit 的整数倍） */
export function crockfordEncode(bytes: Uint8Array): string {
  const bits = bytes.length * 8;
  if (bits % 5 !== 0) throw new Error("crockfordEncode: 字节长度必须为 5 的倍数(bit)");
  const n = bytesToBigInt(bytes);
  const chars = bits / 5;
  let out = "";
  for (let i = 0; i < chars; i++) {
    const idx = Number((n >> BigInt((chars - 1 - i) * 5)) & 31n);
    out += CROCKFORD_ALPHABET[idx];
  }
  return out;
}

/** 将 Crockford Base32 字符串解码为字节（忽略大小写） */
export function crockfordDecode(s: string): Uint8Array {
  const upper = s.toUpperCase();
  let n = 0n;
  for (const ch of upper) {
    const idx = CROCKFORD_ALPHABET.indexOf(ch as (typeof CROCKFORD_ALPHABET)[number]);
    if (idx < 0) throw new Error("crockfordDecode: 非法字符 " + ch);
    n = (n << 5n) | BigInt(idx);
  }
  const bytes = new Uint8Array((upper.length * 5) / 8);
  const bits = upper.length * 5;
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number((n >> BigInt(bits - 8 * (i + 1))) & 0xffn);
  }
  return bytes;
}

/**
 * 生成 12 位邀请码：取 12 字节随机数的低 60 bit → 12 个 Crockford 字符。
 * 低 60 bit 在均匀 96 bit 中仍是均匀的，熵 = 60 bit。
 */
export function generateInviteCode(randomBytes?: Uint8Array): string {
  const buf =
    randomBytes ?? crypto.getRandomValues(new Uint8Array(CODE_LENGTH));
  if (buf.length < CODE_LENGTH) throw new Error("随机字节不足");
  const n = bytesToBigInt(buf) & ((1n << 60n) - 1n);
  let out = "";
  for (let i = 0; i < CODE_LENGTH; i++) {
    const idx = Number((n >> BigInt((CODE_LENGTH - 1 - i) * 5)) & 31n);
    out += CROCKFORD_ALPHABET[idx];
  }
  return out;
}

/** 校验邀请码格式（12 位 Crockford） */
export function isValidCode(s: string): boolean {
  return /^[0-9A-HJKMNP-TV-Z]{12}$/.test(s);
}

/** 归一化用户输入：大写、去空格/分隔符（允许用户输入小写或带空格） */
export function normalizeCode(s: string): string {
  return s.toUpperCase().replace(/[\s\-_]/g, "");
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const src = typeof data === "string" ? utf8Encode(data) : data;
  // 复制一份拥有独立 ArrayBuffer 的视图，满足 crypto.subtle 的 BufferSource 类型要求
  const buf = new Uint8Array(src);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return bytesToHex(await sha256(data));
}

export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function utf8Decode(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0)
    throw new Error("hexToBytes: 非法 hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

export function b64ToBytes(s: string): Uint8Array {
  const str = atob(s);
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i);
  return out;
}
