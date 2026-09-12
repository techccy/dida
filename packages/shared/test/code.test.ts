import { describe, it, expect } from "vitest";
import {
  crockfordEncode,
  crockfordDecode,
  generateInviteCode,
  isValidCode,
  normalizeCode,
  sha256,
  sha256Hex,
  bytesToB64,
  b64ToBytes,
  bytesToHex,
  hexToBytes,
} from "../src/code";
import { CROCKFORD_ALPHABET, CODE_LENGTH } from "../src/constants";

describe("crockford", () => {
  it("encode/decode roundtrip（字节数须为 5 的倍数：bit 数为 5 的整倍数）", () => {
    for (const len of [5, 10, 15, 20, 25, 30]) {
      const bytes = new Uint8Array(len);
      crypto.getRandomValues(bytes);
      const enc = crockfordEncode(bytes);
      expect(enc).toHaveLength((len * 8) / 5);
      expect(crockfordDecode(enc)).toEqual(bytes);
    }
  });

  it("只支持 5 整倍数 bit 的长度", () => {
    expect(() => crockfordEncode(new Uint8Array(32))).toThrow();
  });

  it("only uses alphabet (no I/L/O/U)", () => {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    const enc = crockfordEncode(bytes);
    for (const ch of enc) {
      expect("ILOU".includes(ch)).toBe(false);
      expect(CROCKFORD_ALPHABET.includes(ch as never)).toBe(true);
    }
  });

  it("decodes lowercase", () => {
    const bytes = new Uint8Array(5);
    bytes[0] = 0x01;
    const enc = crockfordEncode(bytes);
    expect(crockfordDecode(enc.toLowerCase())).toEqual(bytes);
  });
});

describe("generateInviteCode", () => {
  it("12 位 Crockford 字符", () => {
    for (let i = 0; i < 200; i++) {
      const code = generateInviteCode();
      expect(code).toHaveLength(CODE_LENGTH);
      expect(isValidCode(code)).toBe(true);
    }
  });

  it("随机且基本均匀", () => {
    const codes = new Set(Array.from({ length: 1000 }, () => generateInviteCode()));
    expect(codes.size).toBe(1000);
  });

  it("确定性：给定随机字节", () => {
    const b = new Uint8Array(12);
    for (let i = 0; i < 12; i++) b[i] = i + 1;
    expect(generateInviteCode(b)).toBe(generateInviteCode(new Uint8Array(b)));
  });
});

describe("normalizeCode", () => {
  it("大小写与空格/分隔符归一化", () => {
    expect(normalizeCode("abcd ef12-gh34")).toBe("ABCDEF12GH34");
    expect(normalizeCode("a-b-c-d-e-f-g-h-1-2-3-4")).toBe("ABCDEFGH1234");
    expect(normalizeCode("  A B C D E F G H 1 2 3 4 ")).toBe("ABCDEFGH1234");
  });

  it("归一化后可通过格式校验", () => {
    const raw = "a b c d e f g h 1 2 3 4";
    expect(isValidCode(normalizeCode(raw))).toBe(true);
  });
});

describe("sha256", () => {
  it("known vector (empty)", async () => {
    expect(await sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("known vector (abc)", async () => {
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("byte input equals string input", async () => {
    expect(await bytesToHex(await sha256(new TextEncoder().encode("dida")))).toBe(
      await sha256Hex("dida"),
    );
  });
});

describe("b64/hex", () => {
  it("b64 roundtrip", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    expect(b64ToBytes(bytesToB64(bytes))).toEqual(bytes);
  });

  it("hex roundtrip", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });
});
