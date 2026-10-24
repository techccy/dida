import { describe, it, expect } from "vitest";
import {
  crockfordEncode,
  crockfordDecode,
  generateCode,
  codeKind,
  isValidCode,
  isValidCodeOfKind,
  formatCode,
  normalizeCode,
  sha256,
  sha256Hex,
  bytesToB64,
  b64ToBytes,
  bytesToHex,
  hexToBytes,
} from "../src/code";
import { CROCKFORD_ALPHABET, CODE_RANDOM_LENGTH } from "../src/constants";

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

describe("generateCode", () => {
  it("前缀 + 8 位 Crockford 字符，类型判定正确", () => {
    for (let i = 0; i < 200; i++) {
      const chat = generateCode("chat");
      const extract = generateCode("extract");
      expect(chat).toHaveLength(1 + CODE_RANDOM_LENGTH);
      expect(chat![0]).toBe("C");
      expect(extract[0]).toBe("E");
      expect(codeKind(chat)).toBe("chat");
      expect(codeKind(extract)).toBe("extract");
      expect(isValidCode(chat)).toBe(true);
      expect(isValidCode(extract)).toBe(true);
      expect(isValidCodeOfKind(chat, "chat")).toBe(true);
      expect(isValidCodeOfKind(chat, "extract")).toBe(false);
      for (const ch of chat.slice(1) + extract.slice(1)) {
        expect("ILOU".includes(ch)).toBe(false);
      }
    }
  });

  it("随机且基本均匀", () => {
    const codes = new Set(
      Array.from({ length: 1000 }, () => generateCode("chat")),
    );
    expect(codes.size).toBe(1000);
  });

  it("确定性：给定随机字节", () => {
    const b = new Uint8Array(12);
    for (let i = 0; i < 12; i++) b[i] = i + 1;
    expect(generateCode("chat", b)).toBe(generateCode("chat", new Uint8Array(b)));
  });
});

describe("isValidCode / formatCode / normalizeCode", () => {
  it("非法输入被拒绝", () => {
    expect(isValidCode("CABC123")).toBe(false); // 随机部分不足 8 位
    expect(isValidCode("CABC123456")).toBe(false); // 超长
    expect(isValidCode("DABC12345")).toBe(false); // 非法前缀
    expect(codeKind("CABC12345")).toBe("chat");
    expect(codeKind("CABC123")).toBe(null);
    expect(codeKind("XABC12345")).toBe(null);
  });

  it("I/L/O/U 出现在随机段时校验失败（Crockford 排除字符）", () => {
    expect(isValidCode("EIABC1234")).toBe(false);
    expect(isValidCode("EABC1234O")).toBe(false);
  });

  it("formatCode 插入连字符，normalizeCode 剥离", () => {
    expect(formatCode("EABC12345")).toBe("E-ABC12345");
    expect(formatCode("C-ABC12345")).toBe("C-ABC12345");
    expect(normalizeCode("e-ab c123 45")).toBe("EABC12345");
    expect(isValidCode(normalizeCode("e-ab c123 45"))).toBe(true);
  });

  it("归一化后可通过格式校验", () => {
    const raw = "c - a b 3d 5f 7h";
    expect(isValidCode(normalizeCode(raw))).toBe(true);
    expect(codeKind(normalizeCode(raw))).toBe("chat");
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
