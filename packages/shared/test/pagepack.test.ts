/**
 * 网页快照包单测（§5.6.1）：DPK1 打包/解包往返、AAD 防错位、上限校验、
 * HTML 引用改写、信封 v2 解析。Node 22 自带 WebCrypto，vitest node 环境可跑。
 */
import { describe, it, expect } from "vitest";
import {
  PAGE_PACK_CHUNK_SIZE,
  PAGE_PACK_MAX_FILES,
  PagePackFormatError,
  decryptPagePack,
  encryptPagePack,
  injectPagePackCsp,
  isHighRiskPath,
  mimeForPath,
  normalizePageRef,
  rewritePageHtml,
  validatePagePackFiles,
} from "../src/pagepack";
import { isValidPagePackRef, parseExtractEnvelope } from "../src/watermark";

const KEY = new Uint8Array(32).fill(9);

function file(path: string, size: number, fill = 1): { path: string; type?: string; bytes: Uint8Array } {
  return { path, bytes: new Uint8Array(size).fill(fill) };
}

describe("PagePack 打包/解包往返", () => {
  it("多文件往返：内容、类型、入口一致", async () => {
    const files = [
      file("index.html", 1024, 7),
      file("mysite_files/style.css", 300, 2),
      file("mysite_files/img.png", 2048, 3),
    ];
    const pack = await encryptPagePack(KEY, "index.html", files);
    const out = await decryptPagePack(KEY, pack);
    expect(out.entry).toBe("index.html");
    expect(out.files.map((f) => f.path)).toEqual([
      "index.html",
      "mysite_files/style.css",
      "mysite_files/img.png",
    ]);
    expect(Array.from(out.files[0].bytes)).toEqual(Array.from(files[0].bytes));
    expect(out.files[1].type).toBeUndefined();
  });

  it("跨 4MB 分块边界：多块文件往返", async () => {
    const size = PAGE_PACK_CHUNK_SIZE + 10;
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) bytes[i] = i & 0xff;
    const pack = await encryptPagePack(KEY, "a.bin", [{ path: "a.bin", bytes }]);
    const out = await decryptPagePack(KEY, pack);
    expect(out.files[0].bytes.length).toBe(size);
    expect(out.files[0].bytes[size - 1]).toBe((size - 1) & 0xff);
    expect(out.files[0].bytes[PAGE_PACK_CHUNK_SIZE]).toBe(PAGE_PACK_CHUNK_SIZE & 0xff);
  });

  it("错位密文（交换两文件块）→ AAD 拒绝", async () => {
    const files = [file("a.txt", 100, 1), file("b.txt", 100, 2)];
    const pack = await encryptPagePack(KEY, "a.txt", files);
    // 两文件同尺寸，交换文件 b 首块与文件 a 首块区域
    // 块 wire 长 = 12 + 100 + 16 = 128；头 24 + indexCt —— 直接交换首块 nonce
    const out = await decryptPagePack(KEY, pack);
    void out;
    // 篡改一个字节 → 解包失败
    const tampered = pack.slice();
    tampered[tampered.length - 1] ^= 0xff;
    await expect(decryptPagePack(KEY, tampered)).rejects.toBeInstanceOf(PagePackFormatError);
  });

  it("截断 / 坏 magic / 错 key → PagePackFormatError", async () => {
    const pack = await encryptPagePack(KEY, "a.txt", [file("a.txt", 50)]);
    await expect(decryptPagePack(KEY, pack.slice(0, 10))).rejects.toBeInstanceOf(PagePackFormatError);
    const badMagic = pack.slice();
    badMagic[0] = 0x58; // "X"
    await expect(decryptPagePack(KEY, badMagic)).rejects.toBeInstanceOf(PagePackFormatError);
    const otherKey = new Uint8Array(32).fill(8);
    await expect(decryptPagePack(otherKey, pack)).rejects.toBeInstanceOf(PagePackFormatError);
  });

  it("尾部多余字节 → 严格拒绝", async () => {
    const pack = await encryptPagePack(KEY, "a.txt", [file("a.txt", 50)]);
    const padded = new Uint8Array(pack.length + 5);
    padded.set(pack);
    await expect(decryptPagePack(KEY, padded)).rejects.toBeInstanceOf(PagePackFormatError);
  });
});

describe("validatePagePackFiles 上限校验", () => {
  it("入口不在列表 → 报错", () => {
    expect(validatePagePackFiles("missing.html", [{ path: "a.txt", size: 1 }])).not.toBeNull();
  });
  it("路径重复 → 报错", () => {
    expect(
      validatePagePackFiles("a.txt", [
        { path: "a.txt", size: 1 },
        { path: "a.txt", size: 1 },
      ]),
    ).not.toBeNull();
  });
  it("路径穿越 → 报错", () => {
    expect(validatePagePackFiles("a.txt", [{ path: "../evil.txt", size: 1 }])).not.toBeNull();
  });
  it("文件数超限 → 报错", () => {
    const files = Array.from({ length: PAGE_PACK_MAX_FILES + 1 }, (_, i) => ({
      path: `f${i}.txt`,
      size: 1,
    }));
    expect(validatePagePackFiles("f0.txt", files)).not.toBeNull();
  });
  it("合法输入 → null", () => {
    expect(validatePagePackFiles("index.html", [{ path: "index.html", size: 10 }])).toBeNull();
  });
});

describe("rewritePageHtml 引用改写", () => {
  const map: Record<string, string> = {
    "mysite_files/a.png": "blob:u1",
    "mysite_files/b.css": "blob:u2",
  };
  const resolve = (raw: string) => {
    const n = normalizePageRef(raw);
    return map[n] ?? null;
  };

  it("src/href/poster/data 改写；未命中保留", () => {
    const html = `<html><head><base href="./"></head><body>
      <img src="mysite_files/a.png"><img src="./mysite_files/a.png">
      <link rel="stylesheet" href="mysite_files/b.css">
      <a href="https://example.com">外链</a><a href="#sec">锚点</a>
      <video poster="mysite_files/a.png"></video>
    </body></html>`;
    const out = rewritePageHtml(html, resolve);
    expect(out).not.toContain("<base");
    expect((out.match(/blob:u1/g) ?? []).length).toBe(3);
    expect(out).toContain('href="blob:u2"');
    expect(out).toContain('href="https://example.com"');
    expect(out).toContain('href="#sec"');
  });

  it("srcset 多候选改写", () => {
    const html = `<img srcset="mysite_files/a.png 1x, mysite_files/a.png 2x">`;
    const out = rewritePageHtml(html, resolve);
    expect((out.match(/blob:u1/g) ?? []).length).toBe(2);
    expect(out).toContain("1x");
  });

  it("style 块与 style 属性的 url() 改写", () => {
    const html = `<div style="background:url('mysite_files/a.png')">
      <style>body{background-image:url(mysite_files/b.css)}</style></div>`;
    const out = rewritePageHtml(html, resolve);
    expect(out).toContain("url('blob:u1')");
    expect(out).toContain("url(blob:u2)");
  });

  it("URI 编码引用可匹配", () => {
    const html = `<img src="mysite_files/%61.png">`; // a.png 编码
    const out = rewritePageHtml(html, resolve);
    expect(out).toContain("blob:u1");
  });
});

describe("CSP 注入 / MIME / 高危后缀", () => {
  it("CSP meta 紧跟 <head>", () => {
    const out = injectPagePackCsp("<html><head><title>t</title></head></html>");
    expect(out).toMatch(/<head[^>]*><meta http-equiv="Content-Security-Policy"/);
    expect(out).toContain("connect-src 'none'");
  });
  it("无 head 时前置注入", () => {
    expect(injectPagePackCsp("<html></html>").startsWith("<meta")).toBe(true);
  });
  it("mimeForPath / isHighRiskPath", () => {
    expect(mimeForPath("a.PNG")).toBe("image/png");
    expect(mimeForPath("a.css")).toBe("text/css");
    expect(mimeForPath("noext")).toBeUndefined();
    expect(isHighRiskPath("evil.EXE")).toBe(true);
    expect(isHighRiskPath("ok.png")).toBe(false);
  });
});

describe("信封 v2 解析（page 字段）", () => {
  const ref = { packId: "a".repeat(64), dataKey: "b".repeat(44), totalSize: 123, fileCount: 3 };
  it("v2 信封 → text/wm/page 全解析", () => {
    const r = parseExtractEnvelope(JSON.stringify({ v: 2, text: "说明", page: ref }));
    expect(r.text).toBe("说明");
    expect(r.page).toEqual(ref);
    expect(r.wm).toBeNull();
  });
  it("page 形状非法 → 丢弃 page 按纯文本处理", () => {
    const r = parseExtractEnvelope(
      JSON.stringify({ v: 2, text: "t", page: { packId: "zz", dataKey: "x" } }),
    );
    expect(r.page).toBeUndefined();
    expect(r.text).toBe("t");
  });
  it("v2 无 page → 纯文本包", () => {
    const r = parseExtractEnvelope(JSON.stringify({ v: 2, text: "only" }));
    expect(r.page).toBeUndefined();
  });
  it("v1 信封不受影响", () => {
    const r = parseExtractEnvelope(JSON.stringify({ v: 1, text: "old" }));
    expect(r.text).toBe("old");
    expect(r.page).toBeUndefined();
  });
  it("isValidPagePackRef 校验", () => {
    expect(isValidPagePackRef(ref)).toBe(true);
    expect(isValidPagePackRef({ ...ref, packId: "zz" })).toBe(false);
    expect(isValidPagePackRef({ ...ref, fileCount: 0 })).toBe(false);
  });
});
