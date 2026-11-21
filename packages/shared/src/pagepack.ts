/**
 * 网页快照包（PagePack / DPK1 容器，§5.6.1）【决策 2026-11-21】
 *
 * 架构不变量：
 * - HTML + 资源文件打包成单一加密对象；服务端（DO/R2/日志）只见密文字节——
 *   文件路径、文件名、类型全部在加密索引内，服务端零知识。
 * - dataKey（32B 随机）与 packId（32B 随机）都在加密信封内（ExtractEnvelope v2）；
 *   提取码 → HKDF → 信封密钥链路不变，文件层与码格式解耦。
 * - 分块 AES-256-GCM（4MB/块）：AAD 绑 path#chunkIndex，防重排/删块/跨文件拼接。
 *
 * DPK1 容器布局（二进制，全小端）：
 *   [4B magic "DPK1"][4B version=1][12B indexNonce][4B indexCtLen][indexCt]
 *   [逐文件：逐块 12B nonce + ct(chunk)]
 * 索引 = JSON({ entry, files: [{ path, size, type? }] })，AES-256-GCM(dataKey,
 *   AAD="dida/v1/pagepack/index")。块 ct 含 16B GCM tag；块边界由索引 size 推导。
 *
 * 本模块全部为纯函数（WebCrypto 用 globalThis.crypto.subtle，Node 22 与浏览器通用），
 * 不依赖 DOM；HTML 引用改写为字符串级实现，可在 Node 环境单测。
 */
import { utf8Decode } from "./code";

// ---------- 常量（§5.6.1 上限与协议） ----------

/** 容器 magic（ASCII "DPK1"） */
export const PAGE_PACK_MAGIC = "DPK1";
/** 容器版本（当前唯一） */
export const PAGE_PACK_VERSION = 1;
/** 整包明文上限 64MB（免费档 100MB 请求体硬限留余量） */
export const PAGE_PACK_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
/** 包内单文件明文上限 32MB */
export const PAGE_PACK_FILE_MAX_BYTES = 32 * 1024 * 1024;
/** 文件数上限（覆盖极端 Cmd+S 产物） */
export const PAGE_PACK_MAX_FILES = 500;
/** 分块加密块大小：4MB（移动端内存可控） */
export const PAGE_PACK_CHUNK_SIZE = 4 * 1024 * 1024;
/** 销毁后 R2 对象惰性 GC 宽限（弱网重试窗口，§4.3） */
export const PAGE_PACK_GC_MS = 10 * 60 * 1000;
/** 上传/下载端点 wire 上限：整包明文 + 头部/索引/分块开销容差 */
export const PAGE_PACK_WIRE_MAX_BYTES = PAGE_PACK_MAX_TOTAL_BYTES + 4 * 1024 * 1024;
/** 索引 AAD */
export const PAGE_PACK_AAD_INDEX = "dida/v1/pagepack/index";
/** 文件块 AAD 前缀（后接 `${path}#${chunkIndex}`） */
export const PAGE_PACK_AAD_FILE_PREFIX = "dida/v1/pagepack/file/";
/** 下载端点限流：同 IP ≤20 次/分钟（独立桶，§7.6.1） */
export const PAGE_PACK_DL_MAX_PER_MINUTE = 20;
/** packId 长度（32B hex） */
export const PAGE_PACK_ID_HEX_LENGTH = 64;

// ---------- 类型 ----------

export interface PagePackFileMeta {
  /** 相对引用路径（如 "mysite_files/img.png"）；不出现在服务端可见明文 */
  path: string;
  /** 明文字节数（块边界由此推导） */
  size: number;
  /** MIME 类型（可选；用于 Blob 构造） */
  type?: string;
}

export interface PagePackIndex {
  /** HTML 入口路径（如 "index.html"），必须存在于 files 中 */
  entry: string;
  files: PagePackFileMeta[];
}

export interface PagePackInputFile {
  path: string;
  type?: string;
  bytes: Uint8Array;
}

export interface PagePackOutputFile {
  path: string;
  type?: string;
  bytes: Uint8Array;
}

// ---------- 校验 ----------

/**
 * 校验快照包输入（创建端与解密端共用）。
 * 返回 null = 合法；否则返回人读错误信息（前端直接展示）。
 */
export function validatePagePackFiles(entry: string, files: PagePackFileMeta[]): string | null {
  if (!entry || entry.length > 255) return "入口 HTML 路径非法";
  if (files.length < 1 || files.length > PAGE_PACK_MAX_FILES)
    return `文件数须在 1–${PAGE_PACK_MAX_FILES} 之间`;
  const seen = new Set<string>();
  let total = 0;
  for (const f of files) {
    if (!f.path || f.path.length > 512) return "文件路径非法";
    if (f.path.includes("..") || f.path.startsWith("/") || f.path.includes("\\")) return "文件路径含非法片段";
    if (seen.has(f.path)) return `文件路径重复：${f.path}`;
    seen.add(f.path);
    if (!Number.isInteger(f.size) || f.size < 0 || f.size > PAGE_PACK_FILE_MAX_BYTES)
      return `单文件超过 ${PAGE_PACK_FILE_MAX_BYTES / 1024 / 1024}MB 上限：${f.path}`;
    total += f.size;
    if (total > PAGE_PACK_MAX_TOTAL_BYTES)
      return `整包超过 ${PAGE_PACK_MAX_TOTAL_BYTES / 1024 / 1024}MB 上限`;
  }
  if (!seen.has(entry)) return "入口 HTML 不在文件列表中";
  return null;
}

// ---------- 内部工具 ----------

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function writeU32LE(buf: Uint8Array, offset: number, v: number): void {
  buf[offset] = v & 0xff;
  buf[offset + 1] = (v >>> 8) & 0xff;
  buf[offset + 2] = (v >>> 16) & 0xff;
  buf[offset + 3] = (v >>> 24) & 0xff;
}

function readU32LE(buf: Uint8Array, offset: number): number {
  return (
    buf[offset] |
    (buf[offset + 1] << 8) |
    (buf[offset + 2] << 16) |
    (buf[offset + 3] << 24)
  ) >>> 0;
}

function aesKey(dataKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    dataKey.slice().buffer,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function aadBytes(aad: string): ArrayBuffer {
  return utf8(aad).slice().buffer;
}

/** 单块加密：输出 [12B nonce][ct(含 16B tag)] */
async function encryptChunk(
  key: CryptoKey,
  aad: string,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce.slice().buffer, additionalData: aadBytes(aad) },
      key,
      plaintext.slice().buffer,
    ),
  );
  return concatBytes([nonce, ct]);
}

/** 单块解密：输入 [12B nonce][ct]，AAD 不符/篡改抛错 */
async function decryptChunk(
  key: CryptoKey,
  aad: string,
  wire: Uint8Array,
): Promise<Uint8Array> {
  if (wire.length < 12 + 16) throw new PagePackFormatError();
  const plain = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: wire.slice(0, 12).buffer,
      additionalData: aadBytes(aad),
    },
    key,
    wire.slice(12).buffer,
  );
  return new Uint8Array(plain);
}

function chunkAad(path: string, chunkIndex: number): string {
  return PAGE_PACK_AAD_FILE_PREFIX + path + "#" + chunkIndex;
}

// ---------- 格式错误 ----------

export class PagePackFormatError extends Error {
  constructor() {
    super("PagePack 容器格式非法或密文损坏");
    this.name = "PagePackFormatError";
  }
}

// ---------- 打包（管理员端） ----------

/**
 * 打包并加密快照包（DPK1）。
 * 输入文件总明文超限抛 validatePagePackFiles 的错误信息（Error）。
 * 输出字节 = 头部 + 索引密文 + 逐文件逐块密文，可整体作为
 * octet-stream 请求体上传（wire 长度 ≤ PAGE_PACK_WIRE_MAX_BYTES）。
 */
export async function encryptPagePack(
  dataKey: Uint8Array,
  entry: string,
  files: PagePackInputFile[],
): Promise<Uint8Array> {
  const metas = files.map((f) => ({ path: f.path, size: f.bytes.length, type: f.type }));
  const err = validatePagePackFiles(entry, metas);
  if (err) throw new Error(err);

  const key = await aesKey(dataKey);
  const indexJson = utf8(JSON.stringify({ entry, files: metas }));
  const indexNonce = crypto.getRandomValues(new Uint8Array(12));
  const indexCt = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: indexNonce.slice().buffer,
        additionalData: aadBytes(PAGE_PACK_AAD_INDEX),
      },
      key,
      indexJson.slice().buffer,
    ),
  );

  // 计算 wire 总长：头 24B + indexCt + Σ块(12 + chunkLen + 16)
  let wireLen = 24 + indexCt.length;
  for (const f of files) {
    const chunks = Math.max(1, Math.ceil(f.bytes.length / PAGE_PACK_CHUNK_SIZE));
    for (let i = 0; i < chunks; i++) {
      const len = Math.min(PAGE_PACK_CHUNK_SIZE, f.bytes.length - i * PAGE_PACK_CHUNK_SIZE);
      wireLen += 12 + len + 16;
    }
  }
  if (wireLen > PAGE_PACK_WIRE_MAX_BYTES) throw new Error("整包超过 wire 上限");

  const out = new Uint8Array(wireLen);
  out.set(utf8(PAGE_PACK_MAGIC), 0);
  writeU32LE(out, 4, PAGE_PACK_VERSION);
  out.set(indexNonce, 8);
  writeU32LE(out, 20, indexCt.length);
  out.set(indexCt, 24);
  let off = 24 + indexCt.length;

  for (const f of files) {
    const chunks = Math.max(1, Math.ceil(f.bytes.length / PAGE_PACK_CHUNK_SIZE));
    for (let i = 0; i < chunks; i++) {
      const start = i * PAGE_PACK_CHUNK_SIZE;
      const plain = f.bytes.slice(start, start + PAGE_PACK_CHUNK_SIZE);
      const wire = await encryptChunk(key, chunkAad(f.path, i), plain);
      out.set(wire, off);
      off += wire.length;
    }
  }
  return out;
}

// ---------- 解包（提取者端） ----------

/**
 * 解包快照包：解密索引 → 逐文件解密。
 * 容器格式非法 / 密文损坏 / AAD 不符 / 尾部字节不齐 → PagePackFormatError。
 */
export async function decryptPagePack(
  dataKey: Uint8Array,
  pack: Uint8Array,
): Promise<{ entry: string; files: PagePackOutputFile[] }> {
  if (pack.length < 24) throw new PagePackFormatError();
  const magic = utf8Decode(pack.slice(0, 4));
  if (magic !== PAGE_PACK_MAGIC) throw new PagePackFormatError();
  const version = readU32LE(pack, 4);
  if (version !== PAGE_PACK_VERSION) throw new PagePackFormatError();

  const indexCtLen = readU32LE(pack, 20);
  if (indexCtLen > pack.length - 24) throw new PagePackFormatError();

  const key = await aesKey(dataKey);
  let plain: Uint8Array;
  try {
    // 头部布局中 indexNonce(8..20) 与 indexCt(24..24+len) 被 ctLen 字段隔开，
    // 组装成 [nonce][ct] 连续布局后解密
    plain = await decryptChunk(
      key,
      PAGE_PACK_AAD_INDEX,
      concatBytes([pack.slice(8, 20), pack.slice(24, 24 + indexCtLen)]),
    );
  } catch {
    throw new PagePackFormatError();
  }
  let index: PagePackIndex;
  try {
    const obj = JSON.parse(new TextDecoder().decode(plain)) as PagePackIndex;
    if (
      typeof obj.entry !== "string" ||
      !Array.isArray(obj.files) ||
      obj.files.some(
        (f) =>
          typeof f?.path !== "string" ||
          !Number.isInteger(f?.size) ||
          (f.size as number) < 0,
      )
    )
      throw new Error("bad index");
    index = obj;
  } catch {
    throw new PagePackFormatError();
  }
  const err = validatePagePackFiles(index.entry, index.files);
  if (err) throw new PagePackFormatError();

  let off = 24 + indexCtLen;
  const files: PagePackOutputFile[] = [];
  let total = 0;
  for (const meta of index.files) {
    const chunks = Math.max(1, Math.ceil(meta.size / PAGE_PACK_CHUNK_SIZE));
    const parts: Uint8Array[] = [];
    let consumed = 0;
    for (let i = 0; i < chunks; i++) {
      const chunkLen = Math.min(PAGE_PACK_CHUNK_SIZE, meta.size - consumed);
      const wireLen = 12 + chunkLen + 16;
      if (off + wireLen > pack.length) throw new PagePackFormatError();
      let chunkPlain: Uint8Array;
      try {
        chunkPlain = await decryptChunk(
          key,
          chunkAad(meta.path, i),
          pack.slice(off, off + wireLen),
        );
      } catch {
        throw new PagePackFormatError();
      }
      parts.push(chunkPlain);
      consumed += chunkPlain.length;
      off += wireLen;
    }
    if (consumed !== meta.size) throw new PagePackFormatError();
    total += consumed;
    if (total > PAGE_PACK_MAX_TOTAL_BYTES) throw new PagePackFormatError();
    files.push({ path: meta.path, type: meta.type, bytes: concatBytes(parts) });
  }
  if (off !== pack.length) throw new PagePackFormatError();
  return { entry: index.entry, files };
}

// ---------- HTML 引用改写（字符串级纯函数，§5.6.1 第 3 步） ----------

/**
 * 归一化 HTML 引用用于索引匹配：剥查询串/锚点、URI 解码、剥 "./" 前缀。
 * 匹配不上原样返回（调用方 resolve 返回 null 时保持不变）。
 */
export function normalizePageRef(raw: string): string {
  let s = raw.trim();
  const q = s.indexOf("?");
  if (q >= 0) s = s.slice(0, q);
  const h = s.indexOf("#");
  if (h >= 0) s = s.slice(0, h);
  try {
    s = decodeURIComponent(s);
  } catch {
    /* 保留原值 */
  }
  if (s.startsWith("./")) s = s.slice(2);
  return s;
}

/**
 * 改写 HTML 中的资源引用为调用方提供的 URL（blob: URL）。
 * 覆盖：src/href/poster/data 属性、srcset 候选、<style> 块与 style 属性的 url(...)；
 * 移除 <base>（防止相对引用逃逸）。匹配不上的引用原样保留（含外链、锚点）。
 * resolve 收到【原始引用值】，返回 null = 不改写。
 */
export function rewritePageHtml(
  html: string,
  resolve: (rawRef: string) => string | null,
): string {
  let out = html.replace(/<base\b[^>]*>/gi, "");

  // src / href / poster / data 属性
  out = out.replace(
    /\s(src|href|poster|data)\s*=\s*("([^"]*)"|'([^']*)')/gi,
    (m, attr: string, _q: string, dq?: string, sq?: string) => {
      const val = dq ?? sq ?? "";
      const mapped = resolve(val);
      if (mapped === null) return m;
      return ` ${attr}="${mapped}"`;
    },
  );

  // srcset（多候选 "url 2x, url 1x"）
  out = out.replace(
    /\ssrcset\s*=\s*("([^"]*)"|'([^']*)')/gi,
    (_m, _q: string, dq?: string, sq?: string) => {
      const val = dq ?? sq ?? "";
      const parts = val
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean)
        .map((cand) => {
          const seg = cand.split(/\s+/);
          const mapped = resolve(seg[0] ?? "");
          if (mapped !== null) seg[0] = mapped;
          return seg.join(" ");
        });
      return ` srcset="${parts.join(", ")}"`;
    },
  );

  // url(...)（<style> 块与 style 属性共用）
  out = out.replace(
    /url\(\s*(['"]?)([^)'"]+)\1\s*\)/gi,
    (m, q: string, val: string) => {
      const mapped = resolve(val.trim());
      if (mapped === null) return m;
      return `url(${q}${mapped}${q})`;
    },
  );

  return out;
}

/**
 * 在 HTML 中注入 CSP meta（紧跟 <head> 之后；无 head 时前置）。
 * 【决策：JS 开 + 封外联】——保真渲染 + 提取者 IP 不泄漏给原页面追踪脚本。
 */
export const PAGE_PACK_CSP = [
  "default-src 'none'",
  "script-src blob: 'unsafe-inline'",
  "style-src blob: data: 'unsafe-inline'",
  "img-src blob: data:",
  "font-src blob: data:",
  "media-src blob: data:",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
].join("; ");

export function injectPagePackCsp(html: string): string {
  const meta = `<meta http-equiv="Content-Security-Policy" content="${PAGE_PACK_CSP.replace(/"/g, "")}">`;
  const headOpen = /<head[^>]*>/i.exec(html);
  if (headOpen) {
    const at = headOpen.index + headOpen[0].length;
    return html.slice(0, at) + meta + html.slice(at);
  }
  return meta + html;
}

// ---------- MIME / 高危后缀 ----------

const EXT_MIME: Record<string, string> = {
  html: "text/html",
  htm: "text/html",
  css: "text/css",
  js: "text/javascript",
  mjs: "text/javascript",
  json: "application/json",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  avif: "image/avif",
  svg: "image/svg+xml",
  ico: "image/x-icon",
  bmp: "image/bmp",
  mp4: "video/mp4",
  webm: "video/webm",
  mp3: "audio/mpeg",
  ogg: "audio/ogg",
  wav: "audio/wav",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
  otf: "font/otf",
  eot: "application/vnd.ms-fontobject",
  txt: "text/plain",
  wasm: "application/wasm",
  xml: "application/xml",
};

export function mimeForPath(path: string): string | undefined {
  const dot = path.lastIndexOf(".");
  if (dot < 0) return undefined;
  return EXT_MIME[path.slice(dot + 1).toLowerCase()];
}

const HIGH_RISK_EXTS = new Set([
  "exe", "msi", "dmg", "pkg", "bat", "cmd", "sh", "ps1",
  "apk", "appimage", "deb", "rpm", "scr", "vbs", "jar",
]);

/** 高危可执行后缀（提取页一次性警示，§5.6.1；仅警示不拦截） */
export function isHighRiskPath(path: string): boolean {
  const dot = path.lastIndexOf(".");
  if (dot < 0) return false;
  return HIGH_RISK_EXTS.has(path.slice(dot + 1).toLowerCase());
}
