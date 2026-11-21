/**
 * 快照包路由（§5.6.1、§7.6.1）【决策 2026-11-21】
 * - POST   /admin/extracts/pagepack            管理员上传 pack（Bearer；流式校验 magic/长度 → R2）
 * - DELETE /admin/extracts/pagepack/:packId    管理员回收（创建失败清理，不留孤儿对象）
 * - GET    /extract/file/:packId               能力 URL 下载（无鉴权；packId=256-bit 随机 id，
 *                                              非凭证仅可达密文，§7.6.1 显式例外；支持单段 Range）
 *
 * 服务端对 pack 只有字节数与随机 id：路径/文件名/类型全在加密索引内（DPK1 容器），
 * 解密 dataKey 只存在于加密信封。零内容日志（§11）。
 */
import {
  PAGE_PACK_MAGIC,
  PAGE_PACK_WIRE_MAX_BYTES,
  PAGE_PACK_ID_HEX_LENGTH,
} from "@dida/shared";
import { verifyToken } from "../admin";
import { clientIp, getSigningKey, json, type Env } from "../env";

const PACK_ID_RE = new RegExp(`^[0-9a-f]{${PAGE_PACK_ID_HEX_LENGTH}}$`);

async function adminOk(request: Request, env: Env): Promise<boolean> {
  const h = request.headers.get("Authorization");
  if (!h || !h.startsWith("Bearer ")) return false;
  const token = h.slice("Bearer ".length).trim();
  if (!token) return false;
  const claims = await verifyToken(await getSigningKey(env), token);
  return claims !== null;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const x of bytes) out += x.toString(16).padStart(2, "0");
  return out;
}

/**
 * 上传：POST /admin/extracts/pagepack（octet-stream，content-length 必填）。
 * 边读边校验 magic 后经 FixedLengthStream 直通 R2 PUT——不在 isolate 缓冲整包
 * （128MB 内存上限；64MB pack 不可整体缓冲）。
 */
export async function handlePackUpload(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "POST") return json({ error: "not-found" }, 404);
  if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);

  const ctHeader = request.headers.get("Content-Type") ?? "";
  if (!ctHeader.startsWith("application/octet-stream"))
    return json({ error: "bad-request" }, 400);
  const lenHeader = request.headers.get("Content-Length");
  const totalLen = lenHeader ? Number(lenHeader) : NaN;
  if (
    !Number.isInteger(totalLen) ||
    totalLen < 1 ||
    totalLen > PAGE_PACK_WIRE_MAX_BYTES
  )
    return json({ error: "too-large" }, 413);
  if (!request.body) return json({ error: "bad-request" }, 400);

  const packId = hex(crypto.getRandomValues(new Uint8Array(32)));
  const reader = request.body.getReader();
  const first = await reader.read();
  if (first.done || !first.value || first.value.length < 4) {
    return json({ error: "bad-request" }, 400);
  }
  const magic = new TextDecoder().decode(first.value.slice(0, 4));
  if (magic !== PAGE_PACK_MAGIC) return json({ error: "bad-request" }, 400);

  // R2 PUT 要求定长流：content-length 已知，用 FixedLengthStream 桥接
  const fixed = new FixedLengthStream(totalLen);
  const put = env.PACKS.put(packId, fixed.readable, {
    httpMetadata: { contentType: "application/octet-stream" },
  });
  try {
    const writer = fixed.writable.getWriter();
    await writer.write(first.value);
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      await writer.write(chunk.value);
    }
    await writer.close();
    await put;
  } catch {
    return json({ error: "upload-failed" }, 502);
  }
  return json({ packId }, 201);
}

/** 回收：DELETE /admin/extracts/pagepack/:packId（创建失败清理；幂等） */
export async function handlePackDelete(
  request: Request,
  env: Env,
  packId: string,
): Promise<Response> {
  if (request.method !== "DELETE") return json({ error: "not-found" }, 404);
  if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
  if (!PACK_ID_RE.test(packId)) return json({ error: "bad-request" }, 400);
  await env.PACKS.delete(packId);
  return json({ ok: true });
}

/** 单段 Range 解析：仅支持 bytes=start-end 与 bytes=start-；其余形式按整包返回 */
function parseRange(
  header: string | null,
): { start?: number; end?: number } | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m) return null;
  const [, s, e] = m;
  if (s === "" && e === "") return null;
  if (s === "") return null; // 后缀形式（bytes=-n）不支持：按整包返回
  const start = Number(s);
  if (!Number.isInteger(start)) return null;
  return { start, end: e === "" ? undefined : Number(e) };
}

/**
 * 下载：GET /extract/file/:packId（能力 URL，§7.6.1）。
 * 限流独立桶 ≤20 次/分钟/IP（重试/续传合法高频）；支持单段 Range（断点续传）。
 */
export async function handlePackDownload(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "GET") return json({ error: "not-found" }, 404);

  const guard = env.GUARD_DO.getByName("main");
  const { allowed } = await guard.downloadAttempt(clientIp(request));
  if (!allowed) return json({ error: "rate-limited" }, 429);

  const path = new URL(request.url).pathname;
  const packId = path.slice("/extract/file/".length);
  if (!PACK_ID_RE.test(packId)) return json({ error: "not-found" }, 404);

  const range = parseRange(request.headers.get("Range"));
  const obj = await env.PACKS.get(
    packId,
    range && range.start !== undefined
      ? {
          range:
            range.end !== undefined && range.end >= range.start
              ? { offset: range.start, length: range.end - range.start + 1 }
              : { offset: range.start },
        }
      : undefined,
  );
  if (!obj) return json({ error: "not-found" }, 404);

  const isPartial = range !== null && range.start !== undefined;
  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "Accept-Ranges": "bytes",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  if (isPartial && range) {
    const start = range.start as number;
    // obj.size 为完整对象大小；range 内请求长度 = end-start+1 或到末尾
    const total = obj.size;
    const end =
      range.end !== undefined && range.end < total ? range.end : total - 1;
    headers["Content-Range"] = `bytes ${start}-${end}/${total}`;
    headers["Content-Length"] = String(end - start + 1);
    return new Response(obj.body, { status: 206, headers });
  }
  headers["Content-Length"] = String(obj.size);
  return new Response(obj.body, { status: 200, headers });
}
