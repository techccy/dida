/**
 * 管理员 API（§9）：Bearer token 鉴权（Authorization 头，token 不进 URL）。
 * - GET  /admin/sessions           会话列表（码哈希引用 + 实时状态/倒计时）
 * - POST /admin/sessions           创建会话 { ttlMs } → { sessionId, code, ttlMs }
 * - POST /admin/sessions/:id/end   提前结束（ended 全清）
 * - GET  /admin/extracts           提取包列表（状态/计数/到期时间，无内容字段）
 * - POST /admin/extracts           创建提取包 { codeHash, ct, nonce, salt, style, ttlMs?, maxCount? }
 * - POST /admin/extracts/:id/destroy 提前销毁
 * 提取码由前端生成（密钥从码派生，码明文不经服务端）【决策】；
 * 服务端只接收 codeHash 与密文，永不持有可解密能力（§5.6）。
 * 零内容日志（§11）：不记录任何请求体/会话内容。
 */
import {
  EXTRACT_DEFAULT_TTL_MS,
  EXTRACT_MAX_BYTES,
  EXTRACT_MAX_COUNT,
  TTL_OPTIONS,
  generateCode,
  sha256Hex,
  type TtlOption,
} from "@dida/shared";
import { verifyToken } from "../admin";
import { getSigningKey, json, type Env } from "../env";
import type { ExtractStyle } from "../extract-do";

export const ADMIN_API_PREFIX = "/admin/sessions";
export const ADMIN_EXTRACT_PREFIX = "/admin/extracts";

/** 密文 b64 上限：32KB 明文 + 16B tag，b64 膨胀 */
const CT_B64_MAX = Math.ceil(((EXTRACT_MAX_BYTES + 16) * 4) / 3) + 8;
const HEX64 = /^[0-9a-f]{64}$/;

async function bearerToken(request: Request): Promise<string | null> {
  const h = request.headers.get("Authorization");
  if (!h || !h.startsWith("Bearer ")) return null;
  const t = h.slice("Bearer ".length).trim();
  return t.length > 0 ? t : null;
}

async function adminOk(request: Request, env: Env): Promise<boolean> {
  const token = await bearerToken(request);
  if (!token) return false;
  const claims = await verifyToken(await getSigningKey(env), token);
  return claims !== null;
}

export async function handleAdminApi(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // POST /admin/sessions → 创建
  if (path === ADMIN_API_PREFIX && request.method === "POST") {
    if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
    let ttlMs: unknown;
    try {
      const body = (await request.json()) as { ttlMs?: unknown };
      ttlMs = body.ttlMs;
    } catch {
      return json({ error: "bad-request" }, 400);
    }
    const opt = TTL_OPTIONS.find((o) => o.ms === ttlMs) as
      | TtlOption
      | undefined;
    if (!opt) return json({ error: "bad-ttl" }, 400);

    const code = generateCode("chat");
    const codeHash = await sha256Hex(code);
    // 会话 ID 由码哈希经 namespace 确定性派生（新 DO ID 方案，必须落在 namespace 内）：
    // 注册表与 Session DO 用同一 ID 互指；不含任何明文信息
    const sessionId = env.SESSION_DO.idFromName(codeHash).toString();
    const createdAt = Date.now();

    const session = env.SESSION_DO.get(env.SESSION_DO.idFromString(sessionId));
    const created = await session.create({ codeHash, ttlMs: opt.ms, createdAt });
    if ("error" in created) return json({ error: "conflict" }, 409);
    await env.REGISTRY_DO.getByName("main").addRef({
      refId: sessionId,
      codeHash,
      createdAt,
      kind: "session",
    });
    // 码明文只在这里返回一次，供管理员复制后 OOB 发给对方（§8）
    return json({ sessionId, code, ttlMs: opt.ms }, 201);
  }

  // GET /admin/sessions → 列表
  if (path === ADMIN_API_PREFIX && request.method === "GET") {
    if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
    const refs = await env.REGISTRY_DO.getByName("main").listRefs();
    const sessions = await Promise.all(
      refs
        .filter((r) => (r.kind ?? "session") === "session")
        .map(async (ref) => {
          const st = await env.SESSION_DO.get(
            env.SESSION_DO.idFromString(ref.refId),
          ).status();
          return {
            sessionId: ref.refId,
            createdAt: ref.createdAt,
            status: st.status,
            joinedAt: st.joinedAt,
            deadline: st.deadline,
          };
        }),
    );
    return json({ sessions });
  }

  // POST /admin/sessions/:id/end → 提前结束
  const m = path.match(
    /^\/admin\/sessions\/([A-Za-z0-9._-]{1,128})\/end$/,
  );
  if (m && request.method === "POST") {
    if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
    const result = await env.SESSION_DO.get(env.SESSION_DO.idFromString(m[1])).adminEnd();
    if (!result.ok) return json({ error: "not-found" }, 404);
    return json({ ok: true });
  }

  return json({ error: "not-found" }, 404);
}

/** 提取包管理 API（§5.6）：仅元数据，无任何内容字段 */
export async function handleAdminExtractApi(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // POST /admin/extracts → 创建（载荷为密文；码明文不经服务端）
  if (path === ADMIN_EXTRACT_PREFIX && request.method === "POST") {
    if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
    let body: {
      codeHash?: unknown;
      ct?: unknown;
      nonce?: unknown;
      salt?: unknown;
      style?: unknown;
      ttlMs?: unknown;
      maxCount?: unknown;
    };
    try {
      body = (await request.json()) as typeof body;
    } catch {
      return json({ error: "bad-request" }, 400);
    }

    if (typeof body.codeHash !== "string" || !HEX64.test(body.codeHash))
      return json({ error: "bad-request" }, 400);
    if (
      typeof body.ct !== "string" ||
      body.ct.length === 0 ||
      body.ct.length > CT_B64_MAX
    )
      return json({ error: "bad-request" }, 400);
    if (typeof body.nonce !== "string" || body.nonce.length > 24)
      return json({ error: "bad-request" }, 400);
    if (typeof body.salt !== "string" || body.salt.length > 64)
      return json({ error: "bad-request" }, 400);
    if (body.style !== "packet" && body.style !== "message")
      return json({ error: "bad-request" }, 400);

    let expiresAt: number;
    if (body.ttlMs === undefined) {
      expiresAt = Date.now() + EXTRACT_DEFAULT_TTL_MS;
    } else {
      const opt = TTL_OPTIONS.find((o) => o.ms === body.ttlMs) as
        | TtlOption
        | undefined;
      if (!opt) return json({ error: "bad-ttl" }, 400);
      expiresAt = Date.now() + opt.ms;
    }

    let maxCount = 1;
    if (body.maxCount !== undefined) {
      if (
        typeof body.maxCount !== "number" ||
        !Number.isInteger(body.maxCount) ||
        body.maxCount < 1 ||
        body.maxCount > EXTRACT_MAX_COUNT
      )
        return json({ error: "bad-request" }, 400);
      maxCount = body.maxCount;
    }

    const codeHash = body.codeHash;
    const extractId = env.EXTRACT_DO.idFromName(codeHash).toString();
    const createdAt = Date.now();

    const created = await env.EXTRACT_DO.get(
      env.EXTRACT_DO.idFromString(extractId),
    ).create({
      codeHash,
      ct: body.ct,
      nonce: body.nonce,
      salt: body.salt,
      style: body.style,
      createdAt,
      expiresAt,
      maxCount,
    });
    if ("error" in created) return json({ error: "conflict" }, 409);
    await env.REGISTRY_DO.getByName("main").addRef({
      refId: extractId,
      codeHash,
      createdAt,
      kind: "extract",
    });
    return json({ extractId, expiresAt, maxCount }, 201);
  }

  // GET /admin/extracts → 列表
  if (path === ADMIN_EXTRACT_PREFIX && request.method === "GET") {
    if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
    const refs = await env.REGISTRY_DO.getByName("main").listRefs();
    const extracts = await Promise.all(
      refs
        .filter((r) => r.kind === "extract")
        .map(async (ref) => {
          const st = await env.EXTRACT_DO.get(
            env.EXTRACT_DO.idFromString(ref.refId),
          ).status();
          return {
            extractId: ref.refId,
            createdAt: ref.createdAt,
            status: st.status,
            expiresAt: st.expiresAt,
            maxCount: st.maxCount,
            usedCount: st.usedCount,
            style: st.style,
          };
        }),
    );
    return json({ extracts });
  }

  // POST /admin/extracts/:id/destroy → 提前销毁
  const m = path.match(/^\/admin\/extracts\/([A-Za-z0-9._-]{1,128})\/destroy$/);
  if (m && request.method === "POST") {
    if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
    const result = await env.EXTRACT_DO.get(
      env.EXTRACT_DO.idFromString(m[1]),
    ).adminDestroy();
    if (!result.ok) return json({ error: "not-found" }, 404);
    return json({ ok: true });
  }

  return json({ error: "not-found" }, 404);
}
