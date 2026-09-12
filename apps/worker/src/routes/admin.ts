/**
 * 管理员 API（§9）：Bearer token 鉴权（Authorization 头，token 不进 URL）。
 * - GET  /admin/sessions         会话列表（码哈希引用 + 实时状态/倒计时）
 * - POST /admin/sessions         创建会话 { ttlMs } → { sessionId, code, ttlMs }
 * - POST /admin/sessions/:id/end 提前结束（ended 全清）
 * 零内容日志（§11）：不记录任何请求体/会话内容。
 */
import {
  TTL_OPTIONS,
  generateInviteCode,
  sha256Hex,
  type TtlOption,
} from "@dida/shared";
import { verifyToken } from "../admin";
import { getSigningKey, json, type Env } from "../env";

export const ADMIN_API_PREFIX = "/admin/sessions";

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

    const code = generateInviteCode();
    const codeHash = await sha256Hex(code);
    // 会话 ID 由码哈希经 namespace 确定性派生（新 DO ID 方案，必须落在 namespace 内）：
    // 注册表与 Session DO 用同一 ID 互指；不含任何明文信息
    const sessionId = env.SESSION_DO.idFromName(codeHash).toString();
    const createdAt = Date.now();

    const session = env.SESSION_DO.get(env.SESSION_DO.idFromString(sessionId));
    const created = await session.create({ codeHash, ttlMs: opt.ms, createdAt });
    if ("error" in created) return json({ error: "conflict" }, 409);
    await env.REGISTRY_DO.getByName("main").addRef({
      sessionId,
      codeHash,
      createdAt,
    });
    // 码明文只在这里返回一次，供管理员复制后 OOB 发给对方（§8）
    return json({ sessionId, code, ttlMs: opt.ms }, 201);
  }

  // GET /admin/sessions → 列表
  if (path === ADMIN_API_PREFIX && request.method === "GET") {
    if (!(await adminOk(request, env))) return json({ error: "unauthorized" }, 401);
    const refs = await env.REGISTRY_DO.getByName("main").listRefs();
    const sessions = await Promise.all(
      refs.map(async (ref) => {
        const st = await env.SESSION_DO.get(env.SESSION_DO.idFromString(ref.sessionId)).status();
        return {
          sessionId: ref.sessionId,
          createdAt: ref.createdAt,
          status: st.status,
          joinedAt: st.joinedAt,
          deadline: st.deadline,
          adminVerified: st.adminVerified,
          partVerified: st.partVerified,
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
