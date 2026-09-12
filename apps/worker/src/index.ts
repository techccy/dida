/**
 * Worker 入口（§15）：路由分发。
 * - POST /admin/login            管理员登录（§9）
 * - GET/POST /admin/sessions...  管理员 API（§9）
 * - GET /ws                      WSS 升级 → Session DO 桥接（§6）
 * - OPTIONS                      CORS 预检（前端托管在 GitHub Pages，跨站）
 *
 * 零内容日志（§11）：本文件及所有路由不记录任何请求体/会话内容。
 */
import { handleAdminApi } from "./routes/admin";
import { handleLogin } from "./routes/login";
import { handleWsUpgrade, WS_PATH } from "./ws";
import { corsHeaders, json, type Env } from "./env";

// Durable Object 类必须从入口点导出（wrangler 要求）
export { SessionDO } from "./session-do";
export { GuardDO } from "./guard-do";
export { RegistryDO } from "./registry-do";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // 健康检查（部署验证用，无信息量）
    if (path === "/" && request.method === "GET") {
      return json({ ok: true });
    }

    if (path === "/admin/login" && request.method === "POST") {
      return handleLogin(request, env);
    }

    if (path.startsWith("/admin/sessions")) {
      return handleAdminApi(request, env);
    }

    if (path === "/debug-ws") {
      // TEMP DEBUG: 立即移除
      return json({ wsDebug });
    }

    if (path === WS_PATH && request.method === "GET") {
      return handleWsUpgrade(request, env);
    }

    return json({ error: "not-found" }, 404);
  },
};
