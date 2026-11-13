/**
 * Worker 入口（§15）：路由分发。
 * - GET  /admin/oauth/start     管理员登录跳转（统一账号中心 OAuth，§9）
 * - POST /admin/oauth/callback  管理员登录回调（code 换 token + 邮箱白名单，§9）
 * - GET/POST /admin/sessions...  管理员 API（§9）
 * - GET/POST /admin/extracts...  提取包管理 API（§5.6）
 * - POST /extract                提取（凭提取码兑换密文，§5.6）
 * - GET /ws                      WSS 升级 → Session DO 桥接（§6）
 * - OPTIONS                      CORS 预检（前端托管在 GitHub Pages，跨站）
 *
 * 零内容日志（§11）：本文件及所有路由不记录任何请求体/会话内容。
 */
import { handleAdminApi, handleAdminExtractApi } from "./routes/admin";
import { handleOAuthCallback, handleOAuthStart } from "./routes/oauth";
import { handleExtract, EXTRACT_PATH } from "./routes/extract";
import { handleWsUpgrade, WS_PATH } from "./ws";
import { corsHeaders, json, type Env } from "./env";

// Durable Object 类必须从入口点导出（wrangler 要求）
export { SessionDO } from "./session-do";
export { GuardDO } from "./guard-do";
export { RegistryDO } from "./registry-do";
export { ExtractDO } from "./extract-do";

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

    if (path === "/admin/oauth/start" && request.method === "GET") {
      return handleOAuthStart(request, env);
    }

    if (path === "/admin/oauth/callback" && request.method === "POST") {
      return handleOAuthCallback(request, env);
    }

    if (path.startsWith("/admin/sessions")) {
      return handleAdminApi(request, env);
    }

    if (path.startsWith("/admin/extracts")) {
      return handleAdminExtractApi(request, env);
    }

    if (path === EXTRACT_PATH && request.method === "POST") {
      return handleExtract(request, env);
    }

    // Workers Routes 不分方法：/extract 的 GET 也落到 Worker。
    // SPA 提取页在 /e（Pages 托管）；这里 302 兜底旧深链/直达访问。
    if (path === EXTRACT_PATH && request.method === "GET") {
      return Response.redirect(url.origin + "/e", 302);
    }

    if (path === WS_PATH && request.method === "GET") {
      return handleWsUpgrade(request, env);
    }

    return json({ error: "not-found" }, 404);
  },
};
