/**
 * 管理员登录：统一账号中心 OAuth2 Authorization Code（§9）。
 * - GET  /admin/oauth/start     签发 state → 302 跳账号中心 /authorize
 * - POST /admin/oauth/callback  校验 state → code 换 token（client_secret 只存
 *                               服务端 Secret）→ access_token 本地验签 →
 *                               邮箱白名单 → 签发平台 8h admin token
 * 白名单：本地文件 config/admin-emails.txt（一行一个邮箱，构建时内联进 Worker）。
 * 限流（§10）：bad-state / bad-code 计入 Guard DO（5 次失败锁 15 分钟）；
 * not-whitelisted 不计失败（授权拒绝，非凭据猜测）。
 * 零内容日志（§11）：不记录 code / token / 邮箱等任何回调内容。
 */
import { newAdminToken } from "../admin";
import {
  ACCOUNT_CENTER_BASE,
  isWhitelisted,
  parseWhitelist,
  signState,
  verifyAccessToken,
  verifyState,
} from "../oauth-core";
import { clientIp, getSigningKey, json, type Env } from "../env";
import whitelistTxt from "../../config/admin-emails.txt";

/** 白名单在 Worker 隔离实例启动时解析一次（构建期文件，运行期不变） */
const ADMIN_EMAIL_WHITELIST = parseWhitelist(whitelistTxt);

function oauthConfigured(env: Env): boolean {
  return Boolean(
    env.ACCOUNT_CLIENT_ID && env.ACCOUNT_CLIENT_SECRET && env.ACCOUNT_REDIRECT_URI,
  );
}

/** GET /admin/oauth/start：302 → 账号中心 /authorize */
export async function handleOAuthStart(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "GET") return json({ error: "method-not-allowed" }, 405);
  if (!oauthConfigured(env)) return json({ error: "not-configured" }, 503);

  const state = await signState(await getSigningKey(env));
  const url = new URL(`${ACCOUNT_CENTER_BASE}/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", env.ACCOUNT_CLIENT_ID!);
  url.searchParams.set("redirect_uri", env.ACCOUNT_REDIRECT_URI!);
  url.searchParams.set("state", state);
  return Response.redirect(url.toString(), 302);
}

/** POST /admin/oauth/callback：{ code, state } → { token } */
export async function handleOAuthCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "POST") return json({ error: "method-not-allowed" }, 405);
  if (!oauthConfigured(env)) return json({ error: "not-configured" }, 503);

  let code: string;
  let state: string;
  try {
    const body = (await request.json()) as { code?: unknown; state?: unknown };
    if (
      typeof body.code !== "string" ||
      body.code.length === 0 ||
      typeof body.state !== "string" ||
      body.state.length === 0
    ) {
      return json({ error: "bad-request" }, 400);
    }
    code = body.code;
    state = body.state;
  } catch {
    return json({ error: "bad-request" }, 400);
  }

  const guard = env.GUARD_DO.getByName("main");
  const key = clientIp(request);

  // 限流预检（§10）
  const pre = await guard.loginPrecheck(key);
  if (pre.locked) return json({ error: "rate-limited" }, 429);

  // anti-CSRF：state 必须是本服务签发且未过期
  if (!(await verifyState(await getSigningKey(env), state))) {
    const fail = await guard.loginFail(key);
    if (fail.locked) return json({ error: "rate-limited" }, 429);
    return json({ error: "bad-state" }, 400);
  }

  // code 换 token（服务端持有 client_secret；授权码 10 分钟有效、仅一次）
  let tokenRes: Response;
  try {
    tokenRes = await fetch(`${ACCOUNT_CENTER_BASE}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: env.ACCOUNT_CLIENT_ID!,
        client_secret: env.ACCOUNT_CLIENT_SECRET!,
        redirect_uri: env.ACCOUNT_REDIRECT_URI!,
      }).toString(),
    });
  } catch {
    return json({ error: "upstream-error" }, 502);
  }

  if (!tokenRes.ok) {
    // 授权码失效/已用、secret 错、redirect_uri 不匹配等，统一按凭据失败处理
    const fail = await guard.loginFail(key);
    if (fail.locked) return json({ error: "rate-limited" }, 429);
    return json({ error: "bad-code" }, 401);
  }

  let tokens: { access_token?: unknown };
  try {
    tokens = (await tokenRes.json()) as { access_token?: unknown };
  } catch {
    return json({ error: "upstream-error" }, 502);
  }
  if (typeof tokens.access_token !== "string")
    return json({ error: "upstream-error" }, 502);

  const claims = await verifyAccessToken(
    env.ACCOUNT_CLIENT_SECRET!,
    tokens.access_token,
    { issuer: ACCOUNT_CENTER_BASE, audience: env.ACCOUNT_CLIENT_ID! },
  );
  if (!claims) return json({ error: "bad-token" }, 401);

  // 邮箱白名单（本地文件）：不在名单内 → 拒绝，不签发平台 token
  if (!isWhitelisted(ADMIN_EMAIL_WHITELIST, claims.email)) {
    return json({ error: "not-whitelisted" }, 403);
  }

  await guard.loginSuccess(key);
  const token = await newAdminToken(await getSigningKey(env));
  return json({ token });
}
