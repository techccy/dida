/**
 * POST /admin/login（§9）：
 * 校验管理员口令（Secrets 中的 PBKDF2 哈希，timing-safe）→ 签发 8h HMAC token。
 * 限流（§10）：同一来源 5 次失败 → 锁 15 分钟（Guard DO）。
 * 零内容日志（§11）：不记录口令/失败细节。
 */
import { checkAdminPassword, newAdminToken } from "../admin";
import { clientIp, getSigningKey, json, type Env } from "../env";

export async function handleLogin(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "POST") {
    return json({ error: "method-not-allowed" }, 405);
  }
  let password: unknown;
  try {
    const body = (await request.json()) as { password?: unknown };
    password = body.password;
  } catch {
    return json({ error: "bad-request" }, 400);
  }
  if (typeof password !== "string" || password.length === 0) {
    return json({ error: "bad-request" }, 400);
  }

  const key = clientIp(request);

  // 限流预检（§10）
  const pre = await env.GUARD_DO.getByName("main").loginPrecheck(key);
  if (pre.locked) return json({ error: "rate-limited" }, 429);

  const check = await checkAdminPassword(
    password,
    env.ADMIN_PASS_HASH,
    env.DEV_ADMIN_PASSWORD,
  );
  if (!check.ok) {
    const fail = await env.GUARD_DO.getByName("main").loginFail(key);
    if (fail.locked) return json({ error: "rate-limited" }, 429);
    return json({ error: "bad-password" }, 401);
  }

  await env.GUARD_DO.getByName("main").loginSuccess(key);
  const token = await newAdminToken(await getSigningKey(env));
  return json({ token });
}
