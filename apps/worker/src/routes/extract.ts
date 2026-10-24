/**
 * 提取路由（§5.6）：POST /extract，码走请求体不进任何 URL【决策】。
 * - 提取是"一次请求-响应"，无实时双向需求 → 纯 HTTP，不走 WS。
 * - 限流：复用 Guard DO join 限流桶（与 join 同规格，同 IP ≤5 次/分）。
 * - 防探测【决策】：格式错误 / 码不存在 / 已过期 / 次数耗尽 →
 *   统一返回 403 { error: "invalid" }（仅限流返回 429，攻击者可自知的差异）。
 * 零内容日志（§11）：不记录任何请求体/提取内容。
 */
import {
  EXTRACT_MAX_BYTES,
  isValidCodeOfKind,
  normalizeCode,
  sha256Hex,
} from "@dida/shared";
import { clientIp, json, type Env } from "../env";

export const EXTRACT_PATH = "/extract";

/** 提取载荷明文上限 32KB + GCM tag 16B；b64 膨胀约 4/3 */
const CT_B64_MAX = Math.ceil(((EXTRACT_MAX_BYTES + 16) * 4) / 3) + 8;

function b64LenOk(s: unknown, max: number): s is string {
  return typeof s === "string" && s.length <= max;
}

export async function handleExtract(
  request: Request,
  env: Env,
): Promise<Response> {
  if (request.method !== "POST") return json({ error: "not-found" }, 404);

  // 限流：与 join 同桶（同为码猜测面）
  const guard = env.GUARD_DO.getByName("main");
  const { allowed, blocked } = await guard.joinAttempt(clientIp(request));
  if (blocked || !allowed) return json({ error: "invalid" }, 429);

  // 统一模糊错误：任何失败路径都不可区分
  const invalid = () => json({ error: "invalid" }, 403);

  let body: { code?: unknown };
  try {
    body = (await request.json()) as { code?: unknown };
  } catch {
    return invalid();
  }
  if (typeof body.code !== "string") return invalid();
  const code = normalizeCode(body.code);
  if (!isValidCodeOfKind(code, "extract")) return invalid();

  const codeHash = await sha256Hex(code);
  const result = await env.EXTRACT_DO.get(
    env.EXTRACT_DO.idFromName(codeHash),
  ).redeem(codeHash);

  if ("error" in result) return invalid();

  const p = result.payload;
  if (
    !b64LenOk(p.ct, CT_B64_MAX) ||
    !b64LenOk(p.nonce, 24) ||
    !b64LenOk(p.salt, 64)
  )
    return invalid();

  return json({
    ct: p.ct,
    nonce: p.nonce,
    salt: p.salt,
    style: p.style,
    remaining: p.remaining,
    expiresAt: p.expiresAt,
  });
}
