/**
 * Worker 环境类型与共享工具。
 */
import type { SessionDO } from "./session-do";
import type { GuardDO } from "./guard-do";
import type { RegistryDO } from "./registry-do";
import { b64ToBytes } from "@dida/shared";

export interface Env {
  SESSION_DO: DurableObjectNamespace<SessionDO>;
  GUARD_DO: DurableObjectNamespace<GuardDO>;
  REGISTRY_DO: DurableObjectNamespace<RegistryDO>;
  /** Worker Secret：pbkdf2-sha256$<iter>$<salt-b64>$<hash-b64>（§9） */
  ADMIN_PASS_HASH?: string;
  /** Worker Secret：HMAC 签名密钥（b64，§9） */
  TOKEN_SIGNING_KEY?: string;
  /** 仅本地开发：无 ADMIN_PASS_HASH 时比对的口令（wrangler.toml [vars]） */
  DEV_ADMIN_PASSWORD?: string;
}

/**
 * token 签名密钥：生产来自 Secrets；本地开发缺省时用确定性 dev key
 * （不得用于生产——README 有说明）。
 */
export async function getSigningKey(env: Env): Promise<Uint8Array> {
  if (env.TOKEN_SIGNING_KEY) return b64ToBytes(env.TOKEN_SIGNING_KEY);
  const dev = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("dida-dev-signing-key-v1")),
  );
  return dev;
}

/** 客户端来源 IP（CF 边缘注入；本地开发无此头时回退固定 key） */
export function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "local";
}

export function json(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

/**
 * CORS：前端托管在 GitHub Pages（独立源），跨站调用 Worker API。
 * 不使用 cookie（sessionStorage token），故 Allow-Origin: * 安全。
 */
export function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}
