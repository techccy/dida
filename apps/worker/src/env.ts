/**
 * Worker 环境类型与共享工具。
 */
import type { SessionDO } from "./session-do";
import type { GuardDO } from "./guard-do";
import type { RegistryDO } from "./registry-do";
import type { ExtractDO } from "./extract-do";
import { b64ToBytes } from "@dida/shared";

export interface Env {
  SESSION_DO: DurableObjectNamespace<SessionDO>;
  GUARD_DO: DurableObjectNamespace<GuardDO>;
  REGISTRY_DO: DurableObjectNamespace<RegistryDO>;
  EXTRACT_DO: DurableObjectNamespace<ExtractDO>;
  /** 账号中心应用凭证（可公开）：account.techccy.com/admin「应用管理」创建 */
  ACCOUNT_CLIENT_ID?: string;
  /** OAuth 回调地址：必须与账号中心应用白名单完全一致（含协议/路径/无尾斜杠） */
  ACCOUNT_REDIRECT_URI?: string;
  /** Worker Secret：账号中心应用密钥，只存服务端，绝不进前端 */
  ACCOUNT_CLIENT_SECRET?: string;
  /** Worker Secret：HMAC 签名密钥（b64，§9） */
  TOKEN_SIGNING_KEY?: string;
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
