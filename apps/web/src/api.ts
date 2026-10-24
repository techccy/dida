/**
 * API / WSS 基地址解析（§17.1）：
 * - 生产：构建时注入 VITE_API_URL / VITE_WS_URL（Worker 域名，跨站）
 * - 本地开发：未注入 → 同源，由 Vite 代理 /admin/* 与 /ws 到 miniflare
 */
import { clearAdminToken, loadAdminToken } from "./crypto/crypto";

export function apiBase(): string {
  return import.meta.env.VITE_API_URL ?? "";
}

export function wsUrl(): string {
  const v = import.meta.env.VITE_WS_URL;
  if (v) return v.replace(/\/$/, "") + "/ws";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/ws`;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** 管理员 API：token 只走 Authorization 头，不进 URL（§9） */
export async function adminFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = loadAdminToken();
  const res = await fetch(apiBase() + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
  });
  if (res.status === 401) {
    clearAdminToken();
    window.dispatchEvent(new Event("dida-admin-401"));
  }
  return res;
}

export interface SessionInfo {
  sessionId: string;
  createdAt: number;
  status: "created" | "active" | "ended";
  joinedAt?: number;
  deadline?: number;
}

export async function listSessions(): Promise<SessionInfo[]> {
  const res = await adminFetch("/admin/sessions");
  if (!res.ok) throw new ApiError(res.status, "list-failed");
  const data = (await res.json()) as { sessions: SessionInfo[] };
  return data.sessions;
}

export async function createSession(
  ttlMs: number,
): Promise<{ sessionId: string; code: string; ttlMs: number }> {
  const res = await adminFetch("/admin/sessions", {
    method: "POST",
    body: JSON.stringify({ ttlMs }),
  });
  if (!res.ok) throw new ApiError(res.status, "create-failed");
  return (await res.json()) as {
    sessionId: string;
    code: string;
    ttlMs: number;
  };
}

export async function endSession(id: string): Promise<void> {
  const res = await adminFetch(`/admin/sessions/${id}/end`, {
    method: "POST",
  });
  if (!res.ok && res.status !== 404) throw new ApiError(res.status, "end-failed");
}

// ---------- 提取包 API（§5.6） ----------

export interface ExtractInfo {
  extractId: string;
  createdAt: number;
  status: "ready" | "destroyed";
  expiresAt: number;
  maxCount: number;
  usedCount: number;
  style: "packet" | "message";
}

export interface CreateExtractArgs {
  /** SHA-256(完整配对码) hex——码明文不经服务端【决策】 */
  codeHash: string;
  ct: string;
  nonce: string;
  salt: string;
  style: "packet" | "message";
  ttlMs?: number;
  maxCount?: number;
}

export async function createExtract(
  args: CreateExtractArgs,
): Promise<{ extractId: string; expiresAt: number; maxCount: number }> {
  const res = await adminFetch("/admin/extracts", {
    method: "POST",
    body: JSON.stringify(args),
  });
  if (!res.ok) throw new ApiError(res.status, "create-extract-failed");
  return (await res.json()) as {
    extractId: string;
    expiresAt: number;
    maxCount: number;
  };
}

export async function listExtracts(): Promise<ExtractInfo[]> {
  const res = await adminFetch("/admin/extracts");
  if (!res.ok) throw new ApiError(res.status, "list-extracts-failed");
  const data = (await res.json()) as { extracts: ExtractInfo[] };
  return data.extracts;
}

export async function destroyExtract(id: string): Promise<void> {
  const res = await adminFetch(`/admin/extracts/${id}/destroy`, {
    method: "POST",
  });
  if (!res.ok && res.status !== 404) throw new ApiError(res.status, "destroy-failed");
}

/** 提取（无鉴权，凭码兑换密文；码走请求体不进 URL） */
export async function extractRedeem(
  code: string,
): Promise<{
  ct: string;
  nonce: string;
  salt: string;
  style: "packet" | "message";
  remaining: number;
  expiresAt: number;
}> {
  const res = await fetch(apiBase() + "/extract", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw new ApiError(res.status, "invalid");
  return (await res.json()) as {
    ct: string;
    nonce: string;
    salt: string;
    style: "packet" | "message";
    remaining: number;
    expiresAt: number;
  };
}
