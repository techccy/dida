/**
 * WSS 端点（§6）：
 * - 升级 URL 无任何 query（凭证不进 URL）【决策】
 * - 首帧鉴权：连接建立后 5s 内未收到有效 auth/join → 关闭；校验失败 → error + close（§6.3）
 * - join 前置限流：同 IP ≤5 次/分钟（§10，Worker 边缘判定，IP 在首帧之前即可知）
 * - 鉴权通过后，Worker 与 Session DO 建立桥接（内部请求头带 role/token，
 *   不经过任何 URL），双向泵帧。
 *
 * 时序约束（Workers HTTP→WS 模型）：
 * 101 响应在 fetch 返回时发出，客户端只有收到 101 才能发帧——
 * 因此"读首帧"必须发生在返回 101 之后：本端点立即返回 101，
 * 随后在 server 侧运行 5s 首帧窗口 + 鉴权 + 桥接（独立异步延续，
 * 跨事件边界存活；首帧到达前的后续帧先进缓冲，鉴权通过后冲刷）。
 */
import {
  AUTH_TIMEOUT_MS,
  ERROR_CODES,
  normalizeCode,
  sha256Hex,
} from "@dida/shared";
import { getSigningKey, type Env } from "./env";
import { verifyToken } from "./admin";

export const WS_PATH = "/ws";

interface FirstFrame {
  type: string;
  credential?: string;
  code?: string;
  sessionId?: string;
}

function parseFirst(raw: string | null): FirstFrame | null {
  if (!raw) return null;
  try {
    const f = JSON.parse(raw) as FirstFrame;
    if (typeof f !== "object" || f === null || typeof f.type !== "string")
      return null;
    return f;
  } catch {
    return null;
  }
}

export async function handleWsUpgrade(
  request: Request,
  env: Env,
): Promise<Response> {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  // workerd 要求 server 端先 accept() 才开始投递消息（最小验证通过）
  server.accept();
  // 立即返回 101；首帧窗口在连接建立后计时（§6.3）
  const response = new Response(null, { status: 101, webSocket: client });
  void afterOpen(server, request, env);
  return response;
}

async function afterOpen(
  server: WebSocket,
  request: Request,
  env: Env,
): Promise<void> {
  const ip = request.headers.get("cf-connecting-ip") ?? "local";

  let doWs: WebSocket | null = null;
  let authDone = false;
  let firstConsumed = false;
  let finished = false;
  const pending: (string | ArrayBuffer)[] = [];

  const sendErr = (code: string) => {
    try {
      server.send(JSON.stringify({ type: "error", code }));
    } catch {
      /* 客户端已断 */
    }
  };
  const close = (code = 4000, reason = "error") => {
    if (finished) return;
    finished = true;
    clearTimeout(authTimer);
    try {
      server.close(code, reason);
    } catch {
      /* 客户端已断 */
    }
    if (doWs) {
      try {
        doWs.close(4000, "client-gone");
      } catch {
        /* ignore */
      }
    }
  };
  const flush = () => {
    for (const data of pending.splice(0)) {
      try {
        doWs?.send(data);
      } catch {
        /* DO 侧已断 */
      }
    }
  };

  // ---- 1. 首帧窗口：5s 未鉴权 → 关闭（§6.3）----
  const authTimer = setTimeout(() => {
    if (!authDone) close(4001, "auth-timeout");
  }, AUTH_TIMEOUT_MS);

  const onFirst = async (raw: string | ArrayBuffer) => {
    firstConsumed = true;
    const text =
      typeof raw === "string" ? raw : new TextDecoder().decode(raw);
    const first = parseFirst(text);
    if (!first) return close(4000, "bad-frame");

    let role: "admin" | "participant" | null = null;
    let sessionId: string | null = null;
    let codeHash = "";

    if (first.type === "auth") {
      if (typeof first.credential !== "string" || !first.credential)
        return close(4000, "bad-cred");
      const claims = await verifyToken(
        await getSigningKey(env),
        first.credential,
      );
      if (!claims) return close(4002, "bad-cred");
      if (
        typeof first.sessionId !== "string" ||
        !/^[A-Za-z0-9._-]{1,128}$/.test(first.sessionId)
      )
        return close(4000, "bad-session");
      sessionId = first.sessionId;
      role = "admin";
    } else if (first.type === "join") {
      // 限流前置（§10）：同 IP ≤5 次/分，超限封 15 分钟
      const join = await env.GUARD_DO.getByName("main").joinAttempt(ip);
      if (!join.allowed) {
        sendErr(ERROR_CODES.RATE_LIMITED);
        return close(4008, "rate-limited");
      }
      if (typeof first.code !== "string" || !first.code)
        return close(4000, "bad-code");
      codeHash = await sha256Hex(normalizeCode(first.code));
      const refs = await env.REGISTRY_DO.getByName("main").listRefs();
      const ref = refs.find((r) => r.codeHash === codeHash);
      if (!ref) return close(4003, "code-expired");
      sessionId = ref.sessionId;
      role = "participant";
    } else {
      return close(4000, "bad-first");
    }
    if (finished) return;

    // ---- 2. 桥接到 Session DO（内部头，非 URL）----
    const stub = env.SESSION_DO.get(env.SESSION_DO.idFromString(sessionId));
    let bridgeResp: Response;
    try {
      bridgeResp = await stub.fetch(
        new Request("https://dida.internal/bridge", {
          method: "GET",
          headers: {
            "x-dida-role": role as string,
            "x-dida-auth": first.credential ?? "",
            "x-dida-code-hash": codeHash,
            Upgrade: "websocket",
            Connection: "Upgrade",
          },
        }),
      );
    } catch {
      return close(4000, "bridge-rejected");
    }
    if (bridgeResp.status !== 101 || !bridgeResp.webSocket) {
      await bridgeResp.body?.cancel().catch(() => {});
      const code =
        bridgeResp.status === 403
          ? ERROR_CODES.BAD_CRED
          : bridgeResp.status === 404
            ? ERROR_CODES.CODE_EXPIRED
            : ERROR_CODES.BUSY;
      sendErr(code);
      return close(4000, "bridge-rejected");
    }
    doWs = bridgeResp.webSocket;
    // workerd 要求先 accept() 才能向该 socket 发送（本地已验证）
    doWs.accept();

    // ---- 3. 双向泵帧（首帧已被上面消费，不再转发）----
    // DO → 客户端：DO 的响应（ok/peer/msg/backlog/…）立即发给客户端
    doWs.addEventListener("message", (e) => {
      const data = (e as MessageEvent).data;
      try {
        server.send(data);
      } catch {
        /* 客户端已断 */
      }
    });
    doWs.addEventListener("close", () => {
      close(4001, "session-end");
    });

    authDone = true;
    clearTimeout(authTimer);
    flush();
  };

  server.addEventListener("message", (e) => {
    const data = (e as MessageEvent).data as string | ArrayBuffer;
    if (!firstConsumed) {
      void onFirst(data);
      return;
    }
    if (!authDone) {
      // 桥接建立中：缓冲，建立后冲刷
      pending.push(data);
      return;
    }
    try {
      doWs?.send(data);
    } catch {
      /* DO 侧已断 */
    }
  });
  server.addEventListener("close", (e) => {
    if (finished) return;
    const ce = e as CloseEvent;
    // 客户端主动关闭：正常码（1000/1001）原样回显；异常断连 → 4000
    if (ce.code === 1000 || ce.code === 1001) close(ce.code, ce.reason);
    else close(4000, "client-gone");
  });
}
