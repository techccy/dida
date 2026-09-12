/**
 * Session DO：会话状态机（§4）、密钥中继（§5.2）、消息中继 + backlog（§7.5）、
 * 三类闹钟（§7.4）、Hibernation attachment（§7.3）、密文零落盘（§7.2）。
 *
 * 持久存储只有 meta（几百字节元数据）：码哈希/公钥/salt/状态/时间戳/seq 水位/verified。
 * 消息密文只存在于内存 backlog，DO 消亡即失，从不上盘（§7.2）。
 *
 * 连接模型：WS 升级由 Worker 边缘完成首帧鉴权（auth/join，§6），
 * 随后 Worker 通过桥接把后续帧转发到本 DO（DO 的 fetch 只接受已鉴权连接）。
 * 因此本 DO 的 attachment 自始即为已鉴权态（role 由 Worker 经内部头传递）。
 */
import { DurableObject } from "cloudflare:workers";
import {
  BACKLOG_LIMIT,
  ERROR_CODES,
  GRACE_PERIOD_MS,
  UNUSED_CODE_TTL_MS,
  b64ToBytes,
  type RelayedMsgFrame,
  type Role,
} from "@dida/shared";
import { verifyToken } from "./admin";
import { getSigningKey, type Env } from "./env";

interface SessionMeta {
  codeHash: string;
  status: "created" | "active";
  ttlMs: number;
  pubAdmin?: string; // b64 32B
  pubPart?: string; // b64 32B
  salt?: string; // b64 32B（管理员携带）
  createdAt: number;
  joinedAt?: number;
  deadline?: number;
  adminVerified: boolean;
  partVerified: boolean;
  /** 管理员已发送的最大 seq（发送方水位） */
  maxSentAdmin?: number;
  /** 对方已发送的最大 seq（发送方水位） */
  maxSentPart?: number;
  /** 对方消息中，管理员已 ack 的最大 seq（= 管理员侧 lastAck） */
  ackPart?: number;
  /** 管理员消息中，对方已 ack 的最大 seq（= 对方侧 lastAck） */
  ackAdmin?: number;
  alarm?: { kind: "unused" | "grace" | "deadline"; at: number };
}

interface Attachment {
  role: Role;
  /** 本方已发送的最大 seq（重连时从 meta 恢复） */
  lastSent: number;
  /** 本方已 ack 的对端消息最大 seq（重连时从 meta 恢复） */
  lastAck: number;
  /** 是否已收到 peer 帧（对端公钥 + salt） */
  peerSent: boolean;
  /** 本方是否已点"已核对" */
  verified: boolean;
  /** 已被同公钥新连接接替（刷新/StrictMode 双挂载）：不再视为活连接 */
  replaced?: boolean;
}

interface MsgRec {
  seq: number;
  nonce: string;
  ct: string;
}

const META_KEY = "meta";
const PUB_LEN = 32;
const NONCE_LEN = 12;
const MSG_CT_MAX = 8 * 1024 + 16; // 明文上限 8KB + GCM tag

function parseFrame(raw: string | ArrayBuffer): Record<string, unknown> | null {
  try {
    const s = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
    const f = JSON.parse(s) as Record<string, unknown>;
    if (typeof f !== "object" || f === null || typeof f.type !== "string") return null;
    return f;
  } catch {
    return null;
  }
}

function validPub(b64: string): boolean {
  try {
    return b64ToBytes(b64).length === PUB_LEN;
  } catch {
    return false;
  }
}

export class SessionDO extends DurableObject<Env> {
  /** 基类 ctx 的别名（沿用 state 命名） */
  private get state(): DurableObjectState {
    return this.ctx;
  }

  // 内存态：休眠/逐出即失（设计使然，§7.5）。恢复靠 meta + attachment。
  private backlog: Record<Role, MsgRec[]> = { admin: [], participant: [] };
  private ending = false;

  // ---------------- RPC 接口（Worker 调用） ----------------

  /** 创建会话（管理员；Worker 已验证 token）。返回 ok 或错误。 */
  async create(args: {
    codeHash: string;
    ttlMs: number;
    createdAt: number;
  }): Promise<{ ok: true } | { error: "exists" }> {
    const existing = await this.state.storage.get<SessionMeta>(META_KEY);
    if (existing) return { error: "exists" };
    const meta: SessionMeta = {
      codeHash: args.codeHash,
      status: "created",
      ttlMs: args.ttlMs,
      createdAt: args.createdAt,
      adminVerified: false,
      partVerified: false,
      alarm: { kind: "unused", at: args.createdAt + UNUSED_CODE_TTL_MS },
    };
    this.state.storage.put(META_KEY, meta);
    await this.state.storage.setAlarm(args.createdAt + UNUSED_CODE_TTL_MS);
    return { ok: true };
  }

  /** 管理员提前结束（§4.2）：ended(全清) */
  async adminEnd(): Promise<{ ok: boolean }> {
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (!meta) return { ok: false };
    await this.endSession("admin-end");
    return { ok: true };
  }

  /** 会话状态（管理员列表用） */
  async status(): Promise<{
    status: "created" | "active" | "ended";
    createdAt: number;
    joinedAt?: number;
    deadline?: number;
    adminVerified: boolean;
    partVerified: boolean;
  }> {
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (!meta)
      return {
        status: "ended",
        createdAt: 0,
        adminVerified: false,
        partVerified: false,
      };
    return {
      status: meta.status,
      createdAt: meta.createdAt,
      joinedAt: meta.joinedAt,
      deadline: meta.deadline,
      adminVerified: meta.adminVerified,
      partVerified: meta.partVerified,
    };
  }

  // ---------------- WS 生命周期 ----------------

  /**
   * Worker 桥接：接受已鉴权连接（首帧 auth/join 已由 Worker 边缘消费）。
   * role/凭证经内部请求头传递（不经过任何 URL）。DO 内部再做一次校验（纵深）：
   * - admin：x-dida-auth = 管理员 token（HMAC 校验）
   * - participant：x-dida-code-hash = SHA-256(邀请码) 必须匹配 meta.codeHash
   */
  async fetch(request: Request): Promise<Response> {
    const role = request.headers.get("x-dida-role") as Role | null;
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (
      !role ||
      (role !== "admin" && role !== "participant") ||
      !meta ||
      this.ending
    ) {
      const code = meta ? 409 : 404;
      return new Response("rejected", { status: code });
    }

    // 纵深校验（Worker 已校验一次）
    if (role === "admin") {
      const token = request.headers.get("x-dida-auth") ?? "";
      const signingKey = await getSigningKey(this.env);
      const claims = await verifyToken(signingKey, token);
      if (!claims) return new Response("bad-cred", { status: 403 });
    } else {
      const codeHash = request.headers.get("x-dida-code-hash") ?? "";
      if (codeHash !== meta.codeHash)
        return new Response("bad-code", { status: 403 });
      // 注意：active 态允许凭码重连（刷新/断线 = 同公钥重连，§4.2）。
      // "一次性"由公钥级保证：新公钥 → onPub 判定 key-loss → 全清；
      // 会话 ended 后 meta 已删 → 码哈希不在注册表 → code-expired。
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    this.state.acceptWebSocket(server);

    // ok 帧（§6.2）：鉴权成功确认；lastSent = 服务端记录的本方已发最大 seq，
    // 客户端刷新/重连后据此续发（§4.2 续聊）
    const lastSent =
      role === "admin" ? meta.maxSentAdmin ?? 0 : meta.maxSentPart ?? 0;
    try {
      server.send(JSON.stringify({ type: "ok", role, lastSent }));
    } catch {
      /* 连接已断 */
    }

    // participant 首次加入：created → active，deadline = joined_at + TTL（§8）
    if (role === "participant" && meta.status === "created") {
      const now = Date.now();
      meta.status = "active";
      meta.joinedAt = now;
      meta.deadline = now + meta.ttlMs;
      this.persistMeta(meta, { kind: "deadline", at: meta.deadline });
    }

    // attachment（§7.3，16KB，休眠存活）：seq 水位从 meta 恢复（刷新续聊的依据）
    const att: Attachment = {
      role,
      lastSent: role === "admin" ? meta.maxSentAdmin ?? 0 : meta.maxSentPart ?? 0,
      lastAck: role === "admin" ? meta.ackPart ?? 0 : meta.ackAdmin ?? 0,
      peerSent: false,
      verified: role === "admin" ? meta.adminVerified : meta.partVerified,
    };
    server.serializeAttachment(att);

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
    const att = ws.deserializeAttachment() as Attachment | null;
    if (!att) return;
    const frame = parseFrame(message);
    if (!frame) {
      this.send(ws, { type: "error", code: ERROR_CODES.BAD_FRAME });
      ws.close(4000, "bad-frame");
      return;
    }
    try {
      switch (frame.type) {
        case "ping":
          this.send(ws, { type: "pong" });
          return;
        case "pub":
          await this.onPub(ws, att, frame);
          return;
        case "msg":
          await this.onMsg(ws, att, frame);
          return;
        case "ack":
          if (Number.isInteger(frame.seq) && (frame.seq as number) > att.lastAck) {
            att.lastAck = frame.seq as number;
            ws.serializeAttachment(att);
            const meta = await this.state.storage.get<SessionMeta>(META_KEY);
            if (meta) {
              if (att.role === "admin") meta.ackPart = att.lastAck;
              else meta.ackAdmin = att.lastAck;
              this.state.storage.put(META_KEY, meta);
            }
          }
          return;
        case "verify":
          await this.onVerify(ws, att);
          return;
        case "end":
          await this.onPeerLeave(ws, att);
          try {
            ws.close(4000, "leave");
          } catch {
            /* ignore */
          }
          return;
        case "auth":
        case "join":
          // 首帧由 Worker 消费；重复收到 → 关
          ws.close(4000, "dup-first");
          return;
        default:
          this.send(ws, { type: "error", code: ERROR_CODES.BAD_FRAME });
          ws.close(4000, "unknown");
      }
    } catch {
      // 零内容日志（§11）：不记录细节，直接关连接
      try {
        ws.close(4000, "internal");
      } catch {
        /* already closed */
      }
    }
  }

  webSocketClose(ws: WebSocket, _code: number, _reason: string, _wasClean: boolean) {
    const att = ws.deserializeAttachment() as Attachment | null;
    if (!att || this.ending) return;
    // 被同公钥新连接接替的旧连接：不算"离开"（同公钥重连 = 续聊，§4.2），
    // 不通知对端、不触发 grace
    if (att.replaced) return;
    // 只处理"该角色当前活连接"的断开；被同公钥新连接替换的旧连接忽略
    const live = this.liveConnections();
    if (live[att.role] !== ws) return;
    void this.onPeerLeave(ws, att);
  }

  async alarm() {
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (!meta || !meta.alarm) return;
    const now = Date.now();
    if (meta.alarm.at > now + 2000) {
      // 迟到触发（闹钟时间已被更新）：重新排程
      await this.state.storage.setAlarm(meta.alarm.at);
      return;
    }
    switch (meta.alarm.kind) {
      case "unused":
        // 7 天无人使用 → ended(全清)（§7.4）
        await this.endSession("ttl");
        return;
      case "deadline":
        // TTL 到期 → ended(全清)
        await this.endSession("ttl");
        return;
      case "grace": {
        // 60s 超时：任一方未以同公钥重连 → ended(全清)（§4.2）
        const live = this.liveConnections();
        const bothBack = Boolean(live.admin) && Boolean(live.participant);
        if (bothBack) {
          meta.alarm = { kind: "deadline", at: meta.deadline ?? now };
          this.persistMeta(meta, meta.alarm);
        } else {
          await this.endSession("grace-timeout");
        }
        return;
      }
      default:
        this.state.storage.deleteAlarm();
    }
  }

  // ---------------- 内部逻辑 ----------------

  private async onPub(
    ws: WebSocket,
    att: Attachment,
    frame: { pub?: unknown; salt?: unknown },
  ) {
    if (typeof frame.pub !== "string" || !validPub(frame.pub)) {
      this.send(ws, { type: "error", code: ERROR_CODES.BAD_FRAME });
      ws.close(4000, "bad-pub");
      return;
    }
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (!meta || this.ending) {
      ws.close(4003, "ended");
      return;
    }
    const role = att.role;

    // 同角色已有活连接（旧连接尚未断）：
    // 同公钥 → 新连接接替（续聊规则，覆盖刷新竞态）；新公钥 → key-loss 全清
    const live = this.liveConnections();
    const old = live[role];
    if (old && old !== ws) {
      const oldAtt = old.deserializeAttachment() as Attachment | null;
      if (oldAtt?.role === role && oldAtt && this.pubOf(oldAtt, meta) !== frame.pub) {
        await this.endSession("key-loss");
        return;
      }
      if (oldAtt) {
        // 同公钥接替（刷新 / 客户端双实例挂载）：标记旧连接，其关闭不触发"离开"
        oldAtt.replaced = true;
        old.serializeAttachment(oldAtt);
      }
      try {
        old.close(4000, "replaced");
      } catch {
        /* ignore */
      }
    }

    if (role === "admin") {
      // 管理员重连带新公钥（sessionStorage 被清）= key-loss
      if (meta.pubAdmin && meta.pubAdmin !== frame.pub) {
        await this.endSession("key-loss");
        return;
      }
      if (typeof frame.salt !== "string" || b64ToBytes(frame.salt).length !== PUB_LEN) {
        this.send(ws, { type: "error", code: ERROR_CODES.BAD_FRAME });
        ws.close(4000, "bad-salt");
        return;
      }
      if (meta.salt && meta.salt !== frame.salt) {
        await this.endSession("key-loss");
        return;
      }
      meta.pubAdmin = frame.pub;
      meta.salt = frame.salt;
    } else {
      if (meta.pubPart && meta.pubPart !== frame.pub) {
        await this.endSession("key-loss");
        return;
      }
      meta.pubPart = frame.pub;
    }
    this.state.storage.put(META_KEY, meta);
    ws.serializeAttachment(att);

    // 双方公钥齐备 → 向双方发 peer 帧（DO 只中继，不计算指纹、不碰明文，§5.2）
    if (meta.pubAdmin && meta.pubPart && meta.salt) {
      this.deliverPeerAndBacklog(ws, att, meta);
      for (const conn of Object.values(live)) {
        if (!conn || conn === ws) continue;
        const a = conn.deserializeAttachment() as Attachment | null;
        if (!a || a.peerSent) continue;
        this.deliverPeerAndBacklog(conn, a, meta);
      }
    }
  }

  private pubOf(att: Attachment, meta: SessionMeta): string | undefined {
    return att.role === "admin" ? meta.pubAdmin : meta.pubPart;
  }

  private deliverPeerAndBacklog(ws: WebSocket, att: Attachment, meta: SessionMeta) {
    if (att.peerSent) return;
    // 重连接收方补发内存中尚存的未确认消息 + 尽力丢失计数（§7.5）
    const role = att.role;
    const peerRole: Role = role === "admin" ? "participant" : "admin";
    const senderMax =
      peerRole === "admin" ? meta.maxSentAdmin ?? 0 : meta.maxSentPart ?? 0;
    const pending = this.backlog[peerRole].filter((m) => m.seq > att.lastAck);
    if (pending.length > 0) {
      this.send(ws, {
        type: "backlog",
        msgs: pending.map(
          (m) =>
            ({
              type: "msg",
              from: peerRole,
              seq: m.seq,
              nonce: m.nonce,
              ct: m.ct,
            }) as RelayedMsgFrame,
        ),
      });
    }
    const lost = Math.max(0, senderMax - att.lastAck) - pending.length;
    if (lost > 0) this.send(ws, { type: "lost", n: lost });

    const theirPub = role === "admin" ? meta.pubPart : meta.pubAdmin;
    const peerVerified =
      role === "admin" ? meta.partVerified : meta.adminVerified;
    this.send(ws, {
      type: "peer",
      pub: theirPub,
      salt: meta.salt as string,
      deadline: meta.deadline,
      verified: peerVerified,
    });
    att.peerSent = true;
    ws.serializeAttachment(att);
  }

  private async onMsg(
    ws: WebSocket,
    att: Attachment,
    frame: { seq?: unknown; nonce?: unknown; ct?: unknown },
  ) {
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (!meta || this.ending) {
      this.send(ws, { type: "error", code: ERROR_CODES.ENDED });
      ws.close(4003, "ended");
      return;
    }
    const role = att.role;
    const seq = frame.seq as number;
    if (
      !Number.isInteger(seq) ||
      seq !== att.lastSent + 1 ||
      typeof frame.nonce !== "string" ||
      b64ToBytes(frame.nonce).length !== NONCE_LEN ||
      typeof frame.ct !== "string"
    ) {
      this.send(ws, { type: "error", code: ERROR_CODES.BAD_FRAME });
      ws.close(4000, "bad-msg");
      return;
    }
    // 单条消息上限 8KB（§5.3；ct = 密文 + 16B tag）
    if (b64ToBytes(frame.ct).length > MSG_CT_MAX) {
      this.send(ws, { type: "error", code: ERROR_CODES.BAD_FRAME });
      ws.close(4000, "msg-too-large");
      return;
    }
    att.lastSent = seq;
    ws.serializeAttachment(att);
    if (role === "admin") meta.maxSentAdmin = seq;
    else meta.maxSentPart = seq;
    this.state.storage.put(META_KEY, meta);

    // 密文只进内存 backlog（§7.2 零落盘）；超限丢弃最旧（§21：保留最近 500 条）
    const list = this.backlog[role];
    list.push({ seq, nonce: frame.nonce as string, ct: frame.ct as string });
    if (list.length > BACKLOG_LIMIT) list.splice(0, list.length - BACKLOG_LIMIT);

    // 中继给对端；对端离线 → 留在内存，重连时补发/计 lost
    const peerRole: Role = role === "admin" ? "participant" : "admin";
    const out: RelayedMsgFrame = {
      type: "msg",
      from: role,
      seq,
      nonce: frame.nonce as string,
      ct: frame.ct as string,
    };
    const live = this.liveConnections();
    if (live[peerRole]) this.send(live[peerRole], out);
  }

  private async onVerify(ws: WebSocket, att: Attachment) {
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (!meta) return;
    if (att.role === "admin") meta.adminVerified = true;
    else meta.partVerified = true;
    this.state.storage.put(META_KEY, meta);
    att.verified = true;
    ws.serializeAttachment(att);
    const peerRole: Role = att.role === "admin" ? "participant" : "admin";
    const live = this.liveConnections();
    if (live[peerRole]) this.send(live[peerRole], { type: "verified" });
  }

  /** 某方离开（end 帧或 WS close）：通知对端 + 进入 grace（仅 active 态，§4.2） */
  private async onPeerLeave(ws: WebSocket, att: Attachment) {
    void ws;
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    if (!meta || this.ending) return;
    if (meta.status !== "active") return; // created 态离开不触发 grace（对方之后仍可加入）

    const peerRole: Role = att.role === "admin" ? "participant" : "admin";
    const live = this.liveConnections();
    if (live[peerRole]) this.send(live[peerRole], { type: "peer-left" });

    // grace：60s 后若该方未以同公钥重连 → ended(全清)。
    // 不缩短已在跑的 grace 窗口（双方先后离开时以最早断开为准）。
    const now = Date.now();
    const alarm = meta.alarm;
    if (!alarm || alarm.kind !== "grace" || alarm.at > now + GRACE_PERIOD_MS) {
      meta.alarm = { kind: "grace", at: now + GRACE_PERIOD_MS };
      this.persistMeta(meta, meta.alarm);
    }
  }

  /**
   * ended(全清)（§4.2）：
   * 删 DO 持久化元数据 + 清所有闹钟 + 通知在线方 end + 清注册表引用。
   */
  private async endSession(
    reason: "ttl" | "admin-end" | "key-loss" | "grace-timeout",
  ) {
    if (this.ending) return;
    this.ending = true;
    const meta = await this.state.storage.get<SessionMeta>(META_KEY);
    const live = Object.values(this.liveConnections()).filter((c) => c !== undefined);
    for (const conn of live) {
      if (!conn) continue;
      this.send(conn, { type: "peer-gone" });
      this.send(conn, { type: "end", reason });
      try {
        conn.close(4001, "session-end");
      } catch {
        /* ignore */
      }
    }
    this.backlog = { admin: [], participant: [] };
    this.state.storage.delete(META_KEY);
    this.state.storage.deleteAlarm();
    // 清注册表引用（管理员列表）；失败不影响全清（§7.2：引用不含内容）
    if (meta) {
      try {
        await this.env.REGISTRY_DO.getByName("main").deleteRef(meta.codeHash);
      } catch {
        /* ignore */
      }
    }
  }

  private persistMeta(
    meta: SessionMeta,
    alarm?: { kind: "unused" | "grace" | "deadline"; at: number },
  ) {
    if (alarm) meta.alarm = alarm;
    this.state.storage.put(META_KEY, meta);
    if (meta.alarm) void this.state.storage.setAlarm(meta.alarm.at);
  }

  /** 当前各角色的活连接（休眠唤醒后从 attachment 重建，§7.3） */
  private liveConnections(): Record<Role, WebSocket | undefined> {
    const out: Record<Role, WebSocket | undefined> = {
      admin: undefined,
      participant: undefined,
    };
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() as Attachment | null;
      if (!att?.role || att.replaced) continue;
      if (!out[att.role]) out[att.role] = ws;
    }
    return out;
  }

  private send(ws: WebSocket, frame: unknown) {
    try {
      ws.send(JSON.stringify(frame));
    } catch {
      /* 连接已断 */
    }
  }
}
