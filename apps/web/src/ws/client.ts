/**
 * WSS 客户端（§5.5、§6、§4.2）：
 * - 首帧鉴权（auth/join，凭证不进 URL）
 * - 30s 心跳探测（ping/pong），死链 → 重连
 * - 断线自动重连（指数退避，覆盖 60s grace 窗口；同公钥 = 续聊）
 * - 消息：方向性密钥加解密、seq 顺序交付、ack 最高连续 seq
 * - backlog 补发 / lost 计数 / peer-left / end 处理
 *
 * 密钥与 salt 来自 sessionStorage（crypto/ 层）；刷新后同密钥重连即续聊。
 */
import {
  PING_INTERVAL_MS,
  type RelayedMsgFrame,
  type Role,
  type ServerFrame,
  b64ToBytes,
  bytesToB64,
  computeFingerprint,
} from "@dida/shared";
import {
  decryptMsg,
  deriveDirectionKeys,
  encryptMsg,
  type DirectionKeys,
  type KeyPair,
  type PlainMessage,
} from "../crypto/crypto";

export type ConnState =
  | "connecting"
  | "waiting-peer"
  | "ready"
  | "ended"
  | "error";

export interface ClientOptions {
  /** WSS 地址（无 query） */
  wsUrl: string;
  role: Role;
  /** 管理员 token（role=admin） */
  credential?: string;
  /** 会话 ID（role=admin） */
  sessionId?: string;
  /** 邀请码（role=participant） */
  code?: string;
  /** 本方密钥对（调用方从 sessionStorage 加载/生成后传入） */
  keyPair: KeyPair;
  /** 本方 salt（仅管理员） */
  salt?: Uint8Array;
  onState: (state: ConnState, detail?: string) => void;
  onMessage: (msg: PlainMessage) => void;
  onFingerprint: (fingerprint: string) => void;
  /** peer 帧元数据：会话截止时间 + 对端是否已核对（§6.2） */
  onPeerMeta: (meta: { deadline?: number; verified: boolean }) => void;
  onVerified: (peerVerified: boolean) => void;
  onLost: (n: number) => void;
  onPeerLeft: () => void;
  onEnd: (reason: string) => void;
  onError: (code: string) => void;
}

const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 10_000;
/** 无 pong 超过该时长视为死链（探测，§5.5） */
const PONG_TIMEOUT_MS = 15_000;
/** 乱序缓冲上限 */
const GAP_BUFFER_MAX = 200;

export class DidaClient {
  private readonly opts: ClientOptions;
  private ws: WebSocket | null = null;
  private state: ConnState = "connecting";
  private closedByUser = false;
  private reconnectTimer: number | null = null;
  private pingTimer: number | null = null;
  private pongTimer: number | null = null;
  private reconnectAttempt = 0;

  // 发送水位（ok.lastSent 恢复）
  private lastSent = 0;
  // 接收：最高连续 seq（= 已 ack 的 seq）
  private lastReceived = 0;
  private gap = new Map<number, RelayedMsgFrame>();
  /** 密钥未就绪时先缓冲（backlog 可能先于 peer 帧到达，§7.5） */
  private pendingFrames: RelayedMsgFrame[] = [];

  private keys: DirectionKeys | null = null;
  private pubAdmin: Uint8Array | null = null;
  private pubParticipant: Uint8Array | null = null;
  private salt: Uint8Array | null = null;

  constructor(opts: ClientOptions) {
    this.opts = opts;
    this.connect();
  }

  private connect() {
    const ws = new WebSocket(this.opts.wsUrl);
    this.ws = ws;
    this.setState("connecting");

    const firstFrame =
      this.opts.role === "admin"
        ? {
            type: "auth",
            credential: this.opts.credential,
            sessionId: this.opts.sessionId,
          }
        : { type: "join", code: this.opts.code };

    ws.onopen = () => {
      // 首帧鉴权（§6.1）；凭证只在这一帧，不进 URL
      ws.send(JSON.stringify(firstFrame));
    };

    ws.onmessage = (ev) => {
      let frame: ServerFrame;
      try {
        frame = JSON.parse(typeof ev.data === "string" ? ev.data : "") as ServerFrame;
      } catch {
        return;
      }
      this.handleFrame(frame);
    };

    ws.onclose = () => {
      this.clearTimers();
      this.keys = null;
      if (this.closedByUser) return;
      // 会话已 ended 的连接不重连
      if (this.state === "ended") return;
      this.scheduleReconnect();
    };

    ws.onerror = () => {
      /* onclose 会跟进 */
    };
  }

  private handleFrame(frame: ServerFrame) {
    switch (frame.type) {
      case "ok": {
        this.reconnectAttempt = 0;
        // 续聊：服务端记录的本方已发最大 seq（§4.2）
        this.lastSent = typeof frame.lastSent === "number" ? frame.lastSent : 0;
        this.setState("waiting-peer");
        this.sendPub();
        this.startHeartbeat();
        return;
      }
      case "peer": {
        this.opts.onPeerMeta({
          deadline: typeof frame.deadline === "number" ? frame.deadline : undefined,
          verified: frame.verified === true,
        });
        void this.onPeer(frame.pub, frame.salt);
        return;
      }
      case "msg": {
        this.onRelayed(frame);
        return;
      }
      case "backlog": {
        // 重连补发（可能含已交付的 seq，按 seq 去重）
        for (const m of frame.msgs) this.onRelayed(m);
        return;
      }
      case "lost": {
        if (frame.n > 0) {
          // 丢失的消息不可恢复（§7.5 尽力而为）：推进接收水位，
          // 否则后续消息会永久卡在 gap 缓冲区，对话从此不可用
          this.lastReceived += frame.n;
          for (const k of [...this.gap.keys()])
            if (k <= this.lastReceived) this.gap.delete(k);
          this.sendAck();
          void this.deliverNext();
          this.opts.onLost(frame.n);
        }
        return;
      }
      case "peer-left": {
        this.opts.onPeerLeft();
        return;
      }
      case "peer-gone": {
        this.opts.onPeerLeft();
        return;
      }
      case "verified": {
        this.opts.onVerified(true);
        return;
      }
      case "end": {
        this.setState("ended", frame.reason);
        this.opts.onEnd(frame.reason);
        this.clearTimers();
        return;
      }
      case "error": {
        this.opts.onError(frame.code);
        // 终态错误：不再重连
        if (
          frame.code === "code-expired" ||
          frame.code === "bad-cred"
        ) {
          this.setState("error", frame.code);
          this.clearTimers();
        }
        return;
      }
      case "pong": {
        this.armPongTimer();
        return;
      }
    }
  }

  /** 发送本方公钥（+ salt，仅管理员） */
  private sendPub() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const frame =
      this.opts.role === "admin"
        ? {
            type: "pub" as const,
            pub: bytesToB64(this.opts.keyPair.pubRaw),
            salt: this.opts.salt ? bytesToB64(this.opts.salt) : undefined,
          }
        : { type: "pub" as const, pub: bytesToB64(this.opts.keyPair.pubRaw) };
    this.ws.send(JSON.stringify(frame));
  }

  private async onPeer(pubB64: string, saltB64: string) {
    try {
      const peerPub = b64ToBytes(pubB64);
      this.salt = b64ToBytes(saltB64);
      if (this.opts.role === "admin") {
        this.pubAdmin = this.opts.keyPair.pubRaw;
        this.pubParticipant = peerPub;
      } else {
        this.pubAdmin = peerPub;
        this.pubParticipant = this.opts.keyPair.pubRaw;
      }
      const peerKey = await crypto.subtle.importKey(
        "raw",
        peerPub.slice().buffer,
        { name: "X25519" },
        true,
        // 浏览器 WebCrypto 要求公钥导入时用空 usages（Node 22 亦兼容）
        [],
      );
      this.keys = await deriveDirectionKeys(
        this.opts.keyPair.privateKey,
        peerKey,
        this.salt,
        this.opts.role,
      );
      // 重连时 backlog 帧可能先于 peer 帧到达（DO 先发 backlog 再发 peer，§7.5）
      this.flushPendingFrames();
      // 指纹：双方本地各算（DO 不参与，§5.4）
      const fp = await computeFingerprint(
        this.pubAdmin,
        this.pubParticipant,
        this.salt,
      );
      this.opts.onFingerprint(fp);
      this.setState("ready");
    } catch {
      this.setState("error", "crypto");
    }
  }

  /**
   * 接收消息：按 seq 顺序交付（乱序缓冲），ack 最高连续 seq。
   * 重复 seq（backlog 补发已交付过的）直接忽略。
   * 密钥未就绪（peer 帧未处理完）时先缓冲，就绪后统一交付。
   */
  private onRelayed(m: RelayedMsgFrame) {
    if (!this.keys) {
      if (this.pendingFrames.length < GAP_BUFFER_MAX) this.pendingFrames.push(m);
      return;
    }
    if (m.seq <= this.lastReceived) return; // 重复（补发）
    if (this.gap.size >= GAP_BUFFER_MAX) return;
    this.gap.set(m.seq, m);
    // 顺序/乱序统一从 gap 头部按序交付
    void this.deliverNext();
  }

  /** 密钥就绪后交付缓冲的帧 */
  private flushPendingFrames() {
    for (const m of this.pendingFrames.splice(0)) this.onRelayed(m);
  }

  private async deliverNext() {
    for (;;) {
      const next = this.lastReceived + 1;
      const m = this.gap.get(next);
      if (!m) break;
      this.gap.delete(next);
      try {
        const plain = await decryptMsg(
          this.keys!.decKey,
          m.from,
          m.nonce,
          m.ct,
        );
        this.lastReceived = next;
        this.sendAck();
        this.opts.onMessage(plain);
      } catch {
        // 解密失败（篡改/AAD 不匹配）：丢弃该 seq 并继续
        this.lastReceived = next;
        this.sendAck();
      }
    }
  }

  private sendAck() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    if (this.lastReceived > 0)
      this.ws.send(JSON.stringify({ type: "ack", seq: this.lastReceived }));
  }

  /** 发送一条明文消息（加密后经 WS 发出）。返回 false = 超限未发 */
  async sendText(text: string): Promise<boolean> {
    if (!this.keys || !this.ws || this.ws.readyState !== WebSocket.OPEN)
      return false;
    try {
      const { nonce, ct } = await encryptMsg(
        this.keys.encKey,
        { text, ts: Date.now() },
        this.opts.role,
      );
      this.lastSent += 1;
      this.ws.send(
        JSON.stringify({ type: "msg", seq: this.lastSent, nonce, ct }),
      );
      return true;
    } catch {
      // MsgTooLargeError 等：拒发
      return false;
    }
  }

  /** 本方已完成指纹 OOB 核对 */
  verify() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN)
      this.ws.send(JSON.stringify({ type: "verify" }));
  }

  /** 主动离开（发 end 帧）；不清本地密钥 —— 60s 内同密钥可重连续聊 */
  leave() {
    this.closedByUser = true;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify({ type: "end" }));
      } catch {
        /* ignore */
      }
    }
    this.closeWs();
  }

  dispose() {
    this.closedByUser = true;
    this.clearTimers();
    this.closeWs();
  }

  private closeWs() {
    try {
      this.ws?.close(4000, "leave");
    } catch {
      /* ignore */
    }
    this.ws = null;
  }

  // ---------- 心跳与重连 ----------

  private startHeartbeat() {
    this.clearTimers();
    this.pingTimer = window.setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
      try {
        this.ws.send(JSON.stringify({ type: "ping" }));
      } catch {
        return;
      }
      this.armPongTimer();
    }, PING_INTERVAL_MS);
  }

  private armPongTimer() {
    if (this.pongTimer) window.clearTimeout(this.pongTimer);
    this.pongTimer = window.setTimeout(() => {
      // 死链（NAT/休眠）：强制关闭触发重连
      this.closeWs();
    }, PONG_TIMEOUT_MS);
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return;
    const delay = Math.min(
      RECONNECT_BASE_MS * 2 ** this.reconnectAttempt,
      RECONNECT_MAX_MS,
    );
    this.reconnectAttempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      if (this.closedByUser || this.state === "ended") return;
      this.connect();
    }, delay);
  }

  private clearTimers() {
    if (this.pingTimer) window.clearInterval(this.pingTimer);
    if (this.pongTimer) window.clearTimeout(this.pongTimer);
    if (this.reconnectTimer) window.clearTimeout(this.reconnectTimer);
    this.pingTimer = null;
    this.pongTimer = null;
    this.reconnectTimer = null;
  }

  private setState(state: ConnState, detail?: string) {
    this.state = state;
    this.opts.onState(state, detail);
  }
}
