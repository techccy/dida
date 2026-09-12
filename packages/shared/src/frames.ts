/**
 * WS 帧类型（§6 完整帧 schema）
 * 客户端 → DO：auth / join / pub / msg / ack / verify / end / ping
 * DO → 客户端：ok / peer / msg / backlog / lost / peer-left / peer-gone /
 *              verified / end / error / pong
 *
 * 约定：
 * - 所有二进制字段均为 base64 字符串（公钥 32B / salt 32B / nonce 12B / 密文 ≤8KB+tag）。
 * - 凭证只出现在 WS 首帧，绝不出现在任何 URL。
 */
import type { Role } from "./constants";

// ---- 客户端 → DO ----

export interface AuthFrame {
  type: "auth";
  /** 管理员签名 token（HMAC，§9） */
  credential: string;
  /** 目标会话 ID（创建会话时由 API 返回；非凭证，鉴权仍靠 token） */
  sessionId: string;
}

export interface JoinFrame {
  type: "join";
  /** 12 位邀请码（明文仅存在内存帧中） */
  code: string;
}

export interface PubFrame {
  type: "pub";
  /** 本方 X25519 公钥（32B b64） */
  pub: string;
  /** salt（32B b64）——仅管理员携带；对方可省略 */
  salt?: string;
}

export interface MsgFrame {
  type: "msg";
  /** 发送方从 1 递增 */
  seq: number;
  /** 12B b64 */
  nonce: string;
  /** AES-256-GCM 密文（含 tag，b64） */
  ct: string;
}

export interface AckFrame {
  type: "ack";
  /** 收到的最高连续 seq */
  seq: number;
}

export interface VerifyFrame {
  type: "verify";
}

export interface EndFrame {
  type: "end";
}

export interface PingFrame {
  type: "ping";
}

export type ClientFrame =
  | AuthFrame
  | JoinFrame
  | PubFrame
  | MsgFrame
  | AckFrame
  | VerifyFrame
  | EndFrame
  | PingFrame;

// ---- DO → 客户端 ----

export interface OkFrame {
  type: "ok";
  role: Role;
  /**
   * 服务端记录的"本方已发送最大 seq"（附件/meta 恢复的水位）。
   * 客户端重连/刷新后以此为准继续递增（§4.2 续聊；
   * 对 §6.2 ok 帧的向后兼容扩展）。
   */
  lastSent?: number;
}

export interface PeerFrame {
  type: "peer";
  /** 对端公钥（32B b64） */
  pub: string;
  /** salt（32B b64） */
  salt: string;
  /** 会话 deadline（joined_at + TTL，ms）——客户端倒计时用（扩展字段） */
  deadline?: number;
  /** 对端是否已核对指纹（扩展字段） */
  verified?: boolean;
}

export interface RelayedMsgFrame {
  type: "msg";
  from: Role;
  seq: number;
  nonce: string;
  ct: string;
}

export interface BacklogFrame {
  type: "backlog";
  /** 内存中尚存的未确认消息（补发） */
  msgs: RelayedMsgFrame[];
}

export interface LostFrame {
  type: "lost";
  /** 断线窗口内丢失的消息数（尽力而为，可能为 0/未知） */
  n: number;
}

export interface PeerLeftFrame {
  type: "peer-left";
}

export interface PeerGoneFrame {
  type: "peer-gone";
}

export interface VerifiedFrame {
  type: "verified";
}

export interface EndResultFrame {
  type: "end";
  reason: "ttl" | "admin-end" | "key-loss" | "grace-timeout";
}

export interface ErrorFrame {
  type: "error";
  code: string;
}

export interface PongFrame {
  type: "pong";
}

export type ServerFrame =
  | OkFrame
  | PeerFrame
  | RelayedMsgFrame
  | BacklogFrame
  | LostFrame
  | PeerLeftFrame
  | PeerGoneFrame
  | VerifiedFrame
  | EndResultFrame
  | ErrorFrame
  | PongFrame;

export type AnyFrame = ClientFrame | ServerFrame;
