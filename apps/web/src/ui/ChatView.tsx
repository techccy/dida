/**
 * 聊天视图（管理员后台内嵌 / 对方聊天页共用）：
 * 消息列表 + 输入框 + 状态指示 + 剩余时间倒计时 + 信息包气泡（§3、§5.4）。
 */
import { useEffect, useRef, useState } from "react";
import { DidaClient, type ConnState } from "../ws/client";
import {
  clearLocalKeyPair,
  generateKeyPair,
  loadAdminSalt,
  loadLocalKeyPair,
  saveLocalKeyPair,
  type KeyPair,
} from "../crypto/crypto";
import { wsUrl } from "../api";
import type { Role } from "@dida/shared";
import { MSG_MAX_BYTES } from "@dida/shared";

interface Props {
  role: Role;
  /** 管理员 token（role=admin） */
  credential?: string;
  /** 会话 ID（role=admin） */
  sessionId?: string;
  /** 邀请码（role=participant） */
  code?: string;
  /** 会话结束后回调（返回上级页面） */
  onEnded?: (reason: string) => void;
  onUnauthorized?: () => void;
}

const END_TEXT: Record<string, string> = {
  ttl: "会话已到期，已终止并清除",
  "admin-end": "管理员已结束会话并清除",
  "key-loss": "密钥已变化（如开了第二个标签页），会话已终止并清除",
  "grace-timeout": "对方长时间未返回，会话已终止并清除",
};

interface ChatMsg {
  text: string;
  ts: number;
  mine: boolean;
  /** 信息包（§5.4）：截断展示 + 一键复制全文 */
  packet?: boolean;
}

/** 信息包气泡截断预览：前 24 字符 + 省略号 */
function packetPreview(text: string): string {
  const chars = Array.from(text.trim());
  return chars.length > 24 ? chars.slice(0, 24).join("") + "…" : chars.join("");
}

export default function ChatView({
  role,
  credential,
  sessionId,
  code,
  onEnded,
  onUnauthorized,
}: Props) {
  const [state, setState] = useState<ConnState>("connecting");
  const [stateDetail, setStateDetail] = useState<string | undefined>();
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [deadline, setDeadline] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());
  const [lostTotal, setLostTotal] = useState(0);
  const [peerLeft, setPeerLeft] = useState(false);
  const [input, setInput] = useState("");
  const [tooLong, setTooLong] = useState(false);
  /** 信息包复制反馈：最近一次复制的消息下标 */
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const clientRef = useRef<DidaClient | null>(null);
  const keyRef = useRef<KeyPair | null>(null);
  const messagesRef = useRef<HTMLDivElement | null>(null);
  const copiedTimerRef = useRef<number | null>(null);

  // 加载/生成本方密钥（sessionStorage；刷新后同密钥 = 续聊）
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const admin = role === "admin";
      let kp = await loadLocalKeyPair(admin ? "admin" : "part");
      let salt: Uint8Array | undefined;
      if (!kp) {
        kp = await generateKeyPair();
        if (admin) salt = crypto.getRandomValues(new Uint8Array(32));
        await saveLocalKeyPair(admin ? "admin" : "part", kp, salt);
      } else if (admin) {
        salt = loadAdminSalt() ?? undefined;
      }
      if (cancelled) return;
      keyRef.current = kp;
      clientRef.current = new DidaClient({
        wsUrl: wsUrl(),
        role,
        credential,
        sessionId,
        code,
        keyPair: kp,
        salt,
        onState: (s, detail) => {
          setState(s);
          setStateDetail(detail);
          if (s === "error" && detail === "bad-cred") onUnauthorized?.();
        },
        onMessage: (m) => {
          // 能收到对端消息即对端在线：兜底清"对方暂时离开"
          setPeerLeft(false);
          setMessages((prev) => [
            ...prev,
            { text: m.text, ts: m.ts, mine: false, packet: m.packet },
          ]);
        },
        onPeerMeta: (meta) => {
          if (meta.deadline !== undefined) setDeadline(meta.deadline);
        },
        onLost: (n) => setLostTotal((t) => t + n),
        onPeerLeft: () => setPeerLeft(true),
        onPeerBack: () => setPeerLeft(false),
        onEnd: (reason) => {
          // ended 全清（§4.2）：本方密钥/token 一并清除
          clearLocalKeyPair(role === "admin" ? "admin" : "part");
          onEnded?.(reason);
        },
        onError: (c) => {
          if (c === "bad-cred") onUnauthorized?.();
        },
      });
    })();
    return () => {
      cancelled = true;
      clientRef.current?.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [role, credential, sessionId, code]);

  // 倒计时
  useEffect(() => {
    if (deadline === null) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [deadline]);

  // 复制反馈计时器清理
  useEffect(() => {
    return () => {
      if (copiedTimerRef.current) window.clearTimeout(copiedTimerRef.current);
    };
  }, []);

  // 滚动到底
  useEffect(() => {
    messagesRef.current?.scrollTo({ top: messagesRef.current.scrollHeight });
  }, [messages]);

  const overLimit = (text: string) =>
    new TextEncoder().encode(text).length > MSG_MAX_BYTES - 32;

  const send = async (packet = false) => {
    const text = input.trim();
    if (!text || !clientRef.current) return;
    if (overLimit(text)) {
      setTooLong(true);
      return;
    }
    const ok = await clientRef.current.sendText(text, packet);
    if (ok) {
      setMessages((prev) => [
        ...prev,
        { text, ts: Date.now(), mine: true, packet },
      ]);
      setInput("");
      setTooLong(false);
    } else {
      setTooLong(true);
    }
  };

  const copyMsg = (i: number, text: string) => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopiedIdx(i);
      if (copiedTimerRef.current) window.clearTimeout(copiedTimerRef.current);
      copiedTimerRef.current = window.setTimeout(() => setCopiedIdx(null), 1500);
    });
  };

  const statusText = (() => {
    if (state === "connecting") return "连接中…";
    if (state === "waiting-peer")
      return role === "admin" ? "等待对方加入…" : "等待管理员…";
    if (state === "ready") return "已连接";
    if (state === "ended") return "会话已结束";
    return "连接出错";
  })();

  const remain =
    deadline !== null ? Math.max(0, deadline - now) : null;
  const remainText =
    remain === null
      ? null
      : `${Math.floor(remain / 3600000)} 小时 ${Math.floor(
          (remain % 3600000) / 60000,
        )} 分 ${Math.floor((remain % 60000) / 1000)} 秒`;

  return (
    <div className="chat-wrap">
      <div className="status-line">
        {statusText}
        {remainText ? ` · 剩余 ${remainText}` : ""}
        {lostTotal > 0 ? ` · 断线期间丢失约 ${lostTotal} 条` : ""}
        {peerLeft && state === "ready" ? " · 对方暂时离开" : ""}
      </div>

      <div className="messages" ref={messagesRef}>
        {messages.length === 0 && (
          <div className="muted" style={{ padding: 8 }}>
            {state === "ready" ? "开始对话。" : "等待连接…"}
          </div>
        )}
        {messages.map((m, i) =>
          m.packet ? (
            <div key={i} className={`msg packet ${m.mine ? "mine" : "theirs"}`}>
              <div className="packet-head">📦 信息包</div>
              <div className="packet-preview">{packetPreview(m.text)}</div>
              <button
                className="copy-btn"
                onClick={() => copyMsg(i, m.text)}
              >
                {copiedIdx === i ? "已复制" : "复制"}
              </button>
              <span className="ts">
                {new Date(m.ts).toLocaleTimeString("zh-CN", {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
            </div>
          ) : (
            <div key={i} className={`msg ${m.mine ? "mine" : "theirs"}`}>
              {m.text}
              <span className="ts">
                {new Date(m.ts).toLocaleTimeString("zh-CN", {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </span>
            </div>
          ),
        )}
      </div>

      {state === "ended" && (
        <div className="banner">{END_TEXT[stateDetail ?? ""] ?? "会话已终止"}</div>
      )}

      {state !== "ended" && (
        <div className="composer">
          <textarea
            value={input}
            placeholder="输入消息…"
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send();
              }
            }}
          />
          {role === "admin" && (
            <button onClick={() => void send(true)} disabled={!input.trim()}>
              打包发送
            </button>
          )}
          <button className="primary" onClick={() => void send()}>
            发送
          </button>
        </div>
      )}
      {tooLong && <div className="banner">单条消息超过 8KB 上限，未发送</div>}
      {stateDetail && state === "error" && (
        <div className="banner">连接错误：{stateDetail}</div>
      )}
    </div>
  );
}
