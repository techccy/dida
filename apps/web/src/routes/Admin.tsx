/**
 * 管理员后台（§3、§9）：
 * 登录（PBKDF2 口令 → 8h HMAC token，存 sessionStorage）→
 * 创建会话（TTL 档位）→ 会话列表（状态/剩余时间倒计时/提前结束）→
 * 点进活跃会话内嵌聊天视图。
 * token 只走 Authorization 头与 WS 首帧，不进 URL（§9）。
 */
import { useCallback, useEffect, useState } from "react";
import { TTL_OPTIONS } from "@dida/shared";
import {
  apiBase,
  createSession,
  endSession,
  listSessions,
  type SessionInfo,
} from "../api";
import {
  clearAdminToken,
  loadAdminToken,
  saveAdminToken,
} from "../crypto/crypto";
import ChatView from "../ui/ChatView";

function fmtRemain(deadline: number, now: number): string {
  const remain = Math.max(0, deadline - now);
  const h = Math.floor(remain / 3600000);
  const m = Math.floor((remain % 3600000) / 60000);
  const s = Math.floor((remain % 60000) / 1000);
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
}

const STATUS_TEXT: Record<SessionInfo["status"], string> = {
  created: "等待加入",
  active: "进行中",
  ended: "已结束",
};

export default function Admin() {
  const [authed, setAuthed] = useState(() => loadAdminToken() !== null);
  const [password, setPassword] = useState("");
  const [loginErr, setLoginErr] = useState<string | null>(null);
  const [loginBusy, setLoginBusy] = useState(false);

  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [now, setNow] = useState(Date.now());
  const [apiErr, setApiErr] = useState<string | null>(null);

  const [ttlMs, setTtlMs] = useState<number>(TTL_OPTIONS[1].ms);
  const [creating, setCreating] = useState(false);
  const [newCode, setNewCode] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [openId, setOpenId] = useState<string | null>(null);
  const [endedReason, setEndedReason] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await listSessions();
      setSessions(list);
      setApiErr(null);
    } catch {
      setApiErr("加载会话列表失败");
    }
  }, []);

  // 秒级倒计时 + 5s 轮询刷新状态
  useEffect(() => {
    if (!authed) return;
    void refresh();
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    const poll = window.setInterval(() => void refresh(), 5000);
    return () => {
      window.clearInterval(tick);
      window.clearInterval(poll);
    };
  }, [authed, refresh]);

  // token 失效（401）→ 回登录
  useEffect(() => {
    const on401 = () => {
      setAuthed(false);
      setSessions([]);
      setOpenId(null);
    };
    window.addEventListener("dida-admin-401", on401);
    return () => window.removeEventListener("dida-admin-401", on401);
  }, []);

  const doLogin = async () => {
    if (!password) return;
    setLoginBusy(true);
    setLoginErr(null);
    try {
      const res = await fetch(apiBase() + "/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (res.status === 429) {
        setLoginErr("失败次数过多，已锁定 15 分钟");
        return;
      }
      if (!res.ok) {
        setLoginErr("口令错误");
        return;
      }
      const data = (await res.json()) as { token: string };
      saveAdminToken(data.token);
      setAuthed(true);
      setPassword("");
    } catch {
      setLoginErr("网络错误");
    } finally {
      setLoginBusy(false);
    }
  };

  const logout = () => {
    clearAdminToken();
    setAuthed(false);
    setSessions([]);
    setOpenId(null);
  };

  const create = async () => {
    setCreating(true);
    try {
      // 码明文只在创建响应里返回一次（§8）；刷新后不再可见
      const created = await createSession(ttlMs);
      setNewCode(created.code);
      setCopied(false);
      await refresh();
    } catch {
      setApiErr("创建失败");
    } finally {
      setCreating(false);
    }
  };

  const copy = () => {
    if (!newCode) return;
    void navigator.clipboard.writeText(newCode).then(() => setCopied(true));
  };

  const doEnd = async (id: string) => {
    try {
      await endSession(id);
      if (openId === id) {
        setOpenId(null);
      }
      await refresh();
    } catch {
      setApiErr("结束会话失败");
    }
  };

  if (!authed) {
    return (
      <div className="card">
        <div className="muted">管理员登录</div>
        <input
          type="password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setLoginErr(null);
          }}
          onKeyDown={(e) => e.key === "Enter" && void doLogin()}
          placeholder="管理员口令"
          autoFocus
        />
        {loginErr && <div className="banner">{loginErr}</div>}
        <button
          className="primary"
          onClick={() => void doLogin()}
          disabled={loginBusy}
          style={{ marginTop: 10 }}
        >
          {loginBusy ? "登录中…" : "登录"}
        </button>
      </div>
    );
  }

  const openSession = sessions.find((s) => s.sessionId === openId);

  return (
    <div className="card" style={{ marginTop: 24, marginBottom: 24 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <strong>会话管理</strong>
        <button onClick={logout}>退出登录</button>
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
        <select
          value={ttlMs}
          onChange={(e) => setTtlMs(Number(e.target.value))}
          style={{ width: "auto" }}
        >
          {TTL_OPTIONS.map((o) => (
            <option key={o.ms} value={o.ms}>
              {o.label}
            </option>
          ))}
        </select>
        <button
          className="primary"
          onClick={() => void create()}
          disabled={creating}
        >
          {creating ? "创建中…" : "创建会话"}
        </button>
      </div>
      <div className="muted" style={{ marginTop: 6 }}>
        会话时长从对方加入时起算；未使用的码 7 天后自动作废。
      </div>

      {newCode && (
        <div style={{ margin: "12px 0", border: "1px solid #27ae60", borderRadius: 8, padding: 12 }}>
          <div className="muted">新邀请码（仅此一次，请复制后通过独立渠道发给对方）</div>
          <div className="code" style={{ margin: "6px 0" }}>{newCode}</div>
          <button onClick={copy}>{copied ? "已复制" : "复制"}</button>
        </div>
      )}

      {apiErr && <div className="banner">{apiErr}</div>}

      {endedReason && <div className="banner">{endedReason}</div>}

      <table>
        <thead>
          <tr>
            <th>状态</th>
            <th>剩余时间</th>
            <th>指纹核对</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {sessions.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                暂无会话
              </td>
            </tr>
          )}
          {sessions.map((s) => (
            <tr key={s.sessionId}>
              <td>{STATUS_TEXT[s.status]}</td>
              <td>
                {s.status === "active" && s.deadline
                  ? fmtRemain(s.deadline, now)
                  : "—"}
              </td>
              <td>
                {s.status === "active"
                  ? [
                      s.adminVerified ? "你 ✓" : "你 ✗",
                      s.partVerified ? "对方 ✓" : "对方 ✗",
                    ].join(" / ")
                  : "—"}
              </td>
              <td>
                {s.status === "active" && (
                  <>
                    <button
                      className="ok"
                      onClick={() => {
                        setEndedReason(null);
                        setOpenId(s.sessionId);
                      }}
                    >
                      进入
                    </button>
                    <button
                      className="danger"
                      style={{ marginLeft: 6 }}
                      onClick={() => {
                        if (window.confirm("确定结束该会话？将清除全部数据。"))
                          void doEnd(s.sessionId);
                      }}
                    >
                      提前结束
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {openSession && (
        <div style={{ marginTop: 16 }}>
          <ChatView
            role="admin"
            credential={loadAdminToken() ?? undefined}
            sessionId={openSession.sessionId}
            onEnded={(reason) => {
              setEndedReason(
                reason === "admin-end"
                  ? "你已结束该会话"
                  : reason === "ttl"
                    ? "会话已到期并清除"
                    : reason === "key-loss"
                      ? "密钥变化，会话已终止并清除"
                      : "对方长时间未返回，会话已终止并清除",
              );
              setOpenId(null);
              void refresh();
            }}
          />
        </div>
      )}
    </div>
  );
}
