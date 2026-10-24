/**
 * 管理员后台（§3、§9）：
 * 登录（PBKDF2 口令 → 8h HMAC token，存 sessionStorage）→
 * 创建会话（TTL 档位）→ 会话列表（状态/剩余时间倒计时/提前结束）→
 * 点进活跃会话内嵌聊天视图。
 * token 只走 Authorization 头与 WS 首帧，不进 URL（§9）。
 */
import { useCallback, useEffect, useState } from "react";
import {
  EXTRACT_MAX_BYTES,
  EXTRACT_MAX_COUNT,
  TTL_OPTIONS,
  bytesToB64,
  formatCode,
  generateCode,
  parseCustomCode,
  sha256Hex,
} from "@dida/shared";
import {
  ApiError,
  apiBase,
  createExtract,
  createSession,
  destroyExtract,
  endSession,
  listExtracts,
  listSessions,
  type ExtractInfo,
  type SessionInfo,
} from "../api";
import {
  clearAdminToken,
  deriveExtractKey,
  encryptExtract,
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
  // 自定义对话码【决策 2026-10-24：全局允许自定义配对码】：留空 = 随机生成
  const [customChatCode, setCustomChatCode] = useState("");

  const [openId, setOpenId] = useState<string | null>(null);
  const [endedReason, setEndedReason] = useState<string | null>(null);

  // ---------- 提取包（§5.6） ----------
  const [extracts, setExtracts] = useState<ExtractInfo[]>([]);
  const [extractContent, setExtractContent] = useState("");
  const [extractStyle, setExtractStyle] = useState<"packet" | "message">("packet");
  const [extractTtlMs, setExtractTtlMs] = useState<number>(TTL_OPTIONS[4].ms);
  const [extractCount, setExtractCount] = useState(1);
  const [extractBusy, setExtractBusy] = useState(false);
  const [extractErr, setExtractErr] = useState<string | null>(null);
  const [newExtractCode, setNewExtractCode] = useState<string | null>(null);
  const [newExtractCopied, setNewExtractCopied] = useState(false);
  // 自定义提取码【决策 2026-10-24】：留空 = 随机生成；仍纯前端生成，码明文不经服务端
  const [customExtractCode, setCustomExtractCode] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [list, extList] = await Promise.all([listSessions(), listExtracts()]);
      setSessions(list);
      setExtracts(extList);
      setApiErr(null);
    } catch {
      setApiErr("加载列表失败");
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
      setExtracts([]);
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
    setExtracts([]);
    setOpenId(null);
  };

  const create = async () => {
    setCreating(true);
    setApiErr(null);
    try {
      // 自定义码留空 → 服务端随机生成；填写 → 归一化 + 格式校验后随请求发送
      let code: string | undefined;
      const raw = customChatCode.trim();
      if (raw) {
        const parsed = parseCustomCode(raw, "chat");
        if (!parsed) {
          setApiErr("自定义对话码无效：需为 C + 8 位（Crockford 字符，不含 I/L/O/U）");
          return;
        }
        code = parsed;
      }
      // 码明文只在创建响应里返回一次（§8）；刷新后不再可见
      const created = await createSession(ttlMs, code);
      setNewCode(created.code);
      setCopied(false);
      setCustomChatCode("");
      await refresh();
    } catch (e) {
      if (e instanceof ApiError && e.status === 400)
        setApiErr("自定义对话码无效：需为 C + 8 位（Crockford 字符，不含 I/L/O/U）");
      else if (e instanceof ApiError && e.status === 409)
        setApiErr("该对话码已被活跃会话占用，请换一个");
      else setApiErr("创建失败");
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

  // ---------- 提取包（§5.6）：前端生成码 → 码派生密钥加密 → 只上传哈希+密文 ----------

  const createExtractPkg = async () => {
    if (!extractContent || extractBusy) return;
    setExtractErr(null);
    if (new TextEncoder().encode(extractContent).length > EXTRACT_MAX_BYTES) {
      setExtractErr("内容超过 32KB 上限");
      return;
    }
    setExtractBusy(true);
    try {
      // 码明文只在本地存在：服务端只见 SHA-256 哈希与密文（服务端永不持有可解密能力）。
      // 自定义提取码同样纯前端生成、派生密钥，码明文不经服务端【决策 2026-10-24】
      const raw = customExtractCode.trim();
      let code: string;
      if (raw) {
        const parsed = parseCustomCode(raw, "extract");
        if (!parsed) {
          setExtractErr("自定义提取码无效：需为 E + 8 位（Crockford 字符，不含 I/L/O/U）");
          return;
        }
        code = parsed;
      } else {
        code = generateCode("extract");
      }
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveExtractKey(code, salt);
      const { nonce, ct } = await encryptExtract(key, extractContent);
      const codeHash = await sha256Hex(code);
      await createExtract({
        codeHash,
        ct,
        nonce,
        salt: bytesToB64(salt),
        style: extractStyle,
        ttlMs: extractTtlMs,
        maxCount: extractCount,
      });
      setNewExtractCode(formatCode(code));
      setNewExtractCopied(false);
      setExtractContent("");
      setCustomExtractCode("");
      await refresh();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409)
        setExtractErr("该提取码已被未销毁的提取包占用，请换一个");
      else setExtractErr("创建提取包失败");
    } finally {
      setExtractBusy(false);
    }
  };

  const copyNewExtractCode = () => {
    if (!newExtractCode) return;
    void navigator.clipboard.writeText(newExtractCode).then(() => setNewExtractCopied(true));
  };

  const doDestroyExtract = async (id: string) => {
    try {
      await destroyExtract(id);
      await refresh();
    } catch {
      setExtractErr("销毁提取包失败");
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

      <div style={{ display: "flex", gap: 8, marginTop: 14, flexWrap: "wrap" }}>
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
        <input
          value={customChatCode}
          onChange={(e) => setCustomChatCode(e.target.value)}
          placeholder="自定义对话码（可选，C-XXXXXXXX）"
          style={{ width: 260 }}
          spellCheck={false}
          autoCapitalize="characters"
        />
        <button
          className="primary"
          onClick={() => void create()}
          disabled={creating}
        >
          {creating ? "创建中…" : "创建会话"}
        </button>
      </div>
      <div className="muted" style={{ marginTop: 6 }}>
        会话时长从对方加入时起算；未使用的码 7 天后自动作废。自定义码留空则随机生成；弱码会降低防猜测强度。
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
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {sessions.length === 0 && (
            <tr>
              <td colSpan={3} className="muted">
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

      {/* ---------- 提取包（§5.6） ---------- */}
      <div
        style={{
          borderTop: "1px solid #d6d9de",
          marginTop: 20,
          paddingTop: 14,
        }}
      >
        <strong>提取包</strong>
        <div className="muted" style={{ marginTop: 4 }}>
          键入内容生成提取码，对方凭码在本站主页提取；到期或次数用尽即销毁。
        </div>

        <textarea
          value={extractContent}
          onChange={(e) => {
            setExtractContent(e.target.value);
            setExtractErr(null);
          }}
          placeholder="输入要交付的内容（密钥、配置、文本…，上限 32KB）"
          rows={4}
          style={{ marginTop: 10, resize: "vertical" }}
        />
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          <select
            value={extractStyle}
            onChange={(e) => setExtractStyle(e.target.value as "packet" | "message")}
            style={{ width: "auto" }}
          >
            <option value="packet">信息包（截断+复制）</option>
            <option value="message">消息（只读展示）</option>
          </select>
          <select
            value={extractTtlMs}
            onChange={(e) => setExtractTtlMs(Number(e.target.value))}
            style={{ width: "auto" }}
          >
            {TTL_OPTIONS.map((o) => (
              <option key={o.ms} value={o.ms}>
                有效期 {o.label}
              </option>
            ))}
          </select>
          <select
            value={extractCount}
            onChange={(e) => setExtractCount(Number(e.target.value))}
            style={{ width: "auto" }}
          >
            {Array.from({ length: EXTRACT_MAX_COUNT }, (_, i) => i + 1).map((n) => (
              <option key={n} value={n}>
                可提取 {n} 次
              </option>
            ))}
          </select>
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input
            value={customExtractCode}
            onChange={(e) => setCustomExtractCode(e.target.value)}
            placeholder="自定义提取码（可选，E-XXXXXXXX）"
            style={{ width: 260 }}
            spellCheck={false}
            autoCapitalize="characters"
          />
          <button
            className="primary"
            onClick={() => void createExtractPkg()}
            disabled={extractBusy || !extractContent.trim()}
          >
            {extractBusy ? "生成中…" : "生成提取码"}
          </button>
        </div>
        <div className="muted" style={{ marginTop: 6 }}>
          自定义码留空则随机生成。提取码密钥由码派生，弱码会显著降低抗离线枚举强度，敏感内容建议用随机码。
        </div>
        {extractErr && <div className="banner">{extractErr}</div>}

        {newExtractCode && (
          <div
            style={{
              margin: "12px 0",
              border: "1px solid #27ae60",
              borderRadius: 8,
              padding: 12,
            }}
          >
            <div className="muted">新提取码（仅此一次，请复制后通过独立渠道发给对方）</div>
            <div className="code" style={{ margin: "6px 0" }}>{newExtractCode}</div>
            <button onClick={copyNewExtractCode}>
              {newExtractCopied ? "已复制" : "复制"}
            </button>
          </div>
        )}

        <table>
          <thead>
            <tr>
              <th>状态</th>
              <th>剩余时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {extracts.length === 0 && (
              <tr>
                <td colSpan={3} className="muted">
                  暂无提取包
                </td>
              </tr>
            )}
            {extracts.map((e) => (
              <tr key={e.extractId}>
                <td>
                  {e.status === "destroyed"
                    ? "已销毁"
                    : e.usedCount > 0
                      ? `已提取 ${e.usedCount}/${e.maxCount}`
                      : "待提取"}
                </td>
                <td>
                  {e.status === "ready" ? fmtRemain(e.expiresAt, now) : "—"}
                </td>
                <td>
                  {e.status === "ready" && (
                    <button
                      className="danger"
                      onClick={() => {
                        if (window.confirm("确定销毁该提取包？内容将不可再提取。"))
                          void doDestroyExtract(e.extractId);
                      }}
                    >
                      提前销毁
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

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
