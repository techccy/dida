/**
 * 主页面（§3）：仅一个"邀请码输入框 + 加入按钮"。
 * 无 logo、无功能介绍、无多余信息；邀请码明文只存 sessionStorage，不进 URL。
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { isValidCode, normalizeCode } from "@dida/shared";
import { saveCode } from "../crypto/crypto";

export default function Entry() {
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const nav = useNavigate();

  const join = () => {
    const c = normalizeCode(code);
    if (!isValidCode(c)) {
      setErr("邀请码无效（应为 12 位字符）");
      return;
    }
    saveCode(c);
    nav("/c");
  };

  return (
    <div className="card">
      <div className="muted">输入邀请码</div>
      <input
        className="code-input"
        value={code}
        onChange={(e) => {
          setCode(e.target.value);
          setErr(null);
        }}
        onKeyDown={(e) => e.key === "Enter" && join()}
        placeholder="12 位邀请码"
        autoFocus
      />
      {err && <div className="banner">{err}</div>}
      <button className="primary" onClick={join}>
        加入
      </button>
    </div>
  );
}
