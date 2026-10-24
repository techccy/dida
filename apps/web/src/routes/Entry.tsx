/**
 * 主页面（§3）：仅一个"配对码输入框 + 粘贴按钮 + 加入按钮"。
 * 无 logo、无功能介绍、无多余信息；码明文只存 sessionStorage，不进 URL。
 * 按前缀路由【决策】：C=对话码 → /c；E=提取码 → /e（不用 /extract，与 Worker API 路径冲突）。
 * 前缀必填：缺前缀直接报错，不做自动猜测。
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { codeKind, isValidCode, normalizeCode } from "@dida/shared";
import { saveCode, saveExtractCode } from "../crypto/crypto";

export default function Entry() {
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const nav = useNavigate();

  const join = () => {
    const c = normalizeCode(code);
    const kind = codeKind(c);
    if (kind === null) {
      // 8 位无前缀 → 提示补首字母；其余按无效处理
      setErr(
        /^[0-9A-HJKMNP-TV-Z]{8}$/.test(c)
          ? "请输入完整配对码（含首字母：对话码 C、提取码 E）"
          : "配对码无效",
      );
      return;
    }
    if (!isValidCode(c)) {
      setErr("配对码无效");
      return;
    }
    if (kind === "chat") {
      saveCode(c);
      nav("/c");
    } else {
      saveExtractCode(c);
      nav("/e");
    }
  };

  const paste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text.trim()) return;
      setCode(text.trim());
      setErr(null);
    } catch {
      setErr("无法读取剪贴板，请手动粘贴");
    }
  };

  return (
    <div className="card">
      <div className="muted">输入配对码</div>
      <div className="entry-row">
        <input
          className="code-input"
          value={code}
          onChange={(e) => {
            setCode(e.target.value);
            setErr(null);
          }}
          onKeyDown={(e) => e.key === "Enter" && join()}
          placeholder="C/E-XXXXXXXX"
          autoFocus
        />
        <button onClick={() => void paste()}>粘贴</button>
      </div>
      {err && <div className="banner">{err}</div>}
      <button className="primary" onClick={join}>
        加入
      </button>
    </div>
  );
}
