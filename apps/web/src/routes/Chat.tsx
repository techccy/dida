/**
 * 对方聊天页（§3）：凭 sessionStorage 中的对话码（C 前缀）加入会话。
 * 码不进 URL；无码或码类型不符时回主页面。
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { isValidCodeOfKind } from "@dida/shared";
import ChatView from "../ui/ChatView";
import { clearCode, loadCode } from "../crypto/crypto";

export default function Chat() {
  const [code, setCode] = useState<string | null>(null);
  const nav = useNavigate();

  useEffect(() => {
    const c = loadCode();
    if (!c || !isValidCodeOfKind(c, "chat")) {
      if (c) clearCode();
      nav("/", { replace: true });
      return;
    }
    setCode(c);
  }, [nav]);

  if (code === null) return null;
  return (
    <ChatView
      role="participant"
      code={code}
      onEnded={() => nav("/", { replace: true })}
    />
  );
}
