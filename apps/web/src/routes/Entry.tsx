/**
 * 主页面（§3）：分格配对码输入（1 前缀框 + 连字符 + 8 位框，仿 Filebox）+ 粘贴按钮 + 加入按钮。
 * 无 logo、无功能介绍、无多余信息；码明文只存 sessionStorage，不进 URL。
 * 按前缀路由【决策】：C=对话码 → /c；E=提取码 → /e（不用 /extract，与 Worker API 路径冲突）。
 * 前缀必填：缺前缀直接报错，不做自动猜测。
 * 【决策 2026-10-24：分格输入】单一隐藏 input 承载状态、视觉切格——粘贴/移动端/输入法行为
 * 由原生 input 保证。顺序填充：输入自动跳下一格，退格回删上一格；粘贴归一化（大写、剥
 * 离分隔符）后从第一格顺序填充；非法字符不拦截、提交时统一校验；保留粘贴按钮与加入按钮。
 */
import { Fragment, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  CODE_RANDOM_LENGTH,
  codeKind,
  isValidCode,
  normalizeCode,
} from "@dida/shared";
import { saveCode, saveExtractCode } from "../crypto/crypto";

const TOTAL_LEN = 1 + CODE_RANDOM_LENGTH;

export default function Entry() {
  const [code, setCode] = useState("");
  const [focused, setFocused] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const nav = useNavigate();

  /** 归一化：大写、剥离空格/连字符/下划线，截断到前缀+随机段总长 */
  const normalize = (s: string) =>
    normalizeCode(s).slice(0, TOTAL_LEN);

  /** 光标恒定钉在末尾：顺序填充/顺序回删模型，不支持中间插入 */
  const pinCaret = () => {
    const el = inputRef.current;
    if (el && el.selectionStart !== el.value.length)
      el.setSelectionRange(el.value.length, el.value.length);
  };

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

  /** 粘贴（按钮与 paste 事件同语义）：归一化后从第一格顺序填充（整体替换） */
  const paste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text.trim()) return;
      setCode(normalize(text));
      setErr(null);
    } catch {
      setErr("无法读取剪贴板，请手动粘贴");
      inputRef.current?.focus();
    }
  };

  const onPasteEvent = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const text = e.clipboardData.getData("text");
    if (text.trim()) {
      setCode(normalize(text));
      setErr(null);
    }
  };

  return (
    <div className="card">
      <div className="muted">输入配对码</div>
      <div className="entry-row">
        <div
          className="code-boxes"
          onClick={() => inputRef.current?.focus()}
          role="textbox"
          aria-label="配对码输入"
        >
          {Array.from({ length: TOTAL_LEN }, (_, i) => (
            <Fragment key={i}>
              {i === 1 && <span className="code-dash">-</span>}
              <div
                className={
                  "code-box" +
                  (focused && i === code.length && code.length < TOTAL_LEN
                    ? " active"
                    : "") +
                  (err ? " invalid" : "")
                }
              >
                {code[i] ?? ""}
              </div>
            </Fragment>
          ))}
          <input
            ref={inputRef}
            className="code-boxes-input"
            value={code}
            onChange={(e) => {
              setCode(normalize(e.target.value));
              setErr(null);
            }}
            onPaste={onPasteEvent}
            onKeyDown={(e) => {
              if (e.key === "Enter") join();
              // 阻止光标移动/选区，维持"只在末尾编辑"的顺序模型
              if (
                e.key === "ArrowLeft" ||
                e.key === "ArrowRight" ||
                e.key === "Home" ||
                e.key === "End"
              )
                e.preventDefault();
            }}
            onSelect={pinCaret}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            autoFocus
            autoCapitalize="characters"
            autoCorrect="off"
            autoComplete="off"
            spellCheck={false}
            enterKeyHint="go"
            aria-label="配对码"
          />
        </div>
        <button onClick={() => void paste()}>粘贴</button>
      </div>
      {err && <div className="banner">{err}</div>}
      <button className="primary" onClick={join}>
        加入
      </button>
    </div>
  );
}
