/**
 * 提取页（§5.6，SPA 路由 /e）：凭 sessionStorage 中的提取码（E 前缀）兑换并解密内容。
 * - 码不进 URL；无码回主页面。
 * - 解密后的明文存本标签页 sessionStorage【决策】：刷新可回看，关标签页即清，
 *   防止"次数=1 的包被误刷新永久丢失"。
 * - 呈现样式由管理员创建时选定：
 *   packet  = 信息包样式（📦 截断预览 + 一键复制全文，承载可传输内容）
 *   message = 消息样式（全文只读、无复制按钮，承载保密内容）
 * - 水印（§5.7）：配置嵌在密文内（ExtractEnvelope），服务端不可见；
 *   IP/时间取兑换响应中服务端注入的访问者自身值。
 * - 兑换失败（错码/过期/次数耗尽）统一模糊提示【决策】：防探测。
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  isValidCodeOfKind,
  normalizeCode,
  parseExtractEnvelope,
  b64ToBytes,
} from "@dida/shared";
import { extractRedeem } from "../api";
import Watermark, { deviceInfo } from "../ui/Watermark";
import {
  clearExtractCache,
  clearExtractCode,
  decryptExtract,
  deriveExtractKey,
  loadExtractCache,
  loadExtractCode,
  saveExtractCache,
  type ExtractCache,
} from "../crypto/crypto";

function packetPreview(text: string): string {
  const chars = Array.from(text.trim());
  return chars.length > 24 ? chars.slice(0, 24).join("") + "…" : chars.join("");
}

export default function Extract() {
  const [cache, setCache] = useState<ExtractCache | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [copied, setCopied] = useState(false);
  const copiedTimerRef = useRef<number | null>(null);
  const nav = useNavigate();

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const raw = loadExtractCode();
      if (!raw) {
        nav("/", { replace: true });
        return;
      }
      const code = normalizeCode(raw);
      if (!isValidCodeOfKind(code, "extract")) {
        clearExtractCode();
        nav("/", { replace: true });
        return;
      }
      // 同码缓存命中：直接回看（不重复消耗提取次数）
      const cached = loadExtractCache(code);
      if (cached) {
        setCache(cached);
        setBusy(false);
        return;
      }
      try {
        const payload = await extractRedeem(code);
        const key = await deriveExtractKey(code, b64ToBytes(payload.salt));
        const raw = await decryptExtract(key, payload.nonce, payload.ct);
        // 明文信封解析（§5.7）：v1 = JSON({v,text,wm})；旧版包为裸文本（无水印）
        const { text, wm } = parseExtractEnvelope(raw);
        const next: ExtractCache = {
          code,
          text,
          style: payload.style,
          remaining: payload.remaining,
          expiresAt: payload.expiresAt,
          wm: { cfg: wm, ip: payload.ip, ts: payload.ts },
        };
        saveExtractCache(next);
        if (!cancelled) {
          setCache(next);
          setBusy(false);
        }
      } catch {
        if (!cancelled) {
          setErr("提取码无效或已失效");
          setBusy(false);
        }
      }
    })();
    return () => {
      cancelled = true;
      if (copiedTimerRef.current) window.clearTimeout(copiedTimerRef.current);
    };
  }, [nav]);

  const copy = () => {
    if (!cache) return;
    void navigator.clipboard.writeText(cache.text).then(() => {
      setCopied(true);
      if (copiedTimerRef.current) window.clearTimeout(copiedTimerRef.current);
      copiedTimerRef.current = window.setTimeout(() => setCopied(false), 1500);
    });
  };

  const leave = () => {
    clearExtractCode();
    clearExtractCache();
    nav("/", { replace: true });
  };

  // 水印文案（§5.7）：按密文内配置拼接；IP/时间为兑换时服务端注入值（静态）
  const wmText = useMemo(() => {
    const w = cache?.wm;
    if (!w?.cfg) return "";
    const parts: string[] = [];
    if (w.cfg.custom) parts.push(w.cfg.custom);
    if (w.cfg.ip) parts.push("IP " + (w.ip ?? "未知"));
    if (w.cfg.device) parts.push(deviceInfo());
    if (w.cfg.time && w.ts)
      parts.push(new Date(w.ts).toLocaleString("zh-CN", { hour12: false }));
    return parts.join(" · ");
  }, [cache]);

  if (busy) {
    return (
      <div className="card extract-page">
        <div className="muted">提取中…</div>
      </div>
    );
  }

  if (err || !cache) {
    return (
      <div className="card extract-page">
        <div className="banner">{err ?? "提取失败"}</div>
        <button className="primary" onClick={leave}>
          返回
        </button>
      </div>
    );
  }

  return (
    <div className="card extract-page">
      <div className="muted">提取内容</div>

      {cache.style === "packet" ? (
        <div className="extract-packet">
          <div className="packet-head">📦 信息包</div>
          <div className="packet-preview">{packetPreview(cache.text)}</div>
          <button className="copy-btn" onClick={copy}>
            {copied ? "已复制" : "复制"}
          </button>
        </div>
      ) : (
        <div className="extract-message">
          <div className="packet-head">🔒 保密内容</div>
          <div className="extract-plain">{cache.text}</div>
          <div className="muted" style={{ marginTop: 6 }}>
            此内容仅供查看，不提供复制。
          </div>
        </div>
      )}

      <div className="status-line">
        {cache.remaining > 0 ? `剩余 ${cache.remaining} 次提取机会 · ` : ""}
        有效期至 {new Date(cache.expiresAt).toLocaleString("zh-CN")}
      </div>
      <div className="muted">刷新本页可回看；关闭标签页后内容不可再恢复。</div>

      <button style={{ marginTop: 12 }} onClick={leave}>
        完成（清除本页内容）
      </button>
      {wmText && <Watermark text={wmText} />}
    </div>
  );
}
