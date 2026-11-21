/**
 * 网页快照渲染（§5.6.1）【决策 2026-11-21：渲染而非下载，JS 开 + 封外联】
 *
 * 流程：下载 pack（能力 URL，§7.6.1）→ 解密索引+逐文件 → blob: URL 映射 →
 * 改写 HTML 引用（src/href/srcset/url()、移除 <base>）→ 注入 CSP →
 * sandbox iframe（srcdoc）渲染。
 *
 * 安全机制：
 * - iframe 无 allow-same-origin → opaque origin，无法触达父页面 DOM/cookie/storage；
 * - CSP（injectPagePackCsp）封死全部外联：connect-src 'none'，资源仅 blob:/data:
 *   ——保存页残留的追踪脚本无法外联，提取者访问事实/IP 不泄漏给原站点（§5.6.1）；
 * - 全程客户端解密，服务端只见密文；水印由提取页全局 canvas 覆盖（含 iframe）。
 * - 刷新回放：缓存含 packId/dataKey（sessionStorage），重新下载 pack 重渲染；
 *   pack 已被 GC（销毁 + 10min 宽限窗过）→ 明确报错。
 */
import { useEffect, useRef, useState } from "react";
import {
  b64ToBytes,
  decryptPagePack,
  injectPagePackCsp,
  isHighRiskPath,
  mimeForPath,
  normalizePageRef,
  rewritePageHtml,
  type PagePackRef,
} from "@dida/shared";
import { downloadPagePack } from "../api";

type Phase = "download" | "render" | "done" | "error";

export default function PageSnapshot({ page }: { page: PagePackRef }) {
  const [phase, setPhase] = useState<Phase>("download");
  const [err, setErr] = useState<string | null>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [highRisk, setHighRisk] = useState(false);
  const urlsRef = useRef<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        setPhase("download");
        const pack = await downloadPagePack(page.packId);
        setPhase("render");
        const { entry, files } = await decryptPagePack(b64ToBytes(page.dataKey), pack);
        if (cancelled) return;
        const entryFile = files.find((f) => f.path === entry);
        if (!entryFile) throw new Error("missing entry");
        if (files.some((f) => isHighRiskPath(f.path))) setHighRisk(true);
        // blob URL 映射；归一化匹配覆盖 ./ 前缀、查询串、锚点、URI 编码变体
        const map = new Map<string, string>();
        for (const f of files) {
          const blob = new Blob([f.bytes.slice().buffer], {
            type: f.type ?? mimeForPath(f.path) ?? "application/octet-stream",
          });
          const url = URL.createObjectURL(blob);
          urlsRef.current.push(url);
          map.set(f.path, url);
        }
        const resolve = (raw: string): string | null => map.get(normalizePageRef(raw)) ?? null;
        const rewritten = injectPagePackCsp(
          rewritePageHtml(new TextDecoder().decode(entryFile.bytes), resolve),
        );
        setHtml(rewritten);
        setPhase("done");
      } catch (e) {
        if (cancelled) return;
        const status = (e as { status?: number })?.status;
        setErr(
          status === 404
            ? "快照数据已被服务端销毁（销毁后 10 分钟下载宽限窗已过）"
            : "快照解密失败或数据损坏",
        );
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
      for (const u of urlsRef.current) URL.revokeObjectURL(u);
      urlsRef.current = [];
    };
  }, [page.packId, page.dataKey]);

  if (phase === "error") {
    return <div className="err" style={{ marginTop: 12 }}>{err}</div>;
  }
  if (phase !== "done" || !html) {
    return (
      <div className="muted" style={{ margin: "24px 0" }}>
        {phase === "download" ? "下载快照中…" : "解密渲染中…"}
      </div>
    );
  }
  return (
    <div style={{ marginTop: 12 }}>
      {highRisk && (
        <div className="banner warn" style={{ marginBottom: 10 }}>
          ⚠️ 快照中包含可执行文件类型（如 .exe/.dmg/.sh），谨慎处理来源不明的内容。
        </div>
      )}
      <iframe
        title="网页快照"
        sandbox="allow-scripts"
        srcDoc={html}
        style={{
          width: "100%",
          height: "72vh",
          border: "1px solid rgba(127,127,127,0.35)",
          borderRadius: 8,
          background: "#fff",
        }}
      />
      <div className="muted" style={{ marginTop: 8 }}>
        快照在本页沙箱内渲染，已封断全部外部网络请求；水印覆盖全页仅作溯源威慑。
      </div>
    </div>
  );
}
