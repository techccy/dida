/**
 * 全屏 canvas 水印覆盖层（§5.7）【决策 2026-10-24：浏览器内最强对抗 + §18 诚实声明】
 *
 * 对抗手段（均为提高抹除成本，非绝对防御——对方完全控制自己的浏览器时
 * 水印可被技术手段绕过，DESIGN.md §18 已如实声明）：
 * - canvas 像素绘制（非 DOM 文本，"删节点/改文本"不适用）
 * - MutationObserver + 周期自检：被移除立即重挂；display/visibility/opacity
 *   被样式隐藏时以 inline !important 压回（inline important 优先级最高）
 * - 约 30° 斜向平铺 + 逐行错位 + 瓦片内双行重复（单瓦片被裁掉仍可溯源）
 * - devtools 打开探测（console 对象 getter 探针）：页面模糊 + 提示条，
 *   不销毁内容、不断开连接（关闭 devtools 自动恢复）【决策：否决内容自毁】
 * - pointer-events: none，不拦截任何交互；深浅色主题自适应
 */
import { useEffect, useRef, useState } from "react";

/** 访问者设备信息（解析后简洁形式）：浏览器 + 操作系统 + 屏幕分辨率 */
export function deviceInfo(): string {
  const ua = navigator.userAgent;
  let browser = "浏览器";
  const m = ua.match(/(?:Edg|OPR|Firefox|Chrome|Safari)\/([\d]+)/);
  if (m) {
    const name = m[0].startsWith("Edg")
      ? "Edge"
      : m[0].startsWith("OPR")
        ? "Opera"
        : m[0].startsWith("Firefox")
          ? "Firefox"
          : m[0].startsWith("Chrome")
            ? "Chrome"
            : "Safari";
    browser = `${name} ${m[1]}`;
  }
  let os = "未知系统";
  if (/Android/.test(ua)) os = "Android";
  else if (/iPhone|iPad|iPod/.test(ua)) os = "iOS";
  else if (/Windows NT/.test(ua)) os = "Windows";
  else if (/Mac OS X/.test(ua)) os = "macOS";
  else if (/Linux/.test(ua)) os = "Linux";
  return `${browser} / ${os} / ${window.screen.width}×${window.screen.height}`;
}

const CANVAS_ID = "dida-wm-canvas";
/** 行距：同瓦片两份副本垂直相差半格（75px），不同行带亦不共 y，防叠印 */
const TILE_H = 150;
/** 相邻水印副本的最小水平安全间隙（px），防叠印 */
const GAP_X = 90;
const FONT_SIZE = 13;
/** devtools 探测：探针周期（ms）与关闭判定宽限 */
const PROBE_INTERVAL_MS = 2000;
const PROBE_CLOSE_GRACE_MS = 4500;

function drawWatermark(canvas: HTMLCanvasElement, text: string): void {
  const dpr = Math.min(window.devicePixelRatio || 1, 3);
  const w = window.innerWidth;
  const h = window.innerHeight;
  canvas.width = Math.max(1, Math.floor(w * dpr));
  canvas.height = Math.max(1, Math.floor(h * dpr));
  canvas.style.width = `${w}px`;
  canvas.style.height = `${h}px`;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const dark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  ctx.fillStyle = dark ? "rgba(205, 210, 220, 0.14)" : "rgba(55, 60, 70, 0.13)";
  ctx.font = `${FONT_SIZE}px system-ui, -apple-system, "Segoe UI", "PingFang SC", sans-serif`;
  ctx.textBaseline = "middle";
  // 动态瓦片宽度：按实测文本宽度 + 安全间隙计算，杜绝相邻副本叠印
  // （水印串含 IP/设备/时间时可达数百像素，固定间距会互相重叠）
  const textW = ctx.measureText(text).width;
  const cellW = Math.max(Math.ceil(textW) + GAP_X, 260);
  const cellH = TILE_H;
  // 旋转坐标系平铺：覆盖旋转后的对角线范围（外扩一圈防边缘漏铺）
  const diag = Math.sqrt(w * w + h * h);
  const half = diag / 2;
  ctx.save();
  ctx.translate(w / 2, h / 2);
  ctx.rotate((-30 * Math.PI) / 180);
  let row = 0;
  for (let y = -half - cellH; y < half; y += cellH, row++) {
    const offset = row % 2 === 0 ? 0 : cellW / 2; // 逐行错位，防整列裁剪
    for (let x = -half - cellW; x < half; x += cellW) {
      // 瓦片内双份重复：错位两份（水平半格 + 垂直半格），单份被裁掉仍可溯源；
      // 两份处于不同 y 带（相差 cellH/2），与相邻行也不共 y，互不叠印
      ctx.fillText(text, x + offset, y);
      ctx.fillText(text, x + offset + cellW / 2, y + cellH / 2);
    }
  }
  ctx.restore();
}

function hardenStyle(canvas: HTMLCanvasElement): void {
  const s = canvas.style;
  s.setProperty("position", "fixed", "important");
  s.setProperty("inset", "0", "important");
  s.setProperty("pointer-events", "none", "important");
  s.setProperty("display", "block", "important");
  s.setProperty("visibility", "visible", "important");
  s.setProperty("opacity", "1", "important");
  s.setProperty("z-index", "2147483647", "important");
}

export default function Watermark({ text }: { text: string }) {
  const [devtools, setDevtools] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const textRef = useRef(text);
  textRef.current = text;

  // 挂载/防护（一次性）
  useEffect(() => {
    // 去重（StrictMode 双挂载/重复进入）
    document.getElementById(CANVAS_ID)?.remove();
    const canvas = document.createElement("canvas");
    canvas.id = CANVAS_ID;
    hardenStyle(canvas);
    document.body.appendChild(canvas);
    canvasRef.current = canvas;

    const redraw = () => {
      if (canvas.isConnected && textRef.current)
        drawWatermark(canvas, textRef.current);
    };
    redraw();

    // 防移除：子树变动即检查重挂
    const mo = new MutationObserver(() => {
      if (!canvas.isConnected) document.body.appendChild(canvas);
    });
    mo.observe(document.documentElement, { childList: true, subtree: true });

    // 周期自检：重挂被删节点 + 内联 important 压回被 CSS 隐藏的样式
    const guard = window.setInterval(() => {
      if (!canvas.isConnected) document.body.appendChild(canvas);
      const st = getComputedStyle(canvas);
      if (
        st.display === "none" ||
        st.visibility === "hidden" ||
        Number(st.opacity) === 0
      ) {
        hardenStyle(canvas);
      }
    }, 1500);

    // 视口变化重绘
    window.addEventListener("resize", redraw);

    // devtools 打开探测：console 对象的 id getter 仅在 devtools 打开
    // （console 预览对象）时触发；连续周期未触发则判定关闭恢复
    let lastFired = 0;
    const probe = window.setInterval(() => {
      let fired = false;
      const obj: Record<string, string> = {};
      Object.defineProperty(obj, "id", {
        get() {
          fired = true;
          return "dida-wm-probe";
        },
        configurable: true,
      });
      console.log(obj);
      window.setTimeout(() => {
        if (fired) {
          lastFired = Date.now();
          setDevtools(true);
        } else if (lastFired > 0 && Date.now() - lastFired > PROBE_CLOSE_GRACE_MS) {
          setDevtools(false);
        }
      }, 120);
    }, PROBE_INTERVAL_MS);

    return () => {
      window.clearInterval(guard);
      window.clearInterval(probe);
      window.removeEventListener("resize", redraw);
      mo.disconnect();
      canvas.remove();
      canvasRef.current = null;
    };
  }, []);

  // 文本变化重绘；空文本清空画布（首次挂载时 effect 顺序保证 canvas 已存在）
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (text) drawWatermark(canvas, text);
    else canvas.getContext("2d")?.clearRect(0, 0, canvas.width, canvas.height);
  }, [text]);

  if (!text) return null;

  return devtools ? (
    <div className="wm-devtools-mask">
      <div className="wm-devtools-tip">
        检测到开发者工具已打开，页面内容已模糊。
        <br />
        关闭开发者工具后自动恢复。本页面内容带水印溯源。
      </div>
    </div>
  ) : null;
}
