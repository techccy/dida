/**
 * Vite 配置（§16、§17）：
 * - base 由 VITE_BASE 注入（GitHub Pages 项目站点：/dida/）
 * - 本地开发：/admin/* 与 /ws 代理到 wrangler dev（miniflare，默认 8787）
 * - 构建产物 SPA 回退：index.html 复制为 404.html（GitHub Pages 深链）
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const base = process.env.VITE_BASE ?? "/";

/** 构建后把 index.html 复制为 404.html，GitHub Pages 深链回退 */
function spa404(): Plugin {
  return {
    name: "dida-spa-404",
    apply: "build",
    writeBundle() {
      const out = resolve(process.cwd(), "dist");
      const html = readFileSync(resolve(out, "index.html"), "utf8");
      writeFileSync(resolve(out, "404.html"), html);
    },
  };
}

export default defineConfig({
  base,
  plugins: [react(), spa404()],
  server: {
    proxy: {
      // 仅代理 /admin/ 下的 API 路径（login / sessions）；SPA 路由 /admin 本体仍由前端处理（§16）
      "/admin/": { target: "http://localhost:8787", changeOrigin: true },
      "/ws": {
        target: "http://localhost:8787",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    sourcemap: false,
  },
});
