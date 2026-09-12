/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** REST API 基地址（生产 = Worker 域名；本地开发 = 空串，走 Vite 代理） */
  readonly VITE_API_URL?: string;
  /** WSS 基地址（生产 = wss://<worker>.workers.dev；本地 = 空串，走 Vite 代理） */
  readonly VITE_WS_URL?: string;
  /** 部署路径前缀（GitHub Pages project pages：/dida/） */
  readonly VITE_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
