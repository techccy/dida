/**
 * 路由（§3）：/ 主页面（配对码输入，按前缀路由）· /admin 管理员后台 ·
 * /c 对方聊天页 · /e 提取页（注意：SPA 路由用 /e，避免与 Worker API 的
 * POST /extract 冲突——Workers Routes 不分方法，/extract 会落到 Worker）。
 * base 由 VITE_BASE 注入（GitHub Pages 项目站点需要 /dida/ 前缀）。
 */
import { BrowserRouter, Route, Routes } from "react-router-dom";
import Entry from "./routes/Entry";
import Admin from "./routes/Admin";
import Chat from "./routes/Chat";
import Extract from "./routes/Extract";

const base = import.meta.env.VITE_BASE ?? "/";

export default function App() {
  return (
    <BrowserRouter basename={base}>
      <div className="app">
        <Routes>
          <Route path="/" element={<Entry />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/c" element={<Chat />} />
          <Route path="/e" element={<Extract />} />
          <Route path="*" element={<Entry />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
