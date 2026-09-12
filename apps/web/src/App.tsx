/**
 * 路由（§3）：/ 主页面（邀请码输入）· /admin 管理员后台 · /c 对方聊天页。
 * base 由 VITE_BASE 注入（GitHub Pages 项目站点需要 /dida/ 前缀）。
 */
import { BrowserRouter, Route, Routes } from "react-router-dom";
import Entry from "./routes/Entry";
import Admin from "./routes/Admin";
import Chat from "./routes/Chat";

const base = import.meta.env.VITE_BASE ?? "/";

export default function App() {
  return (
    <BrowserRouter basename={base}>
      <div className="app">
        <Routes>
          <Route path="/" element={<Entry />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/c" element={<Chat />} />
          <Route path="*" element={<Entry />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
