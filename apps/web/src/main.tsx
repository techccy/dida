import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
// 自托管字体（woff2 进构建产物，零第三方请求；中文走系统栈）
import "@fontsource/space-grotesk/400.css";
import "@fontsource/space-grotesk/500.css";
import "@fontsource/space-grotesk/600.css";
import "@fontsource/space-grotesk/700.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "./index.css";

const root = document.getElementById("root");
if (!root) throw new Error("root element missing");

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
