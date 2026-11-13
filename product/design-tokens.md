# dida — 设计 Tokens 规范

> 2026-11-13 UI 重设计拍板产物。事实来源锚定 `DESIGN.md`（产品事实不变，本文件只定义视觉层）。
> 调性：**暗色「无痕」风**——近黑底、青绿点缀、等宽安全锚点。

## 1. 决策记录

| 决策 | 结论 |
|---|---|
| 改造范围 | 重排布局 + 全新视觉；协议/路由/水印/分格输入逻辑不动 |
| 调性 | 暗色「无痕」风（dark-first，浅色做减法适配） |
| 字体 | Space Grotesk（display）+ JetBrains Mono（mono），@fontsource self-host，零第三方请求 |
| 点缀色 | 青绿（终端/密码学气质） |
| 主页 | 微氛围（暗角光晕 + 极淡噪点）+ 输入居中；无 logo 无介绍（DESIGN.md §3 不变） |
| 管理端 | 分区导航式：登录独立屏；登录后侧栏「会话 / 提取包」 |
| 聊天页 | 全高 messenger 式（顶栏状态+倒计时 / 消息流 / 吸底输入） |
| CSS | 手写 CSS 全面 token 化（CSS variables），零新依赖 |

## 2. 颜色

CSS variables 命名空间 `--d-*`（dida）。

### 暗色（主题基准）

```css
:root {
  /* 背景层 */
  --d-bg:        #0c0e12;   /* 页面底 */
  --d-surface:   #14171d;   /* 卡片/面板 */
  --d-surface-2: #1a1e26;   /* 次级面板 / 输入底 */
  --d-border:    #262b35;   /* 边框 */
  --d-border-strong: #333a47;

  /* 文本 */
  --d-text:      #e8eaf0;
  --d-text-muted:#8a92a3;
  --d-text-faint:#5c6474;

  /* 点缀 */
  --d-accent:        #38d39f;
  --d-accent-strong: #4ee3b1;
  --d-accent-dim:    rgba(56, 211, 159, 0.14);   /* 淡底/选中底 */
  --d-accent-border: rgba(56, 211, 159, 0.45);

  /* 状态 */
  --d-danger: #e5484d;
  --d-warn:   #f5b544;
  --d-ok:     #38d39f;      /* 与点缀同族，语义复用 */

  /* 气泡 */
  --d-bubble-mine:   #1e3a31;   /* 我的消息：青绿深调底 */
  --d-bubble-theirs: #1f232c;
}
```

### 浅色（减法适配）

```css
@media (prefers-color-scheme: light) {
  :root {
    --d-bg:        #f5f6f8;
    --d-surface:   #ffffff;
    --d-surface-2: #f0f2f5;
    --d-border:    #dcdfe5;
    --d-border-strong: #c3c8d1;
    --d-text:      #171a21;
    --d-text-muted:#5c6474;
    --d-text-faint:#8a92a3;
    --d-accent:        #0e9e73;   /* 暗底青绿在浅底对比不足，压深 */
    --d-accent-strong: #0b8763;
    --d-accent-dim:    rgba(14, 158, 115, 0.10);
    --d-accent-border: rgba(14, 158, 115, 0.45);
    --d-danger: #d13438;
    --d-warn:   #b7791f;
    --d-ok:     #0e9e73;
    --d-bubble-mine:   #d8f3e8;
    --d-bubble-theirs: #eef0f4;
  }
}
```

## 3. 字体

```css
--d-font-display: "Space Grotesk", system-ui, -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
--d-font-body:    system-ui, -apple-system, "PingFang SC", "Segoe UI", "Microsoft YaHei", sans-serif;
--d-font-mono:    "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
```

- **display**：页面主标题、品牌字标（管理端侧栏）、大号码展示。
- **body**：正文、消息、表单。中文自动回退系统字体。
- **mono**：配对码（分格输入/大号展示）、倒计时、提取内容预览、密文/哈希类信息。
- **self-host 约束**：`@fontsource/space-grotesk` + `@fontsource/jetbrains-mono`，woff2 进构建产物；**禁止** Google Fonts 等 CDN（访问者 IP 隐私）。中文不引字体文件（体积/隐私），走系统栈。

## 4. 几何与层级

```css
--d-radius-lg: 12px;   /* 卡片/面板 */
--d-radius-md: 8px;    /* 气泡、次级容器 */
--d-radius-sm: 6px;    /* 按钮、输入、码格 */
--d-space-1: 4px;  --d-space-2: 8px;  --d-space-3: 12px;
--d-space-4: 16px; --d-space-5: 24px; --d-space-6: 32px;
--d-max-w: 720px;      /* 内容列上限（聊天/表单区） */
```

- 阴影克制：暗色主题下用**边框分层**而非投影；浅色下允许 `0 1px 2px rgba(0,0,0,.05)` 级微影。
- 聚焦态：`outline: none` + `box-shadow: 0 0 0 2px var(--d-accent-border)`。
- 等宽码格：聚焦格 `--d-accent` 描边 + 闪烁光标（沿用现有 caret 动画）。

## 5. 组件基调

- **按钮**：primary = 青绿实底（暗底上用深字 `#0c0e12` 保证对比）；secondary = 边框式；danger = 红边框式（确认二次弹层）。
- **信息包气泡**：青绿虚线边框 + `📦 信息包` 标签行 + mono 截断预览 + 复制按钮（逻辑不变，视觉重排）。
- **状态指示**：顶栏圆点 + 文案（等待对方=warn 黄、已连接=ok 绿、已结束=faint 灰）。
- **倒计时**：mono 字体；剩余 <10% 时转 warn 色。
- **水印**：canvas 渲染不变；半透明中灰逻辑保留（深浅色自适应，§5.7）。
- **主页氛围**：`radial-gradient` 暗角青绿光晕（约 4% 透明度）+ 极淡 SVG 噪点，`pointer-events:none`，不承载信息。
