# dida

网页版 1对1 临时端到端加密对话平台。

- 只有**管理员**能创建会话，生成 **12 位邀请码**邀请对方加入
- 消息内容**端到端加密**（X25519 + HKDF + AES-256-GCM），服务端不持久化任何密文、从不持有密钥
- 会话在 **TTL 到期 / 任一方离开 / 管理员提前结束** 时清除痕迹
- 前端独立托管（GitHub Pages），后端为 Cloudflare Worker（Durable Objects + Hibernation WebSocket）

实现依据是 [DESIGN.md](./DESIGN.md)——它是唯一的 single source of truth，包含完整的架构、协议、状态机、部署与验收清单。

## 仓库结构

```
apps/web        前端 SPA（React + Vite），托管在 GitHub Pages
apps/worker     Cloudflare Worker + 3 个 Durable Objects（Session / Guard / Registry）
packages/shared 帧协议、常量、邀请码/指纹纯函数（前后端共用）
```

## 快速开始（本地开发）

前置：Node 22（`brew install node@22`）、pnpm（`brew install pnpm`）。

```bash
pnpm install          # 工作区：apps/web + apps/worker + packages/shared
pnpm dev:worker       # miniflare 本地模拟 Worker + Durable Objects（默认 8787）
pnpm dev:web          # Vite dev server（5173，代理 /admin/* 与 /ws 到 miniflare）
```

浏览器开两个标签页联调：一个走 `/admin`（管理员，本地口令见 `apps/worker/wrangler.toml` 的 `DEV_ADMIN_PASSWORD`），一个走 `/`（对方凭码加入），并经由独立渠道核对安全指纹。详见 DESIGN.md §16。

注意：PITR 在本地开发不可用（本地不存持久日志），属预期。

## 测试

```bash
pnpm -r test          # shared / web / worker 全量单测（vitest）
pnpm --filter web build   # tsc --noEmit + vite build
```

## 部署

**前端 → GitHub Pages**：push 到 `main` 触发 `.github/workflows/deploy-web.yml`（`pnpm build` → `apps/web/dist` → Pages；构建产物含 `404.html` SPA 深链回退）。在仓库 Settings → Secrets and variables → **Variables** 配置：

- `VITE_API_URL`：Worker 的 HTTPS 地址（如 `https://dida.<account>.workers.dev`）
- `VITE_WS_URL`：Worker 的 WSS 地址（如 `wss://dida.<account>.workers.dev`），**不得带任何 query 参数**

**后端 → Cloudflare Worker**：

```bash
cd apps/worker
wrangler deployments create            # 首次部署（含 DO 迁移）
wrangler secret put ADMIN_PASS_HASH    # PBKDF2 哈希（格式见 DESIGN.md §9）
wrangler secret put TOKEN_SIGNING_KEY  # HMAC 签名密钥
```

并在 CF 控制台**关闭该 Worker 的 Request Logging**。部署后删除 `wrangler.toml` 中的 `DEV_ADMIN_PASSWORD` 变量（本地兜底，仅 `wrangler dev` 使用）。

**上线检查（§17.3）**：

- [ ] 前端 JS 确实来自 GitHub Pages 域（非 Worker 域）
- [ ] WS URL 无任何 query 参数
- [ ] CF Request Logging 已关
- [ ] Secrets 已设置、未进仓库
- [ ] 限流生效（登录失败锁定、加入 IP 限速）
- [ ] 指纹核对、grace 重连、TTL/提前结束清理均联调通过

## 隐私声明

> dida 在会话销毁时删除应用层数据；**服务端不持久化任何消息密文**，也从不持有可解密密钥。平台底层基础设施（含 30 天 PITR 机制）可能保留**无内容元数据**的历史副本，无法保证物理彻底消失。
>
> 前端代码独立托管于后端之外，即使后端恶意也无法篡改前端逻辑。
>
> 传输全程加密。安全指纹**须经独立渠道核对**；未核对时，仅能防止"存储型泄露"，**不能保证抵抗主动中间人攻击**。
>
> 托管方边缘层仍可观测到流量元数据（如 IP、时间戳）；关闭请求日志是可达的最小化边界。

## 已知限制

1. CF 边缘层可见流量元数据（IP/时间戳）；关请求日志是最小边界，非根除
2. 同浏览器开第二个标签页会结束会话（新密钥 = 会话终止）
3. 刷新可续聊（60s grace），关标签页即全失
4. 无历史恢复：密钥丢失后，密文永久不可读
5. 断线窗口内消息可能丢失（尽力补齐，非保证）
6. 未核对安全指纹时，不保证抵抗主动中间人攻击
7. PITR（30 天）可恢复 DO 存储历史，但本方案不落盘任何密文，至多恢复无内容元数据
8. 单管理员、1对1、纯文本（v1 范围）

完整清单与决策理由见 DESIGN.md §18–§20。
