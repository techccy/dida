# dida

网页版 1对1 临时端到端加密对话平台。

- 只有**管理员**能创建会话，生成 **12 位邀请码**邀请对方加入
- 消息内容**端到端加密**（X25519 + HKDF + AES-256-GCM），服务端不持久化任何密文、从不持有密钥
- 会话在 **TTL 到期 / 任一方离开 / 管理员提前结束** 时清除痕迹
- 前端独立托管（GitHub Pages），后端为 Cloudflare Worker（Durable Objects + Hibernation WebSocket）

> **本仓库当前只有设计文档，尚无代码。**
> 实现依据是 [DESIGN.md](./DESIGN.md)——它是唯一的 single source of truth，包含完整的架构、协议、状态机、部署与验收清单。新会话实现时请严格按它执行，不要回退其中的任何已定决策。

## 快速开始（本地开发）

前置：Node 22（`brew install node`）、pnpm（`brew install pnpm`）。

```bash
pnpm install          # 工作区：apps/web + apps/worker + packages/shared
pnpm dev:worker       # miniflare 本地模拟 Worker + Durable Objects
pnpm dev:web          # Vite dev server（WS 代理到 miniflare）
```

浏览器开两个标签页联调：一个走 `/admin`（管理员），一个走 `/`（对方凭码加入），并经由独立渠道核对安全指纹。详见 DESIGN.md §16。

## 部署

- 前端：GitHub Actions 构建 → GitHub Pages（独立于后端）
- 后端：`wrangler` 部署 Cloudflare Worker；Secrets 存 `ADMIN_PASS_HASH` 与 `TOKEN_SIGNING_KEY`；关闭该 Worker 的 Request Logging

详见 DESIGN.md §17。

## 隐私声明

dida 在会话销毁时删除应用层数据；**服务端不持久化任何消息密文**，也从不持有可解密密钥。平台底层基础设施（含 30 天 PITR 机制）可能保留**无内容元数据**的历史副本，无法保证物理彻底消失。

前端代码独立托管于后端之外，即使后端恶意也无法篡改前端逻辑。

传输全程加密。安全指纹**须经独立渠道核对**；未核对时，仅能防止"存储型泄露"，**不能保证抵抗主动中间人攻击**。

托管方边缘层仍可观测到流量元数据（如 IP、时间戳）；关闭请求日志是可达的最小化边界。

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
