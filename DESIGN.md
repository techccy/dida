# dida — 临时端到端加密对话平台 · 设计文档

> **本文档是唯一的实现依据（single source of truth）。**
> 新会话/新实现者应严格按本文档实现，不要"简化"或"优化"掉任何已定决策。
> 文档中标注【决策】的地方是已经过评审拍板的取舍，附理由，请勿回退。
> 技术名词保留英文；面向用户的文案用简体中文。

---

## 0. 一句话定位

网页版 **1对1 临时对话**：只有**管理员**能创建会话并生成 **12 位邀请码**；**对方**凭码加入；消息内容**端到端加密**（服务端只经手密文，且**密文零落盘**）；会话在 **TTL 到期 / 任一方离开（60s grace 超时）/ 管理员提前结束** 时清除痕迹。

核心卖点：**尽量不留下痕迹** + **诚实的安全边界声明**。

---

## 1. 威胁模型（显式，必须照此实现与表述）

| 类别 | 威胁 | 本方案 |
|---|---|---|
| 能防 | 服务端从**正常存储**中读出明文 | ✅ 密文零落盘 + 服务端永远没有密钥 |
| 能防 | 恶意后端**篡改前端 JS** 直接读明文 | ✅ 前端独立托管（GitHub Pages），与后端分离 |
| 能防 | 传输层**被动**窃听（中间人只读） | ✅ 全程 TLS / WSS |
| 缓解但需配合 | 传输层**主动** MITM（篡改密钥交换） | ⚠️ 安全指纹经独立渠道 OOB 核对（软验证） |
| 边界/不防 | 托管方边缘层的流量元数据（IP、时间戳） | ❌ 关 CF Request Logging 是可达的最小边界，无法根除 |
| 边界/不防 | 双方**未核对**指纹时的主动 MITM | ❌ 实时可读（必须靠指纹核对兜住） |

**实现者须知**：本方案**不是**"即使服务器恶意也绝对读不到"的强 E2EE；它是"防止服务器从存储中拿到明文 + 防止后端篡改前端 + 用指纹核对兜住主动 MITM"的组合。所有对外文案必须与 §13 的隐私声明一致，**不得夸大为绝对安全**。

---

## 2. 总体架构（双托管）【决策：前后端分离】

```
┌─────────────────────────────────────────────┐
│  静态前端（GitHub Pages，独立基础设施）        │
│  React SPA（Vite 构建产物）                    │
│  路由：/   /admin   /c                        │
│  —— CF 无法篡改这里的 JS ——                    │
└─────────────────────────────────────────────┘
        │  HTTPS (fetch)  +  WSS
        ▼
┌─────────────────────────────────────────────┐
│  Cloudflare Worker（API 域）                 │
│  · POST /admin/login  → 签发签名 token        │
│  · WSS 端点 → Durable Object                │
│  · Session DO × N（Hibernation WebSocket）   │
│  · Guard DO（限流计数）                       │
└─────────────────────────────────────────────┘
```

**理由**：前端 JS 若也由后端提供，恶意后端改 JS 即可直接取走加密前明文。分离托管后，后端最多只能做"密钥交换的主动 MITM"，而该威胁由 §5 的安全指纹 OOB 核对兜住。

**技术边界**：无 Node 服务器、无 PostgreSQL、无 Redis、无 Docker。后端是 Cloudflare Worker（TypeScript，V8 isolate，**不是** Node 运行时）。

---

## 3. 页面与路由

单 React SPA，client-side 路由（react-router），三条路由：

| 路由 | 内容 | 说明 |
|---|---|---|
| `/` | **主页面** | 仅一个"邀请码输入框 + 加入按钮"。**无 logo、无功能介绍、无多余信息**。不暴露任何产品能力。 |
| `/admin` | **管理员后台** | 登录 → 创建会话（选 TTL 档位）→ 会话列表（码 / 状态 / 剩余时间倒计时 / **提前结束按钮**）→ 点进活跃会话在后台内嵌聊天视图。 |
| `/c` | **对方聊天页** | 对方凭码进入。码存 sessionStorage，**不进 URL**（页面 URL 无、WS URL 也无，见 §6）。 |

**UI 基调**：简体中文、极简。聊天页 = 消息列表 + 输入框 + 状态指示（等待对方 / 已连接 / 会话已结束）+ 剩余时间倒计时 + 安全指纹核对区（§5.4）。

---

## 4. 会话生命周期与状态机

### 4.1 状态

- `created`：已创建，码未被使用。
- `active`：对方已用有效码加入。
- `ended`：已终止（全清后）。

### 4.2 状态机

```
created ──(对方用有效码加入)──▶ active
   │
   └──(7 天无人使用, unused 闹钟)──▶ ended(全清)

active：
   · WS 断开(任一方) ──▶ grace period 60s（设 alarm）
        ├─ 同公钥重连     → 续聊（补发内存中尚存的 backlog）
        ├─ 新公钥重连     → 判定密钥丢失 → ended(全清)
        └─ 60s 超时       → ended(全清)
   · TTL 到期（deadline 闹钟）   → ended(全清)
   · 管理员点"提前结束"          → ended(全清)

ended(全清) = 删 DO 持久化元数据 + 清所有闹钟 + 通知在线方 end
```

**关键规则**【决策：60s grace，取代"断开即删"】：
- **同公钥重连** = 续聊（覆盖刷新、地铁信号丢失、手机锁屏唤醒）。
- **新公钥重连** = 旧密钥已丢（sessionStorage 被清）= 会话死亡。
- **任一方彻底离开** → grace 60s 后全清（TTL 闹钟只是最大寿命兜底，不是主清理路径）。
- 实际寿命通常 < TTL。

**同浏览器第二标签页** = 新密钥 = 按"新公钥重连"规则结束会话。这是**文档明写的已知限制**（§18），不做额外处理。

---

## 5. E2E 加密协议（Web Crypto，零第三方加密依赖）

### 5.1 密钥与 salt 生成

- **双方**各自在聊天页生成一对 **X25519** 密钥（Web Crypto `generateKey`），存 **sessionStorage**（关标签页即失）。
- **管理员**额外生成 **32 字节随机 salt**（`crypto.getRandomValues`），存 sessionStorage，随其公钥发出。
- 密钥对、salt、管理员 token 全部只存 sessionStorage，**不落 localStorage / IndexedDB / 磁盘**。

### 5.2 密钥交换与派生

1. 管理员连接成功（`auth`）后，发 `pub` 帧（含自身公钥 + salt）。
2. 对方连接成功（`join`）后，发 `pub` 帧（含自身公钥）。
3. DO 收齐双方公钥后，向**双方**各发 `peer` 帧：对端公钥 + salt。（**DO 只中继，不计算指纹、不接触明文/密钥**。）
4. 双方各自计算：
   - `sharedSecret = X25519(私钥mine, 公钥theirs)`（ECDH，双方算出同一 32 字节值）
   - `keyA = HKDF-SHA256(ikm=sharedSecret, salt=salt, info="dida/v1/admin->participant", L=32)`
   - `keyB = HKDF-SHA256(ikm=sharedSecret, salt=salt, info="dida/v1/participant->admin", L=32)`
   - **方向性密钥**：管理员用 `keyA` 加密发送 / 用 `keyB` 解密接收；对方反之。
5. 交换完成，开始聊天。

> 方向性密钥 + 每方向独立 AAD（§5.3）防止跨方向重放。

### 5.3 消息加密

- 明文 = JSON 字节：`{ "text": string, "ts": number(毫秒时间戳) }`
- 算法 = **AES-256-GCM**
  - `nonce` = 每次随机 **12 字节**（`getRandomValues`）
  - `AAD` = `UTF8("dida/v1/" + fromRole)`（fromRole ∈ {`admin`,`participant`}），绑定发送方向，防跨方向重放
  - 输出 `ct`（含 GCM tag）
- **单条消息上限 8KB**（超限前端拒发并提示）。

### 5.4 安全指纹（安全码）——抗主动 MITM 的核心

- 定义（双方各自本地计算，**DO 不参与**）：
  ```
  fingerprint = CrockfordBase32( SHA-256( pubAdmin ‖ pubParticipant ‖ salt )[0:10] )
  ```
  - `pubAdmin` = 管理员 X25519 公钥（32B），`pubParticipant` = 对方公钥（32B），`salt` = 32B
  - 取哈希前 10 字节 → Crockford Base32 → **16 字符** → 格式化为 `XXXX-XXXX-XXXX-XXXX`
  - 双方输入顺序固定（admin 公钥在前），故算出同一值。
- **MITM 检测原理**：若 DO 恶意，给 A 一个假 B 公钥、给 B 一个假 A 公钥，则 A、B 各算出**不同**指纹 → 经独立渠道比对时发现不一致 → 判定被 MITM。
- **交互（软验证）【决策：软验证，非硬门禁】**：
  - 双方在 UI 展示各自算出的安全码。
  - 双方经**独立可信渠道**（就是传递邀请码的那个渠道：电话/另一 IM/当面）核对。
  - 核对一致后各自点"已核对"→ 前端发 `verify` 帧；DO 把 `verified` 转发给对端。
  - 双方都点过 → UI 显示绿色"已核对"；否则持续显示**警告横幅**（"未核对安全指纹：仅能防存储型泄露，不能保证抗主动中间人"）。
  - **未核对也可聊天**（避免"拒绝服务"）。管理员保留"提前结束"可随时终止。

### 5.5 客户端心跳

- 客户端每 **30s** 发 `ping`（DO 回 `pong`），用于**探测**手机休眠 / NAT 死链并触发重连。
- **注意**：这不是架构依赖——WSS 连接由 Hibernation API 保持（§7），心跳只做 liveness 检测。

---

## 6. WS 协议（完整帧 schema）

**鉴权走首帧，URL 保持干净**【决策：凭证不进任何 URL】。
WS 升级请求的 URL **无任何 query**（管理员 token、邀请码都不放 URL），避免进入 devtools / 反代日志 / APM / 错误采集。凭证只在 WS 第一帧（内存、瞬时）。

### 6.1 客户端 → DO

| 帧 | 字段 | 说明 |
|---|---|---|
| `auth` | `{ type:"auth", credential:"<token>" }` | **管理员**首帧，管理员签名 token |
| `join` | `{ type:"join", code:"<12位>" }` | **对方**首帧，邀请码 |
| `pub` | `{ type:"pub", pub:"<b64 32B>", salt:"<b64 32B>" }` | 公钥交换；**salt 仅管理员携带**，对方可省略 salt |
| `msg` | `{ type:"msg", seq:number, nonce:"<b64 12B>", ct:"<b64>" }` | 加密消息；`seq` 发送方从 1 递增 |
| `ack` | `{ type:"ack", seq:number }` | 收到最高连续 seq 的确认 |
| `verify` | `{ type:"verify" }` | 本方已完成指纹 OOB 核对 |
| `end` | `{ type:"end" }` | 本方主动结束/离开 |
| `ping` | `{ type:"ping" }` | 心跳 |

### 6.2 DO → 客户端

| 帧 | 字段 | 说明 |
|---|---|---|
| `ok` | `{ type:"ok", role:"admin"\|"participant" }` | 鉴权/加入成功 |
| `peer` | `{ type:"peer", pub:"<b64>", salt:"<b64>" }` | 对端公钥 + salt（**不含指纹**，指纹由客户端自算） |
| `msg` | `{ type:"msg", from:"admin"\|"participant", seq:number, nonce:"<b64>", ct:"<b64>" }` | 中继消息 |
| `backlog` | `{ type:"backlog", msgs:[ <msg帧> ] }` | 重连时补发内存中尚存的未确认消息 |
| `lost` | `{ type:"lost", n:number }` | 断线窗口内丢失的消息数（尽力而为，可能为 0/未知） |
| `peer-left` | `{ type:"peer-left" }` | 对端断开（进入 grace） |
| `peer-gone` | `{ type:"peer-gone" }` | 对端彻底离开/会话将终止 |
| `verified` | `{ type:"verified" }` | 对端已核对指纹 |
| `end` | `{ type:"end", reason:"ttl"\|"admin-end"\|"key-loss"\|"grace-timeout" }` | 会话终止 |
| `error` | `{ type:"error", code:"<string>" }` | 错误（`bad-cred`/`code-expired`/`rate-limited`/`busy` 等） |
| `pong` | `{ type:"pong" }` | 心跳响应 |

### 6.3 连接级规则

- **未鉴权超时**：WS 升级后 **5s** 内未收到有效 `auth`/`join` 首帧 → DO 关闭连接。
- **首帧校验失败** → 立即 `close`（可先发 `error`）。
- **每会话每角色仅一个活跃连接**：同角色新连接到达且旧连接未断 → 按"新公钥/新连接"规则处理（通常 = key-loss → 结束）。

---

## 7. Durable Object 设计（Hibernation + 密文零落盘）

### 7.1 为什么用 Hibernation WebSocket API【决策】

- CF 官方推荐：DO 空闲可休眠，**WS 客户端连接保持打开**，来事件时唤醒、constructor 重跑。
- **休眠期间内存状态被清零**（不是挂起）。唤醒后只能靠持久化存储 + `serializeAttachment` 恢复。
- 空闲 **10s** 触发休眠；非可休眠 DO 空闲 **70–140s** 被逐出；WS 在休眠期间无硬时限。
- 因此**不要**把"100s 断开"当架构假设；连接保活交给 Hibernation，心跳只做 liveness 探测（§5.5）。

### 7.2 密文零落盘【决策：不建消息表】

- 消息流：`WS → DO 内存 → 转发`。**SQLite/存储中不存任何消息密文。**
- 持久存储只放**会话元数据**（几百字节）：
  ```
  code_hash   = SHA-256(邀请码)   // 码的明文从不上盘
  status      = created | active
  pubAdmin    = <32B b64>
  pubPart     = <32B b64>
  salt        = <32B b64>
  created_at  = <ms>
  joined_at   = <ms>
  deadline    = <ms>   // joined_at + TTL
  ```
- **效果**：PITR（§18.3）最多恢复出"无内容、不可解"的元数据。产品叙事从"删了但 CF 留 30 天"变成"**服务端本来就没有内容**"。

### 7.3 per-connection attachment（16KB，休眠存活）

每个 WS 连接序列化保存（`serializeAttachment`），休眠唤醒后恢复：
```
{ role:"admin"|"participant", pub:<32B>, lastSeq:<int>, verified:<bool> }
```

### 7.4 闹钟（alarming，存于持久存储，实例消亡后仍能触发）

| 闹钟 | 触发点 | 动作 |
|---|---|---|
| `unused` | created 后 7 天 | 若仍 `created` → ended(全清) |
| `grace` | 任一方 WS 断开 | 60s 后若该方未以同公钥重连 → ended(全清) |
| `deadline` | joined_at + TTL | ended(全清) |

> 闹钟持久化于 DO 存储，实例被逐出/休眠后到期仍会重新实例化 DO 并执行 handler，故即使双方都离线，清理仍会发生。

### 7.5 断线窗口丢消息【已确认接受】

- 对方刷新 → 60s 内重连 → 可续聊，能补发**仍在内存**的未确认消息（`backlog`）。
- 若断线窗口内 DO 已休眠（静默 10s）→ 内存清零 → 该窗口消息**丢失**，DO 发 `lost`（尽力计数；若 DO 也被逐出则无计数，静默继续）。
- 即"刷新可续聊"是**尽力补齐**，不是保证补齐。README 写明（§18）。

---

## 8. 邀请码

- **格式**：**12 位** Crockford Base32 字符，字母表（32 符号，已排除 I/L/O/U，视觉无歧义）：
  ```
  0123456789ABCDEFGHJKMNPQRSTVWXYZ
  ```
  12 位 ≈ **60 bit** 熵，配合限流（§10）足以抗慢速爆破。
- **生成**：`getRandomValues(12 字节)` → Crockford Base32 → 12 字符。
- **存储**：DO 只存 **SHA-256 哈希**；**明文从不上盘**，只在创建时返回给管理员展示一次（供复制）。
- **有效期**【决策】：码不设独立有效期，**与 TTL 同生死**；未使用的码 **7 天**强制作废（unused 闹钟）。
- **TTL 起算**【决策】：从**对方加入**时起算（`deadline = joined_at + TTL`）。
- **TTL 档位**【决策，v1 不做自定义分钟数】：`15 分钟 / 1 小时 / 6 小时 / 24 小时 / 7 天`。
- **一次性**：1对1，码被有效使用一次即标记（`created→active`），不可复用。

---

## 9. 管理员认证【决策：token 存 sessionStorage，非 httpOnly cookie】

- **凭据存储**：管理员口令的 **PBKDF2-SHA256 哈希**存 **Worker Secrets**（CF 加密环境变量，不进代码库/仓库）。参数：salt 16 字节、迭代 **600,000 次**、派生密钥 32 字节（OWASP 推荐）。注意：**Workers WebCrypto 不支持 scrypt**（仅 PBKDF2/HKDF），故用 PBKDF2。
- **登录**：`POST /admin/login { password }` → 服务端用 Secrets 里的哈希校验（timing-safe 比较）→ 成功签发 **HMAC 签名 token**（含 `exp = now + 8h`），返回给前端。
- **前端存储**：token 存 **sessionStorage**（与密钥同生命周期，关标签页即失）。
  - **为何不用 httpOnly cookie**：前端（GitHub Pages）与后端（Worker）**跨站**，`SameSite` 会拦截跨站 cookie，故改用 sessionStorage token。
- **WS 鉴权**：token 走 **WS 首帧** `auth`（§6），**不进 URL**。
- **fetch 鉴权**：后续 API 调用（如提前结束）用 `Authorization: Bearer <token>` 头。
- **过期**：8h；前端检测到 `401` 清 token 回登录页。

> 安全权衡：sessionStorage token 可被 XSS 读取（cookie 方案本也无法完全防 XSS）。本模型中浏览器即受信任端点（E2EE 密钥本就存于此），故可接受；前端需做基本的输入转义/CSP。

---

## 10. 限流（Guard DO，轻量）【决策】

CF 边缘自带基础 DDoS 防护；应用层加轻量限流，计数存 Guard DO，**随时间自然过期，不留持久记录**。

| 对象 | 规则 |
|---|---|
| 管理员登录 | 同一来源 **5 次失败 → 锁 15 分钟** |
| 邀请码加入 | 同一 IP **≤5 次/分钟**，超限封 **15 分钟** |
| WS 连接 | 边缘按 IP 限制未鉴权连接数 + 5s 未鉴权超时（§6.3），防无鉴权 DoS |

> 来源 IP 在 WS 升级时（首帧之前）即可知，故"同 IP ≤5 次/分"可在 **Worker 边缘**前置判定，不必等 DO。

---

## 11. 痕迹清除矩阵

| 痕迹 | 位置 | 清除时机 |
|---|---|---|
| 消息密文 | **DO 内存** | DO 消亡即失，**从不上盘** |
| 会话元数据（码哈希/公钥/salt/状态/时间戳） | DO 持久存储 | 会话 ended 即删（PITR 可能留 30 天**无内容**副本，如实声明） |
| 邀请码明文 | 从不上盘 | — |
| 管理员 token | 浏览器 sessionStorage | 8h 过期 / 关标签页即失 |
| X25519 密钥对 + salt | 双方 sessionStorage | 关标签页即失 |
| 消息明文 | 浏览器内存 | 关页面即失 |
| 应用日志 | — | **生产零内容日志** + 关闭 CF Request Logging |
| 前端 JS | GitHub Pages | 独立于后端，不可被后端篡改 |

---

## 12. 数据流总览（一次完整会话）

```
[管理员]                        [Worker / DO]                      [对方]
 登录 → token(sessionStorage)
 建会话 → 展示 12 位码 + 选 TTL
   │  (OOB 把码发给对方)
   │ WS 连接(无 query)
   │ → auth{token}
   │            校验 token ✓ → ok
   │ → pub{pubAdmin, salt}
   │            (等待对方)
   │                                   WS 连接(无 query)
   │                                   → join{code}
   │                            校验 code 哈希 ✓
   │                            created→active, 设 deadline 闹钟
   │                                   → ok
   │                                   → pub{pubPart}
   │ ← peer{pubPart, salt}
   │            双方本地算 sharedSecret/HKDF/指纹
   │ → verify (OOB 核对后)
   │            转发 verified 给对方
   │                                   ← verify
   │ → msg{...}  ── 内存中继 ──→  msg{...}
   ...（30s 心跳；断线走 §4.2 grace）
 提前结束 / TTL 到期 / grace 超时
   → 删元数据 + 清闹钟 + 通知在线方 end
```

---

## 13. 隐私声明（精确文案，对外必须一致，不得夸大）

> dida 在会话销毁时删除应用层数据；**服务端不持久化任何消息密文**，也从不持有可解密密钥。平台底层基础设施（含 30 天 PITR 机制）可能保留**无内容元数据**的历史副本，无法保证物理彻底消失。
>
> 前端代码独立托管于后端之外，即使后端恶意也无法篡改前端逻辑。
>
> 传输全程加密。安全指纹**须经独立渠道核对**；未核对时，仅能防止"存储型泄露"，**不能保证抵抗主动中间人攻击**。
>
> 托管方边缘层仍可观测到流量元数据（如 IP、时间戳）；关闭请求日志是可达的最小化边界。

---

## 14. 技术栈与版本

| 层 | 选型 |
|---|---|
| 前端 | React + TypeScript + **Vite**（SPA，react-router） |
| 前端托管 | **GitHub Pages**（独立于后端） |
| 后端 | **Cloudflare Worker**（TypeScript，V8 isolate，非 Node） |
| 实时 | **WebSocket**（Durable Object，**Hibernation WebSocket API**） |
| 存储 | **DO 持久存储（KV）** 仅存元数据；**不建 SQLite 消息表** |
| 限流 | **Guard DO**（独立 Durable Object） |
| 加密 | **Web Crypto API**：X25519 + HKDF-SHA256 + AES-256-GCM（零第三方依赖） |
| 管理员凭据 | **PBKDF2-SHA256** 哈希存 **Worker Secrets**（600k 迭代） |
| 运行 | Node 22（本地开发用，brew 安装）+ pnpm |
| 本地模拟 | **miniflare**（Worker + DO 本地模拟） |

**明确不用**：Node 服务器、PostgreSQL、Redis、Docker、libsodium（Web Crypto 足够）、Next.js/SSR。

---

## 15. 仓库结构（monorepo）

```
dida/
├── apps/
│   ├── web/                      # React SPA（部署到 GitHub Pages）
│   │   ├── src/
│   │   │   ├── routes/
│   │   │   │   ├── Entry.tsx      # /  邀请码输入
│   │   │   │   ├── Admin.tsx      # /admin 登录+后台+内嵌聊天
│   │   │   │   └── Chat.tsx       # /c  对方聊天
│   │   │   ├── crypto/            # X25519 密钥对、HKDF、AES-GCM、指纹派生、sessionStorage 存取
│   │   │   ├── ws/                # WSS 连接、首帧鉴权、心跳、重连、backlog/lost 处理
│   │   │   ├── auth/              # 登录、token 存/读 sessionStorage
│   │   │   ├── ui/                # 极简组件（消息列表/输入/状态/指纹核对区/倒计时）
│   │   │   ├── App.tsx
│   │   │   └── main.tsx
│   │   ├── vite.config.ts         # dev 代理 WSS → miniflare；build 输出
│   │   ├── index.html
│   │   └── package.json
│   └── worker/                    # Cloudflare Worker
│       ├── src/
│       │   ├── index.ts           # 入口：静态兜底(可选)/路由分发
│       │   ├── routes/
│       │   │   ├── login.ts       # POST /admin/login
│       │   │   └── ws.ts          # WSS 升级 → 派发到 Session DO
│       │   ├── session-do.ts      # 会话状态机、首帧校验、密钥中继、消息中继、backlog、alarming
│       │   ├── guard-do.ts        # 限流计数（登录失败/加入尝试）
│       │   └── admin.ts           # token 签发/校验（HMAC）、PBKDF2 校验
│       ├── wrangler.toml          # DO 定义、KV、hibernation、secrets 引用
│       └── package.json
├── packages/
│   └── shared/                    # 前后端共享：协议类型、常量、纯函数
│       ├── src/
│       │   ├── frames.ts          # WS 帧 TS 类型（§6 全部帧）
│       │   ├── constants.ts       # Crockford 字母表、TTL 档位、上限(8KB/16KB/60s/7d)、info 串
│       │   ├── code.ts            # 邀请码生成/校验、SHA-256 哈希
│       │   └── fingerprint.ts     # 指纹派生纯函数（供前端；DO 不用）
│       └── package.json
├── .github/
│   └── workflows/
│       └── deploy-web.yml         # 前端 build → 部署 GitHub Pages
├── pnpm-workspace.yaml
├── package.json                   # Node 22 (engines)、pnpm、workspace scripts
├── DESIGN.md                      # 本文档
└── README.md                      # 运行/部署说明 + §13 隐私声明 + §18 已知限制
```

---

## 16. 本地开发

1. **安装**：Node 22（`brew install node`）、pnpm（`brew install pnpm`）。
2. **工作区**：根目录 `pnpm install`（workspace 含 web / worker / shared）。
3. **后端（miniflare）**：`apps/worker` 内用 miniflare 起本地 Worker + Session DO + Guard DO（`pnpm dev:worker`）。miniflare 支持 DO 与 Hibernation 的本地模拟。
4. **前端（Vite）**：`apps/web` 起 dev server（`pnpm dev:web`），`vite.config.ts` 把 `/admin/login`（HTTP）与 WSS 路径**代理**到 miniflare 端口。
5. **联调**：浏览器开两个标签页（一个走 `/admin`、一个走 `/`），用 OOB（肉眼/另一窗口）核对安全指纹，验证端到端加密与重连/grace。
6. **注意**：PITR 在本地开发不可用（CF 文档：本地不存持久日志）——本地测不到 PITR，属预期。

---

## 17. 部署

### 17.0 生产拓扑（2026-09 修订：同源路由，弃用 workers.dev）
- **背景**：`*.workers.dev` 在中国大陆被 DNS 污染 + 443 阻断，管理员与用户均无法直连；`dida.techccy.com` 的 Cloudflare 链路可达。
- **方案**：在 `techccy.com` 区域配置 **Workers Routes**，把 `dida.techccy.com/admin/*` 与 `dida.techccy.com/ws` 路由到 Worker，其余路径继续回源 GitHub Pages。前端为**同源调用**（`apiBase()=""`、`wss://同源/ws`），不再需要 `VITE_API_URL`/`VITE_WS_URL`（`api.ts` 保留该覆盖能力以备换域）。
- workers.dev 访问入口随 routes 部署默认关闭（wrangler 行为），生产仅暴露自定义域单入口。
- 仓库 Variables `VITE_API_URL`/`VITE_WS_URL` 已废弃（工作流不再读取）；残留值不影响构建。

### 17.1 前端 → GitHub Pages
- CI（`.github/workflows/deploy-web.yml`）：`pnpm build`（web）→ 产物 `apps/web/dist` → 部署到 GitHub Pages。
- SPA 路由需配置 fallback（GitHub Pages 的 `404.html` 兜底或按路径前缀托管），保证 `/admin`、`/c` 刷新可访问。
- API/WS 地址：同源（见 §17.0），无需构建时注入。

### 17.2 后端 → Cloudflare Worker
- `wrangler.toml`：定义 `SessionDO`、`GuardDO`、`RegistryDO` 三个 Durable Object（SQLite 存储类）；启用 **Hibernation WebSocket API**；配置 secrets 与 `routes`（§17.0）。
- **Secrets**（`wrangler secret put`）：
  - `ADMIN_PASS_HASH`：管理员口令的 PBKDF2-SHA256 哈希，格式 `pbkdf2-sha256$<iter>$<salt-b64>$<hash-b64>`。
  - `TOKEN_SIGNING_KEY`：HMAC 签名密钥（b64，32 字节）。
  - 注意 `wrangler secret put NAME < file`（文件**不带尾部换行**）避免杂质入库。
- **本地开发口令**放 `apps/worker/.dev.vars`（`DEV_ADMIN_PASSWORD=...`，已 gitignore，wrangler dev 自动加载）；生产 `[vars]` 不放任何口令类变量。
- **PBKDF2 迭代上限**：Cloudflare Workers WebCrypto 对 PBKDF2 有 **100,000 次迭代硬上限**（超过抛 `NotSupportedError`，本地 miniflare 无此限制——勿以本地表现推断线上）。`PBKDF2_ITERATIONS = 100_000`，由 Guard DO 登录限流补偿。
- **关闭 Request Logging**（控制台/API 对该 Worker 关闭），配合应用零日志（§11）。

### 17.3 上线检查
- [ ] 前端 JS 确实来自 GitHub Pages 域（非 Worker 域）。
- [ ] API 走 `dida.techccy.com/admin/*` 同源路由；WS 为 `wss://dida.techccy.com/ws`，无任何 query 参数。
- [ ] CF Request Logging 已关。
- [ ] Secrets 已设置、未进仓库。
- [ ] 限流生效（登录失败锁定、加入 IP 限速）。
- [ ] 指纹核对、grace 重连、TTL/提前结束清理均联调通过。

---

## 18. 已知限制（必须写进 README，诚实声明）

1. **CF 边缘层可见流量元数据**（IP/时间戳）；关请求日志是最小边界，非根除。
2. **同浏览器开第二个标签页会结束会话**（新密钥 = key-loss）。
3. **刷新可续聊（60s grace），关标签页即全失**（设计使然）。
4. **无历史恢复**：密钥丢失后，密文永久不可读（设计使然）。
5. **断线窗口内消息可能丢失**（尽力补齐，非保证；DO 休眠后内存清零）。
6. **未核对安全指纹时，不保证抵抗主动中间人攻击**（需 OOB 核对兜底）。
7. **PITR（30 天）**：CF 可恢复 DO 存储历史；但本方案**不落盘任何密文**，PITR 至多恢复无内容元数据。
8. **单管理员**：仅一个管理员账号（Secrets 方案），不做多管理员/权限体系。

---

## 19. 实现清单（建议 build order）

1. **monorepo 骨架**：pnpm workspace、`packages/shared`（frames/constants/code/fingerprint 纯函数 + 单测）。
2. **Worker 核心**：`admin.ts`（PBKDF2 校验 + HMAC token 签发/校验）→ `guard-do.ts`（限流）→ `session-do.ts`（状态机 + 首帧校验 + 密钥中继 + 消息中继 + backlog + 三类闹钟 + Hibernation attachment）。
3. **Worker 路由**：`/admin/login`、WSS 升级派发；wrangler.toml（DO/hibernation/secrets）。
4. **前端加密层**：`crypto/`（X25519/HKDF/AES-GCM/指纹 + sessionStorage）+ 单测（含指纹一致性、方向性密钥）。
5. **前端 WS 层**：`ws/`（首帧鉴权、心跳、重连同/新公钥判定、backlog/lost/end 处理）。
6. **前端三路由 + 极简 UI**：Entry / Admin（含会话列表、TTL 档位、提前结束、内嵌聊天）/ Chat（消息列表、指纹核对区、倒计时、警告横幅）。
7. **本地联调**：miniflare + Vite 代理；双标签页端到端（加密、指纹 OOB 核对、刷新续聊、grace、TTL/提前结束清理）。
8. **部署**：GitHub Actions 发前端；wrangler 发后端；§17.3 上线检查。
9. **README**：运行/部署 + §13 隐私声明 + §18 已知限制。

---

## 20. 关键决策与理由（防止实现时回退/简化）

| 决策 | 理由 |
|---|---|
| 前后端分离（GitHub Pages + Worker） | 防"恶意后端改前端 JS 直接读明文"；是威胁模型成立的前提 |
| 密文零落盘（不建消息表） | 契合"不留痕迹"定位；让 PITR 只剩无内容元数据 |
| Hibernation WebSocket API | CF 官方推荐；连接保活交给平台，内存清零用 attachment/持久存储恢复 |
| 60s grace 取代"断开即删" | 浏览器无法可靠区分"刷新/断网"与"主动关闭"；grace 让重连体验合理 |
| 软验证指纹（非硬门禁） | 双方未必总有 OOB 渠道；硬门禁会把"防 MITM"变成"拒绝服务" |
| 凭证走 WS 首帧、不进 URL | 避免 token/邀请码泄漏进 devtools/反代日志/APM/错误采集 |
| 管理员 token 存 sessionStorage（非 cookie） | 前后端跨站，SameSite 拦截 cookie；且与密钥同生命周期更契合 ephemeral |
| Web Crypto（非 libsodium） | X25519+HKDF+AES-GCM 全内置，零依赖、零 WASM |
| DO + KV 取代 Postgres/Redis | 数据模型（按会话隔离、TTL 删除、1对1 中继）与 DO 语义逐条对齐；少两个独立计费服务 |
| 单管理员 / 1对1 / 文本-only（v1） | 最小可用范围；协议预留扩展（消息 type、多角色） |

---

## 21. 安全 / 边界情况检查表（实现与测试须覆盖）

- [ ] 邀请码明文从不出现在：仓库、日志、DO 持久存储、任何 URL（页面/WS）。
- [ ] 管理员 token 从不出现在任何 URL；只走 WS 首帧 / Authorization 头。
- [ ] 前端 JS 源域 = GitHub Pages，非 Worker。
- [ ] 首帧 5s 未鉴权 → 关闭；错误凭证 → 立即 close。
- [ ] 同公钥重连 = 续聊；新公钥重连 = 结束 + 全清。
- [ ] 60s grace 超时 = 结束 + 全清；TTL 到期 = 结束 + 全清；提前结束 = 结束 + 全清。
- [ ] 双方都离线时，闹钟仍触发清理（实例重新实例化）。
- [ ] 指纹：双方本地算出一致；MITM 模拟下双方算出**不同**指纹。
- [ ] 方向性密钥：A→B 用 keyA，B→A 用 keyB；跨方向重放被 AAD 拒。
- [ ] 单条 >8KB 拒发；backlog 上限（建议内存保留最近 500 条）超出丢弃最旧。
- [ ] 限流：登录 5 失败锁 15 分；加入同 IP ≤5/分。
- [ ] 生产零内容日志 + CF Request Logging 关。
- [ ] sessionStorage 在关标签页后密钥/token 确已清除（不残留 localStorage）。
- [ ] 第二标签页 = 新密钥 = 会话结束（文档化行为，测试覆盖）。
