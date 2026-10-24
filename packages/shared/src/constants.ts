/**
 * dida 协议常量（§6、§8、§5）
 * 前后端共享。所有帧/校验逻辑都必须以这里的常量为唯一来源。
 */

/** Crockford Base32 字母表（排除 I/L/O/U）—— 用于邀请码（§8） */
export const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" as const;

/**
 * 配对码（§8）【决策 2026-10-24：6 位 → 前缀 + 8 位】
 * 格式 X-XXXXXXXX（显示含连字符，仅展示用）：首字符为类型前缀
 * （C=对话码 Conversation，E=提取码 Extract），后 8 位 Crockford Base32
 * 随机 ≈ 40 bit 熵。前缀参与哈希与密钥派生，是码的一部分。
 * 提取码为静态密文 + 码派生密钥，存在离线枚举威胁，故统一取 40 bit。
 * 旧 6 位码不兼容，直接切换。
 */
export const CODE_PREFIX = {
  chat: "C",
  extract: "E",
} as const;

export type CodeKind = keyof typeof CODE_PREFIX;

/** 配对码随机部分长度（Crockford 字符数），8 × 5bit = 40 bit 熵 */
export const CODE_RANDOM_LENGTH = 8;

/** 配对码未使用强制作废期限：7 天（§8） */
export const UNUSED_CODE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * TTL 档位（§8）【决策：v1 不做自定义分钟数】
 * 从对方加入时起算：deadline = joined_at + TTL
 */
export const TTL_OPTIONS = [
  { label: "15 分钟", ms: 15 * 60 * 1000 },
  { label: "1 小时", ms: 60 * 60 * 1000 },
  { label: "6 小时", ms: 6 * 60 * 60 * 1000 },
  { label: "24 小时", ms: 24 * 60 * 60 * 1000 },
  { label: "7 天", ms: 7 * 24 * 60 * 60 * 1000 },
] as const;

export type TtlOption = (typeof TTL_OPTIONS)[number];

/** 单条消息明文上限 8KB（§5.3） */
export const MSG_MAX_BYTES = 8 * 1024;

// ---------- 提取包（§5.6）【决策 2026-10-24 新增】 ----------

/** 提取内容明文上限 32KB（信息包场景为整段配置/密钥，比消息宽松） */
export const EXTRACT_MAX_BYTES = 32 * 1024;

/** 提取次数上限（防滥用天花板；默认 1 次） */
export const EXTRACT_MAX_COUNT = 10;

/** 提取包默认有效期：未选择时 7 天（与未用码作废期限一致） */
export const EXTRACT_DEFAULT_TTL_MS = UNUSED_CODE_TTL_MS;

/** 提取密钥 HKDF info 串：码派生密钥（§5.6） */
export const HKDF_INFO_EXTRACT = "dida/v1/extract/v1";

/** 提取密文 GCM AAD：UTF8("dida/v1/extract") */
export const EXTRACT_AAD = "dida/v1/extract";

/** 未鉴权 WS 连接超时：5s（§6.3） */
export const AUTH_TIMEOUT_MS = 5_000;

/** 断线 grace 期：60s（§4.2）【决策：60s grace，取代"断开即删"】 */
export const GRACE_PERIOD_MS = 60_000;

/** 客户端心跳间隔：30s（§5.5） */
export const PING_INTERVAL_MS = 30_000;

/** backlog 内存保留上限：最近 500 条（§21） */
export const BACKLOG_LIMIT = 500;

/** HKDF info 串（§5.2）——方向性密钥 */
export const HKDF_INFO_ADMIN_TO_PARTICIPANT = "dida/v1/admin->participant";
export const HKDF_INFO_PARTICIPANT_TO_ADMIN = "dida/v1/participant->admin";

/** GCM AAD 前缀（§5.3）：UTF8("dida/v1/" + fromRole) */
export const AAD_PREFIX = "dida/v1/";

export const ROLES = {
  ADMIN: "admin",
  PARTICIPANT: "participant",
} as const;

export type Role = (typeof ROLES)[keyof typeof ROLES];

/** 错误码（§6.2 error 帧） */
export const ERROR_CODES = {
  BAD_CRED: "bad-cred",
  CODE_EXPIRED: "code-expired",
  RATE_LIMITED: "rate-limited",
  BUSY: "busy",
  ENDED: "ended",
  BAD_FRAME: "bad-frame",
} as const;

/** 会话结束原因（§6.2 end 帧） */
export const END_REASONS = {
  TTL: "ttl",
  ADMIN_END: "admin-end",
  KEY_LOSS: "key-loss",
  GRACE_TIMEOUT: "grace-timeout",
} as const;

/** 管理员 token 有效期：8 小时（§9） */
export const ADMIN_TOKEN_TTL_MS = 8 * 60 * 60 * 1000;

/** PBKDF2 参数（§9）：salt 16B / 32B。
 * 迭代次数 100_000 = Cloudflare Workers WebCrypto 的硬上限（workerd 拒绝
 * >100k，报 NotSupportedError），低于浏览器端 OWASP 建议值；服务端登录有
 * Guard DO 限流（5 次失败锁 15 分钟）补偿，且口令为高熵随机串。 */
export const PBKDF2_ITERATIONS = 100_000;
export const PBKDF2_SALT_BYTES = 16;
export const PBKDF2_KEY_BYTES = 32;

/**
 * Guard DO 限流（§10）
 * - 管理员登录：同一来源 5 次失败 → 锁 15 分钟
 * - 邀请码加入：同一 IP ≤5 次/分钟，超限封 15 分钟
 */
export const LOGIN_MAX_FAILURES = 5;
export const LOGIN_LOCK_MS = 15 * 60 * 1000;
export const JOIN_MAX_PER_MINUTE = 5;
export const JOIN_WINDOW_MS = 60 * 1000;
export const JOIN_BLOCK_MS = 15 * 60 * 1000;
