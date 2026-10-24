/**
 * 前端加密层（§5）：X25519 + HKDF-SHA256 + AES-256-GCM，零第三方依赖。
 * 密钥/salt/token 全部只存 sessionStorage（关标签页即失，不落 localStorage/IndexedDB/磁盘）。
 */
import {
  HKDF_INFO_ADMIN_TO_PARTICIPANT,
  HKDF_INFO_PARTICIPANT_TO_ADMIN,
  HKDF_INFO_EXTRACT,
  EXTRACT_AAD,
  EXTRACT_MAX_BYTES,
  AAD_PREFIX,
  MSG_MAX_BYTES,
  isValidWatermarkConfig,
  type WatermarkConfig,
  type Role,
} from "@dida/shared";
import { b64ToBytes, bytesToB64, utf8Encode, utf8Decode } from "@dida/shared";

const cryptoSubtle = crypto.subtle;

/**
 * WebCrypto 参数要求 BufferSource（ArrayBuffer 基底视图）。
 * 复制为独立 ArrayBuffer，规避共享缓冲泛型不匹配。
 */
function toBuf(b: Uint8Array): ArrayBuffer {
  return b.slice().buffer;
}

// ---------- sessionStorage 存取（仅 sessionStorage，§5.1） ----------

function ssGet<T>(key: string): T | null {
  const raw = sessionStorage.getItem(key);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function ssSet(key: string, value: unknown): void {
  sessionStorage.setItem(key, JSON.stringify(value));
}

function ssDel(key: string): void {
  sessionStorage.removeItem(key);
}

export const SS_KEYS = {
  ADMIN_TOKEN: "dida.adminToken",
  ADMIN_KEY: "dida.adminKey",
  ADMIN_SALT: "dida.adminSalt",
  PART_KEY: "dida.partKey",
  CODE: "dida.code",
  EXTRACT_CODE: "dida.extractCode",
  EXTRACT: "dida.extract",
} as const;

export function saveAdminToken(token: string): void {
  ssSet(SS_KEYS.ADMIN_TOKEN, token);
}
export function loadAdminToken(): string | null {
  return ssGet<string>(SS_KEYS.ADMIN_TOKEN);
}
export function clearAdminToken(): void {
  ssDel(SS_KEYS.ADMIN_TOKEN);
}

// ---------- 密钥对（X25519） ----------

export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** 公钥原始 32 字节（用于 peer 帧） */
  pubRaw: Uint8Array;
}

export async function generateKeyPair(): Promise<KeyPair> {
  const pair = (await cryptoSubtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveKey", "deriveBits"],
  )) as CryptoKeyPair;
  const pubRaw = new Uint8Array(
    await cryptoSubtle.exportKey("raw", pair.publicKey),
  );
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, pubRaw };
}

export async function exportPubRaw(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await cryptoSubtle.exportKey("raw", key));
}

// ---------- 密钥派生（§5.2） ----------

export interface DirectionKeys {
  /** 本方加密发送用 */
  encKey: CryptoKey;
  /** 本方解密接收用 */
  decKey: CryptoKey;
}

/**
 * 从双方公钥派生方向性密钥对。
 * role="admin" 时：encKey = keyA (admin->participant)，decKey = keyB。
 * role="participant" 时反之。
 */
export async function deriveDirectionKeys(
  myPrivateKey: CryptoKey,
  theirPublicKey: CryptoKey,
  salt: Uint8Array,
  role: Role,
): Promise<DirectionKeys> {
  // X25519 ECDH：双方算出同一 32 字节共享秘密，作为 HKDF 的输入（ikm）。
  // 密钥由下方 deriveKey 派生，此处仅触发 ECDH 计算。
  const sharedSecret = new Uint8Array(
    await cryptoSubtle.deriveBits(
      { name: "X25519", public: theirPublicKey },
      myPrivateKey,
      256,
    ),
  );
  void sharedSecret;

  const info =
    role === "admin"
      ? HKDF_INFO_ADMIN_TO_PARTICIPANT
      : HKDF_INFO_PARTICIPANT_TO_ADMIN;
  const otherInfo =
    role === "admin"
      ? HKDF_INFO_PARTICIPANT_TO_ADMIN
      : HKDF_INFO_ADMIN_TO_PARTICIPANT;

  const encKey = await hkdfAesKey(sharedSecret, salt, info);
  const decKey = await hkdfAesKey(sharedSecret, salt, otherInfo);

  return { encKey, decKey };
}

async function hkdfAesKey(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
): Promise<CryptoKey> {
  const base = await cryptoSubtle.importKey(
    "raw",
    toBuf(ikm),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return cryptoSubtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toBuf(salt),
      info: toBuf(utf8Encode(info)),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// ---------- 消息加解密（§5.3） ----------

export interface PlainMessage {
  text: string;
  ts: number;
  /**
   * 信息包标记（§5.4）：true = 管理员发送的"信息包"。
   * 接收端气泡截断展示（前 ~24 字符），提供一键复制全文。
   */
  packet?: boolean;
  /**
   * 水印控制消息（§5.7）：字段存在即为控制帧（不进消息列表）。
   * 仅管理员方向发送；null = 明确未启用水印（渲染门控的放行信号），
   * 对象 = 启用水印并携带配置。非 null/合法形状按篡改丢弃。
   */
  wm?: WatermarkConfig | null;
}

/**
 * 加密一条消息。
 * 明文 = JSON 字节 {text, ts}；AAD = UTF8("dida/v1/" + fromRole)；nonce 12B 随机。
 * 超过 8KB 抛 MsgTooLargeError（前端据此拒发并提示）。
 */
export class MsgTooLargeError extends Error {
  constructor() {
    super("消息超过 8KB 上限");
    this.name = "MsgTooLargeError";
  }
}

export async function encryptMsg(
  key: CryptoKey,
  msg: PlainMessage,
  fromRole: Role,
): Promise<{ nonce: string; ct: string }> {
  const plain = utf8Encode(JSON.stringify(msg));
  if (plain.length > MSG_MAX_BYTES) throw new MsgTooLargeError();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await cryptoSubtle.encrypt(
      {
        name: "AES-GCM",
        iv: toBuf(nonce),
        additionalData: toBuf(utf8Encode(AAD_PREFIX + fromRole)),
      },
      key,
      toBuf(plain),
    ),
  );
  return { nonce: bytesToB64(nonce), ct: bytesToB64(ct) };
}

/**
 * 解密一条消息。解密失败（含 AAD 不匹配 → 跨方向重放）抛 DecryptError。
 */
export class DecryptError extends Error {
  constructor() {
    super("解密失败（篡改或跨方向重放）");
    this.name = "DecryptError";
  }
}

export async function decryptMsg(
  key: CryptoKey,
  fromRole: Role,
  nonceB64: string,
  ctB64: string,
): Promise<PlainMessage> {
  try {
    const plain = await cryptoSubtle.decrypt(
      {
        name: "AES-GCM",
        iv: toBuf(b64ToBytes(nonceB64)),
        additionalData: toBuf(utf8Encode(AAD_PREFIX + fromRole)),
      },
      key,
      toBuf(b64ToBytes(ctB64)),
    );
    const obj = JSON.parse(new TextDecoder().decode(plain)) as PlainMessage;
    if (typeof obj.text !== "string" || typeof obj.ts !== "number")
      throw new DecryptError();
    if (obj.packet !== undefined && typeof obj.packet !== "boolean")
      throw new DecryptError();
    if (obj.wm !== undefined && !isValidWatermarkConfig(obj.wm))
      throw new DecryptError();
    return obj;
  } catch {
    throw new DecryptError();
  }
}

// ---------- 会话本地状态（密钥/salt 的 sessionStorage 持久化） ----------

export interface LocalSessionState {
  keyPair: KeyPair;
  salt?: Uint8Array; // 仅管理员
  pubB64: string;
  saltB64?: string;
}

export async function saveLocalKeyPair(
  key: "admin" | "part",
  keyPair: KeyPair,
  salt?: Uint8Array,
): Promise<void> {
  const pubB64 = bytesToB64(keyPair.pubRaw);
  const saltB64 = salt ? bytesToB64(salt) : undefined;
  const admin = key === "admin";
  if (admin) {
    ssSet(SS_KEYS.ADMIN_KEY, { keypair: await serializeKeyPair(keyPair) });
    if (saltB64) ssSet(SS_KEYS.ADMIN_SALT, saltB64);
  } else {
    ssSet(SS_KEYS.PART_KEY, { keypair: await serializeKeyPair(keyPair) });
  }
  void pubB64;
}

async function serializeKeyPair(kp: KeyPair) {
  const privateKey = new Uint8Array(
    await cryptoSubtle.exportKey("pkcs8", kp.privateKey),
  );
  const publicKey = new Uint8Array(
    await cryptoSubtle.exportKey("spki", kp.publicKey),
  );
  return {
    privateKey: Array.from(privateKey),
    publicKey: Array.from(publicKey),
  };
}

async function deserializeKeyPair(
  exported: {
    privateKey: ArrayBuffer | Uint8Array;
    publicKey: ArrayBuffer | Uint8Array;
  },
): Promise<KeyPair> {
  const privateKey = await cryptoSubtle.importKey(
    "pkcs8",
    toBuffer(exported.privateKey),
    { name: "X25519" },
    true,
    ["deriveKey", "deriveBits"],
  );
  const publicKey = await cryptoSubtle.importKey(
    "spki",
    toBuffer(exported.publicKey),
    { name: "X25519" },
    true,
    // 浏览器 WebCrypto 要求公钥导入时用空 usages（Node 22 亦兼容）
    [],
  );
  const pubRaw = new Uint8Array(await cryptoSubtle.exportKey("raw", publicKey));
  return { privateKey, publicKey, pubRaw };
}

function toBuffer(d: ArrayBuffer | Uint8Array): ArrayBuffer {
  return d instanceof Uint8Array ? d.slice().buffer : d;
}

export async function loadLocalKeyPair(
  key: "admin" | "part",
): Promise<KeyPair | null> {
  const raw =
    key === "admin"
      ? ssGet<{ keypair: { privateKey: number[]; publicKey: number[] } }>(
          SS_KEYS.ADMIN_KEY,
        )
      : ssGet<{ keypair: { privateKey: number[]; publicKey: number[] } }>(
          SS_KEYS.PART_KEY,
        );
  if (!raw) return null;
  try {
    return await deserializeKeyPair({
      privateKey: Uint8Array.from(raw.keypair.privateKey),
      publicKey: Uint8Array.from(raw.keypair.publicKey),
    });
  } catch {
    return null;
  }
}

export function loadAdminSalt(): Uint8Array | null {
  const b64 = ssGet<string>(SS_KEYS.ADMIN_SALT);
  return b64 ? b64ToBytes(b64) : null;
}

export function clearLocalKeyPair(key: "admin" | "part"): void {
  ssDel(key === "admin" ? SS_KEYS.ADMIN_KEY : SS_KEYS.PART_KEY);
  if (key === "admin") ssDel(SS_KEYS.ADMIN_SALT);
}

// ---------- 提取包加解密（§5.6）【决策：码派生密钥，只存密文】 ----------

/**
 * 从完整配对码派生提取密钥：HKDF-SHA256(ikm=UTF8(code), salt, info)。
 * 码明文只存在于本机内存/输入框，从不上传（服务端只见 SHA-256 哈希）。
 */
export async function deriveExtractKey(
  code: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  return hkdfAesKey(utf8Encode(code), salt, HKDF_INFO_EXTRACT);
}

export class ExtractTooLargeError extends Error {
  constructor() {
    super("提取内容超过 32KB 上限");
    this.name = "ExtractTooLargeError";
  }
}

/** 加密提取内容（管理员创建时；AAD 绑定 extract 域，nonce 12B 随机） */
export async function encryptExtract(
  key: CryptoKey,
  plaintext: string,
): Promise<{ nonce: string; ct: string }> {
  const plain = utf8Encode(plaintext);
  if (plain.length > EXTRACT_MAX_BYTES) throw new ExtractTooLargeError();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await cryptoSubtle.encrypt(
      { name: "AES-GCM", iv: toBuf(nonce), additionalData: toBuf(utf8Encode(EXTRACT_AAD)) },
      key,
      toBuf(plain),
    ),
  );
  return { nonce: bytesToB64(nonce), ct: bytesToB64(ct) };
}

/** 解密提取内容（提取者端）；失败（错码/篡改）抛 DecryptError */
export async function decryptExtract(
  key: CryptoKey,
  nonceB64: string,
  ctB64: string,
): Promise<string> {
  try {
    const plain = await cryptoSubtle.decrypt(
      { name: "AES-GCM", iv: toBuf(b64ToBytes(nonceB64)), additionalData: toBuf(utf8Encode(EXTRACT_AAD)) },
      key,
      toBuf(b64ToBytes(ctB64)),
    );
    return utf8Decode(new Uint8Array(plain));
  } catch {
    throw new DecryptError();
  }
}

// ---------- 提取码与提取结果的 sessionStorage（§3：不进 URL） ----------

export function saveExtractCode(code: string): void {
  ssSet(SS_KEYS.EXTRACT_CODE, code);
}
export function loadExtractCode(): string | null {
  return ssGet<string>(SS_KEYS.EXTRACT_CODE);
}
export function clearExtractCode(): void {
  ssDel(SS_KEYS.EXTRACT_CODE);
}

/** 提取结果缓存（同码刷新可回看；关标签页即清，不落磁盘） */
export interface ExtractCache {
  code: string;
  text: string;
  style: "packet" | "message";
  remaining: number;
  expiresAt: number;
  /** 水印（§5.7）：密文内配置 + 兑换时的服务端环境（旧版包无此字段 = 无水印） */
  wm?: { cfg: WatermarkConfig | null; ip?: string; ts?: number };
}

export function saveExtractCache(cache: ExtractCache): void {
  ssSet(SS_KEYS.EXTRACT, cache);
}

export function loadExtractCache(code: string): ExtractCache | null {
  const c = ssGet<ExtractCache>(SS_KEYS.EXTRACT);
  if (!c || c.code !== code) return null;
  if (typeof c.text !== "string" || (c.style !== "packet" && c.style !== "message"))
    return null;
  return c;
}

export function clearExtractCache(): void {
  ssDel(SS_KEYS.EXTRACT);
}

// ---------- 邀请码 sessionStorage（§3：不进 URL） ----------

export function saveCode(code: string): void {
  ssSet(SS_KEYS.CODE, code);
}
export function loadCode(): string | null {
  return ssGet<string>(SS_KEYS.CODE);
}
export function clearCode(): void {
  ssDel(SS_KEYS.CODE);
}

// ---------- 水印 sessionStorage（§5.7） ----------

/** 访问者环境（首次加入/兑换时的服务端注入值）：首次为准（静态时刻戳决策） */
export interface WmEnv {
  ip?: string;
  ts?: number;
}

/** participant：按对话码缓存首次加入时的 IP/服务端时间（重连刷新不改写） */
export function saveWmEnv(code: string, env: WmEnv): void {
  if (ssGet<WmEnv>("dida.wmEnv." + code)) return; // 首次为准
  ssSet("dida.wmEnv." + code, env);
}
export function loadWmEnv(code: string): WmEnv | null {
  return ssGet<WmEnv>("dida.wmEnv." + code);
}

/** 管理员：会话 → 创建时勾选的水印配置（进入聊天后随 E2EE 控制消息下发） */
export function saveChatWmConfig(
  sessionId: string,
  wm: WatermarkConfig | null,
): void {
  ssSet("dida.wmChat." + sessionId, wm);
}
/** 未配置过（本版本前创建的会话）与显式 null 同样返回 null → 下发 wm:null */
export function loadChatWmConfig(sessionId: string): WatermarkConfig | null {
  return ssGet<WatermarkConfig | null>("dida.wmChat." + sessionId) ?? null;
}

/** participant：按对话码缓存最近收到的水印配置（刷新重连后免等待直接应用） */
export function savePartWmConfig(
  code: string,
  wm: WatermarkConfig | null,
): void {
  ssSet("dida.wmPart." + code, wm);
}
export function loadPartWmConfig(code: string): WatermarkConfig | null | undefined {
  const v = ssGet<WatermarkConfig | null>("dida.wmPart." + code);
  return v === null ? null : (v ?? undefined);
}
