/**
 * 前端加密层（§5）：X25519 + HKDF-SHA256 + AES-256-GCM，零第三方依赖。
 * 密钥/salt/token 全部只存 sessionStorage（关标签页即失，不落 localStorage/IndexedDB/磁盘）。
 */
import {
  HKDF_INFO_ADMIN_TO_PARTICIPANT,
  HKDF_INFO_PARTICIPANT_TO_ADMIN,
  AAD_PREFIX,
  MSG_MAX_BYTES,
  type Role,
} from "@dida/shared";
import {
  computeFingerprint,
  b64ToBytes,
  bytesToB64,
  utf8Encode,
} from "@dida/shared";

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
  /** 公钥原始 32 字节（用于指纹/peer 帧） */
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
  /** 共享秘密（32B），供指纹等本地计算 */
  sharedSecret: Uint8Array;
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
  const sharedSecret = new Uint8Array(
    await cryptoSubtle.deriveBits(
      { name: "X25519", public: theirPublicKey },
      myPrivateKey,
      256,
    ),
  );

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

  return { encKey, decKey, sharedSecret };
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

// ---------- 指纹（§5.4） ----------

export async function localFingerprint(
  pubAdmin: Uint8Array,
  pubParticipant: Uint8Array,
  salt: Uint8Array,
): Promise<string> {
  return computeFingerprint(pubAdmin, pubParticipant, salt);
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
