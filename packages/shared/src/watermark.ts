/**
 * 水印配置与提取内容信封（§5.7）【决策 2026-10-24：全嵌入 E2EE 密文】
 *
 * 架构不变量：
 * - 水印配置由管理员在创建会话/提取包时勾选，**只随 E2EE 密文传输**：
 *   聊天 = 密钥交换后管理员端自动发送水印控制消息（PlainMessage.wm）；
 *   提取 = 配置嵌入加密明文 JSON（ExtractEnvelope）。自定义内容永不经服务端，
 *   服务端零知识叙事不被打破。
 * - 服务端仅在加入/兑换响应中注入访问者**自身** IP 与服务端时间
 *   （ok 帧 ip/ts 字段、POST /extract 响应 ip/ts 字段）——服务端本已知的信息
 *   回传给本人，不新增任何服务端可见性。
 * - 防抹除定位：浏览器内最强对抗（canvas 绘制 + 防移除 + devtools 检测），
 *   §18 诚实声明"技术用户可绕过，水印是溯源威慑非加密保护"。
 */

/** 自定义水印内容长度上限（字符）——限制平铺面积与密文膨胀 */
export const WATERMARK_CUSTOM_MAX = 200;

/**
 * 水印配置（管理员勾选项）。
 * - 字段缺省 = 未勾选该项
 * - 聊天控制消息中 wm=null 表示"明确未启用水印"（渲染门控的显式放行信号）
 */
export interface WatermarkConfig {
  /** 自定义内容（≤ WATERMARK_CUSTOM_MAX 字符） */
  custom?: string;
  /** 显示访问者 IP（服务端注入） */
  ip?: boolean;
  /** 显示访问者设备信息（客户端 UA 解析，简洁形式） */
  device?: boolean;
  /** 显示静态时间戳（服务端加入/兑换时刻，非客户端时钟） */
  time?: boolean;
}

/**
 * 校验水印配置形状（解密端防篡改）：null 合法（= 未启用）；
 * custom 必须为 ≤上限的字符串，ip/device/time 必须为布尔；未知字段容忍（向前兼容）。
 */
export function isValidWatermarkConfig(v: unknown): v is WatermarkConfig | null {
  if (v === null) return true;
  if (typeof v !== "object") return false;
  const c = v as Record<string, unknown>;
  if (
    c.custom !== undefined &&
    (typeof c.custom !== "string" || c.custom.length > WATERMARK_CUSTOM_MAX)
  )
    return false;
  for (const k of ["ip", "device", "time"] as const) {
    if (c[k] !== undefined && typeof c[k] !== "boolean") return false;
  }
  return true;
}

/**
 * 提取内容加密明文信封：
 * - v1：明文 = JSON({v:1, text, wm?})——纯文本包
 * - v2【2026-11-21，§5.6.1】：明文 = JSON({v:2, text?, wm?, page?})——网页快照包
 *   （text 为可选说明文字；page 为快照引用元数据，解密后凭其下载/解密 pack）
 * 旧版（本版本之前）提取包的明文为裸文本——解析失败或无 v 标记时按裸文本
 * 处理（无水印），保证旧包在滚动发布期间仍可正常提取。
 */
export interface ExtractEnvelope {
  v: 1;
  text: string;
  wm?: WatermarkConfig | null;
}

/** v2 信封：网页快照包（text 为可选说明文字；page 必带） */
export interface ExtractEnvelopeV2 {
  v: 2;
  text?: string;
  wm?: WatermarkConfig | null;
  page: PagePackRef;
}

/**
 * 快照包引用元数据（v2 信封 page 字段）：packId/dataKey 都是服务端不可解读的
 * 随机值（packId=32B hex64 R2 对象 key；dataKey=32B b64），服务端零知识。
 */
export interface PagePackRef {
  /** R2 对象 key（32B hex64），能力 URL 路径段（非凭证，仅可达密文） */
  packId: string;
  /** pack 加密密钥（32B b64）——只在加密信封内 */
  dataKey: string;
  /** pack 明文总字节数（下载进度/展示用） */
  totalSize: number;
  /** 文件数（含 HTML 入口） */
  fileCount: number;
}

const HEX64 = /^[0-9a-f]{64}$/;

export function isValidPagePackRef(v: unknown): v is PagePackRef {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  if (typeof r.packId !== "string" || !HEX64.test(r.packId)) return false;
  if (typeof r.dataKey !== "string" || r.dataKey.length === 0 || r.dataKey.length > 128) return false;
  if (typeof r.totalSize !== "number" || !Number.isInteger(r.totalSize) || r.totalSize < 0)
    return false;
  if (typeof r.fileCount !== "number" || !Number.isInteger(r.fileCount) || r.fileCount < 1)
    return false;
  return true;
}

export interface ParsedExtractEnvelope {
  text: string;
  wm: WatermarkConfig | null;
  /** v2 快照包引用；v1/旧版包为 undefined */
  page?: PagePackRef;
}

/**
 * 解析提取明文：v1/v2 信封 → 结构化结果；旧版裸文本 → { text: 原文, wm: null }。
 * wm 形状非法时保留 text、仅丢弃 wm（提取页不因水印配置损坏拒绝展示）。
 * page 字段形状非法时丢弃 page（按纯文本包处理，不拒绝整个包）。
 */
export function parseExtractEnvelope(raw: string): ParsedExtractEnvelope {
  try {
    const obj = JSON.parse(raw) as {
      v?: unknown;
      text?: unknown;
      wm?: unknown;
      page?: unknown;
    };
    if (obj.v === 1 && typeof obj.text === "string") {
      return {
        text: obj.text,
        wm: isValidWatermarkConfig(obj.wm ?? null)
          ? (obj.wm ?? null) as WatermarkConfig | null
          : null,
      };
    }
    if (obj.v === 2) {
      return {
        text: typeof obj.text === "string" ? obj.text : "",
        wm: isValidWatermarkConfig(obj.wm ?? null)
          ? (obj.wm ?? null) as WatermarkConfig | null
          : null,
        page: isValidPagePackRef(obj.page) ? obj.page : undefined,
      };
    }
  } catch {
    /* 旧版裸文本（非 JSON） */
  }
  return { text: raw, wm: null };
}
