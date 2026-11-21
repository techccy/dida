/**
 * Extract DO：提取包（§5.6、§7.6）【决策 2026-10-24 新增】
 * 每包一个 DO，与 Session DO 同构。服务端只存：
 *   codeHash（SHA-256 配对码，码明文从不上盘、也不经服务端——码由前端生成）+
 *   AES-256-GCM 密文 + nonce + salt（HKDF 公开盐）+ 元数据。
 * 密钥由完整码派生（HKDF），服务端永不持有可解密能力。
 *
 * 生命周期（§4.3）：
 *   ready ──(提取请求)──▶ 计数 +1 ──(耗尽)──▶ 销毁
 *   ready ──(expiresAt 到期闹钟)──▶ 销毁
 * 销毁 = 删本 DO 全部存储 + 清闹钟 + 删注册表引用（与 Session DO 全清同构）。
 */
import { DurableObject } from "cloudflare:workers";
import { PAGE_PACK_GC_MS } from "@dida/shared";
import type { Env } from "./env";

export type ExtractStyle = "packet" | "message";

interface ExtractMeta {
  codeHash: string;
  /** AES-256-GCM 密文（含 tag，b64） */
  ct: string;
  /** 12B b64 */
  nonce: string;
  /** 32B b64（HKDF 公开盐） */
  salt: string;
  /** 呈现样式：packet=截断预览+复制；message=全文只读无复制 */
  style: ExtractStyle;
  /** 网页快照包引用（§5.6.1，2026-11-21）；纯文本包无此字段 */
  pack?: { packId: string; totalSize: number };
  createdAt: number;
  expiresAt: number;
  maxCount: number;
  usedCount: number;
}

const META_KEY = "meta";
/** 销毁后待 GC 的快照包（§4.3："已销毁待 GC"中间态；10 分钟后闹钟删 R2 对象） */
const GC_KEY = "gc";

export class ExtractDO extends DurableObject<Env> {
  private get state(): DurableObjectState {
    return this.ctx;
  }

  /** 创建（管理员 API；Worker 已验证 token 与载荷格式）。 */
  async create(args: {
    codeHash: string;
    ct: string;
    nonce: string;
    salt: string;
    style: ExtractStyle;
    pack?: { packId: string; totalSize: number };
    createdAt: number;
    expiresAt: number;
    maxCount: number;
  }): Promise<{ ok: true } | { error: "exists" }> {
    const existing = await this.state.storage.get<ExtractMeta>(META_KEY);
    if (existing) return { error: "exists" };
    const meta: ExtractMeta = { ...args, usedCount: 0 };
    this.state.storage.put(META_KEY, meta);
    await this.state.storage.setAlarm(args.expiresAt);
    return { ok: true };
  }

  /**
   * 提取（凭码兑换）。语义【决策】：
   * - 过期 / 次数耗尽 / 不存在 → 统一 { error: "gone" }（Worker 层转统一模糊错误，防探测）
   * - 成功 = 服务端把密文装进 HTTP 200 响应，此时计数 +1 并持久化；
   *   计数达到上限 → 立即销毁（密文先读出，销毁后返回）
   */
  async redeem(codeHash: string): Promise<
    | {
        ok: true;
        payload: {
          ct: string;
          nonce: string;
          salt: string;
          style: ExtractStyle;
          remaining: number;
          expiresAt: number;
        };
      }
    | { error: "gone" }
  > {
    const meta = await this.state.storage.get<ExtractMeta>(META_KEY);
    if (!meta) {
      await this.gcSweep();
      return { error: "gone" };
    }
    if (meta.codeHash !== codeHash) return { error: "gone" };
    const now = Date.now();
    if (now >= meta.expiresAt) {
      await this.destroy();
      return { error: "gone" };
    }
    if (meta.usedCount >= meta.maxCount) {
      await this.destroy();
      return { error: "gone" };
    }
    meta.usedCount += 1;
    const payload = {
      ct: meta.ct,
      nonce: meta.nonce,
      salt: meta.salt,
      style: meta.style,
      remaining: meta.maxCount - meta.usedCount,
      expiresAt: meta.expiresAt,
    };
    if (meta.usedCount >= meta.maxCount) {
      // 次数耗尽：销毁后返回（payload 已读出；HTTP 响应随即发出）
      await this.destroy();
    } else {
      this.state.storage.put(META_KEY, meta);
    }
    return { ok: true, payload };
  }

  /** 状态（管理员列表用）：不含任何内容字段 */
  async status(): Promise<{
    status: "ready" | "destroyed";
    createdAt: number;
    expiresAt: number;
    maxCount: number;
    usedCount: number;
    style: ExtractStyle;
  }> {
    const meta = await this.state.storage.get<ExtractMeta>(META_KEY);
    if (!meta) {
      await this.gcSweep();
      return {
        status: "destroyed",
        createdAt: 0,
        expiresAt: 0,
        maxCount: 0,
        usedCount: 0,
        style: "packet",
      };
    }
    // 惰性清理：到期未及触发闹钟，查询时顺带销毁
    if (Date.now() >= meta.expiresAt) {
      await this.destroy();
      return {
        status: "destroyed",
        createdAt: 0,
        expiresAt: 0,
        maxCount: 0,
        usedCount: 0,
        style: "packet",
      };
    }
    return {
      status: "ready",
      createdAt: meta.createdAt,
      expiresAt: meta.expiresAt,
      maxCount: meta.maxCount,
      usedCount: meta.usedCount,
      style: meta.style,
    };
  }

  /** 管理员提前销毁 */
  async adminDestroy(): Promise<{ ok: boolean }> {
    const meta = await this.state.storage.get<ExtractMeta>(META_KEY);
    if (!meta) return { ok: false };
    await this.destroy();
    return { ok: true };
  }

  /** 到期闹钟：销毁（§7.4 同构）；meta 已删时执行快照包 GC（§5.6.1） */
  async alarm() {
    const meta = await this.state.storage.get<ExtractMeta>(META_KEY);
    if (!meta) {
      await this.gcSweep();
      return;
    }
    if (meta.expiresAt > Date.now() + 2000) {
      // 迟到触发（异常场景）：重新排程
      await this.state.storage.setAlarm(meta.expiresAt);
      return;
    }
    await this.destroy();
  }

  /**
   * GC 闹钟/惰性兜底：删除宽限窗口结束的快照包 R2 对象（§4.3）。
   * best-effort：R2 删除失败时保留 gc 标记，下次闹钟/惰性调用重试。
   */
  private async gcSweep(): Promise<void> {
    const gc = await this.state.storage.get<{ packId: string }>(GC_KEY);
    if (!gc) return;
    try {
      await this.env.PACKS.delete(gc.packId);
      this.state.storage.delete(GC_KEY);
    } catch {
      /* R2 删除失败：保留标记，等待下次触发重试 */
    }
  }

  /**
   * 销毁 = 删全部存储 + 清闹钟 + 删注册表引用。
   * 带快照包时【决策 2026-11-21】：不立即删 R2 对象——写 gc 标记并设
   * now+10min 闹钟（弱网重试宽限窗口，§4.3）；码已死，仅延长密文对象存活。
   */
  private async destroy() {
    const meta = await this.state.storage.get<ExtractMeta>(META_KEY);
    this.state.storage.delete(META_KEY);
    if (meta?.pack) {
      this.state.storage.put(GC_KEY, { packId: meta.pack.packId });
      await this.state.storage.setAlarm(Date.now() + PAGE_PACK_GC_MS);
    } else {
      this.state.storage.deleteAlarm();
    }
    if (meta) {
      try {
        await this.env.REGISTRY_DO.getByName("main").deleteRef(
          meta.codeHash,
          "extract",
        );
      } catch {
        /* ignore：引用不含内容，失败不影响销毁 */
      }
    }
  }
}
