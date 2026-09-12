/**
 * Guard DO：轻量限流计数（§10）
 * - 管理员登录：同一来源 5 次失败 → 锁 15 分钟
 * - 邀请码加入：同一 IP ≤5 次/分钟，超限封 15 分钟
 * 计数存 DO 持久存储，随时间自然过期（定期清理），不留持久记录。
 */
import { DurableObject } from "cloudflare:workers";
import {
  LOGIN_MAX_FAILURES,
  LOGIN_LOCK_MS,
  JOIN_MAX_PER_MINUTE,
  JOIN_WINDOW_MS,
  JOIN_BLOCK_MS,
} from "@dida/shared";
import type { Env } from "./env";

interface LoginBucket {
  n: number;
  lastFailAt: number;
  lockUntil: number;
}

interface JoinBucket {
  n: number;
  windowStart: number;
  blockUntil: number;
}

const LOGIN_PREFIX = "login:";
const JOIN_PREFIX = "join:";

export class GuardDO extends DurableObject<Env> {
  /** 基类 ctx 的别名（沿用 state 命名） */
  private get state(): DurableObjectState {
    return this.ctx;
  }

  /** 登录前预检：是否处于锁定期 */
  async loginPrecheck(key: string): Promise<{ locked: boolean }> {
    const now = Date.now();
    const b =
      (await this.state.storage.get<LoginBucket>(LOGIN_PREFIX + key)) ?? {
        n: 0,
        lastFailAt: 0,
        lockUntil: 0,
      };
    const locked = b.lockUntil > now;
    if (!locked && b.lockUntil !== 0)
      this.state.storage.delete(LOGIN_PREFIX + key);
    return { locked };
  }

  /** 登录失败：计数 +1；达到上限则锁定 15 分钟 */
  async loginFail(key: string): Promise<{ locked: boolean; remaining: number }> {
    const now = Date.now();
    const b =
      (await this.state.storage.get<LoginBucket>(LOGIN_PREFIX + key)) ?? {
        n: 0,
        lastFailAt: 0,
        lockUntil: 0,
      };
    // 锁定窗口内重复失败：保持锁定，不累计
    if (b.lockUntil > now) return { locked: true, remaining: -1 };
    // 距上次失败超过锁定期，重置计数
    if (now - b.lastFailAt > LOGIN_LOCK_MS) b.n = 0;
    b.n += 1;
    b.lastFailAt = now;
    if (b.n >= LOGIN_MAX_FAILURES) b.lockUntil = now + LOGIN_LOCK_MS;
    this.state.storage.put(LOGIN_PREFIX + key, b);
    await this.maybeSetAlarm();
    return {
      locked: b.lockUntil > now,
      remaining: Math.max(0, LOGIN_MAX_FAILURES - b.n),
    };
  }

  /** 登录成功：清零计数 */
  async loginSuccess(key: string): Promise<void> {
    this.state.storage.delete(LOGIN_PREFIX + key);
  }

  /**
   * 加入尝试：窗口内计数；超限 → 封 15 分钟。
   * 返回 { allowed, blocked }；blocked=true 时调用方应拒绝 join。
   */
  async joinAttempt(ip: string): Promise<{ allowed: boolean; blocked: boolean }> {
    const now = Date.now();
    const b = (await this.state.storage.get<JoinBucket>(JOIN_PREFIX + ip)) ?? {
      n: 0,
      windowStart: now,
      blockUntil: 0,
    };
    if (b.blockUntil > now) return { allowed: false, blocked: true };
    if (now - b.windowStart >= JOIN_WINDOW_MS) {
      b.n = 0;
      b.windowStart = now;
    }
    if (b.n >= JOIN_MAX_PER_MINUTE) {
      b.blockUntil = now + JOIN_BLOCK_MS;
      this.state.storage.put(JOIN_PREFIX + ip, b);
      await this.maybeSetAlarm();
      return { allowed: false, blocked: true };
    }
    b.n += 1;
    this.state.storage.put(JOIN_PREFIX + ip, b);
    return { allowed: true, blocked: false };
  }

  /** 定期清理过期计数，防止无限积累（不留持久记录） */
  async alarm(): Promise<void> {
    const now = Date.now();
    const logins = await this.state.storage.list({ prefix: LOGIN_PREFIX });
    for (const [k, v] of logins) {
      const b = v as LoginBucket;
      if (b.lockUntil <= now) this.state.storage.delete(k);
    }
    const joins = await this.state.storage.list({ prefix: JOIN_PREFIX });
    for (const [k, v] of joins) {
      const b = v as JoinBucket;
      if (b.blockUntil <= now && now - b.windowStart >= JOIN_WINDOW_MS)
        this.state.storage.delete(k);
    }
  }

  private async maybeSetAlarm(): Promise<void> {
    const cur = await this.state.storage.getAlarm();
    if (cur === null || cur === undefined || cur <= Date.now()) {
      await this.state.storage.setAlarm(Date.now() + 10 * 60 * 1000);
    }
  }
}
