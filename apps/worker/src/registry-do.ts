/**
 * Registry DO：管理员会话注册表（单管理员，固定名 "main"）。
 * 只存 { sessionId, codeHash, createdAt } 的引用列表（码明文/密文都不经过它，§7.2）。
 * 会话全清（ended）时由 Session DO 删除自己的引用。
 */
import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";

interface Ref {
  sessionId: string;
  codeHash: string;
  createdAt: number;
}

const KEY = "refs";

export class RegistryDO extends DurableObject<Env> {
  /** 基类 ctx 的别名（沿用 state 命名） */
  private get state(): DurableObjectState {
    return this.ctx;
  }

  async addRef(ref: Ref): Promise<{ ok: boolean }> {
    const refs = (await this.state.storage.get<Ref[]>(KEY)) ?? [];
    if (refs.some((r) => r.codeHash === ref.codeHash)) return { ok: true };
    refs.push(ref);
    this.state.storage.put(KEY, refs);
    return { ok: true };
  }

  async listRefs(): Promise<Ref[]> {
    return (await this.state.storage.get<Ref[]>(KEY)) ?? [];
  }

  async deleteRef(codeHash: string): Promise<void> {
    const refs = (await this.state.storage.get<Ref[]>(KEY)) ?? [];
    this.state.storage.put(
      KEY,
      refs.filter((r) => r.codeHash !== codeHash),
    );
  }
}
