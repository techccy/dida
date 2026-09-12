/**
 * DidaClient 接收序单测（§6.2、§7.5）：
 * 重点验证 lost 帧推进接收水位——丢失一条后，后续消息必须能继续交付
 * （否则 gap 缓冲区会永久卡死整个会话）。
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  generateKeyPair,
  deriveDirectionKeys,
  encryptMsg,
  type KeyPair,
} from "../src/crypto/crypto";
import { bytesToB64, b64ToBytes } from "@dida/shared";
import { DidaClient } from "../src/ws/client";

class FakeWS {
  static OPEN = 1;
  static instances: FakeWS[] = [];
  static last(): FakeWS {
    return this.instances[this.instances.length - 1];
  }
  readyState = 1;
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number; reason: string }) => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(public url: string) {
    FakeWS.instances.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close(_code?: number, _reason?: string) {
    this.readyState = 3;
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  deliver(obj: unknown) {
    this.onmessage?.({ data: JSON.stringify(obj) });
  }
  lastSentFrame(): any {
    return this.sent.length ? JSON.parse(this.sent[this.sent.length - 1]) : null;
  }
}

const SALT = new Uint8Array(crypto.getRandomValues(new Uint8Array(32)));

let admin: KeyPair;
let part: KeyPair;
/** participant→admin 方向的加密密钥（admin 客户端用它解密） */
let partToAdminEnc: CryptoKey;

beforeAll(async () => {
  // 客户端用 window.* 定时器，node 环境桩掉
  (globalThis as any).window = globalThis;
  (globalThis as any).WebSocket = FakeWS;

  admin = await generateKeyPair();
  part = await generateKeyPair();
  const peerKey = await crypto.subtle.importKey(
    "raw",
    admin.pubRaw.slice().buffer,
    { name: "X25519" },
    true,
    [],
  );
  const partKeys = await deriveDirectionKeys(
    part.privateKey,
    peerKey,
    SALT,
    "participant",
  );
  partToAdminEnc = partKeys.encKey;
});

afterAll(() => {
  delete (globalThis as any).WebSocket;
});

async function makeAdminClient() {
  const events: Record<string, any[]> = {
    state: [] as [string, string?][],
    message: [] as any[],
    lost: [] as number[],
    peerLeft: [] as unknown[],
    peerBack: [] as unknown[],
    fp: [] as string[],
  };
  const client = new DidaClient({
    wsUrl: "ws://test/ws",
    role: "admin",
    credential: "tok",
    sessionId: "sid",
    keyPair: admin,
    salt: SALT,
    onState: (s, d) => events.state.push([s, d]),
    onMessage: (m) => events.message.push(m),
    onFingerprint: (fp) => events.fp.push(fp),
    onPeerMeta: () => {},
    onVerified: () => {},
    onLost: (n) => events.lost.push(n),
    onPeerLeft: () => events.peerLeft.push(1),
    onPeerBack: () => events.peerBack.push(1),
    onEnd: () => {},
    onError: () => {},
  });
  const ws = FakeWS.last();
  ws.open();
  ws.deliver({ type: "ok", lastSent: 0 });
  ws.deliver({
    type: "peer",
    pub: bytesToB64(part.pubRaw),
    salt: bytesToB64(SALT),
  });
  await new Promise((r) => setTimeout(r, 50)); // 等密钥派生完成
  return { client, ws, events };
}

/** 用 participant→admin 方向密钥加密一条消息帧 */
async function msgFrame(seq: number): Promise<Record<string, unknown>> {
  const { nonce, ct } = await encryptMsg(
    partToAdminEnc,
    { text: `m${seq}`, ts: 1 },
    "participant",
  );
  return { type: "msg", from: "participant", seq, nonce, ct };
}

describe("DidaClient 接收序", () => {
  it("顺序消息直接交付并 ack", async () => {
    const { client, ws, events } = await makeAdminClient();
    ws.deliver(await msgFrame(1));
    ws.deliver(await msgFrame(2));
    await new Promise((r) => setTimeout(r, 50));
    expect(events.message.map((m: any) => m.text)).toEqual(["m1", "m2"]);
    expect(ws.lastSentFrame()).toEqual({ type: "ack", seq: 2 });
    client.dispose();
  });

  it("lost 帧推进水位：丢 seq1 后 seq2 仍可交付（不卡死）", async () => {
    const { client, ws, events } = await makeAdminClient();
    ws.deliver(await msgFrame(2)); // 先到（seq1 将丢失）→ 进 gap
    await new Promise((r) => setTimeout(r, 20));
    expect(events.message).toHaveLength(0); // 尚未交付
    ws.deliver({ type: "lost", n: 1 }); // 服务端宣告 1 条不可恢复
    await new Promise((r) => setTimeout(r, 50));
    expect(events.message.map((m: any) => m.text)).toEqual(["m2"]);
    expect(events.lost).toEqual([1]);
    expect(ws.lastSentFrame()).toEqual({ type: "ack", seq: 2 });
    client.dispose();
  });

  it("lost 帧在乱序帧之后到达：同样解除卡死", async () => {
    const { client, ws, events } = await makeAdminClient();
    ws.deliver({ type: "lost", n: 1 });
    ws.deliver(await msgFrame(2));
    await new Promise((r) => setTimeout(r, 50));
    expect(events.message.map((m: any) => m.text)).toEqual(["m2"]);
    client.dispose();
  });

  it("重复 seq 去重（backlog 补发已交付过的）", async () => {
    const { client, ws, events } = await makeAdminClient();
    ws.deliver(await msgFrame(1));
    await new Promise((r) => setTimeout(r, 30));
    ws.deliver(await msgFrame(1));
    await new Promise((r) => setTimeout(r, 30));
    expect(events.message).toHaveLength(1);
    client.dispose();
  });

  it("lost n=0 不推进水位、不回调", async () => {
    const { client, ws, events } = await makeAdminClient();
    ws.deliver({ type: "lost", n: 0 });
    ws.deliver(await msgFrame(1));
    await new Promise((r) => setTimeout(r, 50));
    expect(events.message.map((m: any) => m.text)).toEqual(["m1"]);
    expect(events.lost).toHaveLength(0);
    client.dispose();
  });

  it("peer-left / peer-back 分别触发对应回调", async () => {
    const { client, ws, events } = await makeAdminClient();
    ws.deliver({ type: "peer-left" });
    ws.deliver({ type: "peer-back" });
    await new Promise((r) => setTimeout(r, 30));
    expect(events.peerLeft).toHaveLength(1);
    expect(events.peerBack).toHaveLength(1);
    client.dispose();
  });
});
