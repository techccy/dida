import { describe, expect, it } from "vitest";
import {
  WATERMARK_CUSTOM_MAX,
  isValidWatermarkConfig,
  parseExtractEnvelope,
  type WatermarkConfig,
} from "../src/watermark";

describe("isValidWatermarkConfig", () => {
  it("null 合法（= 未启用水印）", () => {
    expect(isValidWatermarkConfig(null)).toBe(true);
  });

  it("合法配置对象", () => {
    const cfg: WatermarkConfig = {
      custom: "内部资料",
      ip: true,
      device: true,
      time: true,
    };
    expect(isValidWatermarkConfig(cfg)).toBe(true);
    expect(isValidWatermarkConfig({})).toBe(true);
    expect(isValidWatermarkConfig({ ip: true })).toBe(true);
  });

  it("字段缺省合法（未勾选项）", () => {
    expect(isValidWatermarkConfig({ custom: "x", time: true })).toBe(true);
  });

  it("非法形状拒绝", () => {
    expect(isValidWatermarkConfig(undefined)).toBe(false);
    expect(isValidWatermarkConfig("wm")).toBe(false);
    expect(isValidWatermarkConfig(123)).toBe(false);
    expect(isValidWatermarkConfig({ ip: "yes" })).toBe(false);
    expect(isValidWatermarkConfig({ time: 1 })).toBe(false);
    expect(isValidWatermarkConfig({ custom: 42 })).toBe(false);
    expect(
      isValidWatermarkConfig({ custom: "x".repeat(WATERMARK_CUSTOM_MAX + 1) }),
    ).toBe(false);
  });

  it("custom 恰好达到上限合法", () => {
    expect(
      isValidWatermarkConfig({ custom: "x".repeat(WATERMARK_CUSTOM_MAX) }),
    ).toBe(true);
  });
});

describe("parseExtractEnvelope", () => {
  it("v1 信封：text + wm 配置", () => {
    const wm: WatermarkConfig = { ip: true, device: true };
    const raw = JSON.stringify({ v: 1, text: "hello", wm });
    expect(parseExtractEnvelope(raw)).toEqual({ text: "hello", wm });
  });

  it("v1 信封：wm 为 null（未启用）", () => {
    const raw = JSON.stringify({ v: 1, text: "hello", wm: null });
    expect(parseExtractEnvelope(raw)).toEqual({ text: "hello", wm: null });
  });

  it("v1 信封：wm 缺省按 null", () => {
    const raw = JSON.stringify({ v: 1, text: "hello" });
    expect(parseExtractEnvelope(raw)).toEqual({ text: "hello", wm: null });
  });

  it("旧版裸文本（非 JSON）→ 无水印", () => {
    expect(parseExtractEnvelope("API_KEY=xxxx\nTLS=yyyy")).toEqual({
      text: "API_KEY=xxxx\nTLS=yyyy",
      wm: null,
    });
  });

  it("形状非法的 wm（wm 为字符串）→ 兜底按无水印处理，不抛错", () => {
    const raw = JSON.stringify({ v: 1, text: "hello", wm: "bad" });
    expect(parseExtractEnvelope(raw)).toEqual({ text: "hello", wm: null });
  });

  it("text 缺失的 JSON → 兜底按裸文本", () => {
    expect(parseExtractEnvelope('{"a":1}')).toEqual({
      text: '{"a":1}',
      wm: null,
    });
  });
});
