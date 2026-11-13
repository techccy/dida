/**
 * wrangler Text 模块规则（见 wrangler.toml rules）：*.txt 以字符串导入。
 * 本声明仅供 tsc 类型检查；vitest 不导入含 *.txt 的路由包装模块（纯逻辑
 * 在 oauth-core.ts 中单测）。
 */
declare module "*.txt" {
  const content: string;
  export default content;
}
