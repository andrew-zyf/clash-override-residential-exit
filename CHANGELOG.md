# Changelog

版本号对应脚本头部的 `@version`。

---

## v12.0 (2026-05-09)

- 项目名更新为 `clash-override-residential-exit`。
- 覆写脚本改名为 `src/residential-exit-override.js`。
- 运行时代码改为通用家宽出口语义：核心出口组为 `az.核心出口.🏠 家宽出口`，只包含 `家宽出口（官方中转）`。
- 默认代理组改为按 `PROXY`、`节点选择`、`手动选择`、`GLOBAL` 四个核心词自动识别，并忽略前后缀。
- AI 浏览器进程并入 `az.严管调度.🤖 AI 高敏阵列`，不再提供单独开关。
- 文档重写为当前架构说明，并移除全部图片引用；架构图改用 Mermaid。
- 删除仓库内 PNG 配图资源。
