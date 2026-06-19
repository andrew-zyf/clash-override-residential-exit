# Changelog

版本号对应脚本头部的 `@version`。

---

## v14.5 (2026-06-19)

**DNS 优化（direct 应用）**
- Apple/iCloud、出口检测站（ping0 / ipinfo / ifconfig / ip.sb）、Tailscale / ZeroTier / Plex / Synology 等 direct 应用的 DoH 由 overseas 改为 domestic。这些流量本就走 DIRECT，国内有 CDN，域内 DoH 直返 CN 节点最快；也避免代理节点断连时 DNS 卡在等 overseas DoH。

**域名增补**
- OpenAI：chat.com、crixet.com、CDN / Azure 静态资源域（openaicom 系列）、livekit 实时语音域（chatgpt.livekit.cloud）、challenges.cloudflare.com、statsig / sentry 遥测上报域。
- Google AI：aiplatform.googleapis.com、Antigravity 的 cloudcode 系列域。

**进程清单扩充**
- AI 桌面 App 新增 Codex / Antigravity / Antigravity IDE，及其 Windows `.exe`、Helper（Renderer / GPU / Plugin）子进程、`language_server` 系列。
- AI CLI 新增 `claude.exe`、`codex` 各平台二进制名（darwin / linux · aarch64 / x86_64）、`agy`、`antigravity`。

**重构**
- 引入 `buildRouteGrouped` + `RESIDENTIAL_ROUTES` / `RESIDENTIAL_ROUTE_GROUPS` / `MEDIA_ROUTE_GROUPS` 数据化路由桶投影，替代手写分桶。
- 新增 `appendDomainRuleGroups` 统一域名规则生成。
- 移除冗余的 `ACTIVE_USER_OPTIONS` / `cloneUserOptions`（直接读 `USER_OPTIONS`）、`removeNamedItem`、`resolveRegionMeta` 的兜底标签参数。
- `@version` 13.0 → 14.5。

## v13.0 (2026-05-22)

**架构变更**
- 新增 `USER_OPTIONS.enabled` 总开关，`false` 时 config 原样透传。
- 订阅全接管：丢弃所有订阅规则和非默认代理组，只保留节点和默认代理组。
- 默认代理组识别：关键词 + MATCH 规则兜底，大小写不敏感。
- 家宽出口和分区测速组注入默认代理组，清理失效引用。
- MATCH / DoH / GFW 统一指向订阅默认代理组。
- 清除订阅 `rule-providers`，防止 RULE-SET 规则逃逸。
- 移除 🇹🇼 台湾分区组。

**规则增强**
- 新增 GFWList 支持：通过 `GEOSITE,gfw` 将 GFW 域路由到默认代理组。
- 规则新增 `DOMAIN-KEYWORD` 兜底，防止 `DOMAIN-SUFFIX` 实现差异遗漏子域。
- 调度组候选顺序：🇺🇸 US → 🇯🇵 JP → 🇸🇬 SG → 🇭🇰 HK → 🏠 家宽出口。

**域名增补**
- AI：poe.com、cohere.com、grammarly.com、deepl.com、suno.ai、leonardo.ai、replit.com、jasper.ai、gamma.app、codeium.com、windsurf.com、v0.dev、bolt.new、lovable.dev、descript.com、udio.com
- 支撑平台：notion.so、linear.app、figma.com
- 集成：intercom.io、launchdarkly.com、fullstory.com
- IM：slack.com、zoom.us
- 社交：linkedin.com

**DNS 优化**
- 移除 `fallback-filter.domain`（与 `nameserver-policy` 重复，nameserver-policy 已逐条绑定 DoH）
- 简化 `sniffer.force-domain`（residentialAll 已覆盖所有 force 条目）
- 修复 `cloudflare-dns.com` 双重归类（同时出现在 CDN.doh 和 CDN.cloud）

**文档**
- README 重构：精简 Rule Abbreviations 表、合并配置与快速开始、缩减至约 110 行。
