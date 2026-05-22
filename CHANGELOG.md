# Changelog

版本号对应脚本头部的 `@version`。

---

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
