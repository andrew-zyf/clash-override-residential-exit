# Changelog

版本号对应脚本头部的 `@version`。

---

## v14.7 (2026-06-19)

**测速探针更换**
- `urlTestProbeUrl` 由 `http://www.gstatic.com/generate_204`（Google）改为 `http://cp.cloudflare.com/generate_204`（Cloudflare）。
- 原因：部分节点出口到 Google 不通，url-test 显示 timeout（假象，节点实际可用）。Cloudflare 探针可达性更通用，延迟显示更准。
- 仅影响脚本生成的 `az.分区测速.*` url-test 组；订阅自带组用订阅自己的探针，不在本脚本控制范围。

- `@version` 14.6 → 14.7。

## v14.6 (2026-06-19)

**反检测：全局拦截 QUIC**
- 规则链最前端注入 `AND,((NETWORK,udp),(DST-PORT,443)),REJECT`，强制客户端从 QUIC 回退到 TCP+TLS，避免运营商借 QUIC 流量特征识别代理 / VPN。
- 移除 sniffer 的 QUIC 嗅探端口（已被上游 REJECT 拦截，成死配置）；TLS / HTTP 嗅探保留。

**DNS 评估（维持现状，未引入 DoH3）**
- 主链路 DNS 全部走 DoH（dns.google / cloudflare-dns / alidns / doh.pub / quad9），不含 DoQ / DoT。
- DoH3 跑在 QUIC 上，与全局 QUIC 拦截直接冲突，故不引入；DoH（TCP+TLS）已满足加密与反识别需要。
- `default-nameserver` 维持明文引导（`223.5.5.5` / `119.29.29.29`）：仅解析 DoH 服务器自身域名。曾尝试 IP 字面量 DoH + `#SNI`，但在目标 mihomo 上导致全部节点 timeout（DNS 引导失败），已回退。

- `@version` 14.5 → 14.6。

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
