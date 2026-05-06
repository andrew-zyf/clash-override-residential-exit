# Changelog

版本号对应脚本头部的 `@version`。

---

## v11.7 (2026-05-06)

- **单文件合并**：`residential-chain-proxy-config.js` + `residential-chain-proxy-override.js` 合并为 `residential-chain-proxy-combined.js`，`MIYA_CREDENTIALS` / `USER_OPTIONS` 作为文件顶部变量直接嵌入。适配 Clash Verge 等只支持单覆写文件的客户端。
- **入口状态精简**：`main(config)` 直接克隆顶部 `USER_OPTIONS`，`merged` 模式把 `MIYA_CREDENTIALS` 作为局部变量传入链式代理入口；移除 `_azChainProxyUserConfig` / `_miya` / `_azChainProxyState` 这类合并后不再需要的临时传递字段。
- **实现去重**：收敛 route 投影 helper、DNS/Sniffer 写入入口和进程规则追加逻辑，删除重复的派生状态 builder，同时保持 POLICY / DERIVED 注释密度不变。
- **测试合并**：`tests/unit.js` + `tests/validate.js` 合并为 `tests/test.js`（11 个纯函数单元测试 + 16 个端到端集成测试），从合并后的单文件加载沙箱。
- 移除旧拆分文件 `residential-chain-proxy-config.js`、`residential-chain-proxy-override.js`、`residential-chain-proxy.min.js` 及旧测试文件。

## v11.6 (2026-05-05)

- **凭证校验加固**：`hasConfiguredMiyaCredentials` 的 `relay.port` / `transit.port` 从 truthy 检查改为正整数范围校验（`typeof port === "number" && port > 0 && port < 65536`），拒绝 `0`、负数、越界值、字符串和空值。
- **代理类型白名单**：`BASE` 新增 `validProxyTypes` 常量，覆盖 Clash 支持的 12 种合法代理类型；`buildMiyaProxy` 在生成 MiyaIP 节点前校验硬编码的 `"http"` 是否在白名单内，防止常量被误改后静默生成非法类型。
- 新增 3 个单元测试（`tests/unit.js`）：port 边界 8 种场景 + `validProxyTypes` 常量完整性 + `buildMiyaProxy` 异常路径。

## v11.5 (2026-05-04)

- CDN 基础设施域名（AWS / Amazon / CloudFront / Fastly / Akamai / Azure CDN / jsDelivr / Bunny / Cloudinary）从默认无路由改为链式代理出口 `chain.cdn`，合并至「支撑平台」UI 组，确保技术服务页面、CDN 资源等流量经家宽 IP 出口。

---

## v11.4 (2026-05-03)

- 拆分用户配置与实现逻辑：新增 `src/residential-chain-proxy-config.js` 保存 `MIYA_CREDENTIALS` / `USER_OPTIONS`，`src/residential-chain-proxy-override.js` 不再保留重复用户配置，只读取临时配置后立即清理，升级实现文件时可保留本地配置。
- DNS 策略改为 `geosite:cn` / `geosite:geolocation-!cn` 大类兜底 + 显式域名覆盖；移除 `geosite:openai`，OpenAI / Claude 等高敏域名全部由源码显式维护。
- 分流策略改为域名优先、进程兜底：高敏域名、媒体、DoH、显式 DIRECT 先匹配，再用 `GEOSITE,cn,DIRECT` / `GEOIP,CN,DIRECT` 处理域内兜底，AI App / CLI / 浏览器进程规则最后兜底。
- 移除全局 `DOMAIN-KEYWORD,stun/turn` 链式规则，避免误伤会议、语音、游戏和 P2P 场景。
- 新增 `DNS_ONLY` 解析例外桶，只参与 DNS / fallback-filter，不生成路由规则；测试扩展到 18 个用例，覆盖拆分文件传参、缺失配置报错和配置清理。

---

## v11.3 (2026-05-03)

- 将 Option A / Option B 收敛到单一入口 `src/residential-chain-proxy-override.js`，由 `USER_OPTIONS.overrideMode` 选择 `dns-sniffer-only` 或 `merged`。
- `dns-sniffer-only` 只写入 `config.dns` / `config.sniffer`，不会读取 `MIYA_CREDENTIALS`，也不会改动 `proxies` / `proxy-groups` / `rules`。
- 移除独立 `src/dns-sniffer-override.js`，避免同时导入两个覆写入口造成配置边界不清。
- README 和测试改为围绕单文件模式开关描述与校验。

---

## v11.2 (2026-05-02)

- 将完整链式代理脚本从中文文件名改为 `src/residential-chain-proxy-override.js`。
- 同步 README、测试和脚本版本号，仓库内两个 JS 入口均使用英文命名。

---

## v11.1 (2026-05-02)

- 新增 `src/dns-sniffer-override.js`，作为独立 DNS / Sniffer 选项；它只写入 `config.dns` / `config.sniffer`，不改代理组、不改分流规则。
- README 改为 Option A（独立 DNS / Sniffer）与 Option B（完整链式代理）两条路径，方便用户按风险和部署复杂度选择。
- 使用 gpt-image-2 重新生成 README 配图，并统一替换为英文文件名：`hero-cover.png`、`options-overview.png`、`proxy-groups-overview.png`、`architecture-flow.png`。
- 丢弃旧版中文命名插图和旧 `data-flow.png`，测试新增独立 DNS / Sniffer 覆写校验。

---

## v11.0 (2026-05-02)

- 将 `DNS解析和域名嗅探.js`、`MiyaIP 凭证_样本.js`、`residential-chain-proxy-override.js` 合并为单一入口 `residential-chain-proxy-override.js`。
- 新增顶部 `MIYA_CREDENTIALS` 配置块；脚本运行时临时写入凭证并在生成最终配置前删除，避免凭证泄漏到 Clash 配置。
- DNS / Sniffer 逻辑改为内部模块，仍与路由规则共享同一份 POLICY / DERIVED 派生结果，保持域内、域外解析策略一致。
- `tests/validate.js` 改为只加载单文件脚本，并新增空凭证校验；README 改为单文件导入流程。

---

## v10.1 (2026-04-29)

- 将 DNS 解析与域名嗅探拆到 `DNS解析和域名嗅探.js` 前置覆写；链式代理脚本改为消费 `_azChainProxyState`，执行顺序固定为 DNS/Sniffer → MiyaIP 凭证（静态 IP 信息登记）→ 链式代理。
- `tests/validate.js` 改为按多覆写顺序运行，并新增缺少 DNS/Sniffer 前置状态的顺序校验。
- `_azChainProxyState` 精简为仅传递 `DERIVED` 派生状态，并新增前后脚本版本一致性校验。

---

## v10.0 (2026-04-17)

重大架构升级：代理组重命名、POLICY/DERIVED 层简化、域名覆盖全面扩充、DNS 防泄漏加固。

### 架构

- **POLICY 层简化**：移除 `routeBucket` 字段；`buildNameserverPolicy` 和 `buildDirectRules` 改为直接遍历 POLICY，删除中间表 `buildNameserverPolicyTable`。
- **DERIVED 层扁平化**：`patterns` 从 4 层嵌套树（`strict.{ai,support,...}` / `general.{media,...}` / `direct.{domestic.{ai,...},overseas.{...},...}`）压缩为 5 个平坦字段 `{ chain, media, direct, fakeIpBypass, sniffer }`；`processNames` 从 `strict.base` / `general.browser` 等别名简化为 `{ aiApps, aiCli, browser }`。
- **死代码清理**：移除 `matchRouteBucket` / `matchSnifferOnly` / `appendRawRules` / `writeRelayIntoNodeSelection` / `writeMediaIntoNodeSelection` 等未使用的函数；移除始终为空的 `strict.validation` 和从未被消费的 `direct.overseas` 子树。
- **`buildDnsFallbackFilterDomains`**（10 行手工拼装 7 个派生路径）→ `projectPolicyPatterns(matchFallbackFilter)`（1 行）。
- 新增 `endsWithString(str, suffix)` ES5 安全辅助函数，替换两处 `lastIndexOf` 惯用法。

### 代理组命名

- 组名后缀加入 `-AI|` 标识：`-链式代理.跳板` → `-AI|链式代理.跳板`，`-链式代理.家宽出口` → `-AI|链式代理.家宽出口`。
- 旗帜与地区名之间移除 `|` 分隔符：`🇸🇬|新加坡` → `🇸🇬新加坡`。
- `家宽IP出口` 简化为 `家宽出口`。

### 地区

- 新增 `TW`（台湾 🇹🇼）地区支持。
- 链式出口 fallback 顺序更新为 `SG → TW → JP → US`。
- 媒体组 fallback 顺序更新为 `US → JP → HK`。

### 域名覆盖扩充

#### SOURCE_CHAIN（链式代理 → 家宽出口）

- **AI 服务** — 新增 Mistral / Hugging Face（`hf.co` / `hf.space`）/ Replicate（含 `replicate.delivery` CDN）/ Groq / Together / ElevenLabs / Midjourney / Runway / Stability / Ideogram / Civitai / Character.ai / Pi / You.com / Phind / Kagi；新增 Cursor 后端域名（`cursor.sh` / `cursor.com`）。
- **支撑平台** — `developer` 拆分为 5 个子组：`git_hosts`（+ GitLab / Atlassian / Bitbucket）、`package_registries`（+ PyPI / pythonhosted / crates.io / RubyGems / Docker Hub）、`deployment`（Vercel / Netlify / Supabase / Fly.io / Render / Railway）、`tools`（JetBrains）、`docs_and_qa`（Stack Overflow / Mozilla MDN / Read the Docs / GitBook）。
- **共享集成** — `antibot` / `payments` / `telemetry` 三桶合并为 `integrations` 单一桶；新增 `auth_providers`（Auth0 / Clerk / Okta）；`antibot` 补充 hCaptcha；`payments` 补充 PayPal / Paddle / Lemon Squeezy；`telemetry` 补充 PostHog / Segment / Mixpanel / Amplitude / Datadog RUM。

#### SOURCE_MEDIA（媒体地区组）

- **视频流媒体** — 新增 Disney+（`dssott.com` / `bamgrid.com`）/ HBO Max（`hbonow.com` / `maxgo.com`）/ Hulu / Prime Video（`aiv-cdn.net` / `aiv-delivery.net`）/ Twitch（`ttvnw.net` / `jtvnw.net`）/ Peacock / Paramount+ / Crunchyroll / Vimeo / Dailymotion。
- **音乐** — 新增 Spotify（`scdn.co` / `spotifycdn.com`）/ SoundCloud / Bandcamp。
- **社交** — `facebook` 桶重命名为 `meta`，新增 Threads；新增 Reddit / TikTok（海外版）/ Snapchat / Pinterest / Bluesky / Tumblr / Medium / Substack / Patreon / Goodreads / Letterboxd。
- **即时通讯** — 新增 LINE（`line.me` / `line-apps.com` / `line-scdn.net` / `line-cdn.net`）/ WhatsApp / Signal。

#### SOURCE_CN_DIRECT（域内直连）

- **AI** — 新增 DeepSeek / Doubao（含 `volcengineapi.com`）/ MiniMax（`minimaxi.com` / `hailuoai.com`）/ Baichuan / Stepfun。
- **消费类**（新增 `consumer` 子桶 + POLICY 条目 `direct.cn.consumer`）— Baidu / Bilibili（`hdslb.com` / `bilivideo.com` / `bilicdn1.com` 等）/ Weibo + Sina / Zhihu / 小红书 / 抖音 + 快手 / 网易 / 爱奇艺 / 优酷 / 芒果TV / 搜狐 / 淘宝 + 天猫 / 京东 / 拼多多 / 美团 + 大众点评 / 米哈游。

#### 其他 SOURCE

- **SOURCE_GLOBAL_DEFAULT** — 新增 Bunny CDN（`b-cdn.net`）/ Cloudinary。
- **SOURCE_OVERSEAS_DIRECT** — 出口验证补充 `ifconfig.me` / `ip.sb`；应用补充 ZeroTier / Plex（`plex.direct`）/ Synology（`quickconnect.to`）。
- **SOURCE_LOCAL_DIRECT** — 新增 `home.arpa`（RFC 8375）。
- **SOURCE_NETWORK_DIRECT** — 新增 RFC 1918（10/8、172.16/12、192.168/16）/ 链路本地（169.254/16、fe80::/10）/ IPv6 ULA（fc00::/7）。

### DNS、Sniffer 与安全

- **`respect-rules: true`** — DNS 查询遵循分流规则：chain 域名的 DoH 经链式代理从 SG 家宽出去，direct 域名走 `direct-nameserver`（域内 DoH）。出差 CN 时 `dns.google` 只看到 SG 家宽 IP，不会暴露临时 CN IP。
- **Apple DNS 修复** — Apple POLICY 条目移除 `dnsZone: "overseas"` 硬绑定，改为 `fallbackFilter: true`，走 nameserver + fallback 并行查询 + geoip 仲裁。SG 走域外结果，CN 走域内 Apple CDN，不再因域外 DoH 被墙导致 Apple Store 无法登录。
- **Sniffer 说明** — README 新增专节解释 Sniffer 在 fake-ip 模式下的安全网作用：当 fake-IP 映射丢失或 QUIC 跳过 DNS 时，Sniffer 从 TLS SNI / HTTP Host 恢复域名，确保 AI 流量命中链式代理规则而非漏到 MATCH 兜底。`force-domain`（chain 域名 + Cloudflare）和 `skip-domain`（Tailscale / Plex / Apple 推送等 P2P 应用）的取舍逻辑一并记录。

### 文档

- README 引言新增出差场景段落（SG → CN 酒店 Wi-Fi 开发环境瘫痪）。
- Usage 重组为 5 步编号流程 + FAQ（含自定义地区正则、新增地区指引）+ 升级/卸载说明。
- SOURCE 对照表按实际内容全面重写。
- 新增 Sniffer 专节（Fake-IP 安全网原理 + force/skip 取舍）。
- 新增 `respect-rules: true` 三阶防泄漏时序说明及 Secure DNS 警告。
