// 家宽 IP 官方中转 — 单文件合并版
//
// 使用方式：将此文件作为 Clash 覆写脚本导入。
// 请在下面的 RESIDENTIAL_CREDENTIALS 和 USER_OPTIONS 中填写你的配置。
// 兼容性：Clash Verge / Clash Party 的 JavaScriptCore；只用 ES5 语法。
//
// @version 14.5

// ===========================================================================
// 用户配置
// ===========================================================================

var USER_OPTIONS = {
  enabled: true, // false = 关闭覆写，config 原样透传
  overrideMode: "merged" // "merged" = 全覆写 | "dns-sniffer-only" = 仅 DNS/Sniffer
};

var RESIDENTIAL_CREDENTIALS = {
  username: "",
  password: "",
  transit: {
    server: "",
    port: 8001
  }
};

// ===========================================================================
// 1. 共享工具函数
// ===========================================================================

// 对字符串列表做稳定去重，保留首次出现的顺序。
function uniqueStrings(values) {
  var uniqueValues = [];
  var seen = {};
  for (var i = 0; i < values.length; i++) {
    var value = values[i];
    if (seen[value]) continue;
    seen[value] = true;
    uniqueValues.push(value);
  }
  return uniqueValues;
}

// 为字符串数组构建便于查询的哈希表。
function buildStringLookup(values) {
  var lookup = {};
  for (var i = 0; i < values.length; i++) {
    lookup[values[i]] = true;
  }
  return lookup;
}

// 把带通配前缀的域名模式转换成规则使用的裸域名后缀。
function toSuffix(domainPattern) {
  return domainPattern.indexOf("+.") === 0
    ? domainPattern.substring(2)
    : domainPattern;
}

function createUserError(message) {
  return new Error(message);
}

// ===========================================================================
// 3. DNS / Sniffer 策略模块
// ===========================================================================

var DNS_SNIFFER_MODULE = (function () {
// ---------------------------------------------------------------------------
// 3a. 基础常量
// ---------------------------------------------------------------------------

// DNS/Sniffer 模块只保留解析与派生分类所需的运行期常量。
var BASE = {
  ruleTargets: {
    direct: "DIRECT"
  },
  dns: {
    overseas: [
      "https://dns.google/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ],
    domestic: [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],
    domesticGeosite: "geosite:cn",
    overseasGeosite: "geosite:geolocation-!cn"
  }
};

// fallback 在 overseas 基础上追加 Quad9。
BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

// ---------------------------------------------------------------------------
// 3a. 域名模式数据
// ---------------------------------------------------------------------------

// 这里只列"哪些域名属于哪个业务桶"，路由/DNS/sniffer 行为统一在下面的 POLICY 注入。
// 模式形如 `+.domain`，转成规则时由 `toSuffix` 去掉 `+.` 前缀。

// ---------- Fake-IP Filter · 需返回真实 IP 的域名 ----------
// 这些域名不进入 fake-ip 映射，始终返回真实 DNS 解析结果。
// 原因：NTP 对时、STUN 打洞、游戏主机联机、路由器管理等需要真实 IP。
var FAKE_IP_BYPASS = {
  localNetwork: [
    "+.push.apple.com",
    "+.lan",
    "+.local",
    "+.localhost",
    "localhost.ptlogin2.qq.com"
  ],
  timeSync: [
    "time.*.com",
    "time.*.gov",
    "time.*.edu.cn",
    "time.*.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
    "ntp.*.com",
    "ntp1.aliyun.com",
    "pool.ntp.org",
    "+.pool.ntp.org"
  ],
  connectivityTest: [
    "+.msftconnecttest.com",
    "+.msftncsi.com"
  ],
  gamingRealtime: [
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com",
    "+.xboxlive.com",
    "+.battlenet.com.cn",
    "+.blzstatic.cn"
  ],
  stunRealtime: [
    "stun.*.*",
    "stun.*.*.*"
  ],
  homeRouter: [
    "+.router.asus.com",
    "+.linksys.com",
    "+.tplinkwifi.net",
    "+.xiaoqiang.net"
  ]
};

// ---------- Residential Exit · 家宽出口 ----------
var RESIDENTIAL_EXIT = {
  support: {
    google_core: [
      "+.google.com",
      "+.googleapis.com",
      "+.googleusercontent.com"
    ],
    google_static: [
      "+.gstatic.com",
      "+.ggpht.com",
      "+.gvt1.com",
      "+.gvt2.com"
    ],
    google_workspace: ["+.withgoogle.com"], // `googleworkspace.com` 证据不足，先不默认注入
    google_cloud: [
      "+.cloud.google.com"
    ],
    microsoft_core: [
      "+.microsoft.com",
      "+.live.com",
      "+.windows.net"
    ], // `windows.net` 作为 Microsoft 官方基础设施宽域名保留
    microsoft_productivity: [
      "+.office.com",
      "+.office.net",
      "+.office365.com",
      "+.m365.cloud.microsoft",
      "+.sharepoint.com",
      "+.onenote.com",
      "+.onedrive.com"
    ],
    microsoft_auth: [
      "+.microsoftonline.com",
      "+.msftauth.net",
      "+.msauth.net",
      "+.msecnd.net"
    ],
    microsoft_developer: [
      "+.visualstudio.com",
      "+.vsassets.io",
      "+.vsmarketplacebadges.dev"
    ], // Microsoft 开发者与 VS Code 生态基础设施
    developer_git_hosts: [
      "+.github.com",
      "+.githubusercontent.com", // raw.githubusercontent.com 等，GFW 下常被 DNS 污染
      "+.gitlab.com",
      "+.gitlab-static.net",
      "+.bitbucket.org",
      "+.atlassian.com",         // Jira / Confluence / Bitbucket 官网
      "+.atlassian.net"          // 客户工作区子域
    ],
    developer_package_registries: [
      "+.npmjs.org",             // npm registry（Claude Code 自更新 + JS 项目依赖）
      "+.npmjs.com",
      "+.pypi.org",              // Python
      "+.pythonhosted.org",      // PyPI 包文件 CDN
      "+.crates.io",             // Rust
      "+.rubygems.org",          // Ruby
      "+.docker.com",            // Docker Hub
      "+.docker.io"
    ],
    developer_deployment: [
      "+.vercel.com",
      "+.vercel.app",
      "+.vercel-storage.com",
      "+.netlify.com",
      "+.netlify.app",
      "+.supabase.com",
      "+.supabase.co",
      "+.fly.io",
      "+.fly.dev",
      "+.render.com",
      "+.onrender.com",
      "+.railway.app"
    ],
    developer_tools: [
      "+.jetbrains.com",
      "+.jetbrains.space"
    ],
    developer_docs_and_qa: [
      "+.stackoverflow.com",
      "+.sstatic.net",           // Stack Exchange 静态资源
      "+.mozilla.org",           // 含 developer.mozilla.org / MDN
      "+.readthedocs.io",
      "+.readthedocs.org",
      "+.gitbook.io",
      "+.gitbook.com"
    ],
    developer_productivity: [
      "+.notion.so",             // Notion 协作知识库
      "+.notion.com",
      "+.linear.app",            // Linear 项目管理
      "+.figma.com",             // Figma 设计协作
      "+.figstatic.com"          // Figma 静态资源
    ]
  },
  ai: {
    anthropic: [
      "+.claude.ai",
      "+.claude.com",
      "+.anthropic.com",
      "+.claudeusercontent.com",
      "+.clau.de" // Anthropic 官方场景使用过的短链
    ],
    openai: [
      "+.openai.com",
      "+.chatgpt.com",
      "+.chat.com",
      "+.sora.com",
      "+.crixet.com",
      "+.oaiusercontent.com", // OpenAI 官方静态资源与内容分发基础设施
      "+.oaistatic.com",
      "+.openai.com.cdn.cloudflare.net",
      "+.openaiapi-site.azureedge.net",
      "+.openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
      "+.openaicom.imgix.net",
      "+.openaicomproductionae4b.blob.core.windows.net",
      "+.production-openaicom-storage.azureedge.net",
      "+.chatgpt.livekit.cloud",
      "+.host.livekit.cloud",
      "+.challenges.cloudflare.com",
      "+.events.statsigapi.net",
      "+.o33249.ingest.sentry.io"
    ],
    google_ai: [
      "+.gemini.google.com",
      "+.aistudio.google.com",
      "+.ai.google.dev",
      "+.aiplatform.googleapis.com",
      "+.generativelanguage.googleapis.com",
      "+.ai.google",
      "+.notebooklm.google",
      "+.makersuite.google.com", // 历史兼容入口，Google 已迁移到 AI Studio
      "+.deepmind.google",
      "+.labs.google"
    ],
    google_antigravity: [
      "+.antigravity.google",
      "+.antigravity-ide.com", // Antigravity IDE 的非 google 子域资源站
      "+.cloudcode-pa.googleapis.com",
      "+.daily-cloudcode-pa.googleapis.com",
      "+.daily-cloudcode-pa.sandbox.googleapis.com"
    ],
    perplexity: [
      "+.perplexity.ai",
      "+.perplexitycdn.com" // Perplexity 资源分发域名
    ],
    router_and_tools: [
      "+.openrouter.ai"
    ],
    meta: [
      "+.meta.ai"
    ],
    xai: [
      "+.x.ai",
      "+.grok.com"
    ],
    cursor: [
      "+.cursor.sh",
      "+.cursor.com"
    ], // Cursor 后端与鉴权域名；PROCESS-NAME 仅覆盖进程，域名层仍需显式入链
    mistral: [
      "+.mistral.ai"        // 含 api / console / codestral 全部子域
    ],
    huggingface: [
      "+.huggingface.co",
      "+.hf.co",            // 短链
      "+.hf.space"          // Spaces 应用托管
    ],
    replicate: [
      "+.replicate.com",
      "+.replicate.delivery" // 模型输出 CDN
    ],
    groq: [
      "+.groq.com"
    ],
    together: [
      "+.together.ai",
      "+.together.xyz"
    ],
    elevenlabs: [
      "+.elevenlabs.io"      // 语音合成
    ],
    midjourney: [
      "+.midjourney.com"
    ],
    runway: [
      "+.runwayml.com"       // Runway 视频生成
    ],
    stability: [
      "+.stability.ai"
    ],
    ideogram: [
      "+.ideogram.ai"
    ],
    civitai: [
      "+.civitai.com"        // SD 模型与社区
    ],
    ai_search: [
      "+.you.com",           // You.com / YouChat
      "+.phind.com",         // Phind 编程搜索
      "+.kagi.com"           // Kagi 付费搜索
    ],
    character_and_companion: [
      "+.character.ai",
      "+.pi.ai"              // Inflection / Pi
    ],
    writing_and_translation: [
      "+.grammarly.com",     // Grammarly AI 写作助手
      "+.grammarly.io",
      "+.deepl.com"          // DeepL AI 翻译
    ],
    ai_creative_tools: [
      "+.suno.ai",           // AI 音乐生成
      "+.udio.com",          // Udio AI 音乐
      "+.leonardo.ai",       // AI 图像生成
      "+.descript.com"       // AI 视频/音频编辑
    ],
    ai_platforms: [
      "+.poe.com",           // Quora Poe AI 平台
      "+.cohere.com",        // Cohere 企业 AI API
      "+.replit.com",        // Replit AI 编程平台
      "+.jasper.ai",         // Jasper AI 写作
      "+.gamma.app"          // Gamma AI 演示文稿
    ],
    ai_coding: [
      "+.codeium.com",       // Windsurf AI IDE
      "+.windsurf.com",
      "+.v0.dev",            // Vercel AI UI builder
      "+.bolt.new",          // StackBlitz AI 编程
      "+.lovable.dev"        // Lovable AI 应用构建
    ]
  },
  // AI 会话共享的第三方集成（反作弊、鉴权、支付、遥测）。
  // 这些请求的出口 IP 必须与 AI 主会话一致，否则会触发风控。
  integrations: {
    antibot: [
      "+.arkoselabs.com",  // ChatGPT 登录的 Arkose FunCaptcha（token 绑定客户端 IP）
      "+.funcaptcha.com",
      "+.recaptcha.net",   // reCAPTCHA 独立域，并不走 google.com
      "+.hcaptcha.com"     // hCaptcha（Discord / 部分 AI 注册）
    ],
    auth_providers: [
      "+.auth0.com",       // ChatGPT Team 等使用 Auth0
      "+.auth0cdn.com",
      "+.clerk.com",       // OpenRouter / 多家 AI 创业用 Clerk
      "+.clerk.dev",
      "+.clerk.accounts.dev",
      "+.okta.com"         // 企业 SSO（含 Anthropic Console 团队席位）
    ],
    payments: [
      "+.stripe.com",      // Claude Pro / ChatGPT Plus / Perplexity Pro 主要结算入口
      "+.stripe.network",
      "+.paypal.com",      // PayPal
      "+.paypalobjects.com", // PayPal CDN
      "+.paddle.com",      // Paddle（Apple 友好的订阅平台）
      "+.lemonsqueezy.com" // 独立 AI 应用常用
    ],
    customer_engagement: [
      "+.intercom.io",      // Intercom 客服（Anthropic / OpenAI 等使用）
      "+.intercomcdn.com",
      "+.launchdarkly.com", // LaunchDarkly feature flag
      "+.fullstory.com"     // FullStory 会话录制
    ],
    telemetry: [
      "+.statsig.com",     // Claude Code / Claude.ai / ChatGPT 的 feature flag
      "+.statsigapi.net",
      "+.featuregates.org",
      "+.featureassets.org",
      "+.sentry.io",       // Sentry 错误上报
      "+.sentry-cdn.com",
      "+.posthog.com",     // PostHog（Claude.ai 等）
      "+.segment.com",     // Segment / Twilio Segment
      "+.segment.io",
      "+.segmentapis.com",
      "+.mixpanel.com",
      "+.amplitude.com",
      "+.datadoghq.com",   // Datadog RUM 浏览器端
      "+.browser-intake-datadoghq.com"
    ]
  },
  force: {
    cloudflare: [
      "+.cloudflare.com"
    ]
  },
  apps: {
    ai: {
      apps: [
        "Claude",
        "ChatGPT",
        "Codex",
        "Perplexity",
        "Cursor",
        "Antigravity",
        "Antigravity IDE"
      ],
      helperSuffixes: [
        "Helper"
      ],
      exact: [
        "ChatGPTHelper",
        "Claude.exe",
        "Claude Helper (Renderer)",
        "Claude Helper (GPU)",
        "Claude Helper (Plugin)",
        "Codex.exe",
        "Codex Helper (Renderer)",
        "Codex Helper (GPU)",
        "Codex Helper (Plugin)",
        "Antigravity.exe",
        "Antigravity Helper (Renderer)",
        "Antigravity Helper (GPU)",
        "Antigravity Helper (Plugin)",
        "Antigravity IDE.exe",
        "Antigravity IDE Helper (Renderer)",
        "Antigravity IDE Helper (GPU)",
        "Antigravity IDE Helper (Plugin)",
        "language_server",
        "language_server.exe",
        "language_server_macos_arm",
        "language_server_macos_x64",
        "language_server_linux_x64",
        "language_server_windows_x64.exe",
        "antigravity_tools",
        // macOS PROCESS-NAME 匹配 Bundle 可执行名，不含 `.app` 后缀；Electron 进程名太宽，不列入。
        // Claude Code / URL Handler 都以 `claude` 运行，统一通过 ai.cli 命中。
        "Quotio"
      ],
      cli: [
        "claude",
        "claude.exe",
        "gemini",
        "codex",
        "codex.exe",
        "codex-aarch64-apple-darwin",
        "codex-x86_64-apple-darwin",
        "codex-aarch64-unknown-linux-musl",
        "codex-x86_64-unknown-linux-musl",
        "agy",
        "agy.exe",
        "antigravity"
      ]
    },
    browser: {
      apps: [
        "Dia",
        "Atlas",
        "SunBrowser"
      ],
      helperSuffixes: [
        "Helper",
        "Helper (Renderer)",
        "Helper (GPU)",
        "Helper (Plugin)",
        "Helper (Alerts)"
      ]
    }
  }
};

// ---------- Global Default · 域外默认代理 ----------
var CDN = {
  doh: {
    core: [
      "+.dns.google",
      "+.cloudflare-dns.com",
      "+.quad9.net"
    ]
  },
  cloud: {
    cloudflare: [
      "+.cdn.cloudflare.net",
      "+.workers.dev",
      "+.pages.dev"
    ],
    aws: [
      "+.amazonaws.com",
      "+.amazon.com",
      "+.awsstatic.com",
      "+.cloudfront.net"
    ],
    fastly: [
      "+.fastly.com",
      "+.fastly.net",
      "+.fastlylb.net"
    ],
    akamai: [
      "+.akamai.net",
      "+.akamaiedge.net",
      "+.akamaihd.net",
      "+.akamaized.net",
      "+.edgekey.net",
      "+.edgesuite.net"
    ],
    azure_cdn: [
      "+.azureedge.net",
      "+.azurefd.net"
    ],
    jsdelivr: [
      "+.jsdelivr.net"
    ],
    bunny: [
      "+.bunnycdn.com",
      "+.b-cdn.net"        // BunnyCDN 客户加速域
    ],
    cloudinary: [
      "+.cloudinary.com"   // 图片 / 视频 SaaS CDN
    ]
  }
};

// ---------- Media（独立地区组，不走家宽出口） ----------
// 分四类：视频流媒体 / 音乐流媒体 / 社交 / 即时通讯。
// 这一桶里的所有域名都路由到媒体分区面板，与家宽出口解耦，
// 也借此跨越对这些站点不友好的网络环境（GFW、地区封锁等）。
var MEDIA = {
  // 按 UI 面板分为 video, music, social, im 四个路由分桶
  video: {
  // ---- 视频流媒体 ----
  youtube: [
    "+.youtube.com",
    "+.googlevideo.com",
    "+.ytimg.com",
    "+.youtube-nocookie.com",
    "+.yt.be"
  ],
  netflix: [
    "+.netflix.com",
    "+.netflix.net",
    "+.nflxvideo.net",
    "+.nflxso.net",
    "+.nflximg.net",
    "+.nflximg.com",
    "+.nflxext.com"
  ],
  disney_plus: [
    "+.disneyplus.com",
    "+.disney-plus.net",
    "+.dssott.com",   // Disney+ 流媒体 CDN
    "+.bamgrid.com"   // BAMTech（Disney 流媒体后端）
  ],
  hbo_max: [
    "+.max.com",
    "+.hbomax.com",
    "+.hbomaxcdn.com",
    "+.hbonow.com",
    "+.maxgo.com"
  ],
  peacock: [
    "+.peacocktv.com"      // NBCUniversal Peacock
  ],
  paramount_plus: [
    "+.paramountplus.com",
    "+.cbsivideo.com",     // 旧 CBS All Access 残留 CDN
    "+.paramount.com"
  ],
  crunchyroll: [
    "+.crunchyroll.com",   // 动漫流媒体
    "+.cr-bundles.com"
  ],
  vimeo: [
    "+.vimeo.com",
    "+.vimeocdn.com"
  ],
  dailymotion: [
    "+.dailymotion.com",
    "+.dmcdn.net"
  ],
  hulu: [
    "+.hulu.com",
    "+.hulustream.com",
    "+.huluim.com"
  ],
  prime_video: [
    "+.primevideo.com",
    "+.aiv-cdn.net",     // Prime Video CDN（不会牵连 amazon.com 主站 and AWS）
    "+.aiv-delivery.net"
  ],
  twitch: [
    "+.twitch.tv",
    "+.ttvnw.net",
    "+.jtvnw.net"
  ]
  },
  music: {
  // ---- 音乐流媒体 ----
  spotify: [
    "+.spotify.com",
    "+.scdn.co",         // Spotify 静态资源
    "+.spotifycdn.com"
  ],
  soundcloud: [
    "+.soundcloud.com",
    "+.sndcdn.com"       // SoundCloud CDN
  ],
  bandcamp: [
    "+.bandcamp.com"
  ]
  },
  social: {
  // ---- 社交 ----
  twitter: [
    "+.twitter.com",
    "+.x.com",
    "+.twimg.com",
    "+.t.co"
  ],
  meta: [
    "+.facebook.com",
    "+.fbcdn.net",
    "+.fb.com",
    "+.facebook.net",
    "+.instagram.com",
    "+.cdninstagram.com",
    "+.threads.net"      // Meta 旗下 Threads
  ],
  reddit: [
    "+.reddit.com",
    "+.redditmedia.com",
    "+.redditstatic.com"
  ],
  tiktok: [              // TikTok 海外版（与抖音 douyin.com 无关，不会触发境内分流）
    "+.tiktok.com",
    "+.tiktokcdn.com",
    "+.tiktokv.com",
    "+.ibyteimg.com"
  ],
  snapchat: [
    "+.snapchat.com",
    "+.snap.com",
    "+.sc-cdn.net"
  ],
  pinterest: [
    "+.pinterest.com",
    "+.pinimg.com"
  ],
  bluesky: [
    "+.bsky.app",
    "+.bsky.social"
  ],
  tumblr: [
    "+.tumblr.com",
    "+.tumblr.media"
  ],
  long_form_writing: [
    "+.medium.com",
    "+.substack.com",
    "+.patreon.com"
  ],
  niche_communities: [
    "+.goodreads.com",     // 读书
    "+.letterboxd.com"     // 电影日记
  ],
  linkedin: [
    "+.linkedin.com",      // LinkedIn 职业社交
    "+.licdn.com"          // LinkedIn CDN
  ]
  },
  im: {
  // ---- 即时通讯 ----
  telegram: [
    "+.telegram.org",
    "+.t.me",
    "+.telegra.ph",
    "+.telesco.pe"
  ],
  discord: [
    "+.discord.com",
    "+.discord.gg",
    "+.discordapp.com",
    "+.discordapp.net",
    "+.discord.media"
  ],
  line: [                // LINE（日 / 韩 / 台主流 IM）
    "+.line.me",
    "+.line-apps.com",
    "+.line-scdn.net",
    "+.line-cdn.net"
  ],
  whatsapp: [            // WhatsApp（Meta 旗下，但放 IM 桶更直观）
    "+.whatsapp.com",
    "+.whatsapp.net"
  ],
  signal: [
    "+.signal.org"
  ],
  slack: [
    "+.slack.com",       // Slack 企业即时通讯
    "+.slack-edge.com",
    "+.slack-imgs.com"
  ],
  zoom: [
    "+.zoom.us",         // Zoom 视频会议
    "+.zoomgov.com"
  ]
  }
};

// ---------- CN Direct · 境内直连 ----------
var CN = {
  ai: {
    tongyi: [
      "+.tongyi.aliyun.com",
      "+.qianwen.aliyun.com",
      "+.dashscope.aliyuncs.com"
    ],
    modelscope: [ 
      "+.modelscope.cn"
    ],
    moonshot: [
      "+.moonshot.cn"
    ],
    zhipu: [
      "+.chatglm.cn",
      "+.zhipuai.cn",
      "+.bigmodel.cn"
    ],
    siliconflow: [
      "+.siliconflow.cn"
    ],
    deepseek: [
      "+.deepseek.com"      // api / platform / chat 全部子域
    ],
    doubao: [
      "+.doubao.com",       // 字节豆包
      "+.volcengineapi.com" // 火山方舟（豆包模型 API）
    ],
    minimax: [
      "+.minimaxi.com",     // MiniMax 域内域名
      "+.hailuoai.com"      // 海螺 AI
    ],
    baichuan: [
      "+.baichuan-ai.com"
    ],
    stepfun: [
      "+.stepfun.com"       // 阶跃星辰
    ]
  },
  office: {
    tencent_messaging_and_collab: [
      "+.qq.com",
      "+.qqmail.com",
      "+.exmail.qq.com",
      "+.weixin.qq.com",
      "+.work.weixin.qq.com",
      "+.docs.qq.com",
      "+.meeting.tencent.com"
    ],
    alibaba_productivity: [
      "+.dingtalk.com",
      "+.dingtalkapps.com",
      "+.aliyundrive.com",
      "+.quark.cn",
      "+.teambition.com"
    ],
    bytedance_productivity: [
      "+.feishu.cn",
      "+.feishu.net",
      "+.feishucdn.com",
      "+.larksuite.com",
      "+.larkoffice.com"
    ],
    wps_productivity: [
      "+.wps.cn",
      "+.wps.com",
      "+.kdocs.cn",
      "+.kdocs.com"
    ]
  },
  cloud: {
    alibaba_cloud: [
      "+.aliyun.com",
      "+.aliyuncs.com",
      "+.alibabacloud.com"
    ],
    tencent_cloud: [
      "+.tencentcloud.com",
      "+.cloud.tencent.com",
      "+.qcloud.com"
    ],
    bytedance_cloud: [
      "+.volcengine.com",
      "+.volces.com"
    ],
    huawei_cloud: [
      "+.myhuaweicloud.com",
      "+.huaweicloud.com",
      "+.huaweicloud.cn"
    ],
    baidu_cloud_and_cdn: [
      "+.baidubce.com",
      "+.bcebos.com",
      "+.bdstatic.com"
    ],
    jd_cloud: [
      "+.jdcloud.com",
      "+.jcloudcs.com"
    ],
    qiniu_cdn: [
      "+.qiniu.com",
      "+.qbox.me",
      "+.qiniucdn.com"
    ],
    upyun: [
      "+.upyun.com",
      "+.upaiyun.com"
    ],
    wangsu_cdn: [
      "+.wangsu.com",
      "+.wscdns.com",
      "+.wscloudcdn.com"
    ],
    ctyun: [
      "+.ctyun.cn"
    ],
    ksyun: [
      "+.ksyun.com"
    ]
  },
  // 域内消费类高频站点；放 DIRECT 既走最近 CN CDN，也避免占用代理带宽。
  consumer: {
    baidu: [
      "+.baidu.com",         // 搜索 / 网盘 / 地图统一入口
      "+.bdimg.com"          // 百度图片站静态资源
    ],
    bilibili: [
      "+.bilibili.com",
      "+.hdslb.com",         // B 站全站静态 / 图片 CDN
      "+.biliapi.net",
      "+.biliapi.com",
      "+.bilivideo.com",     // 视频流分发
      "+.bilicdn1.com",
      "+.biligame.com"
    ],
    weibo_and_sina: [
      "+.weibo.com",
      "+.weibo.cn",
      "+.weibocdn.com",
      "+.sinaimg.cn",        // Weibo 图片 / 视频 CDN
      "+.sina.com.cn"
    ],
    zhihu: [
      "+.zhihu.com",
      "+.zhimg.com"          // 知乎静态资源
    ],
    xiaohongshu: [
      "+.xiaohongshu.com",
      "+.xhscdn.com"
    ],
    douyin_and_kuaishou: [
      "+.douyin.com",        // 抖音（与海外 TikTok 不冲突）
      "+.douyinpic.com",
      "+.douyincdn.com",
      "+.kuaishou.com",
      "+.gifshow.com",       // 快手早期域 / 静态资源
      "+.yximgs.com"         // 快手图片 CDN
    ],
    netease: [
      "+.163.com",           // 含网易邮箱 / 网易云音乐 / 新闻
      "+.126.com",
      "+.netease.com"
    ],
    video_streaming: [
      "+.iqiyi.com",
      "+.iqiyipic.com",
      "+.youku.com",
      "+.mgtv.com",
      "+.sohu.com"
    ],
    e_commerce: [
      "+.taobao.com",
      "+.tbcdn.cn",
      "+.taobaocdn.com",
      "+.tmall.com",
      "+.jd.com",
      "+.360buyimg.com",     // 京东图片 CDN
      "+.pinduoduo.com",
      "+.yangkeduo.com"      // 拼多多前端域
    ],
    local_services: [
      "+.meituan.com",
      "+.meituan.net",
      "+.dianping.com"
    ],
    gaming: [
      "+.mihoyo.com"         // 米哈游国服（原神 / 星穹铁道）；hoyoverse.com 走默认
    ]
  }
};

// ---------- Local Direct · 本地与推送直连 ----------
var LOCAL = {
  local_and_push: [
    "+.push.apple.com",
    "+.lan",
    "+.local",
    "+.localhost",
    "+.home.arpa"          // RFC 8375 家庭网络保留域
  ]
};

// ---------- Overseas Direct · 域外 DoH + 直连 ----------
var OVERSEAS = {
  special: {
    apple: {
      core: [
        "+.apple.com",
        "+.icloud.com"
      ],
      content: [
        "+.icloud-content.com",
        "+.mzstatic.com",
        "+.cdn-apple.com",
        "+.aaplimg.com"
      ],
      services: ["+.apple-cloudkit.com"]
    },
    egressCheck: {
      core: [
        "+.ping0.cc",
        "+.ipinfo.io",
        "+.ifconfig.me",     // 常用 curl 出口检测
        "+.ip.sb"            // NextDNS 提供的快速出口查询
      ]
    }
  },
  global: {
    // 域内应用，但使用域外 DoH 解析以避免域内 DNS 返回错误结果。
    cnApps: {
      immersive_translate: [
        "+.immersivetranslate.com"
      ],
      mineru: [
        "+.mineru.org.cn",
        "+.openxlab.org.cn"
      ]
    },
    apps: {
      tailscale: [
        "+.tailscale.com",
        "+.tailscale.io",
        "+.ts.net"
      ],
      zerotier: [
        "+.zerotier.com"     // ZeroTier P2P，定位与 Tailscale 类似
      ],
      plex: [
        "+.plex.tv",
        "+.plex.direct"      // Plex 客户端直连家用服务器走 plex.direct 通配子域
      ],
      synology: [
        "+.synology.com",
        "+.quickconnect.to"  // Synology QuickConnect 中继
      ],
      typeless: [
        "+.typeless.com"
      ],
      clash_vpn: [
        "+.51feitu.com",
        "+.lovetutujiejie.com"
      ]
    }
  }
};

// ---------- DNS Only · 仅解析例外 ----------
// 这些域名只进入 nameserver-policy / fallback-filter，不生成分流规则。
// 用于修正 geosite 大类未覆盖或解析质量异常的个别站点。
var DNS_ONLY = {
  domestic: {
    cn_registry_and_public: [
      "+.cnnic.cn",
      "+.12306.cn"
    ]
  },
  overseas: {
    internet_standards: [
      "+.iana.org",
      "+.ietf.org"
    ]
  }
};

// ---------- Network Direct · 网络地址直连 ----------
// 私有 / 链路本地 / CGNAT / Tailscale ULA 都走 DIRECT，避免被无意中走代理。
var NETWORK = {
  direct: [
    // RFC 1918 私有网络
    { type: "IP-CIDR", value: "10.0.0.0/8", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR", value: "172.16.0.0/12", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR", value: "192.168.0.0/16", target: BASE.ruleTargets.direct },
    // 链路本地
    { type: "IP-CIDR", value: "169.254.0.0/16", target: BASE.ruleTargets.direct },
    // CGNAT (RFC 6598) + Tailscale magic IP
    { type: "IP-CIDR", value: "100.64.0.0/10", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR", value: "100.100.100.100/32", target: BASE.ruleTargets.direct },
    // IPv6 ULA + 链路本地 + Tailscale ULA
    { type: "IP-CIDR6", value: "fc00::/7", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fe80::/10", target: BASE.ruleTargets.direct },
    { type: "IP-CIDR6", value: "fd7a:115c:a1e0::/48", target: BASE.ruleTargets.direct }
  ]
};

// 端到端样本：声明"这些域名 / 进程必须落到这个出口"。
//   - 加载期 assertExpectedRoutesCoverage：样本必须能在域名模式中匹配。
//   - 运行期 validateManagedRouting：每条样本规则的 target 必须正确。
//   - tests/validate.js：直接读 sandbox.EXPECTED_ROUTES 当端到端期望。
// 字段：
//   domains       裸域名（DOMAIN-SUFFIX 命中）
//   processNames  受管桌面 App 进程名
//   cliNames      AI CLI 可执行名（固定走家宽出口面板）
var EXPECTED_ROUTES = {
  toResidential: {
    domains: [
      "claude.ai",
      "chatgpt.com",
      "chat.com",
      "openaiapi-site.azureedge.net",
      "chatgpt.livekit.cloud",
      "challenges.cloudflare.com",
      "gemini.google.com",
      "aiplatform.googleapis.com",
      "antigravity.google",
      "cloudcode-pa.googleapis.com",
      "daily-cloudcode-pa.googleapis.com",
      "daily-cloudcode-pa.sandbox.googleapis.com",
      "perplexity.ai",
      "google.com",
      "cursor.sh",             // Cursor 后端
      "arkoselabs.com",        // Arkose 登录反机器人（integrations.antibot）
      "stripe.com",            // AI 订阅支付（integrations.payments）
      "statsig.com",           // feature flag（integrations.telemetry）
      "githubusercontent.com", // GitHub 原始内容，GFW 下易污染
      "npmjs.org",             // npm 官方 registry
      "poe.com",               // Quora Poe AI 平台
      "grammarly.com",         // Grammarly AI 写作
      "deepl.com",             // DeepL AI 翻译
      "notion.so",             // Notion 协作知识库
      "intercom.io"            // Intercom 客服（Anthropic 等使用）
    ],
    processNames: ["Claude", "Claude.exe", "Codex", "Codex.exe", "Antigravity", "Antigravity IDE", "language_server"],
    cliNames: ["claude", "claude.exe", "codex", "codex.exe", "codex-aarch64-apple-darwin", "agy"]
  },
  toMedia: {
    domains: [
      "youtube.com",     // 视频流媒体
      "x.com",           // 社交
      "twitch.tv",       // 直播
      "spotify.com",     // 音乐
      "line.me",         // IM
      "whatsapp.com",    // IM
      "slack.com",       // IM（企业即时通讯）
      "linkedin.com",    // 社交（职业社交）
      "zoom.us"          // IM（视频会议）
    ]
  }
};

// ---------------------------------------------------------------------------
// 3c. 模块内工具函数
// ---------------------------------------------------------------------------

// 合并多组字符串列表并保持稳定去重。
function mergeStringGroups(groups) {
  var mergedValues = [];
  for (var i = 0; i < groups.length; i++) {
    mergedValues.push.apply(mergedValues, groups[i]);
  }
  return uniqueStrings(mergedValues);
}

// 为应用展开主进程、显式 helper，以及精确进程名。
function expandProcessNamesWithHelpers(appNames, helperSuffixes, exactProcessNames) {
  var processNames = [];
  var i;
  var j;
  var exactNames = exactProcessNames || [];

  for (i = 0; i < appNames.length; i++) {
    processNames.push(appNames[i]);
    for (j = 0; j < helperSuffixes.length; j++) {
      processNames.push(appNames[i] + " " + helperSuffixes[j]);
    }
  }

  processNames.push.apply(processNames, exactNames);
  return uniqueStrings(processNames);
}

// 从字符串数组中排除另一组字符串，保留原顺序。
function excludeStrings(values, excludedValues) {
  var filteredValues = [];
  var excludedLookup = buildStringLookup(excludedValues);
  for (var i = 0; i < values.length; i++) {
    if (excludedLookup[values[i]]) continue;
    filteredValues.push(values[i]);
  }
  return uniqueStrings(filteredValues);
}

// 约束：`+.` 前缀 + 一或多个标签（字母/数字/连字符，不以 `-` 起止），标签间用单个 `.` 分隔，
// 禁止 `*`、连续点、首尾点等通配或畸形写法。单标签（如 +.lan）允许。
var PATTERN_SHAPE = /^\+\.[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

// 断言所有模式符合 `+.domain` 形状，拦截漏写前缀或通配符滥用。
function assertPatternsHavePlusPrefix(patterns) {
  for (var i = 0; i < patterns.length; i++) {
    if (!PATTERN_SHAPE.test(patterns[i])) {
      throw createUserError("pattern 形状非法（应为 +.domain）: " + patterns[i]);
    }
  }
}

// ES5 安全的 `endsWith`：判断 str 是否以 suffix 结尾。
function endsWithString(str, suffix) {
  if (suffix.length > str.length) return false;
  return str.lastIndexOf(suffix) === str.length - suffix.length;
}

// 把按类别分组的域名模式对象展平成单个数组并去重。
function flattenGroupedPatterns(groupedPatterns) {
  var flattenedPatterns = [];
  Object.keys(groupedPatterns).forEach(function (groupName) {
    flattenedPatterns.push.apply(flattenedPatterns, groupedPatterns[groupName]);
  });
  return uniqueStrings(flattenedPatterns);
}
// ---------------------------------------------------------------------------
// 3d. 策略表（POLICY）与派生分类
// ---------------------------------------------------------------------------

// POLICY — 所有域名模式的单一权威来源。
// 每条 entry 声明 route / dnsZone / sniffer / fakeIpBypass。
// 下游 DNS、Sniffer、规则、断言都从 POLICY 投影。
//
// 字段：
//   key            标识（调试用）
//   patterns       `+.domain` 模式数组
//   route          "residential.*" | "media.*" | "direct" | "proxy"，省略 = 不生成规则
//   dnsZone        "overseas" | "domestic"，省略 = 不进 nameserver-policy
//   sniffer        "force" | "skip"，省略 = 不参与 sniffer
//   fakeIpBypass   true = 进入 fake-ip-filter
//
// fallback-filter 只使用 geoip + gfw geosite 兜底，不逐条 domain 列表，
// 因为 nameserver-policy 已将高价值域名显式绑定 DoH。
//
// 冲突解决：direct 优先于 residential/media（派生时 excludeStrings）。
function buildPolicy() {
  return [
    // ---- residential · 走家宽出口 ----
    {
      key: "residential.support", patterns: flattenGroupedPatterns(RESIDENTIAL_EXIT.support),
      route: "residential.support", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "residential.ai", patterns: flattenGroupedPatterns(RESIDENTIAL_EXIT.ai),
      route: "residential.ai", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "residential.integrations", patterns: flattenGroupedPatterns(RESIDENTIAL_EXIT.integrations),
      route: "residential.integrations", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "residential.cloudflare", patterns: flattenGroupedPatterns(RESIDENTIAL_EXIT.force),
      route: "residential.cloudflare", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },

    // ---- media · 走媒体独立选区 ----
    {
      key: "media.video", patterns: flattenGroupedPatterns(MEDIA.video),
      route: "media.video", dnsZone: "overseas", fallbackFilter: true
    },
    {
      key: "media.music", patterns: flattenGroupedPatterns(MEDIA.music),
      route: "media.music", dnsZone: "overseas", fallbackFilter: true
    },
    {
      key: "media.social", patterns: flattenGroupedPatterns(MEDIA.social),
      route: "media.social", dnsZone: "overseas", fallbackFilter: true
    },
    {
      key: "media.im", patterns: flattenGroupedPatterns(MEDIA.im),
      route: "media.im", dnsZone: "overseas", fallbackFilter: true
    },

    // ---- proxy · DoH 端点走通用代理寻址 ----
    {
      key: "default.doh", patterns: flattenGroupedPatterns(CDN.doh),
      route: "proxy", dnsZone: "overseas", fallbackFilter: true
    },
    // ---- residential · CDN 基础设施走家宽出口 ----
    {
      key: "residential.cdn", patterns: flattenGroupedPatterns(CDN.cloud),
      route: "residential.cdn", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "dnsOnly.domestic", patterns: flattenGroupedPatterns(DNS_ONLY.domestic),
      dnsZone: "domestic"
    },
    {
      key: "dnsOnly.overseas", patterns: flattenGroupedPatterns(DNS_ONLY.overseas),
      dnsZone: "overseas", fallbackFilter: true
    },

    // ---- direct · 直连 ----
    // Apple/iCloud 绑定 domestic DoH：国内有 Apple CDN，域内 DoH 直返 CN 节点，直连最快；
    // 不经 overseas fallback，避免节点断连时 DNS 卡在等 overseas DoH（Apple 流量本就走 DIRECT）。
    {
      key: "direct.apple", patterns: flattenGroupedPatterns(OVERSEAS.special.apple),
      route: "direct", dnsZone: "domestic", fakeIpBypass: true, fallbackFilter: true
    },
    // 出口检测站 DIRECT 展示本机真实 IP；未被墙，domestic DoH 足够且不依赖代理。
    {
      key: "direct.egressCheck", patterns: flattenGroupedPatterns(OVERSEAS.special.egressCheck),
      route: "direct", dnsZone: "domestic", fallbackFilter: true
    },
    // Tailscale/ZeroTier/Plex/Synology 等直连应用未被墙，domestic DoH 返回真实 IP 即可，
    // 不走 overseas DoH，避免节点断连时解析卡死。
    {
      key: "direct.overseasApps", patterns: flattenGroupedPatterns(OVERSEAS.global.apps),
      route: "direct", dnsZone: "domestic", sniffer: "skip", fallbackFilter: true
    },
    {
      key: "direct.cnAppsOverseasDoh", patterns: flattenGroupedPatterns(OVERSEAS.global.cnApps),
      route: "direct", dnsZone: "overseas", sniffer: "skip", fallbackFilter: true
    },
    {
      key: "direct.cn.ai", patterns: flattenGroupedPatterns(CN.ai),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.cn.office", patterns: flattenGroupedPatterns(CN.office),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.cn.cloud", patterns: flattenGroupedPatterns(CN.cloud),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.cn.consumer", patterns: flattenGroupedPatterns(CN.consumer),
      route: "direct", dnsZone: "domestic"
    },
    {
      key: "direct.localAndPush", patterns: flattenGroupedPatterns(LOCAL),
      route: "direct", dnsZone: "domestic", sniffer: "skip"
    }
  ];
}

var POLICY = buildPolicy();

// 加载期断言：每条 POLICY 条目的 patterns 都符合 `+.domain` 形状。
(function () {
  for (var i = 0; i < POLICY.length; i++) {
    assertPatternsHavePlusPrefix(POLICY[i].patterns);
  }
})();

// 投影工具：对每条 POLICY 跑断言函数，把命中的 patterns 合并去重返回。
function projectPolicyPatterns(predicate) {
  var result = [];
  for (var i = 0; i < POLICY.length; i++) {
    if (predicate(POLICY[i])) result.push.apply(result, POLICY[i].patterns);
  }
  return uniqueStrings(result);
}

// POLICY 谓词工厂。
function matchRoute(route) {
  return function (entry) { return entry.route === route; };
}
function matchSniffer(mode) {
  return function (entry) { return entry.sniffer === mode; };
}
function matchFakeIpBypass(entry) { return entry.fakeIpBypass === true; }

// 按 route 投影并应用 direct 优先级。
function projectRoutedPatterns(route, directPatterns) {
  return excludeStrings(projectPolicyPatterns(matchRoute(route)), directPatterns);
}

// 从 POLICY 投影出下游真正消费的三类域名集合：
//   residential → 进家宽出口（排除被 direct 抢占的模式）
//   media    → 媒体地区组
//   direct   → 全量 DIRECT 模式，用于生成直连规则与 fake-ip/sniffer 判断
//   proxy    → 进通用代理组（用于强制 DoH 服务器等前跳代理寻址）
//   sniffer  → force / skip 两侧的嗅探决策
//   fakeIpBypass → 需要返回真实 IP 的域名（Apple 等）

// 家宽出口 route 顺序与桶分组。support 桶合并 residential.cdn，integrations 桶合并
// residential.cloudflare —— 把这条隐藏的合并规则显式写成数据（决定 cdn/cloudflare 落到哪个 UI 面板）。
var RESIDENTIAL_ROUTES = [
  "residential.ai",
  "residential.support",
  "residential.integrations",
  "residential.cloudflare",
  "residential.cdn"
];
var RESIDENTIAL_ROUTE_GROUPS = {
  ai: ["residential.ai"],
  support: ["residential.support", "residential.cdn"],
  integrations: ["residential.integrations", "residential.cloudflare"]
};
var MEDIA_ROUTE_GROUPS = {
  video: ["media.video"],
  music: ["media.music"],
  social: ["media.social"],
  im: ["media.im"]
};

// 按 routeGroups 把每条 route 投影（排除 direct）后合并成桶；
// allRoutes 指定 .all 汇总顺序——桶内合并会重排，.all 需按原始 route 序保持稳定。
function buildRouteGrouped(routeGroups, directPatterns, allRoutes) {
  var grouped = {};
  Object.keys(routeGroups).forEach(function (bucketKey) {
    var routes = routeGroups[bucketKey];
    var bucketPatterns = [];
    for (var i = 0; i < routes.length; i++) {
      bucketPatterns.push(projectRoutedPatterns(routes[i], directPatterns));
    }
    grouped[bucketKey] = mergeStringGroups(bucketPatterns);
  });
  var allOrdered = allRoutes;
  if (!allOrdered) {
    allOrdered = [];
    Object.keys(routeGroups).forEach(function (bucketKey) {
      var routes = routeGroups[bucketKey];
      for (var m = 0; m < routes.length; m++) allOrdered.push(routes[m]);
    });
  }
  var allPatterns = [];
  for (var j = 0; j < allOrdered.length; j++) {
    allPatterns.push(projectRoutedPatterns(allOrdered[j], directPatterns));
  }
  grouped.all = mergeStringGroups(allPatterns);
  return grouped;
}

function buildDerivedPatterns() {
  var direct = projectPolicyPatterns(matchRoute("direct"));
  var proxy = projectRoutedPatterns("proxy", direct);
  var residential = buildRouteGrouped(RESIDENTIAL_ROUTE_GROUPS, direct, RESIDENTIAL_ROUTES);
  var media = buildRouteGrouped(MEDIA_ROUTE_GROUPS, direct);

  return {
    proxy: proxy,
    residential: residential,
    media: media,
    direct: direct,
    fakeIpBypass: projectPolicyPatterns(matchFakeIpBypass),
    // Sniffer 是 fake-ip 模式的安全网：当 fake-IP 映射丢失或 QUIC 跳过 DNS 时，
    // 从 TLS SNI / HTTP Host 恢复域名，确保 AI 流量命中家宽出口规则而非漏到 MATCH。
    //   force → 家宽出口域名 + 所有 sniffer:"force" 条目（Cloudflare 等）
    //   skip  → Tailscale / Plex / Apple 推送等故意用 IP 语义的直连应用
    sniffer: {
      force: residential.all,
      skip: projectPolicyPatterns(matchSniffer("skip"))
    }
  };
}

// 从 RESIDENTIAL_EXIT.apps 展开出三类进程入口：
//   aiApps  → 受管 AI 桌面 App + 显式 helper（始终走家宽出口面板）
//   aiCli   → AI 命令行（始终走家宽出口面板）
//   browser → AI 浏览器 + 全部 helper（并入 AI 高敏阵列）
function buildDerivedProcessNames() {
  return {
    aiApps: expandProcessNamesWithHelpers(
      RESIDENTIAL_EXIT.apps.ai.apps,
      RESIDENTIAL_EXIT.apps.ai.helperSuffixes,
      RESIDENTIAL_EXIT.apps.ai.exact
    ),
    aiCli: uniqueStrings(RESIDENTIAL_EXIT.apps.ai.cli.slice()),
    browser: expandProcessNamesWithHelpers(
      RESIDENTIAL_EXIT.apps.browser.apps,
      RESIDENTIAL_EXIT.apps.browser.helperSuffixes
    )
  };
}

// DERIVED 是后续执行函数唯一应直接消费的派生入口。
var DERIVED = {
  patterns: buildDerivedPatterns(),
  processNames: buildDerivedProcessNames(),
  networkRules: {
    direct: NETWORK.direct.slice()
  }
};

// 判断裸域是否被一组 `+.xxx` 模式覆盖（等值或作为子域）。
function isDomainCoveredBySuffixPatterns(domain, suffixPatterns) {
  for (var i = 0; i < suffixPatterns.length; i++) {
    var suffix = toSuffix(suffixPatterns[i]);
    if (domain === suffix) return true;
    if (endsWithString(domain, "." + suffix)) return true;
  }
  return false;
}

// 断言每个样本域名 / 进程都能在对应的 DERIVED 源集合中找到覆盖，防止样本与源头漂移。
function assertExpectedRoutesCoverage() {
  var i;
  var sample;

  for (i = 0; i < EXPECTED_ROUTES.toResidential.domains.length; i++) {
    sample = EXPECTED_ROUTES.toResidential.domains[i];
    if (!isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.residential.all)) {
      throw createUserError("toResidential 样本未被 residential 源覆盖: " + sample);
    }
  }

  for (i = 0; i < EXPECTED_ROUTES.toMedia.domains.length; i++) {
    sample = EXPECTED_ROUTES.toMedia.domains[i];
    if (!isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.media.all)) {
      throw createUserError("toMedia 样本未被 media 源覆盖: " + sample);
    }
  }

  var procLookup = buildStringLookup(
    DERIVED.processNames.aiApps.concat(DERIVED.processNames.aiCli)
  );
  var procSamples = EXPECTED_ROUTES.toResidential.processNames
    .concat(EXPECTED_ROUTES.toResidential.cliNames);
  for (i = 0; i < procSamples.length; i++) {
    if (!procLookup[procSamples[i]]) {
      throw createUserError("toResidential 样本进程未在 RESIDENTIAL_EXIT.apps 中: " + procSamples[i]);
    }
  }
}

assertExpectedRoutesCoverage();

// 把字符串数组映射为 { type, value } 规则目标列表。
// ---------------------------------------------------------------------------
// 3e. DNS / Sniffer 配置构建
// ---------------------------------------------------------------------------

// 从 POLICY 按 dnsZone 生成 nameserver-policy 映射。
function buildNameserverPolicy() {
  var dohByZone = { overseas: BASE.dns.overseas, domestic: BASE.dns.domestic };
  var policy = {};
  policy[BASE.dns.domesticGeosite] = dohByZone.domestic;
  policy[BASE.dns.overseasGeosite] = dohByZone.overseas;

  for (var i = 0; i < POLICY.length; i++) {
    var entry = POLICY[i];
    if (!entry.dnsZone) continue;
    var dohServers = dohByZone[entry.dnsZone];
    if (!dohServers) throw createUserError("nameserver-policy 未知 zone: " + entry.dnsZone);
    for (var j = 0; j < entry.patterns.length; j++) {
      policy[entry.patterns[j]] = dohServers;
    }
  }

  return policy;
}

// 构建 fake-ip-filter 白名单。
// `+.` 匹配域名及子域；中部通配（`time.*.com` 等）保留 glob 写法。
function buildDnsFakeIpFilter(derived) {
  return []
    .concat(FAKE_IP_BYPASS.localNetwork)
    .concat(FAKE_IP_BYPASS.timeSync)
    .concat(FAKE_IP_BYPASS.connectivityTest)
    .concat(derived.patterns.fakeIpBypass)
    .concat(FAKE_IP_BYPASS.gamingRealtime)
    .concat(FAKE_IP_BYPASS.stunRealtime)
    .concat(FAKE_IP_BYPASS.homeRouter);
}

// DNS fallback-filter 配置。
// nameserver-policy 已将高价值域名显式绑定 DoH，不需要 domain 列表重复。
// geoip + gfw 兜底处理未被显式覆盖的域名。
function buildDnsFallbackFilter() {
  return {
    geoip: true,
    "geoip-code": "CN",
    geosite: ["gfw"],
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"]
  };
}

// 构建不含动态列表项的基础 DNS 配置。
//
// respect-rules: true — 让 DNS 查询也走分流规则，而不是全部从本地直连发出。
// 效果：
//   家宽出口域名的 DoH 查询 → 经家宽出口面板出去 → dns.google 看到的是所选出口 IP
//   direct 域名的 DoH 查询 → 走 direct-nameserver（域内 DoH）→ 本地直连
//   media 域名的 DoH 查询 → 经 media 代理组出去
// 为什么需要：
//   respect-rules: false 时，所有 DoH 查询都从本地网络直连发出。
//   在 CN 出差时这意味着：
//     1. 域外 DoH（dns.google / cloudflare）被墙 → 查询超时
//     2. 即使部分可达，dns.google 也会看到"CN IP 在查 claude.ai"
//   虽然 fake-ip 模式让数据连接不依赖本地 DNS 结果（代理服务端自行解析），
//   但 DNS 查询本身仍是从本地发出的——respect-rules: true 堵住这个口。
// 引导依赖：
//   proxy-server-nameserver（域内 DoH）负责解析代理服务器本身的域名，
//   不走分流规则，打破循环依赖。
function buildDnsBaseConfig() {
  return {
    enable: true,
    listen: "0.0.0.0:1053",
    ipv6: true,
    "respect-rules": true,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    nameserver: BASE.dns.domestic,
    "proxy-server-nameserver": BASE.dns.domestic,
    "direct-nameserver": BASE.dns.domestic.slice(),
    "direct-nameserver-follow-policy": true,
    fallback: BASE.dns.fallback
  };
}

// 组装完整的 DNS 配置。
function buildDnsConfig(derived) {
  var dnsConfig = buildDnsBaseConfig();
  dnsConfig["fake-ip-filter"] = buildDnsFakeIpFilter(derived);
  dnsConfig["fallback-filter"] = buildDnsFallbackFilter();
  dnsConfig["nameserver-policy"] = buildNameserverPolicy();
  return dnsConfig;
}

// 构建 Sniffer 配置。
// TLS (443/8443) / HTTP (80/8080/8880) / QUIC (443) 三种协议均开启嗅探。
// force-domain：从 SNI/Host 恢复域名，防止 AI 流量因缺域名漏到 MATCH。
// skip-domain：保留 IP 语义，避免破坏 P2P 打洞和推送通道。
function buildSnifferConfig(derived) {
  return {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, 8080, 8880], "override-destination": true },
      QUIC: { ports: [443] }
    },
    "force-domain": derived.patterns.sniffer.force,
    "skip-domain": derived.patterns.sniffer.skip
  };
}

// ---------------------------------------------------------------------------
// 3f. 模块入口
// ---------------------------------------------------------------------------

function applyDnsAndSniffer(config) {
  config.dns = buildDnsConfig(DERIVED);
  config.sniffer = buildSnifferConfig(DERIVED);
  return config;
}

return {
  BASE: BASE,
  DERIVED: DERIVED,
  FAKE_IP_BYPASS: FAKE_IP_BYPASS,
  apply: applyDnsAndSniffer
};

})();

// ===========================================================================
// 4. 基础常量
// ===========================================================================

// 所有运行期稳定常量的单一来源：地区、节点名、组名后缀、DoH 服务器、规则前缀。
var BASE = {
  regions: {
    US: { regex: /🇺🇸|美国|United\s*States|^US(?:[|丨\-_ ]|\d)/i, label: "美国", flag: "🇺🇸" },
    JP: { regex: /🇯🇵|日本|Japan|^JP(?:[|丨\-_ ]|\d)/i, label: "日本", flag: "🇯🇵" },
    HK: { regex: /🇭🇰|香港|Hong\s*Kong|^HK(?:[|丨\-_ ]|\d)/i, label: "香港", flag: "🇭🇰" },
    SG: { regex: /🇸🇬|新加坡|Singapore|^SG(?:[|丨\-_ ]|\d)/i, label: "新加坡", flag: "🇸🇬" }
  },
  nodeNames: {
    transit: "家宽出口（官方中转）"
  },
  defaultProxyGroupKeywords: [
    "PROXY",
    "节点选择",
    "手动选择",
    "GLOBAL"
  ],
  ruleTargets: {
    direct: "DIRECT"
  },
  rulePrefixes: {
    match: "MATCH," // Clash 兜底规则固定前缀
  },
  urlTestProbeUrl: "http://www.gstatic.com/generate_204",
  residentialProxyNameKeyword: "家宽出口",
  groupNameSuffixes: {
    base: "节点组"
  },
  groupNamePrefixes: {
    base: "az.分区测速."
  },
  residentialGroupName: "az.核心出口.🏠 家宽出口",
  // Clash 支持的合法代理类型；buildResidentialProxy 会校验硬编码类型在此白名单内。
  validProxyTypes: ["http", "https", "socks5", "ss", "ssr", "vmess", "trojan", "vless", "hysteria", "tuic", "snell", "wireguard"]
};

// ===========================================================================
// 5. 代理出口与选区
// ===========================================================================

// 确保主配置里存在代理、代理组和规则三个容器。
function writeContainers(config) {
  if (!config.proxies) config.proxies = [];
  if (!config["proxy-groups"]) config["proxy-groups"] = [];
  if (!config.rules) config.rules = [];
}

// 把地区输入统一转成大写字符串键；非字符串或空串直接拒绝，便于尽早暴露配置错误。
function normalizeRegionKey(region) {
  if (typeof region !== "string" || region === "") {
    throw createUserError("region 必须是非空字符串，实际: " + region);
  }
  return region.toUpperCase();
}

function resolveRegionMeta(region) {
  var regionKey = normalizeRegionKey(region);
  var source = BASE.regions[regionKey];
  if (!source) return null;
  return { regex: source.regex, label: source.label, flag: source.flag, code: regionKey };
}

// 基于地区国旗与中文标签拼出代理组名称（如 分区测速.🇸🇬 新加坡节点组）。
function buildRegionGroupName(regionMeta, groupNameSuffix) {
  return BASE.groupNamePrefixes.base + regionMeta.flag + " " + regionMeta.label + groupNameSuffix;
}

// 根据凭证和端点信息生成一个家宽出口 HTTP 代理节点。
function buildResidentialProxy(residentialCredentials, proxyName, endpoint) {
  if (BASE.validProxyTypes.indexOf("http") < 0) {
    throw createUserError("家宽出口代理类型 http 不在 Clash 合法代理类型列表中，请检查 BASE.validProxyTypes");
  }
  return {
    name: proxyName,
    type: "http",
    server: endpoint.server,
    port: endpoint.port,
    username: residentialCredentials.username,
    password: residentialCredentials.password,
    udp: true
  };
}

// 在按 `name` 命名的数组项中查找条目下标；未命中返回 -1。
function findNamedItemIndex(items, targetName) {
  for (var i = 0; i < items.length; i++) {
    if (items[i].name === targetName) return i;
  }
  return -1;
}

// 在按 `name` 命名的数组项中查找单个条目，复用下标查找避免重复遍历。
function findNamedItem(items, targetName) {
  var index = findNamedItemIndex(items, targetName);
  return index >= 0 ? items[index] : null;
}

// 按名称更新或插入一个完整条目，避免沿用同名旧对象。
function upsertNamedItem(items, itemDefinition) {
  var itemIndex = findNamedItemIndex(items, itemDefinition.name);
  if (itemIndex >= 0) items[itemIndex] = itemDefinition;
  else items.push(itemDefinition);
  return itemDefinition;
}

// 按名称查找单个代理节点。
function findProxyByName(proxies, proxyName) {
  return findNamedItem(proxies, proxyName);
}

// 按名称查找单个代理组。
function findProxyGroupByName(proxyGroups, groupName) {
  return findNamedItem(proxyGroups, groupName);
}

// 判断代理组名是否包含默认代理核心词。
function defaultProxyGroupNameMatches(groupName, keyword) {
  if (typeof groupName !== "string" || typeof keyword !== "string") return false;
  return groupName.toUpperCase().indexOf(keyword.toUpperCase()) >= 0;
}

// 识别订阅默认代理组：先关键词匹配，失败时从 MATCH 规则提取。
function resolveDefaultProxyGroupName(config) {
  var proxyGroups = config["proxy-groups"] || [];
  for (var i = 0; i < BASE.defaultProxyGroupKeywords.length; i++) {
    for (var j = 0; j < proxyGroups.length; j++) {
      if (defaultProxyGroupNameMatches(proxyGroups[j].name, BASE.defaultProxyGroupKeywords[i])) {
        return proxyGroups[j].name;
      }
    }
  }
  return resolveDefaultGroupFromMatch(config);
}

// 从 MATCH 规则提取默认代理组名。
function resolveDefaultGroupFromMatch(config) {
  var rules = config.rules || [];
  for (var i = rules.length - 1; i >= 0; i--) {
    var line = rules[i];
    if (line.indexOf(BASE.rulePrefixes.match) === 0) {
      var commaIndex = line.indexOf(",");
      if (commaIndex >= 0) {
        var targetName = line.substring(commaIndex + 1);
        if (findProxyGroupByName(config["proxy-groups"], targetName)) {
          return targetName;
        }
      }
    }
  }
  return null;
}

// 将管理组追加到订阅默认代理组的候选列表。
function writeManagedGroupIntoDefaultProxy(config, managedGroupName, defaultProxyGroupName) {
  if (!defaultProxyGroupName) return;
  var defaultProxyGroup = findProxyGroupByName(config["proxy-groups"], defaultProxyGroupName);
  if (!defaultProxyGroup || !defaultProxyGroup.proxies) return;
  var nextProxyNames = [].concat(defaultProxyGroup.proxies);
  nextProxyNames.push(managedGroupName);
  defaultProxyGroup.proxies = uniqueStrings(nextProxyNames);
}

// 判断给定名称是否在节点或代理组中存在。
function hasProxyOrGroup(config, targetName) {
  return !!(
    findProxyByName(config.proxies || [], targetName) ||
    findProxyGroupByName(config["proxy-groups"] || [], targetName)
  );
}

// 收集匹配地区特征且非家宽出口的节点名称列表。
function collectRegionNodeNames(proxies, regionRegex) {
  var regionNodeNames = [];
  for (var i = 0; i < proxies.length; i++) {
    var proxy = proxies[i];
    if (
      regionRegex.test(proxy.name) &&
      proxy.name.indexOf(BASE.residentialProxyNameKeyword) < 0
    ) {
      regionNodeNames.push(proxy.name);
    }
  }
  return regionNodeNames;
}

// 把地区节点列表包装成一个 `url-test` 代理组，并覆盖同名旧组。
function upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames) {
  upsertNamedItem(proxyGroups, {
    name: groupName,
    type: "url-test",
    proxies: regionNodeNames,
    url: BASE.urlTestProbeUrl,
    interval: 300,
    tolerance: 50
  });
}

// 注入家宽出口官方中转节点。
function writeResidentialProxies(config, residentialCredentials) {
  upsertNamedItem(
    config.proxies,
    buildResidentialProxy(residentialCredentials, BASE.nodeNames.transit, residentialCredentials.transit)
  );
}

// 仅根据订阅节点创建或修正指定地区的 `url-test` 代理组。
function writeRegionGroup(config, region, groupNameSuffix) {
  var regionMeta = resolveRegionMeta(region);
  if (!regionMeta) return null;

  var regionRegex = regionMeta.regex;
  var groupName = buildRegionGroupName(regionMeta, groupNameSuffix);
  var proxyGroups = config["proxy-groups"];

  var regionNodeNames = collectRegionNodeNames(config.proxies, regionRegex);
  if (regionNodeNames.length === 0) return null;

  upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames); // 用订阅地区节点创建或修正目标组

  return groupName;
}

// 创建家宽出口 select 组（仅保留家宽出口官方中转）。
function writeResidentialGroup(config) {
  var residentialGroupName = BASE.residentialGroupName;

  upsertNamedItem(config["proxy-groups"], {
    name: residentialGroupName,
    type: "select",
    proxies: [BASE.nodeNames.transit]
  });

  return residentialGroupName;
}

// UI 面板代理组名常量。
var UI_GROUPS = {
  ai: "az.严管调度.🤖 AI 高敏阵列",
  support: "az.严管调度.🛠️ 支撑平台",
  integrations: "az.严管调度.🛡️ 生态域集成",
  video: "az.其他调度.🎬 视频流媒体",
  music: "az.其他调度.🎵 音乐播客",
  social: "az.其他调度.🌐 社交长文",
  im: "az.其他调度.💬 即时通讯"
};

// 写入 UI 面板策略组。调度顺序：US → JP → SG → HK → 家宽出口。
function writeExpandedProxyGroups(config, residentialTarget, regionalTargets) {
  var proxyGroups = config["proxy-groups"];

  var dispatchChoices = [];
  if (regionalTargets.US) dispatchChoices.push(regionalTargets.US);
  var remainingRegions = ["JP", "SG", "HK"];
  for (var j = 0; j < remainingRegions.length; j++) {
    var target = regionalTargets[remainingRegions[j]];
    if (target) dispatchChoices.push(target);
  }
  dispatchChoices.push(residentialTarget);
  dispatchChoices = uniqueStrings(dispatchChoices);

  var subgroups = [
    { name: UI_GROUPS.ai, type: "select", proxies: dispatchChoices },
    { name: UI_GROUPS.support, type: "select", proxies: dispatchChoices },
    { name: UI_GROUPS.integrations, type: "select", proxies: dispatchChoices },
    { name: UI_GROUPS.video, type: "select", proxies: dispatchChoices },
    { name: UI_GROUPS.music, type: "select", proxies: dispatchChoices },
    { name: UI_GROUPS.social, type: "select", proxies: dispatchChoices },
    { name: UI_GROUPS.im, type: "select", proxies: dispatchChoices }
  ];
  for (var i = 0; i < subgroups.length; i++) {
    upsertNamedItem(proxyGroups, subgroups[i]);
  }
}

// 解析路由目标：创建家宽出口组、地区测速组、UI 面板组。
function resolveRoutingTargets(config) {
  var residentialGroupName = writeResidentialGroup(config);
  var defaultProxyGroupName = resolveDefaultProxyGroupName(config);

  // 将家宽出口组注入订阅默认代理组的候选列表
  writeManagedGroupIntoDefaultProxy(config, residentialGroupName, defaultProxyGroupName);

  var regionalTargets = {};
  // 为所有已定义地区生成标准 url-test 组
  var definedRegions = ["US", "JP", "HK", "SG"];
  for (var i = 0; i < definedRegions.length; i++) {
    var code = definedRegions[i];
    var standardGroup = writeRegionGroup(config, code, BASE.groupNameSuffixes.base);
    if (standardGroup) {
      writeManagedGroupIntoDefaultProxy(config, standardGroup, defaultProxyGroupName);
      regionalTargets[code] = standardGroup;
    }
  }

  // 注入 UI 面板分组
  writeExpandedProxyGroups(config, residentialGroupName, regionalTargets);

  // 清除订阅自带的代理组，只保留 az.* 管理组和默认代理组
  cleanupSubscriptionProxyGroups(config, defaultProxyGroupName);

  return {
    residentialGroupName: residentialGroupName,
    defaultProxyTarget: defaultProxyGroupName || residentialGroupName,
    strictAiTarget: residentialGroupName
  };
}

// 清除订阅自带的代理组（自动选择、故障转移、Bahamut 等），
// 只保留 az.* 管理组和订阅默认代理组作为 MATCH/DoH/GFW 出口。
function cleanupSubscriptionProxyGroups(config, defaultProxyGroupName) {
  var groups = config["proxy-groups"];
  var managedGroups = [];

  for (var i = 0; i < groups.length; i++) {
    var gName = groups[i].name;
    if (gName.indexOf("az.") === 0 || gName === defaultProxyGroupName) {
      managedGroups.push(groups[i]);
    }
  }

  // 清理默认组中指向已删除订阅组的引用
  if (defaultProxyGroupName) {
    for (var j = 0; j < managedGroups.length; j++) {
      if (managedGroups[j].name === defaultProxyGroupName && managedGroups[j].proxies) {
        var cleanProxies = [];
        var oldProxies = managedGroups[j].proxies;
        for (var k = 0; k < oldProxies.length; k++) {
          var pName = oldProxies[k];
          if (pName === "DIRECT" || pName === "REJECT" ||
              pName.indexOf("az.") === 0 ||
              findProxyByName(config.proxies, pName)) {
            cleanProxies.push(pName);
          }
        }
        managedGroups[j].proxies = cleanProxies;
        break;
      }
    }
  }

  config["proxy-groups"] = managedGroups;
}

// 写入分流规则。
function writeManagedRouting(config, routingTargets, derived) {
  writeManagedRules(config, routingTargets, derived);
}

// ===========================================================================
// 6. 规则注入
// ===========================================================================

// 提取规则的 `"TYPE,value"` 标识。
function getRuleIdentity(ruleLine) {
  var firstCommaIndex = ruleLine.indexOf(",");
  if (firstCommaIndex < 0) return null;

  var secondCommaIndex = ruleLine.indexOf(",", firstCommaIndex + 1);
  if (secondCommaIndex < 0) return null;

  return ruleLine.substring(0, secondCommaIndex);
}

// 按规则标识（TYPE,value）首次出现即保留，丢弃后续同标识行，解决跨段重复。
function dedupeRulesByIdentity(ruleLines) {
  var deduped = [];
  var seen = {};
  for (var i = 0; i < ruleLines.length; i++) {
    var identity = getRuleIdentity(ruleLines[i]);
    if (identity === null) {
      deduped.push(ruleLines[i]);
      continue;
    }
    if (seen[identity]) continue;
    seen[identity] = true;
    deduped.push(ruleLines[i]);
  }
  return deduped;
}

// 拼接所有管理规则。顺序即优先级：显式域名 → 媒体 → DoH → 直连 → CN → GFW → 进程 → MATCH。
function buildManagedRules(derived, routingTargets) {
  var concatenated = buildResidentialDomainRules(derived)
    .concat(buildMediaRules(derived))
    .concat(buildProxyRules(derived, routingTargets.defaultProxyTarget))
    .concat(buildDirectRules(derived))
    .concat(buildChinaFallbackRules())
    .concat(buildGfwProxyRule(routingTargets.defaultProxyTarget))
    .concat(buildStrictProcessRules(derived))
    .concat(buildBrowserResidentialRules(derived));
  return dedupeRulesByIdentity(concatenated);
}

// 注入管理规则（置顶），由脚本生成 MATCH 兜底。
// 同时清除订阅的 rule-providers，防止 RULE-SET 规则逃逸。
function writeManagedRules(config, routingTargets, derived) {
  var managedRules = buildManagedRules(derived, routingTargets);

  // 清空所有订阅规则，写入管理规则 + 管理 MATCH
  config.rules.length = 0;
  config.rules.push.apply(config.rules, managedRules);
  config.rules.push("MATCH," + routingTargets.defaultProxyTarget);

  // 清除订阅 rule-providers
  if (typeof config["rule-providers"] === "object" && config["rule-providers"] !== null) {
    config["rule-providers"] = {};
  }
}

// 批量追加指定类型规则。
function appendTypedRules(ruleLines, values, ruleType, target) {
  for (var i = 0; i < values.length; i++) {
    ruleLines.push(ruleType + "," + values[i] + "," + target);
  }
}

// 批量追加 `DOMAIN-SUFFIX` 规则。
function appendSuffixRules(ruleLines, domains, target) {
  var suffixes = [];
  for (var i = 0; i < domains.length; i++) {
    suffixes.push(toSuffix(domains[i]));
  }
  appendTypedRules(ruleLines, suffixes, "DOMAIN-SUFFIX", target);
}

// 从域名后缀中提取二级域关键词，生成 DOMAIN-KEYWORD 兜底规则。
// 用于接住 DOMAIN-SUFFIX 未能匹配的子域（如 bps.openai.com 不被 suffix 匹配时）。
function appendKeywordRules(ruleLines, domains, target) {
  var seen = {};
  for (var i = 0; i < domains.length; i++) {
    var suffix = toSuffix(domains[i]);
    var dotIndex = suffix.indexOf(".");
    if (dotIndex <= 0) continue;
    var keyword = suffix.substring(0, dotIndex);
    if (keyword.length < 3 || seen[keyword]) continue;
    seen[keyword] = true;
    ruleLines.push("DOMAIN-KEYWORD," + keyword + "," + target);
  }
}

// 批量追加 `PROCESS-NAME` 规则。
function appendProcessRules(ruleLines, processNames, target) {
  appendTypedRules(ruleLines, processNames, "PROCESS-NAME", target);
}

// 批量追加多个进程分组。
function appendProcessRuleGroups(ruleLines, processGroups, target) {
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], target);
  }
}

// 返回应纳入严格 AI 路由的进程分组；AI CLI 固定走家宽出口面板。
function buildStrictProcessGroups(derived) {
  return [derived.processNames.aiApps, derived.processNames.aiCli];
}

// 对一组派生域名桶批量生成 DOMAIN-SUFFIX + DOMAIN-KEYWORD 规则。
// bucket 每个键（跳过汇总键 all）映射到 targetByKey 中同名的 UI 面板。
function appendDomainRuleGroups(ruleLines, bucket, targetByKey) {
  Object.keys(bucket).forEach(function (bucketKey) {
    if (bucketKey === "all") return;
    var target = targetByKey[bucketKey];
    appendSuffixRules(ruleLines, bucket[bucketKey], target);
    appendKeywordRules(ruleLines, bucket[bucketKey], target);
  });
}

// 生成家宽出口域名规则：AI / 支撑平台 / 集成服务显式锁定到家宽出口面板。
function buildResidentialDomainRules(derived) {
  var ruleLines = [];
  appendDomainRuleGroups(ruleLines, derived.patterns.residential, UI_GROUPS);
  return ruleLines;
}

// 生成 AI App / CLI 进程兜底规则。放在域名规则和 CN 兜底之后，避免压过明确域名。
function buildStrictProcessRules(derived) {
  var ruleLines = [];
  appendProcessRuleGroups(ruleLines, buildStrictProcessGroups(derived), UI_GROUPS.ai); // 统一丢向 AI 可视化面板
  return ruleLines;
}

// 生成 DoH 端点的代理规则，确保 DNS 查询在境外加密隧道内完成。
function buildProxyRules(derived, defaultProxyTarget) {
  var ruleLines = [];
  appendSuffixRules(ruleLines, derived.patterns.proxy, defaultProxyTarget);
  return ruleLines;
}

// 生成浏览器进程规则，承载按应用名强制分流的 AI 浏览器进程。
function buildBrowserResidentialRules(derived) {
  var ruleLines = [];
  appendProcessRuleGroups(ruleLines, [derived.processNames.browser], UI_GROUPS.ai); // 统一丢向 AI 高敏阵列
  return ruleLines;
}

// 生成媒体组选区规则，只承载媒体域名。
function buildMediaRules(derived) {
  var ruleLines = [];
  appendDomainRuleGroups(ruleLines, derived.patterns.media, UI_GROUPS);
  return ruleLines;
}

// 生成所有 DIRECT 规则：固定 IP-CIDR 网段（带 `no-resolve`）+ 全部 direct 模式。
function buildDirectRules(derived) {
  var ruleLines = [];
  for (var i = 0; i < derived.networkRules.direct.length; i++) {
    var r = derived.networkRules.direct[i];
    ruleLines.push(r.type + "," + r.value + "," + r.target + ",no-resolve");
  }
  appendSuffixRules(ruleLines, derived.patterns.direct, BASE.ruleTargets.direct);
  return ruleLines;
}

// 生成中国站点直连兜底。DNS geosite 已负责解析，这里负责未显式维护域名的出口。
function buildChinaFallbackRules() {
  return [
    "GEOSITE,cn," + BASE.ruleTargets.direct,
    "GEOIP,CN," + BASE.ruleTargets.direct
  ];
}

// 生成 GFWList 代理规则，GFW 域通过 GEOSITE,gfw 走默认代理组。
function buildGfwProxyRule(defaultProxyTarget) {
  return ["GEOSITE,gfw," + defaultProxyTarget];
}

// 基于预构建的规则行查找表 O(1) 断言管理规则是否命中预期目标。
function assertManagedRuleTargetExpanded(ruleLineLookup, type, value, validTargets) {
  for (var i = 0; i < validTargets.length; i++) {
    var ruleLine = type + "," + value + "," + validTargets[i];
    if (ruleLineLookup[ruleLine]) return;
  }
  throw createUserError(
    "关键规则未正确写入: " + type + "," + value + "（未查到映射至合规的可视化分组），请检查脚本源数据覆盖"
  );
}

// 断言路由目标一致性：strictAi = 家宽出口组。
function assertRoutingTargetCoherence(routingTargets) {
  if (routingTargets.strictAiTarget !== routingTargets.residentialGroupName) {
    throw createUserError(
      "域外 AI 与支撑平台未直接指向当前家宽出口组，请检查代理组注入逻辑"
    );
  }
}

// 断言家宽出口组在节点/代理组中存在。
function assertRoutingTargetsExist(config, routingTargets) {
  if (!hasProxyOrGroup(config, routingTargets.residentialGroupName)) {
    throw createUserError(
      "当前家宽出口组不存在，请检查代理组注入逻辑"
    );
  }
}

// 断言官方中转节点状态。
function assertTransitBindings(config) {
  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (!transitProxy) {
    throw createUserError(
      "官方中转节点状态异常，请检查 RESIDENTIAL_CREDENTIALS 和节点注入逻辑"
    );
  }
}

// 断言家宽出口组 shape 与成员集合。
function assertResidentialGroupShape(config, residentialGroupName) {
  var expectedMembers = [BASE.nodeNames.transit];
  var residentialGroup = findProxyGroupByName(config["proxy-groups"], residentialGroupName);
  if (
    !residentialGroup ||
    residentialGroup.type !== "select" ||
    !haveSameStringSet(residentialGroup.proxies || [], expectedMembers)
  ) {
    throw createUserError(
      "当前家宽出口组内容异常，请检查代理组注入逻辑"
    );
  }
}

// 判断两个字符串数组集合相等（无视顺序、不允许重复）。
function haveSameStringSet(values, expectedValues) {
  if (values.length !== expectedValues.length) return false;
  var lookup = buildStringLookup(values);
  for (var i = 0; i < expectedValues.length; i++) {
    if (!lookup[expectedValues[i]]) return false;
  }
  return true;
}

// 逐条断言一批校验目标在最终规则里命中预期合规集合的任何一个。
function assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets, validTargets) {
  for (var i = 0; i < validationTargets.length; i++) {
    assertManagedRuleTargetExpanded(
      ruleLineLookup,
      validationTargets[i].type,
      validationTargets[i].value,
      validTargets
    );
  }
}

// 验证关键规则目标是否正确写入。
function validateManagedRouting(config, routingTargets, derived) {
  assertRoutingTargetCoherence(routingTargets);
  assertRoutingTargetsExist(config, routingTargets);
  assertTransitBindings(config);
  assertResidentialGroupShape(config, routingTargets.residentialGroupName);

  var ruleLineLookup = buildStringLookup(config.rules);
  var validationTargets = buildRoutingValidationTargets(derived);
  // 断言规则落在正确的 UI 分组中
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.strict, [UI_GROUPS.ai, UI_GROUPS.support, UI_GROUPS.integrations]);
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.browser, [UI_GROUPS.ai]);
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.media, [UI_GROUPS.video, UI_GROUPS.music, UI_GROUPS.social, UI_GROUPS.im]);
}

// ===========================================================================
// 7. 路由校验
// ===========================================================================

function buildRoutingValidationTargets(derived) {
  return {
    strict: buildDomainValidationTargets(derived.patterns.residential.all)
      .concat(buildProcessValidationTargets(derived.processNames.aiApps))
      .concat(buildProcessValidationTargets(derived.processNames.aiCli)),
    media: buildDomainValidationTargets(derived.patterns.media.all),
    browser: buildProcessValidationTargets(derived.processNames.browser)
  };
}

function buildValidationTargets(ruleType, values, valueMapper) {
  var targets = [];
  var mapValue = valueMapper || function (value) { return value; };
  for (var i = 0; i < values.length; i++) {
    targets.push({ type: ruleType, value: mapValue(values[i]) });
  }
  return targets;
}

function buildDomainValidationTargets(domainPatterns) {
  return buildValidationTargets("DOMAIN-SUFFIX", domainPatterns, toSuffix);
}

function buildProcessValidationTargets(processNames) {
  return buildValidationTargets("PROCESS-NAME", processNames);
}

// 家宽出口入口。装配顺序：容器 → 家宽出口 节点 → 路由目标 → 规则 → 校验。
function applyResidentialExit(config, derived, residentialCredentials) {
  var routingTargets;

  writeContainers(config); // 初始化基础容器
  writeResidentialProxies(config, residentialCredentials); // 注入 家宽出口 节点

  routingTargets = resolveRoutingTargets(config); // 解析链路目标
  writeManagedRouting(config, routingTargets, derived); // 写入拨号与规则
  validateManagedRouting(config, routingTargets, derived); // 校验关键目标

  return config;
}

// ===========================================================================
// 8. 一体化覆写入口（合并版）
// ===========================================================================

function hasConfiguredResidentialCredentials(credentials) {
  return !!(
    credentials &&
    typeof credentials.username === "string" && credentials.username !== "" &&
    typeof credentials.password === "string" && credentials.password !== "" &&
    credentials.transit &&
    typeof credentials.transit.server === "string" && credentials.transit.server !== "" &&
    typeof credentials.transit.port === "number" && credentials.transit.port > 0 && credentials.transit.port < 65536
  );
}

function cloneResidentialCredentials(credentials) {
  return {
    username: credentials.username,
    password: credentials.password,
    transit: {
      server: credentials.transit.server,
      port: credentials.transit.port
    }
  };
}

function normalizeOverrideMode(mode) {
  if (mode === undefined || mode === null || mode === "") return "merged";
  if (typeof mode !== "string") {
    throw createUserError("USER_OPTIONS.overrideMode 必须是字符串");
  }

  var normalizedMode = mode.toLowerCase();
  if (
    normalizedMode === "merged" ||
    normalizedMode === "option-b" ||
    normalizedMode === "optionb" ||
    normalizedMode === "full"
  ) {
    return "merged";
  }
  if (
    normalizedMode === "dns-sniffer-only" ||
    normalizedMode === "dns-sniffer" ||
    normalizedMode === "dns" ||
    normalizedMode === "option-a" ||
    normalizedMode === "optiona"
  ) {
    return "dns-sniffer-only";
  }

  throw createUserError(
    "未知 USER_OPTIONS.overrideMode: " + mode + "，可选 merged / dns-sniffer-only"
  );
}

function shouldApplyOnlyDnsAndSniffer() {
  return normalizeOverrideMode(USER_OPTIONS.overrideMode) === "dns-sniffer-only";
}

function resolveConfiguredResidentialCredentials(credentials) {
  if (hasConfiguredResidentialCredentials(credentials)) {
    return cloneResidentialCredentials(credentials);
  }
  throw createUserError(
    "请先填写 RESIDENTIAL_CREDENTIALS 中的用户名、密码和官方中转端点"
  );
}

// merged 模式前置校验：在 DNS/Sniffer 写入之前完成所有可抛项。
function preflightMergedMode(config) {
  var credentials = resolveConfiguredResidentialCredentials(RESIDENTIAL_CREDENTIALS);
  return credentials;
}

function main(config) {
  var residentialCredentials = null;

  if (USER_OPTIONS.enabled === false) return config;

  if (!shouldApplyOnlyDnsAndSniffer()) {
    residentialCredentials = preflightMergedMode(config);
  }

  DNS_SNIFFER_MODULE.apply(config);
  if (shouldApplyOnlyDnsAndSniffer()) {
    return config;
  }

  return applyResidentialExit(config, DNS_SNIFFER_MODULE.DERIVED, residentialCredentials);
}
