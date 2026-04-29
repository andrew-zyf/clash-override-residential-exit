// DNS 解析和域名嗅探前置覆写脚本
//
// 先写入 Clash DNS / Sniffer 配置，并把 POLICY 派生结果暂存到 config._azChainProxyState，
// 供后续的 MiyaIP 凭证登记和链式代理覆写继续消费。
//
// 兼容性：Clash Party 的 JavaScriptCore；只用 ES5 语法。
//
// @version 10.1

// ---------------------------------------------------------------------------
// 基础常量
// ---------------------------------------------------------------------------

// DNS/Sniffer 前置脚本只保留解析与派生分类所需的运行期常量。
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
    openaiGeosite: "geosite:openai" // nameserver-policy 专用 geosite 键
  }
};

// fallback 在 overseas 基础上追加 Quad9。
BASE.dns.fallback = BASE.dns.overseas.concat(["https://dns.quad9.net/dns-query"]);

// ---------------------------------------------------------------------------
// 域名模式
// ---------------------------------------------------------------------------

// 这里只列"哪些域名属于哪个业务桶"，路由/DNS/sniffer 行为统一在下面的 POLICY 注入。
// 模式形如 `+.domain`，转成规则时由 `toSuffix` 去掉 `+.` 前缀。

// ---------- Chain · 链式代理 ----------
var CHAIN = {
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
      "+.sora.com",
      "+.oaiusercontent.com", // OpenAI 官方静态资源与内容分发基础设施
      "+.oaistatic.com"
    ],
    google_ai: [
      "+.gemini.google.com",
      "+.aistudio.google.com",
      "+.ai.google.dev",
      "+.generativelanguage.googleapis.com",
      "+.ai.google",
      "+.notebooklm.google",
      "+.makersuite.google.com", // 历史兼容入口，Google 已迁移到 AI Studio
      "+.deepmind.google",
      "+.labs.google"
    ],
    google_antigravity: [
      "+.antigravity.google",
      "+.antigravity-ide.com" // Antigravity IDE 的非 google 子域资源站
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
        "Perplexity",
        "Cursor"
      ],
      helperSuffixes: [
        "Helper"
      ],
      exact: [
        "ChatGPTHelper",
        "Claude Helper (Renderer)",
        "Claude Helper (GPU)",
        "Claude Helper (Plugin)",
        // macOS PROCESS-NAME 匹配 Bundle 可执行名，不含 `.app` 后缀。
        // 未列入此处的应用：
        //   - Claude Code / URL Handler 都以 `claude` 运行，统一通过 ai.cli 命中。
        //   - Antigravity 的 Bundle 可执行名是 `Electron`，无法按进程名精确匹配，改走域名规则。
        "Quotio"
      ],
      cli: ["claude", "gemini", "codex"]
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
      "+.cloudflare-dns.com",
      "+.cdn.cloudflare.net",
      "+.workers.dev",
      "+.pages.dev"
    ],
    aws: [
      "+.amazonaws.com",
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

// ---------- Media（独立地区组，不走家宽链路） ----------
// 分四类：视频流媒体 / 音乐流媒体 / 社交 / 即时通讯。
// 这一桶里的所有域名都路由到 `mediaRegion`（默认 US），与家宽 chain 解耦，
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
    "+.aiv-cdn.net",     // Prime Video CDN（不会牵连 amazon.com 主站和 AWS）
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
//   cliNames      AI CLI 可执行名（固定走 chainRegion）
var EXPECTED_ROUTES = {
  toChain: {
    domains: [
      "claude.ai",
      "chatgpt.com",
      "gemini.google.com",
      "perplexity.ai",
      "google.com",
      "cursor.sh",             // Cursor 后端
      "arkoselabs.com",        // Arkose 登录反机器人（integrations.antibot）
      "stripe.com",            // AI 订阅支付（integrations.payments）
      "statsig.com",           // feature flag（integrations.telemetry）
      "githubusercontent.com", // GitHub 原始内容，GFW 下易污染
      "npmjs.org"              // npm 官方 registry
    ],
    processNames: ["Claude"],
    cliNames: ["claude", "codex"]
  },
  toMedia: {
    domains: [
      "youtube.com",     // 视频流媒体
      "x.com",           // 社交
      "twitch.tv",       // 直播
      "spotify.com",     // 音乐
      "line.me",         // IM
      "whatsapp.com"     // IM
    ]
  }
};

// ---------------------------------------------------------------------------
// 通用数据处理工具
// ---------------------------------------------------------------------------

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

// 为字符串数组构建便于查询的哈希表。
function buildStringLookup(values) {
  var lookup = {};
  for (var i = 0; i < values.length; i++) {
    lookup[values[i]] = true;
  }
  return lookup;
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

// 把带通配前缀的域名模式转换成规则使用的裸域名后缀。
function toSuffix(domainPattern) {
  return domainPattern.indexOf("+.") === 0
    ? domainPattern.substring(2)
    : domainPattern;
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

function createUserError(message) {
  return new Error(message);
}

// ---------------------------------------------------------------------------
// 策略表（POLICY）与派生分类
// ---------------------------------------------------------------------------

// POLICY — 所有域名模式的单一权威来源。
// 每条 entry 声明 route / dnsZone / sniffer / fakeIpBypass / fallbackFilter。
// 下游 DNS、Sniffer、规则、断言都从 POLICY 投影。
//
// 字段：
//   key            标识（调试用）
//   patterns       `+.domain` 模式数组
//   route          "chain.*" | "media.*" | "direct" | "proxy"，省略 = 不生成规则
//   dnsZone        "overseas" | "domestic"，省略 = 不进 nameserver-policy
//   sniffer        "force" | "skip"，省略 = 不参与 sniffer
//   fakeIpBypass   true = 进入 fake-ip-filter
//   fallbackFilter true = 进入 fallback-filter.domain
//
// 冲突解决：direct 优先于 chain/media（派生时 excludeStrings）。
function buildPolicy() {
  return [
    // ---- chain · 走家宽出口 ----
    {
      key: "chain.support", patterns: flattenGroupedPatterns(CHAIN.support),
      route: "chain.support", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.ai", patterns: flattenGroupedPatterns(CHAIN.ai),
      route: "chain.ai", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.integrations", patterns: flattenGroupedPatterns(CHAIN.integrations),
      route: "chain.integrations", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
    },
    {
      key: "chain.cloudflare", patterns: flattenGroupedPatterns(CHAIN.force),
      route: "chain.cloudflare", dnsZone: "overseas", sniffer: "force", fallbackFilter: true
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

    // ---- 默认代理（不写 route，仅做 DNS / fallback-filter）----
    {
      key: "default.doh", patterns: flattenGroupedPatterns(CDN.doh),
      route: "proxy", dnsZone: "overseas", fallbackFilter: true
    },
    {
      key: "default.overseasCloudCdn", patterns: flattenGroupedPatterns(CDN.cloud),
      dnsZone: "overseas", fallbackFilter: true
    },

    // ---- direct · 直连 ----
    // Apple 不绑定 dnsZone，走 nameserver + fallback 并行查询 + fallback-filter geoip 仲裁：
    // SG：域内 DoH 返回非 CN IP → fallback-filter 选域外结果 → 全球 CDN；
    // CN：域内 DoH 返回 CN Apple CDN → 直接使用。两端都不依赖单侧 DoH 可用性。
    {
      key: "direct.apple", patterns: flattenGroupedPatterns(OVERSEAS.special.apple),
      route: "direct", fakeIpBypass: true, fallbackFilter: true
    },
    {
      key: "direct.egressCheck", patterns: flattenGroupedPatterns(OVERSEAS.special.egressCheck),
      route: "direct", dnsZone: "overseas", fallbackFilter: true
    },
    {
      key: "direct.overseasApps", patterns: flattenGroupedPatterns(OVERSEAS.global.apps),
      route: "direct", dnsZone: "overseas", sniffer: "skip", fallbackFilter: true
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
function matchFallbackFilter(entry) { return entry.fallbackFilter === true; }

// 从 POLICY 投影出下游真正消费的三类域名集合：
//   chain    → 进家宽出口（排除被 direct 抢占的模式）
//   media    → 媒体地区组
//   direct   → 全量 DIRECT 模式，用于生成直连规则与 fake-ip/sniffer 判断
//   proxy    → 进通用代理组（用于强制 DoH 服务器等前跳代理寻址）
//   sniffer  → force / skip 两侧的嗅探决策
//   fakeIpBypass → 需要返回真实 IP 的域名（Apple 等）
function buildDerivedPatterns() {
  var direct = projectPolicyPatterns(matchRoute("direct"));
  var proxy = excludeStrings(projectPolicyPatterns(matchRoute("proxy")), direct);

  var chainAi = excludeStrings(projectPolicyPatterns(matchRoute("chain.ai")), direct);
  var chainSupport = excludeStrings(projectPolicyPatterns(matchRoute("chain.support")), direct);
  var chainIntegrations = excludeStrings(projectPolicyPatterns(matchRoute("chain.integrations")), direct);
  var chainCloudflare = excludeStrings(projectPolicyPatterns(matchRoute("chain.cloudflare")), direct);
  var chainAll = mergeStringGroups([chainAi, chainSupport, chainIntegrations, chainCloudflare]);

  var mediaVideo = excludeStrings(projectPolicyPatterns(matchRoute("media.video")), direct);
  var mediaMusic = excludeStrings(projectPolicyPatterns(matchRoute("media.music")), direct);
  var mediaSocial = excludeStrings(projectPolicyPatterns(matchRoute("media.social")), direct);
  var mediaIm = excludeStrings(projectPolicyPatterns(matchRoute("media.im")), direct);
  var mediaAll = mergeStringGroups([mediaVideo, mediaMusic, mediaSocial, mediaIm]);

  return {
    proxy: proxy,
    chain: {
      ai: chainAi,
      support: chainSupport,
      integrations: mergeStringGroups([chainIntegrations, chainCloudflare]),
      all: chainAll
    },
    media: {
      video: mediaVideo,
      music: mediaMusic,
      social: mediaSocial,
      im: mediaIm,
      all: mediaAll
    },
    direct: direct,
    fakeIpBypass: projectPolicyPatterns(matchFakeIpBypass),
    // Sniffer 是 fake-ip 模式的安全网：当 fake-IP 映射丢失或 QUIC 跳过 DNS 时，
    // 从 TLS SNI / HTTP Host 恢复域名，确保 AI 流量命中链式代理规则而非漏到 MATCH。
    //   force → chain 域名 + 所有 sniffer:"force" 条目（Cloudflare 等）
    //   skip  → Tailscale / Plex / Apple 推送等故意用 IP 语义的直连应用
    sniffer: {
      force: mergeStringGroups([chainAll, projectPolicyPatterns(matchSniffer("force"))]),
      skip: projectPolicyPatterns(matchSniffer("skip"))
    }
  };
}

// 从 CHAIN.apps 展开出三类进程入口：
//   aiApps  → 受管 AI 桌面 App + 显式 helper（始终走 chainRegion）
//   aiCli   → AI 命令行（始终走 chainRegion）
//   browser → AI 浏览器 + 全部 helper（是否启用由链式代理脚本的 USER_OPTIONS 决定）
function buildDerivedProcessNames() {
  return {
    aiApps: expandProcessNamesWithHelpers(
      CHAIN.apps.ai.apps,
      CHAIN.apps.ai.helperSuffixes,
      CHAIN.apps.ai.exact
    ),
    aiCli: uniqueStrings(CHAIN.apps.ai.cli.slice()),
    browser: expandProcessNamesWithHelpers(
      CHAIN.apps.browser.apps,
      CHAIN.apps.browser.helperSuffixes
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

  for (i = 0; i < EXPECTED_ROUTES.toChain.domains.length; i++) {
    sample = EXPECTED_ROUTES.toChain.domains[i];
    if (!isDomainCoveredBySuffixPatterns(sample, DERIVED.patterns.chain.all)) {
      throw createUserError("toChain 样本未被 chain 源覆盖: " + sample);
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
  var procSamples = EXPECTED_ROUTES.toChain.processNames
    .concat(EXPECTED_ROUTES.toChain.cliNames);
  for (i = 0; i < procSamples.length; i++) {
    if (!procLookup[procSamples[i]]) {
      throw createUserError("toChain 样本进程未在 CHAIN.apps 中: " + procSamples[i]);
    }
  }
}

assertExpectedRoutesCoverage();

// 把字符串数组映射为 { type, value } 规则目标列表。
// ---------------------------------------------------------------------------
// DNS + Sniffer
// ---------------------------------------------------------------------------

// 写入 DNS 和 Sniffer 配置。
function writeDnsAndSniffer(config, derived) {
  config.dns = buildDnsConfig(derived);
  config.sniffer = buildSnifferConfig(derived);
}

// 从 POLICY 按 dnsZone 生成 nameserver-policy 映射。
function buildNameserverPolicy() {
  var dohByZone = { overseas: BASE.dns.overseas, domestic: BASE.dns.domestic };
  var policy = {};
  policy[BASE.dns.openaiGeosite] = dohByZone.overseas;

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
  var localNetworkDomains = [
    "+.push.apple.com",
    "+.lan",
    "+.local",
    "+.localhost",
    "localhost.ptlogin2.qq.com"
  ];
  var timeSyncDomains = [
    "time.*.com", // 中部通配：保留 glob
    "time.*.gov",
    "time.*.edu.cn",
    "time.*.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
    "ntp.*.com",
    "ntp1.aliyun.com",
    "pool.ntp.org",
    "+.pool.ntp.org"
  ];
  var connectivityTestDomains = [
    "+.msftconnecttest.com", // 覆盖裸域与所有子域（含 www.）
    "+.msftncsi.com"
  ];
  var gamingRealtimeDomains = [
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "xbox.*.microsoft.com", // 中部通配：保留 glob
    "+.xboxlive.com",
    "+.battlenet.com.cn",
    "+.blzstatic.cn"
  ]; // 游戏主机和游戏平台入口通常依赖真实 IP
  var stunRealtimeDomains = [
    "stun.*.*", // 中部通配：保留 glob
    "stun.*.*.*"
  ]; // 通用 STUN 常见于 WebRTC、语音和点对点连接
  var homeRouterDomains = [
    "+.router.asus.com",
    "+.linksys.com",
    "+.tplinkwifi.net",
    "+.xiaoqiang.net"
  ]; // 本地路由器和家庭网络设备入口应返回真实 IP

  return localNetworkDomains
    .concat(timeSyncDomains)
    .concat(connectivityTestDomains)
    .concat(derived.patterns.fakeIpBypass)
    .concat(gamingRealtimeDomains)
    .concat(stunRealtimeDomains)
    .concat(homeRouterDomains);
}

// DNS fallback-filter 配置。
// AI / DoH / 媒体等高价值域名已在 nameserver-policy 中显式绑定 DoH，
// 这里兜底处理未被显式覆盖的域名：geoip: true 让非 CN IP 走 fallback DoH。
function buildDnsFallbackFilter() {
  return {
    geoip: true,
    "geoip-code": "CN",
    geosite: ["gfw"],
    ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
    domain: projectPolicyPatterns(matchFallbackFilter)
  };
}

// 构建不含动态列表项的基础 DNS 配置。
//
// respect-rules: true — 让 DNS 查询也走分流规则，而不是全部从本地直连发出。
// 效果：
//   chain 域名的 DoH 查询 → 经链式代理从 SG 家宽出去 → dns.google 看到的是 SG IP
//   direct 域名的 DoH 查询 → 走 direct-nameserver（域内 DoH）→ 本地直连
//   media 域名的 DoH 查询 → 经媒体代理组出去
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
// 前置覆写入口
// ---------------------------------------------------------------------------

var CHAIN_PROXY_STATE_KEY = "_azChainProxyState";
var CHAIN_PROXY_STATE_VERSION = "10.1";

function buildChainProxyState(derived) {
  return {
    version: CHAIN_PROXY_STATE_VERSION,
    derived: derived
  };
}

function main(config) {
  writeDnsAndSniffer(config, DERIVED);
  config[CHAIN_PROXY_STATE_KEY] = buildChainProxyState(DERIVED);
  return config;
}
