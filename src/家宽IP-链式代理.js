// 家宽 IP 链式代理覆写脚本
//
// 通过链式代理将 AI 相关流量锁定到家宽 IP，防止 IP 指纹不一致导致封号。
//
// 1. 三阶防泄漏：本地 DNS 只解析代理节点 → DoH 查询走代理在境外完成 → AI 请求用 Fake-IP 远端解析。
// 2. 生态链 IP 一致：AI 会话 + STUN/TCP + Arkose + Stripe + Statsig 等全部走同一出口，避免 IP 碎裂。
// 3. 统一策略覆盖：前置脚本输出 DERIVED，链式代理脚本只消费派生后的路由视图。
//
//   USER_OPTIONS     用户可调参数（地区 + 浏览器开关）
//   BASE             运行期常量（地区表、节点名、组名、规则目标）
//   _azChainProxyState
//                    DNS/Sniffer 前置脚本注入的派生状态：patterns / processNames / networkRules
//   main(config)     装配顺序：读取 DNS/Sniffer 派生状态 → 容器 →
//                    MiyaIP 节点 → 地区目标解析 → 规则注入 → 收尾校验
//
// 函数前缀约定：build*=纯产出  resolve*=读+幂等写  write*=改 config  assert*=运行期断言
//
// 依赖：先跑 `DNS解析和域名嗅探.js`，再跑 `MiyaIP 凭证.js`
//      完成静态 IP 信息登记并写到 `config._miya`，最后跑本脚本。
// 兼容性：Clash Party 的 JavaScriptCore；只用 ES5 语法。
//
// @version 10.1

// ---------------------------------------------------------------------------
// 用户可调参数
// ---------------------------------------------------------------------------

var USER_OPTIONS = {
  chainRegion: "SG", // AI 家宽出口前一跳地区，可选 US / JP / HK / SG
  routeBrowserToChain: true // 是否让 AI 向浏览器按应用名继续强制走 chainRegion
};

// ---------------------------------------------------------------------------
// 基础常量
// ---------------------------------------------------------------------------

// 所有运行期稳定常量的单一来源：地区、节点名、组名后缀、DoH 服务器、规则前缀。
var BASE = {
  regions: {
    US: { regex: /🇺🇸|美国|^US[|丨\- ]/i, label: "美国", flag: "🇺🇸" },
    JP: { regex: /🇯🇵|日本|^JP[|丨\- ]/i, label: "日本", flag: "🇯🇵" },
    HK: { regex: /🇭🇰|香港|^HK[|丨\- ]/i, label: "香港", flag: "🇭🇰" },
    SG: { regex: /🇸🇬|新加坡|^SG[|丨\- ]/i, label: "新加坡", flag: "🇸🇬" },
    TW: { regex: /🇹🇼|台湾|^TW[|丨\- ]/i, label: "台湾", flag: "🇹🇼" }
  },
  nodeNames: {
    relay: "自选节点 + 家宽IP",
    transit: "MiyaIP（官方中转）"
  },
  groupNames: {
    nodeSelection: "办公娱乐好帮手" // 适配用户当前订阅里托管的全局选择组
  },
  ruleTargets: {
    direct: "DIRECT"
  },
  rulePrefixes: {
    match: "MATCH," // Clash 兜底规则固定前缀
  },
  urlTestProbeUrl: "http://www.gstatic.com/generate_204",
  miyaProxyNameKeyword: "MiyaIP",
  groupNameSuffixes: {
    base: "节点组"
  },
  groupNamePrefixes: {
    base: "az.分区测速."
  },
  chainGroupName: "az.核心链路.🔗 链式代理-家宽出口",
  regionFallbackOrder: {
    chain: ["SG", "TW", "JP", "US"] // 家宽出口优先低时延亚洲地区，最后再回退到美国
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

// 是否让受管 AI 浏览器继续按应用名强制走 chainRegion。
function shouldRouteBrowserToChain() {
  return USER_OPTIONS.routeBrowserToChain !== false;
}

// ---------------------------------------------------------------------------
// MiyaIP 代理链路与地区组选区
// ---------------------------------------------------------------------------

// 确保主配置里存在代理、代理组和规则三个容器。
function writeContainers(config) {
  if (!config.proxies) config.proxies = [];
  if (!config["proxy-groups"]) config["proxy-groups"] = [];
  if (!config.rules) config.rules = [];
}

// 把地区输入统一转成大写字符串键；非字符串或空串直接拒绝，便于尽早暴露配置错误。
function normalizeRegionKey(region) {
  if (typeof region !== "string" || region === "") {
    throw createUserError("chainRegion / mediaRegion 必须是非空字符串，实际: " + region);
  }
  return region.toUpperCase();
}

// 根据地区键解析地区元数据，并按需提供兜底标签。
function resolveRegionMeta(region, allowFallbackRegionLabel) {
  var regionKey = normalizeRegionKey(region);
  var source = BASE.regions[regionKey];
  var meta = source ? { regex: source.regex, label: source.label, flag: source.flag, code: regionKey } : null;
  if (!meta && allowFallbackRegionLabel) meta = { label: region, flag: "🌐", code: regionKey };
  return meta;
}

// 基于地区国旗与中文标签拼出代理组名称（如 分区测速.🇸🇬 新加坡节点组）。
function buildRegionGroupName(regionMeta, groupNameSuffix) {
  return BASE.groupNamePrefixes.base + regionMeta.flag + " " + regionMeta.label + groupNameSuffix;
}

// 根据凭证和端点信息生成一个 MiyaIP HTTP 代理节点。
function buildMiyaProxy(miyaCredentials, proxyName, endpoint) {
  return {
    name: proxyName,
    type: "http",
    server: endpoint.server,
    port: endpoint.port,
    username: miyaCredentials.username,
    password: miyaCredentials.password,
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

// 判断给定名称是否在节点或代理组中存在。
function hasProxyOrGroup(config, targetName) {
  return !!(
    findProxyByName(config.proxies || [], targetName) ||
    findProxyGroupByName(config["proxy-groups"] || [], targetName)
  );
}

// 收集匹配地区特征且非 MiyaIP 的节点名称列表。
function collectRegionNodeNames(proxies, regionRegex) {
  var regionNodeNames = [];
  for (var i = 0; i < proxies.length; i++) {
    var proxy = proxies[i];
    if (
      regionRegex.test(proxy.name) &&
      proxy.name.indexOf(BASE.miyaProxyNameKeyword) < 0
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

// 将代理组追加到节点选择组。
function writeManagedGroupIntoNodeSelection(config, managedGroupName) {
  var nodeSelectionGroup = findProxyGroupByName(config["proxy-groups"], BASE.groupNames.nodeSelection);
  if (!nodeSelectionGroup || !nodeSelectionGroup.proxies) return;

  var nextProxyNames = [].concat(nodeSelectionGroup.proxies);
  nextProxyNames.push(managedGroupName);
  nodeSelectionGroup.proxies = uniqueStrings(nextProxyNames);
}

// 注入 MiyaIP 代理节点（家宽出口 + 官方中转）。
function writeMiyaProxies(config, miyaCredentials) {
  var miyaProxies = [
    buildMiyaProxy(miyaCredentials, BASE.nodeNames.relay, miyaCredentials.relay),
    buildMiyaProxy(
      miyaCredentials,
      BASE.nodeNames.transit,
      miyaCredentials.transit
    )
  ];

  for (var i = 0; i < miyaProxies.length; i++) {
    upsertNamedItem(config.proxies, miyaProxies[i]);
  }
}

// 仅根据订阅节点创建或修正指定地区的 `url-test` 代理组。
function writeRegionGroup(config, region, groupNameSuffix) {
  var regionMeta = resolveRegionMeta(region, false);
  if (!regionMeta) return null;

  var regionRegex = regionMeta.regex;
  var groupName = buildRegionGroupName(regionMeta, groupNameSuffix);
  var proxyGroups = config["proxy-groups"];

  var regionNodeNames = collectRegionNodeNames(config.proxies, regionRegex);
  if (regionNodeNames.length === 0) return null;

  upsertRegionUrlTestGroup(proxyGroups, groupName, regionNodeNames); // 用订阅地区节点创建或修正目标组

  return groupName;
}

// 按"首选地区 + fallback 顺序"生成实际尝试列表，首位永远保留用户首选。
function buildRegionResolutionOrder(primaryRegion, fallbackRegions) {
  var orderedRegions = [normalizeRegionKey(primaryRegion)];
  var i;
  var regionKey;
  for (i = 0; i < fallbackRegions.length; i++) {
    regionKey = normalizeRegionKey(fallbackRegions[i]);
    if (orderedRegions.indexOf(regionKey) >= 0) continue;
    orderedRegions.push(regionKey);
  }
  return orderedRegions;
}

// 按顺序尝试地区组，命中后返回实际地区与组名。
function resolveRegionGroupTarget(config, primaryRegion, fallbackRegions, groupNameSuffix, targetLabel) {
  var resolutionOrder = buildRegionResolutionOrder(primaryRegion, fallbackRegions);
  var i;
  var regionKey;
  var groupName;

  for (i = 0; i < resolutionOrder.length; i++) {
    regionKey = resolutionOrder[i];
    groupName = writeRegionGroup(config, regionKey, groupNameSuffix);
    if (groupName) {
      return { region: regionKey, target: groupName };
    }
  }

  throw createUserError(
    "未找到可用的 " +
    targetLabel +
    "，已按顺序尝试 " +
    resolutionOrder.join(" / ") +
    "，请检查订阅地区节点与命名"
  );
}

// 解析链式代理跳板组，首选缺失时按 fallback 顺序回退。
function resolveRelayTarget(config, region) {
  return resolveRegionGroupTarget(
    config,
    region,
    BASE.regionFallbackOrder.chain,
    BASE.groupNameSuffixes.base,
    "chainRegion 节点"
  );
}

// 绑定 dialer-proxy：家宽出口节点绑到跳板组，官方中转节点清除绑定。
function writeDialerProxy(config, relayTarget) {
  var relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (relayProxy) {
    if (relayTarget) relayProxy["dialer-proxy"] = relayTarget;
    else delete relayProxy["dialer-proxy"];
  }

  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (transitProxy) delete transitProxy["dialer-proxy"]; // 官方中转节点不挂 dialer-proxy
}

// 创建链式出口 select 组（MiyaIP 官方中转 / 家宽出口二选一）。
function writeChainGroup(config, region) {
  var chainGroupName = BASE.chainGroupName;

  upsertNamedItem(config["proxy-groups"], {
    name: chainGroupName,
    type: "select",
    proxies: [BASE.nodeNames.transit, BASE.nodeNames.relay]
  });

  return chainGroupName;
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

// 写入 UI 面板策略组。
function writeExpandedProxyGroups(config, strictAiTarget, regionalTargets) {
  var proxyGroups = config["proxy-groups"];
  var baseNodeSelection = BASE.groupNames.nodeSelection;
  
  var mediaChoices = [];
  var predefinedOrder = ["US", "HK", "JP", "TW"];
  for (var j = 0; j < predefinedOrder.length; j++) {
    var target = regionalTargets[predefinedOrder[j]];
    if (target) mediaChoices.push(target);
  }
  mediaChoices.push(baseNodeSelection);

  var aiChoices = [strictAiTarget];

  var subgroups = [
    { name: UI_GROUPS.ai, type: "select", proxies: aiChoices },
    { name: UI_GROUPS.support, type: "select", proxies: aiChoices },
    { name: UI_GROUPS.integrations, type: "select", proxies: aiChoices },
    { name: UI_GROUPS.video, type: "select", proxies: mediaChoices },
    { name: UI_GROUPS.music, type: "select", proxies: mediaChoices },
    { name: UI_GROUPS.social, type: "select", proxies: mediaChoices },
    { name: UI_GROUPS.im, type: "select", proxies: mediaChoices }
  ];
  for (var i = 0; i < subgroups.length; i++) {
    upsertNamedItem(proxyGroups, subgroups[i]);
  }
}

// 解析路由目标：创建地区组、链式出口组、UI 面板组。
function resolveRoutingTargets(config, chainRegion) {
  var relayResolution = resolveRelayTarget(config, chainRegion);
  var chainGroupName = writeChainGroup(config, relayResolution.region);
  
  writeManagedGroupIntoNodeSelection(config, relayResolution.target);
  
  var regionalTargets = {};
    // 为所有已定义地区生成标准 url-test 组
  var definedRegions = ["US", "JP", "HK", "SG", "TW"];
  for (var i = 0; i < definedRegions.length; i++) {
    var code = definedRegions[i];
    var standardGroup = writeRegionGroup(config, code, BASE.groupNameSuffixes.base);
    if (standardGroup) {
      writeManagedGroupIntoNodeSelection(config, standardGroup);
      regionalTargets[code] = standardGroup;
    }
  }

  // 注入 UI 面板分组
  writeExpandedProxyGroups(config, chainGroupName, regionalTargets);
  
  return {
    relayTarget: relayResolution.target,
    relayRegion: relayResolution.region,
    chainGroupName: chainGroupName,
    strictAiTarget: chainGroupName
  };
}

// 写入 dialer-proxy 绑定和分流规则。
function writeManagedRouting(config, routingTargets, derived) {
  writeDialerProxy(config, routingTargets.relayTarget);
  writeManagedRules(config, derived);
}

// ---------------------------------------------------------------------------
// 规则注入（去重 + 置顶）
// ---------------------------------------------------------------------------

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

// 拼接所有管理规则。顺序即优先级，浏览器进程规则放在最后避免压过更具体的域名匹配。
function buildManagedRules(derived) {
  var concatenated = buildStrictChainRules(derived)
    .concat(buildMediaRules(derived))
    .concat(buildProxyRules(derived))
    .concat(buildDirectRules(derived))
    .concat(buildBrowserChainRules(derived));
  return dedupeRulesByIdentity(concatenated);
}

// 把规则数组转换成便于查询的规则标识表。
function buildRuleIdentityLookup(ruleLines) {
  var ruleIdentityLookup = {};
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity) ruleIdentityLookup[ruleIdentity] = true;
  }
  return ruleIdentityLookup;
}

// 过滤掉与管理规则命中同一标识的原始订阅规则。
function filterConflictingRules(ruleLines, blockedRuleIdentities) {
  var filteredRules = [];
  for (var i = 0; i < ruleLines.length; i++) {
    var ruleIdentity = getRuleIdentity(ruleLines[i]);
    if (ruleIdentity === null || !blockedRuleIdentities[ruleIdentity]) {
      filteredRules.push(ruleLines[i]);
    }
  }
  return filteredRules;
}

// 将原始规则拆成"非 MATCH 兜底"与"MATCH 兜底"两段，保留后者在末尾以不破坏 Clash 兜底语义。
function splitMatchFallback(ruleLines) {
  var nonMatch = [];
  var matchTail = [];
  for (var i = 0; i < ruleLines.length; i++) {
    var line = ruleLines[i];
    if (line.indexOf(BASE.rulePrefixes.match) === 0) {
      matchTail.push(line);
    } else {
      nonMatch.push(line);
    }
  }
  return { nonMatch: nonMatch, matchTail: matchTail };
}

// 注入管理规则（置顶），MATCH 兜底保持在末尾。
function writeManagedRules(config, derived) {
  var managedRules = buildManagedRules(derived);
  var managedRuleIdentities = buildRuleIdentityLookup(managedRules);
  var remainingRules = filterConflictingRules(config.rules, managedRuleIdentities);
  var split = splitMatchFallback(remainingRules);

  // 管理规则置顶 → 剩余非兜底规则 → MATCH 兜底永远在最后。
  config.rules = managedRules.concat(split.nonMatch).concat(split.matchTail);
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

// 批量追加 `PROCESS-NAME` 规则。
function appendProcessRules(ruleLines, processNames, target) {
  appendTypedRules(ruleLines, processNames, "PROCESS-NAME", target);
}

// 返回应纳入严格 AI 路由的进程分组；AI CLI 固定走 chainRegion。
function buildStrictProcessGroups(derived) {
  return [derived.processNames.aiApps, derived.processNames.aiCli];
}

// 按当前用户选项返回应纳入链式代理的浏览器进程分组。
function buildBrowserChainProcessGroups(derived) {
  if (!shouldRouteBrowserToChain()) return [];
  return [derived.processNames.browser];
}

// 生成 chain 路由规则：受管进程 + AI CLI + chain 域名。
function buildStrictChainRules(derived) {
  var ruleLines = [];
  var processGroups = buildStrictProcessGroups(derived);
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], UI_GROUPS.ai); // 统一丢向 AI 可视化面板
  }
  
  appendSuffixRules(ruleLines, derived.patterns.chain.ai, UI_GROUPS.ai);
  appendSuffixRules(ruleLines, derived.patterns.chain.support, UI_GROUPS.support);
  appendSuffixRules(ruleLines, derived.patterns.chain.integrations, UI_GROUPS.integrations);
  
  // 用 DOMAIN-KEYWORD 匹配 STUN/TURN，防止 WebRTC P2P 打洞泄漏真实 IP。
  appendTypedRules(ruleLines, ["stun", "turn"], "DOMAIN-KEYWORD", UI_GROUPS.ai);

  return ruleLines;
}

// 生成 DoH 端点的代理规则，确保 DNS 查询在境外加密隧道内完成。
function buildProxyRules(derived) {
  var ruleLines = [];
  appendSuffixRules(ruleLines, derived.patterns.proxy, BASE.groupNames.nodeSelection);
  return ruleLines;
}

// 生成链式浏览器规则，承载按应用名强制分流的 AI 浏览器进程。
function buildBrowserChainRules(derived) {
  var ruleLines = [];
  var processGroups = buildBrowserChainProcessGroups(derived);
  for (var i = 0; i < processGroups.length; i++) {
    appendProcessRules(ruleLines, processGroups[i], UI_GROUPS.ai); // 统一丢向 AI 可视化面板
  }
  return ruleLines;
}

// 生成媒体组选区规则，只承载媒体域名。
function buildMediaRules(derived) {
  var ruleLines = [];
  appendSuffixRules(ruleLines, derived.patterns.media.video, UI_GROUPS.video);
  appendSuffixRules(ruleLines, derived.patterns.media.music, UI_GROUPS.music);
  appendSuffixRules(ruleLines, derived.patterns.media.social, UI_GROUPS.social);
  appendSuffixRules(ruleLines, derived.patterns.media.im, UI_GROUPS.im);
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

// 判断两个字符串数组集合相等（无视顺序、不允许重复）。
function haveSameStringSet(values, expectedValues) {
  if (values.length !== expectedValues.length) return false;
  var lookup = buildStringLookup(values);
  for (var i = 0; i < expectedValues.length; i++) {
    if (!lookup[expectedValues[i]]) return false;
  }
  return true;
}

// 断言路由目标一致性：strictAi = chain，relay ≠ chain。
function assertRoutingTargetCoherence(routingTargets) {
  if (routingTargets.strictAiTarget !== routingTargets.chainGroupName) {
    throw createUserError(
      "域外 AI 与支撑平台未直接指向当前 chainRegion 出口，请检查 chainRegion 或代理组注入逻辑"
    );
  }
  // 媒体组已下放到独立阵列，不再验证 mediaTarget 互斥
  if (routingTargets.relayTarget === routingTargets.chainGroupName) {
    throw createUserError(
      "当前 chainRegion 跳板错误复用了家宽出口组，请检查地区代理组复用逻辑"
    );
  }
}

// 断言跳板组在节点/代理组中存在。
function assertRoutingTargetsExist(config, routingTargets) {
  if (!hasProxyOrGroup(config, routingTargets.relayTarget)) {
    throw createUserError(
      "当前 chainRegion 跳板不存在，请检查 chainRegion 和订阅代理组"
    );
  }
}

// 断言 dialer-proxy 绑定状态。
function assertDialerBindings(config, routingTargets) {
  var relayProxy = findProxyByName(config.proxies, BASE.nodeNames.relay);
  if (!relayProxy || relayProxy["dialer-proxy"] !== routingTargets.relayTarget) {
    throw createUserError(
      "家宽出口节点未正确绑定到当前 chainRegion 跳板，请检查代理链路注入逻辑"
    );
  }
  var transitProxy = findProxyByName(config.proxies, BASE.nodeNames.transit);
  if (!transitProxy || transitProxy["dialer-proxy"]) {
    throw createUserError(
      "官方中转节点状态异常，请检查 MiyaIP 凭证.js 和节点注入逻辑"
    );
  }
}

// 断言链式出口组 shape 与成员集合。
function assertChainGroupShape(config, chainGroupName) {
  var expectedMembers = [BASE.nodeNames.transit, BASE.nodeNames.relay];
  var chainGroup = findProxyGroupByName(config["proxy-groups"], chainGroupName);
  if (
    !chainGroup ||
    chainGroup.type !== "select" ||
    !haveSameStringSet(chainGroup.proxies || [], expectedMembers)
  ) {
    throw createUserError(
      "当前 chainRegion 的家宽出口组内容异常，请检查代理组注入逻辑"
    );
  }
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
  assertDialerBindings(config, routingTargets);
  assertChainGroupShape(config, routingTargets.chainGroupName);

  var ruleLineLookup = buildStringLookup(config.rules);
  var validationTargets = buildRoutingValidationTargets(derived);
  // 断言规则落在正确的 UI 分组中
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.strict, [UI_GROUPS.ai, UI_GROUPS.support, UI_GROUPS.integrations]);
  assertRuleTargetBatchExpanded(ruleLineLookup, shouldRouteBrowserToChain() ? validationTargets.browser : [], [UI_GROUPS.ai]);
  assertRuleTargetBatchExpanded(ruleLineLookup, validationTargets.media, [UI_GROUPS.video, UI_GROUPS.music, UI_GROUPS.social, UI_GROUPS.im]);
}

// ---------------------------------------------------------------------------
// 主流程入口
// ---------------------------------------------------------------------------

var CHAIN_PROXY_STATE_KEY = "_azChainProxyState";
var CHAIN_PROXY_STATE_VERSION = "10.1";

function buildChainProxyStateForOverride(derived) {
  return {
    version: CHAIN_PROXY_STATE_VERSION,
    derived: derived
  };
}

function buildRoutingValidationTargets(derived) {
  return {
    strict: buildDomainValidationTargets(derived.patterns.chain.all)
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

function takeChainProxyState(config, derivedOverride) {
  var chainState;
  if (derivedOverride) return buildChainProxyStateForOverride(derivedOverride);

  chainState = config[CHAIN_PROXY_STATE_KEY];
  if (!chainState || !chainState.derived) {
    throw createUserError(
      "缺少 DNS解析和域名嗅探.js 生成的 _azChainProxyState，请确认覆写顺序：DNS解析和域名嗅探 → MiyaIP 凭证（静态IP信息登记）→ 家宽IP-链式代理"
    );
  }
  if (chainState.version !== CHAIN_PROXY_STATE_VERSION) {
    throw createUserError(
      "DNS解析和域名嗅探.js 与 家宽IP-链式代理.js 版本不匹配，请同时更新两份脚本"
    );
  }

  delete config[CHAIN_PROXY_STATE_KEY];
  return chainState;
}

// 读取并移除 MiyaIP 凭证（防止泄漏到最终配置）。
function takeMiyaCredentials(config) {
  if (!config._miya) {
    throw createUserError(
      "缺少 config._miya，请确保 MiyaIP 凭证.js 已启用且排序在本脚本之前"
    );
  }
  var miyaCredentials = config._miya;
  delete config._miya; // 防止凭证输出到最终配置
  return miyaCredentials;
}

// 主入口。装配顺序：读取 DNS/Sniffer 派生状态 → 容器 → MiyaIP 节点 → 路由目标 → 规则 → 校验。
function main(config, derivedOverride) {
  var chainState = takeChainProxyState(config, derivedOverride);
  var derived = chainState.derived;
  var miyaCredentials = takeMiyaCredentials(config); // 先取出并隐藏凭证
  var routingTargets;

  writeContainers(config); // 初始化基础容器
  writeMiyaProxies(config, miyaCredentials); // 注入 MiyaIP 节点

  routingTargets = resolveRoutingTargets(
    config,
    USER_OPTIONS.chainRegion
  ); // 解析链路目标
  writeManagedRouting(config, routingTargets, derived); // 写入拨号与规则
  validateManagedRouting(config, routingTargets, derived); // 校验关键目标

  return config;
}
