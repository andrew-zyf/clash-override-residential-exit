const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const dnsSnifferScriptPath = path.join(__dirname, "..", "src", "DNS解析和域名嗅探.js");
const chainProxyScriptPath = path.join(__dirname, "..", "src", "家宽IP-链式代理.js");
const dnsSnifferScriptCode = fs.readFileSync(dnsSnifferScriptPath, "utf8");
const chainProxyScriptCode = fs.readFileSync(chainProxyScriptPath, "utf8");

const TEST_MIYA_CREDENTIALS = {
  username: "user",
  password: "pass",
  relay: { server: "1.2.3.4", port: 8000 },
  transit: { server: "transit.example.com", port: 8001 }
};

// ---------------------------------------------------------------------------
// Sandbox + config fixtures
// ---------------------------------------------------------------------------

function loadScriptSandbox(scriptCode, scriptPath) {
  const sandbox = { console, Object, Array, String, Error };
  vm.createContext(sandbox);
  vm.runInContext(scriptCode, sandbox, { filename: scriptPath });
  return sandbox;
}

function loadDnsSnifferSandbox() {
  return loadScriptSandbox(dnsSnifferScriptCode, dnsSnifferScriptPath);
}

function loadChainProxySandbox() {
  return loadScriptSandbox(chainProxyScriptCode, chainProxyScriptPath);
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function createBaseConfig() {
  return {
    proxies: [
      { name: "🇸🇬 SG Auto 01", type: "ss" },
      { name: "🇭🇰 HK Auto 01", type: "ss" },
      { name: "🇺🇸 US Auto 01", type: "ss" }
    ],
    "proxy-groups": [
      { name: "办公娱乐好帮手", type: "select", proxies: ["🇸🇬 SG Auto 01"] }
    ],
    rules: [
      "DOMAIN-SUFFIX,claude.ai,DIRECT",
      "DOMAIN-SUFFIX,tailscale.com,REJECT",
      "MATCH,办公娱乐好帮手"
    ],
    _miya: JSON.parse(JSON.stringify(TEST_MIYA_CREDENTIALS))
  };
}

function runMain(configMutator, sandboxMutator) {
  const config = createBaseConfig();
  if (typeof configMutator === "function") configMutator(config);

  const dnsSandbox = loadDnsSnifferSandbox();
  dnsSandbox.main(config);
  const chainState = cloneJson(config._azChainProxyState);
  const dnsBase = cloneJson(dnsSandbox.BASE.dns);

  const sandbox = loadChainProxySandbox();
  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);
  return { sandbox, state: chainState, dnsBase, output: sandbox.main(config) };
}

// ---------------------------------------------------------------------------
// Derive canonical group names / process lists from sandbox metadata
// ---------------------------------------------------------------------------

function regionGroupName(sandbox, regionKey, suffix) {
  var meta = sandbox.resolveRegionMeta(regionKey, true);
  return sandbox.buildRegionGroupName(meta, suffix);
}

function expectedGroupNames(sandbox) {
  const suffix = sandbox.BASE.groupNameSuffixes;
  const opt = sandbox.USER_OPTIONS;
  return {
    relay: regionGroupName(sandbox, opt.chainRegion, suffix.base),
    chainTarget: sandbox.BASE.chainGroupName,
    usRegion: regionGroupName(sandbox, "US", suffix.base)
  };
}

function derivedBrowserProcessNames(state) {
  return state.derived.processNames.browser.slice();
}

function derivedAiCliProcessNames(state) {
  return state.derived.processNames.aiCli.slice();
}

// ---------------------------------------------------------------------------
// Rule and proxy helpers
// ---------------------------------------------------------------------------

function ruleIdentity(ruleLine) {
  const firstComma = ruleLine.indexOf(",");
  const secondComma = ruleLine.indexOf(",", firstComma + 1);
  return ruleLine.slice(0, secondComma);
}

function assertNoDuplicateRuleIdentities(ruleLines) {
  const seen = new Set();
  for (const line of ruleLines) {
    const id = ruleIdentity(line);
    if (line.indexOf("mineru") >= 0) console.log("MINERU RULE: ", line);
    assert(!seen.has(id), "Duplicate managed rule identity: " + id);
    seen.add(id);
  }
}

function assertRulesExist(ruleLines, expected) {
  for (const line of expected) {
    assert(ruleLines.includes(line), "Expected rule not found: " + line);
  }
}

function assertRulesMissing(ruleLines, unexpected) {
  for (const line of unexpected) {
    assert(!ruleLines.includes(line), "Unexpected rule found: " + line);
  }
}

function assertRuleAppearsBefore(ruleLines, earlier, later) {
  const earlierIndex = ruleLines.indexOf(earlier);
  const laterIndex = ruleLines.indexOf(later);
  assert(earlierIndex >= 0, "Expected rule not found: " + earlier);
  assert(laterIndex >= 0, "Expected rule not found: " + later);
  assert(earlierIndex < laterIndex, "Expected rule order: " + earlier + " before " + later);
}

function assertProcessRules(output, enabled, processNames, target) {
  const lines = processNames.map((p) => "PROCESS-NAME," + p + "," + target);
  if (enabled) assertRulesExist(output.rules, lines);
  else assertRulesMissing(output.rules, lines);
}

function findGroup(output, name) {
  return output["proxy-groups"].find((g) => g.name === name);
}

function findProxy(output, name) {
  return output.proxies.find((p) => p.name === name);
}

function assertNameserverPolicyValues(output, domains, expected) {
  for (const domain of domains) {
    assert.deepEqual(output.dns["nameserver-policy"][domain], expected);
  }
}

function assertIncludes(values, expected, label) {
  for (const v of expected) {
    assert(values.includes(v), label + " missing: " + v);
  }
}

function assertExcludes(values, excluded, label) {
  for (const v of excluded) {
    assert(!values.includes(v), label + " unexpectedly contains: " + v);
  }
}

function sameSet(a, b) {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((v) => set.has(v));
}

// ---------------------------------------------------------------------------
// Structural assertions (derived from sandbox metadata)
// ---------------------------------------------------------------------------

function assertManagedProxyTopology(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  const nodeNames = sandbox.BASE.nodeNames;

  const relayProxy = findProxy(output, nodeNames.relay);
  const transitProxy = findProxy(output, nodeNames.transit);

  assert(relayProxy, "relay proxy missing");
  assert.strictEqual(relayProxy.type, "http");
  assert.strictEqual(relayProxy.server, TEST_MIYA_CREDENTIALS.relay.server);
  assert.strictEqual(relayProxy.port, TEST_MIYA_CREDENTIALS.relay.port);
  assert.strictEqual(relayProxy["dialer-proxy"], names.relay);

  assert(transitProxy, "transit proxy missing");
  assert.strictEqual(transitProxy.type, "http");
  assert.strictEqual(transitProxy.server, TEST_MIYA_CREDENTIALS.transit.server);
  assert.strictEqual(transitProxy["dialer-proxy"], undefined);

  const relayGroup = findGroup(output, names.relay);
  assert(relayGroup, "relay group missing");
  assert.strictEqual(relayGroup.type, "url-test");
  assert.deepEqual(relayGroup.proxies, ["🇸🇬 SG Auto 01"]);

  const chainGroup = findGroup(output, names.chainTarget);
  assert(chainGroup, "chain group missing");
  assert.strictEqual(chainGroup.type, "select");
  assert(sameSet(chainGroup.proxies, [nodeNames.transit, nodeNames.relay]),
    "chain group members mismatch");

  const uiGroupAi = findGroup(output, sandbox.UI_GROUPS.ai);
  assert(uiGroupAi, "UI group AI missing");
  assert.deepEqual(uiGroupAi.proxies, [names.chainTarget]);

  const usGroup = findGroup(output, names.usRegion);
  assert(usGroup, "US region group missing");
  assert.strictEqual(usGroup.type, "url-test");
  assert.deepEqual(usGroup.proxies, ["🇺🇸 US Auto 01"]);

  const nodeSelection = findGroup(output, sandbox.BASE.groupNames.nodeSelection);
  assert(nodeSelection, "node selection group missing");
  assertIncludes(
    nodeSelection.proxies,
    ["🇸🇬 SG Auto 01", names.relay, names.usRegion],
    "node selection includes"
  );
}

// EXPECTED_ROUTES sample → rule lines
function sampleRuleLines(sample, target) {
  const lines = [];
  for (const d of sample.domains || []) lines.push("DOMAIN-SUFFIX," + d + "," + target);
  for (const p of sample.processNames || []) lines.push("PROCESS-NAME," + p + "," + target);
  for (const p of sample.cliNames || []) lines.push("PROCESS-NAME," + p + "," + target);
  return lines;
}

function assertCoreStrictRouting(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  
  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,claude.ai," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,chatgpt.com," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,gemini.google.com," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,perplexity.ai," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,google.com," + sandbox.UI_GROUPS.support,
    "DOMAIN-SUFFIX,cursor.sh," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,arkoselabs.com," + sandbox.UI_GROUPS.integrations,
    "DOMAIN-SUFFIX,stripe.com," + sandbox.UI_GROUPS.integrations,
    "DOMAIN-SUFFIX,statsig.com," + sandbox.UI_GROUPS.integrations,
    "DOMAIN-SUFFIX,githubusercontent.com," + sandbox.UI_GROUPS.support,
    "DOMAIN-SUFFIX,npmjs.org," + sandbox.UI_GROUPS.support,
    "PROCESS-NAME,Claude," + sandbox.UI_GROUPS.ai,
    "PROCESS-NAME,claude," + sandbox.UI_GROUPS.ai,
    "PROCESS-NAME,codex," + sandbox.UI_GROUPS.ai
  ]);

  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,meta.ai," + sandbox.UI_GROUPS.ai
  ]);
  assertRulesMissing(output.rules, ["DOMAIN-SUFFIX,claude.ai,DIRECT"]);
  assertRulesMissing(output.rules, ["DOMAIN-SUFFIX,meta.ai,DIRECT"]);
}

function assertMediaRouting(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  
  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,youtube.com," + sandbox.UI_GROUPS.video,
    "DOMAIN-SUFFIX,x.com," + sandbox.UI_GROUPS.social,
    "DOMAIN-SUFFIX,twitch.tv," + sandbox.UI_GROUPS.video,
    "DOMAIN-SUFFIX,spotify.com," + sandbox.UI_GROUPS.music,
    "DOMAIN-SUFFIX,line.me," + sandbox.UI_GROUPS.im,
    "DOMAIN-SUFFIX,whatsapp.com," + sandbox.UI_GROUPS.im
  ]);

  
  assertRulesMissing(output.rules, [
    "DOMAIN-SUFFIX,youtube.com," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,x.com," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,twitch.tv," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,spotify.com," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,line.me," + sandbox.UI_GROUPS.ai,
    "DOMAIN-SUFFIX,whatsapp.com," + sandbox.UI_GROUPS.ai
  ]);

}

function assertBrowserRouting(output, sandbox, state) {
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, true, derivedBrowserProcessNames(state), sandbox.UI_GROUPS.ai);
  // 受管浏览器不应被误路由到媒体目标
  assertProcessRules(output, false, derivedBrowserProcessNames(state), names.media);
  // 未列入源的浏览器不应出现
  assertProcessRules(output, false, ["Google Chrome", "Arc", "Microsoft Edge", "Safari"], sandbox.UI_GROUPS.ai);
}

function assertBrowserRoutingPriority(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  const browserRule = "PROCESS-NAME,Dia," + sandbox.UI_GROUPS.ai;
  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,youtube.com," + sandbox.UI_GROUPS.video, browserRule);
  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,tailscale.com,DIRECT", browserRule);
  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,docs.qq.com,DIRECT", browserRule);
}

function assertDomesticDirectCoverage(output, dnsBase) {
  const officeDomains = ["+.docs.qq.com", "+.dingtalk.com", "+.feishu.cn", "+.wps.cn"];
  const cloudDomains = ["+.aliyuncs.com"];
  assertRulesExist(output.rules, officeDomains.map((d) =>
    "DOMAIN-SUFFIX," + d.replace("+.", "") + ",DIRECT"
  ));
  assertRulesExist(output.rules, cloudDomains.map((d) =>
    "DOMAIN-SUFFIX," + d.replace("+.", "") + ",DIRECT"
  ));
  // 办公软件走域名规则，不应出现进程直连
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,WeChat,DIRECT",
    "PROCESS-NAME,DingTalk,DIRECT",
    "PROCESS-NAME,Feishu,DIRECT"
  ]);
  assertNameserverPolicyValues(output, officeDomains, dnsBase.domestic);
  assertNameserverPolicyValues(output, cloudDomains, dnsBase.domestic);
}

function assertOverseasAppDirectCoverage(output, dnsBase) {
  const overseasAppDomains = ["+.tailscale.com", "+.tailscale.io", "+.ts.net"];
  assertRulesExist(output.rules, [
    "DOMAIN-SUFFIX,tailscale.com,DIRECT",
    "DOMAIN-SUFFIX,tailscale.io,DIRECT",
    "DOMAIN-SUFFIX,ts.net,DIRECT",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR,100.100.100.100/32,DIRECT,no-resolve",
    "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve"
  ]);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,Tailscale,DIRECT",
    "PROCESS-NAME,tailscale,DIRECT"
  ]);
  assertNameserverPolicyValues(output, overseasAppDomains, dnsBase.overseas);
  assertIncludes(output.dns["fallback-filter"].domain, overseasAppDomains, "fallback-filter.domain");
  assertIncludes(output.sniffer["skip-domain"], overseasAppDomains, "sniffer.skip-domain");
  assertExcludes(output.dns["fake-ip-filter"], ["+.tailscale.com"], "fake-ip-filter");
}

function assertOverseasDohDirectCoverage(output, dnsBase) {
  const domains = [
    "+.immersivetranslate.com",
    "+.mineru.org.cn"
  ];
  assertRulesExist(output.rules, domains.map((d) =>
    "DOMAIN-SUFFIX," + d.replace("+.", "") + ",DIRECT"
  ));
  assertNameserverPolicyValues(output, domains, dnsBase.overseas);
  assertIncludes(output.dns["fallback-filter"].domain, domains, "fallback-filter.domain");
  assertIncludes(output.sniffer["skip-domain"], domains, "sniffer.skip-domain");
}

function assertDnsAndSniffer(output, dnsBase) {
  assertNameserverPolicyValues(
    output,
    ["+.sora.com", "+.notebooklm.google", "+.m365.cloud.microsoft", "+.meta.ai"],
    dnsBase.overseas
  );
  assertNameserverPolicyValues(output, ["+.push.apple.com"], dnsBase.domestic);
  assertIncludes(output.dns["fake-ip-filter"], ["+.push.apple.com", "+.xboxlive.com", "stun.*.*"], "fake-ip-filter");
  assertIncludes(output.dns["fallback-filter"].domain, ["+.sora.com", "+.youtube.com", "+.meta.ai"], "fallback-filter.domain");
  assertIncludes(output.sniffer["force-domain"], ["+.claude.ai", "+.google.com"], "sniffer.force-domain");
  assertIncludes(output.sniffer["skip-domain"], ["+.push.apple.com"], "sniffer.skip-domain");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

function testDefaultConfig() {
  const { sandbox, state, dnsBase, output } = runMain();
  assert.strictEqual(sandbox.USER_OPTIONS.routeBrowserToChain, true);
  assert.strictEqual(output._miya, undefined);
  assert.strictEqual(output._azChainProxyState, undefined);
  assertManagedProxyTopology(output, sandbox);
  assertCoreStrictRouting(output, sandbox);
  assertMediaRouting(output, sandbox);
  assertBrowserRouting(output, sandbox, state);
  assertBrowserRoutingPriority(output, sandbox);
  assertDomesticDirectCoverage(output, dnsBase);
  assertOverseasAppDirectCoverage(output, dnsBase);
  assertOverseasDohDirectCoverage(output, dnsBase);
  assertDnsAndSniffer(output, dnsBase);
  assertNoDuplicateRuleIdentities(output.rules.slice(0, 250));
}

function testChainProxyRequiresDnsSnifferState() {
  const sandbox = loadChainProxySandbox();
  assert.throws(() => sandbox.main(createBaseConfig()), /缺少 DNS解析和域名嗅探/);
}

function testChainProxyRejectsMismatchedDnsSnifferState() {
  const config = createBaseConfig();
  const dnsSandbox = loadDnsSnifferSandbox();
  dnsSandbox.main(config);
  config._azChainProxyState.version = "0.0";

  const sandbox = loadChainProxySandbox();
  assert.throws(() => sandbox.main(config), /版本不匹配/);
}

function testDisableBrowserProcessProxy() {
  const { sandbox, state, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.routeBrowserToChain = false;
  });
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, false, derivedBrowserProcessNames(state), sandbox.UI_GROUPS.ai);
}

function testAiCliProcessProxyDefaultsOn() {
  const { sandbox, state, output } = runMain();
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, true, derivedAiCliProcessNames(state), sandbox.UI_GROUPS.ai);
  assertProcessRules(output, false, ["opencode"], sandbox.UI_GROUPS.ai);
}

function testAiCliProcessProxyAlwaysOn() {
  const { sandbox, state, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.routeBrowserToChain = false;
  });
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, true, derivedAiCliProcessNames(state), sandbox.UI_GROUPS.ai);
}

function testOnlyAiAndBrowserProcessesAreManaged() {
  const { sandbox, output } = runMain();
  const names = expectedGroupNames(sandbox);
  assertProcessRules(output, false, ["Google Chrome", "Google Drive", "Visual Studio Code"], sandbox.UI_GROUPS.ai);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,WeChat,DIRECT",
    "PROCESS-NAME,Tailscale,DIRECT"
  ]);
}

function testMissingRegionFails() {
  const dnsSandbox = loadDnsSnifferSandbox();
  const config = createBaseConfig();
  dnsSandbox.main(config);
  const sandbox = loadChainProxySandbox();
  sandbox.USER_OPTIONS.chainRegion = "JP";
  sandbox.BASE.regionFallbackOrder.chain = [];
  assert.throws(() => sandbox.main(config), /未找到可用的 chainRegion 节点/);
}

// testMissingMediaRegionFails removed – mediaRegion config no longer exists

function testChainRegionFallsBackToAvailableRegion() {
  const { sandbox, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.chainRegion = "JP";
  });
  const suffix = sandbox.BASE.groupNameSuffixes;
  const fallbackRelay = regionGroupName(sandbox, "SG", suffix.base);
  const fallbackChain = sandbox.BASE.chainGroupName;
  assert(findGroup(output, fallbackRelay), "fallback relay group missing");
  assert(findGroup(output, fallbackChain), "fallback chain group missing");
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.relay)["dialer-proxy"], fallbackRelay);
}

// testMediaRegionFallsBackToAvailableRegion removed – mediaRegion config no longer exists

function testMissingStrictTargetFails() {
  const dnsSandbox = loadDnsSnifferSandbox();
  const config = createBaseConfig();
  dnsSandbox.main(config);
  const sandbox = loadChainProxySandbox();
  const original = sandbox.resolveRoutingTargets;
  sandbox.resolveRoutingTargets = (config, chainRegion) => {
    const rt = original(config, chainRegion);
    rt.strictAiTarget = "错误目标";
    return rt;
  };
  assert.throws(() => sandbox.main(config),
    /域外 AI 与支撑平台未直接指向当前 chainRegion 出口/);
}

function testExistingManagedObjectsAreReconciled() {
  const { sandbox, output } = runMain((config) => {
    const base = loadChainProxySandbox().BASE;
    const nodeNames = base.nodeNames;
    const suffix = base.groupNameSuffixes;

    config.proxies.push({
      name: nodeNames.relay, type: "http", server: "bad", port: 1,
      username: "bad", password: "bad", udp: false, "dialer-proxy": "错误目标"
    });
    config.proxies.push({
      name: nodeNames.transit, type: "http", server: "bad", port: 2,
      username: "bad", password: "bad", udp: false, "dialer-proxy": "错误目标"
    });
    config["proxy-groups"].push({ name: "SG" + suffix.base, type: "select", proxies: [base.chainGroupName] });
    config["proxy-groups"].push({ name: base.chainGroupName, type: "select", proxies: ["DIRECT"] });
    config["proxy-groups"].push({ name: "US" + suffix.base, type: "select", proxies: ["DIRECT"] });
  });
  assertManagedProxyTopology(output, sandbox);
}

function testChainGroupIsNotReusedAsRelayTarget() {
  const { sandbox, output } = runMain((config) => {
    const base = loadChainProxySandbox().BASE;
    const chainName = base.chainGroupName;
    config["proxy-groups"].push({
      name: chainName, type: "select",
      proxies: [base.nodeNames.transit, base.nodeNames.relay]
    });
  });
  assertManagedProxyTopology(output, sandbox);
}

function testBadExternalRegionGroupIsNotReused() {
  const { sandbox, output } = runMain((config) => {
    config["proxy-groups"].push({
      name: "🇸🇬 错误地区组", type: "select", proxies: ["DIRECT"]
    });
  });
  assertManagedProxyTopology(output, sandbox);
}

function testNodeSelectionKeepsOnlyCurrentRelayGroup() {
  const { sandbox, output } = runMain((config) => {
    const base = loadChainProxySandbox().BASE;
    const staleRelay = "HK" + base.groupNameSuffixes.relaySuffix;
    config["proxy-groups"][0].proxies = ["🇸🇬 SG Auto 01", staleRelay];
  });
  assertManagedProxyTopology(output, sandbox);
}

function testRepeatedRunDoesNotCreateSelfReference() {
  const first = runMain();
  const rerunInput = JSON.parse(JSON.stringify(first.output));
  rerunInput._miya = JSON.parse(JSON.stringify(TEST_MIYA_CREDENTIALS));
  const dnsSandbox = loadDnsSnifferSandbox();
  dnsSandbox.main(rerunInput);
  const sandbox = loadChainProxySandbox();
  const second = sandbox.main(rerunInput);
  const names = expectedGroupNames(sandbox);

  assertManagedProxyTopology(second, sandbox);
  for (const name of [names.chainTarget, names.relay, names.usRegion]) {
    const count = second["proxy-groups"].filter((g) => g.name === name).length;
    assert.strictEqual(count, 1, "duplicate group after rerun: " + name);
  }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const tests = [
  testDefaultConfig,
  testChainProxyRequiresDnsSnifferState,
  testChainProxyRejectsMismatchedDnsSnifferState,
  testDisableBrowserProcessProxy,
  testAiCliProcessProxyDefaultsOn,
  testAiCliProcessProxyAlwaysOn,
  testOnlyAiAndBrowserProcessesAreManaged,
  testChainRegionFallsBackToAvailableRegion,
  testMissingRegionFails,
  testMissingStrictTargetFails,
  testExistingManagedObjectsAreReconciled,
  testChainGroupIsNotReusedAsRelayTarget,
  testBadExternalRegionGroupIsNotReused,
  testNodeSelectionKeepsOnlyCurrentRelayGroup,
  testRepeatedRunDoesNotCreateSelfReference
];

for (const test of tests) {
  test();
}

console.log("validate.js: " + tests.length + " checks passed");
