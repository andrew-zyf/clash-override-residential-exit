// 链式代理覆写 — 合并测试套件
//
// 测试 residential-chain-proxy-combined.js 的纯函数与端到端行为。
// 运行：node tests/test.js

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const combinedPath = path.join(__dirname, "..", "src", "residential-chain-proxy-combined.js");
const combinedCode = fs.readFileSync(combinedPath, "utf8");

const TEST_MIYA_CREDENTIALS = {
  username: "user",
  password: "pass",
  relay: { server: "1.2.3.4", port: 8000 },
  transit: { server: "transit.example.com", port: 8001 }
};

// ---------------------------------------------------------------------------
// Sandbox helpers
// ---------------------------------------------------------------------------

function loadCombinedSandbox() {
  const sandbox = { console, Object, Array, String, Error };
  vm.createContext(sandbox);
  vm.runInContext(combinedCode, sandbox, { filename: combinedPath });
  return sandbox;
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
    ]
  };
}

// Run the combined main with optional config/sandbox mutations.
// sandboxMutator receives the sandbox before main() — use it to override
// MIYA_CREDENTIALS / USER_OPTIONS on the sandbox object.
function runMain(configMutator, sandboxMutator) {
  const sandbox = loadCombinedSandbox();
  // Apply default test credentials
  sandbox.MIYA_CREDENTIALS = cloneJson(TEST_MIYA_CREDENTIALS);
  if (typeof sandboxMutator === "function") sandboxMutator(sandbox);

  let config = createBaseConfig();
  if (typeof configMutator === "function") {
    config = configMutator(config, sandbox) || config;
  }

  const output = sandbox.main(config);
  return {
    sandbox: sandbox,
    state: { derived: cloneJson(sandbox.DNS_SNIFFER_MODULE.DERIVED) },
    dnsBase: cloneJson(sandbox.DNS_SNIFFER_MODULE.BASE.dns),
    output: output
  };
}

// ---------------------------------------------------------------------------
// Canonical group names / process lists from sandbox metadata
// ---------------------------------------------------------------------------

function regionGroupName(sandbox, regionKey, suffix) {
  var meta = sandbox.resolveRegionMeta(regionKey, true);
  return sandbox.buildRegionGroupName(meta, suffix);
}

function expectedGroupNames(sandbox) {
  const suffix = sandbox.BASE.groupNameSuffixes;
  return {
    relay: regionGroupName(sandbox, "SG", suffix.base),
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

function assertRuleIdentitiesMissing(ruleLines, unexpectedIdentities) {
  const identities = ruleLines.map(ruleIdentity);
  for (const identity of unexpectedIdentities) {
    assert(!identities.includes(identity), "Unexpected rule identity found: " + identity);
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

// ===========================================================================
// Pure function unit tests
// ===========================================================================

// Load a baseline sandbox for unit tests
const S = loadCombinedSandbox();

// ---- toSuffix ----
function testToSuffix() {
  assert.strictEqual(S.toSuffix("+.claude.ai"), "claude.ai");
  assert.strictEqual(S.toSuffix("+.google.com"), "google.com");
  assert.strictEqual(S.toSuffix("claude.ai"), "claude.ai");
  assert.strictEqual(S.toSuffix("+."), "");
  assert.strictEqual(S.toSuffix(""), "");
  console.log("  PASS toSuffix");
}

// ---- uniqueStrings ----
function testUniqueStrings() {
  const a = (v) => Array.prototype.slice.call(v);
  assert.deepStrictEqual(a(S.uniqueStrings(["a", "b", "a", "c"])), ["a", "b", "c"]);
  assert.deepStrictEqual(a(S.uniqueStrings([])), []);
  assert.deepStrictEqual(a(S.uniqueStrings(["x"])), ["x"]);
  assert.deepStrictEqual(a(S.uniqueStrings(["a", "a", "a"])), ["a"]);
  console.log("  PASS uniqueStrings");
}

// ---- buildStringLookup ----
function testBuildStringLookup() {
  const lookup = S.buildStringLookup(["a", "b", "c"]);
  assert.strictEqual(lookup["a"], true);
  assert.strictEqual(lookup["b"], true);
  assert.strictEqual(lookup["c"], true);
  assert.strictEqual(lookup["d"], undefined);
  assert.strictEqual(Object.keys(S.buildStringLookup([])).length, 0);
  console.log("  PASS buildStringLookup");
}

// ---- createUserError ----
function testCreateUserError() {
  const err = S.createUserError("test message");
  assert(err instanceof Error);
  assert.strictEqual(err.message, "test message");
  console.log("  PASS createUserError");
}

// ---- normalizeOverrideMode ----
function testNormalizeOverrideMode() {
  assert.strictEqual(S.normalizeOverrideMode("merged"), "merged");
  assert.strictEqual(S.normalizeOverrideMode("dns-sniffer-only"), "dns-sniffer-only");
  assert.strictEqual(S.normalizeOverrideMode("option-b"), "merged");
  assert.strictEqual(S.normalizeOverrideMode("optiona"), "dns-sniffer-only");
  assert.strictEqual(S.normalizeOverrideMode("full"), "merged");
  assert.strictEqual(S.normalizeOverrideMode("dns"), "dns-sniffer-only");
  assert.strictEqual(S.normalizeOverrideMode(undefined), "merged");
  assert.strictEqual(S.normalizeOverrideMode(null), "merged");
  assert.strictEqual(S.normalizeOverrideMode(""), "merged");
  assert.throws(() => S.normalizeOverrideMode("invalid"), /未知/);
  assert.throws(() => S.normalizeOverrideMode(123), /必须是字符串/);
  console.log("  PASS normalizeOverrideMode");
}

// ---- script version marker ----
function testVersionSingleDefinition() {
  assert(combinedCode.includes("// @version 11.7"), "Expected @version 11.7");
  const versionLines = combinedCode.split('\n').filter((l) =>
    l.includes("@version ") || l.includes("CHAIN_PROXY_STATE_VERSION")
  );
  assert.strictEqual(versionLines.length, 1, "Expected one script version marker");
  console.log("  PASS single version definition");
}

// ---- FAKE_IP_BYPASS structure ----
function testFakeIpBypassConstant() {
  const bip = S.DNS_SNIFFER_MODULE.FAKE_IP_BYPASS;
  assert(bip, "FAKE_IP_BYPASS missing");
  assert(Array.isArray(bip.localNetwork));
  assert(Array.isArray(bip.timeSync));
  assert(Array.isArray(bip.connectivityTest));
  assert(Array.isArray(bip.gamingRealtime));
  assert(Array.isArray(bip.stunRealtime));
  assert(Array.isArray(bip.homeRouter));
  assert(bip.localNetwork.includes("+.push.apple.com"));
  assert(bip.timeSync.includes("ntp.*.com"));
  assert(bip.stunRealtime.includes("stun.*.*"));
  console.log("  PASS FAKE_IP_BYPASS");
}

// ---- DNS config output via dns-sniffer-only mode ----
function testDnsConfigContainsFakeIpBypass() {
  const sandbox = loadCombinedSandbox();
  sandbox.USER_OPTIONS.overrideMode = "dns-sniffer-only";
  sandbox.MIYA_CREDENTIALS = {
    username: "", password: "",
    relay: { server: "", port: 8022 },
    transit: { server: "", port: 8001 }
  };
  const baseCfg = { proxies: [], "proxy-groups": [], rules: [] };
  const output = sandbox.main(baseCfg);

  const fif = output.dns["fake-ip-filter"];
  assert(Array.isArray(fif), "fake-ip-filter should be array");
  assert(fif.includes("+.push.apple.com"), "should contain push.apple.com");
  assert(fif.includes("ntp.*.com"), "should contain ntp wildcard");
  assert(fif.includes("stun.*.*"), "should contain stun wildcard");
  assert(fif.includes("+.xboxlive.com"), "should contain xboxlive");
  assert.strictEqual(output._miya, undefined);
  console.log("  PASS DNS config fake-ip-filter");
}

// ---- hasConfiguredMiyaCredentials port validation ----
function testHasConfiguredMiyaCredentialsPort() {
  const fn = S.hasConfiguredMiyaCredentials;
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 1 },
    transit: { server: "5.6.7.8", port: 65535 }
  }), true);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 8080 },
    transit: { server: "5.6.7.8", port: 443 }
  }), true);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 0 },
    transit: { server: "5.6.7.8", port: 443 }
  }), false);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: -1 },
    transit: { server: "5.6.7.8", port: 443 }
  }), false);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 8080 },
    transit: { server: "5.6.7.8", port: 65536 }
  }), false);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: "8080" },
    transit: { server: "5.6.7.8", port: 443 }
  }), false);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 8080 },
    transit: { server: "5.6.7.8", port: "abc" }
  }), false);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4" },
    transit: { server: "5.6.7.8", port: 443 }
  }), false);
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 8080 },
    transit: { server: "5.6.7.8", port: null }
  }), false);
  console.log("  PASS hasConfiguredMiyaCredentials port validation");
}

// ---- validProxyTypes constant ----
function testValidProxyTypesConstant() {
  const types = S.BASE.validProxyTypes;
  assert(Array.isArray(types), "validProxyTypes should be an array");
  assert(types.includes("http"), "validProxyTypes must include http");
  assert(types.includes("https"), "validProxyTypes must include https");
  assert(types.includes("socks5"), "validProxyTypes must include socks5");
  console.log("  PASS validProxyTypes constant");
}

// ---- buildMiyaProxy type validation ----
function testBuildMiyaProxyTypeValidation() {
  const proxy = S.buildMiyaProxy(
    { username: "u", password: "p" },
    "test-proxy",
    { server: "1.2.3.4", port: 8080 }
  );
  assert.strictEqual(proxy.type, "http");
  assert.strictEqual(proxy.name, "test-proxy");
  assert.strictEqual(proxy.server, "1.2.3.4");
  assert.strictEqual(proxy.port, 8080);
  assert.strictEqual(proxy.udp, true);

  var saved = S.BASE.validProxyTypes;
  var httpIdx = S.BASE.validProxyTypes.indexOf("http");
  S.BASE.validProxyTypes.splice(httpIdx, 1);
  try {
    S.buildMiyaProxy(
      { username: "u", password: "p" },
      "test-proxy",
      { server: "1.2.3.4", port: 8080 }
    );
    assert.fail("Expected buildMiyaProxy to throw when http is not in validProxyTypes");
  } catch (e) {
    assert(e.message.indexOf("http 不在") >= 0, "Expected error about invalid proxy type");
  }
  S.BASE.validProxyTypes = saved;
  console.log("  PASS buildMiyaProxy type validation");
}

// ===========================================================================
// Integration tests (ported from validate.js)
// ===========================================================================

// ---- Structural assertions ----

function assertManagedProxyTopology(output, sandbox) {
  const names = expectedGroupNames(sandbox);
  const nodeNames = sandbox.BASE.nodeNames;

  const relayProxy = findProxy(output, nodeNames.relay);
  assert(relayProxy, "relay proxy missing");
  assert.strictEqual(relayProxy.type, "http");
  assert.strictEqual(relayProxy.server, TEST_MIYA_CREDENTIALS.relay.server);
  assert.strictEqual(relayProxy.port, TEST_MIYA_CREDENTIALS.relay.port);
  assert.strictEqual(relayProxy["dialer-proxy"], names.relay);

  const transitProxy = findProxy(output, nodeNames.transit);
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

function assertCoreStrictRouting(output, sandbox) {
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
  assertProcessRules(output, true, derivedBrowserProcessNames(state), sandbox.UI_GROUPS.ai);
  assertProcessRules(output, false, ["Google Chrome", "Arc", "Microsoft Edge", "Safari"], sandbox.UI_GROUPS.ai);
}

function assertBrowserRoutingPriority(output, sandbox) {
  const browserRule = "PROCESS-NAME,Dia," + sandbox.UI_GROUPS.ai;
  const aiAppRule = "PROCESS-NAME,Claude," + sandbox.UI_GROUPS.ai;
  const aiCliRule = "PROCESS-NAME,codex," + sandbox.UI_GROUPS.ai;
  const geositeCnRule = "GEOSITE,cn,DIRECT";
  const geoipCnRule = "GEOIP,CN,DIRECT";
  const matchRule = "MATCH,办公娱乐好帮手";

  assertRulesExist(output.rules, [geositeCnRule, geoipCnRule]);

  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,claude.ai," + sandbox.UI_GROUPS.ai, geositeCnRule);
  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,youtube.com," + sandbox.UI_GROUPS.video, geositeCnRule);
  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,docs.qq.com,DIRECT", geositeCnRule);
  assertRuleAppearsBefore(output.rules, geositeCnRule, geoipCnRule);

  assertRuleAppearsBefore(output.rules, geositeCnRule, aiAppRule);
  assertRuleAppearsBefore(output.rules, geoipCnRule, aiCliRule);
  assertRuleAppearsBefore(output.rules, geositeCnRule, browserRule);
  assertRuleAppearsBefore(output.rules, geoipCnRule, browserRule);

  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,youtube.com," + sandbox.UI_GROUPS.video, browserRule);
  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,tailscale.com,DIRECT", browserRule);
  assertRuleAppearsBefore(output.rules, "DOMAIN-SUFFIX,docs.qq.com,DIRECT", browserRule);
  assertRuleAppearsBefore(output.rules, geositeCnRule, matchRule);
  assertRuleAppearsBefore(output.rules, geoipCnRule, matchRule);

  assertRulesMissing(output.rules, [
    "DOMAIN-KEYWORD,stun," + sandbox.UI_GROUPS.ai,
    "DOMAIN-KEYWORD,turn," + sandbox.UI_GROUPS.ai
  ]);
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
  const domains = ["+.immersivetranslate.com", "+.mineru.org.cn"];
  assertRulesExist(output.rules, domains.map((d) =>
    "DOMAIN-SUFFIX," + d.replace("+.", "") + ",DIRECT"
  ));
  assertNameserverPolicyValues(output, domains, dnsBase.overseas);
  assertIncludes(output.dns["fallback-filter"].domain, domains, "fallback-filter.domain");
  assertIncludes(output.sniffer["skip-domain"], domains, "sniffer.skip-domain");
}

function assertDnsAndSniffer(output, dnsBase) {
  assertNameserverPolicyValues(output, [dnsBase.domesticGeosite], dnsBase.domestic);
  assertNameserverPolicyValues(output, [dnsBase.overseasGeosite], dnsBase.overseas);
  assert.strictEqual(output.dns["nameserver-policy"]["geosite:openai"], undefined);

  assertNameserverPolicyValues(
    output,
    [
      "+.openai.com", "+.chatgpt.com", "+.sora.com", "+.oaiusercontent.com",
      "+.oaistatic.com", "+.claude.ai", "+.anthropic.com", "+.notebooklm.google",
      "+.m365.cloud.microsoft", "+.meta.ai"
    ],
    dnsBase.overseas
  );
  assertNameserverPolicyValues(
    output,
    ["+.push.apple.com", "+.cnnic.cn", "+.12306.cn"],
    dnsBase.domestic
  );
  assertNameserverPolicyValues(output, ["+.iana.org", "+.ietf.org"], dnsBase.overseas);

  assertIncludes(output.dns["fake-ip-filter"], ["+.push.apple.com", "+.xboxlive.com", "stun.*.*"], "fake-ip-filter");
  assertIncludes(
    output.dns["fallback-filter"].domain,
    ["+.sora.com", "+.youtube.com", "+.meta.ai", "+.iana.org", "+.ietf.org"],
    "fallback-filter.domain"
  );
  assertIncludes(
    output.sniffer["force-domain"],
    ["+.openai.com", "+.chatgpt.com", "+.claude.ai", "+.anthropic.com", "+.cloudflare.com"],
    "sniffer.force-domain"
  );
  assertExcludes(
    output.sniffer["force-domain"],
    ["+", "geosite:cn", "geosite:geolocation-!cn", "geosite:openai"],
    "sniffer.force-domain"
  );
  assertIncludes(
    output.sniffer["skip-domain"],
    ["+.push.apple.com", "+.tailscale.com", "+.plex.tv", "+.mineru.org.cn"],
    "sniffer.skip-domain"
  );

  assertRuleIdentitiesMissing(output.rules, [
    "DOMAIN-SUFFIX,cnnic.cn",
    "DOMAIN-SUFFIX,12306.cn",
    "DOMAIN-SUFFIX,iana.org",
    "DOMAIN-SUFFIX,ietf.org"
  ]);
}

// ---- Integration test cases ----

function testDefaultConfig() {
  const { sandbox, state, dnsBase, output } = runMain();
  assert.strictEqual(output._azChainProxyState, undefined);
  assert.strictEqual(output._azChainProxyUserConfig, undefined);
  assert.strictEqual(output._miya, undefined);
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

function testRequiresConfiguredMiyaCredentials() {
  assert.throws(() => runMain(null, (sb) => {
    sb.MIYA_CREDENTIALS = {
      username: "", password: "",
      relay: { server: "", port: 8022 },
      transit: { server: "", port: 8001 }
    };
  }), /MiyaIP|MIYA_CREDENTIALS/);
}

function testUnifiedDnsSnifferOnlyMode() {
  const config = createBaseConfig();
  const inputProxies = cloneJson(config.proxies);
  const inputProxyGroups = cloneJson(config["proxy-groups"]);
  const inputRules = config.rules.slice();

  const { sandbox, output } = runMain(
    () => config,
    (sb) => {
      sb.USER_OPTIONS.overrideMode = "dns-sniffer-only";
      sb.MIYA_CREDENTIALS = {
        username: "", password: "",
        relay: { server: "", port: 8022 },
        transit: { server: "", port: 8001 }
      };
    }
  );
  const dnsBase = sandbox.DNS_SNIFFER_MODULE.BASE.dns;

  assert.deepEqual(output.proxies, inputProxies);
  assert.deepEqual(output["proxy-groups"], inputProxyGroups);
  assert.deepEqual(output.rules, inputRules);
  assert.strictEqual(output._miya, undefined);
  assert.strictEqual(output._azChainProxyState, undefined);
  assert.strictEqual(output._azChainProxyUserConfig, undefined);
  assert.strictEqual(output.dns.enable, true);
  assert.strictEqual(output.sniffer.enable, true);
  assertNameserverPolicyValues(output, [dnsBase.domesticGeosite], dnsBase.domestic);
  assertNameserverPolicyValues(output, [dnsBase.overseasGeosite], dnsBase.overseas);
  assert.strictEqual(output.dns["nameserver-policy"]["geosite:openai"], undefined);
  assertNameserverPolicyValues(output, ["+.docs.qq.com", "+.aliyuncs.com"], dnsBase.domestic);
  assertNameserverPolicyValues(output, ["+.chatgpt.com", "+.claude.ai", "+.githubusercontent.com"], dnsBase.overseas);
  assertIncludes(output.dns["fake-ip-filter"], ["+.push.apple.com", "stun.*.*"], "dns-only fake-ip-filter");
  assertIncludes(output.sniffer["force-domain"], ["+.claude.ai", "+.google.com"], "dns-only sniffer.force-domain");
  assertIncludes(output.sniffer["skip-domain"], ["+.push.apple.com", "+.tailscale.com"], "dns-only sniffer.skip-domain");
}

function testDisableBrowserProcessProxy() {
  const { sandbox, state, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.routeBrowserToChain = false;
  });
  assertProcessRules(output, false, derivedBrowserProcessNames(state), sandbox.UI_GROUPS.ai);
}

function testAiCliProcessProxyDefaultsOn() {
  const { sandbox, state, output } = runMain();
  assertProcessRules(output, true, derivedAiCliProcessNames(state), sandbox.UI_GROUPS.ai);
  assertProcessRules(output, false, ["opencode"], sandbox.UI_GROUPS.ai);
}

function testAiCliProcessProxyAlwaysOn() {
  const { sandbox, state, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.routeBrowserToChain = false;
  });
  assertProcessRules(output, true, derivedAiCliProcessNames(state), sandbox.UI_GROUPS.ai);
}

function testOnlyAiAndBrowserProcessesAreManaged() {
  const { sandbox, output } = runMain();
  assertProcessRules(output, false, ["Google Chrome", "Google Drive", "Visual Studio Code"], sandbox.UI_GROUPS.ai);
  assertRulesMissing(output.rules, [
    "PROCESS-NAME,WeChat,DIRECT",
    "PROCESS-NAME,Tailscale,DIRECT"
  ]);
}

function testMissingRegionFails() {
  assert.throws(() => runMain(
    null,
    (sb) => {
      sb.USER_OPTIONS.chainRegion = "JP";
      sb.BASE.regionFallbackOrder.chain = [];
    }
  ), /未找到可用的 chainRegion 节点/);
}

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

function testMissingStrictTargetFails() {
  assert.throws(() => runMain(
    null,
    (sb) => {
      const original = sb.resolveRoutingTargets;
      sb.resolveRoutingTargets = function(config, chainRegion) {
        const rt = original(config, chainRegion);
        rt.strictAiTarget = "错误目标";
        return rt;
      };
    }
  ), /域外 AI 与支撑平台未直接指向当前 chainRegion 出口/);
}

function testExistingManagedObjectsAreReconciled() {
  const { sandbox, output } = runMain((config) => {
    const base = loadCombinedSandbox().BASE;
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
    const base = loadCombinedSandbox().BASE;
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
    const base = loadCombinedSandbox().BASE;
    const staleRelay = "HK" + base.groupNameSuffixes.relaySuffix;
    config["proxy-groups"][0].proxies = ["🇸🇬 SG Auto 01", staleRelay];
  });
  assertManagedProxyTopology(output, sandbox);
}

function testRepeatedRunDoesNotCreateSelfReference() {
  const first = runMain();
  const rerunInput = JSON.parse(JSON.stringify(first.output));
  const { sandbox, output: second } = runMain(() => rerunInput);
  const names = expectedGroupNames(sandbox);

  assertManagedProxyTopology(second, sandbox);
  for (const name of [names.chainTarget, names.relay, names.usRegion]) {
    const count = second["proxy-groups"].filter((g) => g.name === name).length;
    assert.strictEqual(count, 1, "duplicate group after rerun: " + name);
  }
}

function testChainRegionAndBrowserOverride() {
  const { sandbox, dnsBase, output } = runMain(null, (sb) => {
    sb.USER_OPTIONS.chainRegion = "US";
    sb.USER_OPTIONS.routeBrowserToChain = false;
  });
  const suffix = sandbox.BASE.groupNameSuffixes;
  const usRelay = regionGroupName(sandbox, "US", suffix.base);

  assert.strictEqual(output._miya, undefined);
  assert.strictEqual(output._azChainProxyUserConfig, undefined);
  assert.strictEqual(findProxy(output, sandbox.BASE.nodeNames.relay)["dialer-proxy"], usRelay);
  assertNameserverPolicyValues(output, [dnsBase.domesticGeosite], dnsBase.domestic);
  assertProcessRules(output, false, derivedBrowserProcessNames({ derived: sandbox.DNS_SNIFFER_MODULE.DERIVED }), sandbox.UI_GROUPS.ai);
}

// ===========================================================================
// Runner
// ===========================================================================

const unitTests = [
  testToSuffix,
  testUniqueStrings,
  testBuildStringLookup,
  testCreateUserError,
  testNormalizeOverrideMode,
  testVersionSingleDefinition,
  testFakeIpBypassConstant,
  testDnsConfigContainsFakeIpBypass,
  testHasConfiguredMiyaCredentialsPort,
  testValidProxyTypesConstant,
  testBuildMiyaProxyTypeValidation,
];

const integrationTests = [
  testDefaultConfig,
  testRequiresConfiguredMiyaCredentials,
  testUnifiedDnsSnifferOnlyMode,
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
  testRepeatedRunDoesNotCreateSelfReference,
  testChainRegionAndBrowserOverride,
];

console.log("Unit tests (" + unitTests.length + "):");
for (const t of unitTests) t();

console.log("\nIntegration tests (" + integrationTests.length + "):");
for (const t of integrationTests) t();

console.log("\nAll " + (unitTests.length + integrationTests.length) + " checks passed");
