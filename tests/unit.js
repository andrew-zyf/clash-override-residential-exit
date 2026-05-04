// 纯函数单元测试
//
// 测试全局可访问的纯函数及新增常量结构。
// 运行：node tests/unit.js

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const overridePath = path.join(__dirname, "..", "src", "residential-chain-proxy-override.js");
const overrideCode = fs.readFileSync(overridePath, "utf8");

function loadSandbox() {
  const sandbox = { console, Object, Array, String, Error };
  vm.createContext(sandbox);
  vm.runInContext(overrideCode, sandbox, { filename: overridePath });
  return sandbox;
}

const S = loadSandbox();

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
  // Convert vm-context arrays to native for deepStrictEqual
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

// ---- CHAIN_PROXY_STATE_VERSION single definition ----
function testVersionSingleDefinition() {
  assert.strictEqual(typeof S.CHAIN_PROXY_STATE_VERSION, "string");
  assert.strictEqual(S.CHAIN_PROXY_STATE_VERSION, "11.6");
  // Verify only one definition exists in source
  const defs = overrideCode.split('\n').filter(l => l.includes('CHAIN_PROXY_STATE_VERSION = "11.6"'));
  assert.strictEqual(defs.length, 1, `Expected 1 version definition, found ${defs.length}`);
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
  // Simulate dns-sniffer-only to verify fake-ip-filter is populated
  const configSrc = fs.readFileSync(
    path.join(__dirname, "..", "src", "residential-chain-proxy-config.js"), "utf8"
  );
  const cfgSandbox = { console, Object, Array, String, Error };
  vm.createContext(cfgSandbox);
  vm.runInContext(configSrc, cfgSandbox, { filename: "config.js" });
  cfgSandbox.USER_OPTIONS.overrideMode = "dns-sniffer-only";
  cfgSandbox.MIYA_CREDENTIALS = {
    username: "", password: "",
    relay: { server: "", port: 8022 },
    transit: { server: "", port: 8001 }
  };

  const S2 = loadSandbox();
  const baseCfg = { proxies: [], "proxy-groups": [], rules: [] };
  const output = S2.main(cfgSandbox.main(baseCfg));

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
  // Valid ports
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
  // Invalid: port 0
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 0 },
    transit: { server: "5.6.7.8", port: 443 }
  }), false);
  // Invalid: negative port
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: -1 },
    transit: { server: "5.6.7.8", port: 443 }
  }), false);
  // Invalid: port 65536 (out of range)
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4", port: 8080 },
    transit: { server: "5.6.7.8", port: 65536 }
  }), false);
  // Invalid: string port
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
  // Invalid: missing port
  assert.strictEqual(fn({
    username: "u", password: "p",
    relay: { server: "1.2.3.4" },
    transit: { server: "5.6.7.8", port: 443 }
  }), false);
  // Invalid: null port
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
  // Normal operation
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

  // If "http" were removed from validProxyTypes, buildMiyaProxy should throw.
  // We simulate by temporarily modifying the array.
  var saved = S.BASE.validProxyTypes;
  // Save a copy and mutate to test guard.
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
  // Restore
  S.BASE.validProxyTypes = saved;
  console.log("  PASS buildMiyaProxy type validation");
}

// ---- Runner ----
const tests = [
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

for (const t of tests) t();

console.log(`\nunit.js: ${tests.length} checks passed`);
