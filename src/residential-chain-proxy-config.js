// 家宽 IP 链式代理用户配置
//
// 使用方式：先导入本文件，再导入 residential-chain-proxy-override.js。
// 本文件只保存用户配置；实现逻辑在 override 文件中，升级时通常只需替换 override 文件。
// 兼容性：Clash Party 的 JavaScriptCore；只用 ES5 语法。
//
// @version 11.4

var MIYA_CREDENTIALS = {
  username: "",
  password: "",
  relay: {
    server: "",
    port: 8022
  },
  transit: {
    server: "",
    port: 8001
  }
};

var USER_OPTIONS = {
  overrideMode: "merged", // merged = DNS/Sniffer + 链式/媒体分流；dns-sniffer-only = 只写 DNS/Sniffer
  chainRegion: "SG", // AI 家宽出口前一跳地区，可选 US / JP / HK / SG / TW
  routeBrowserToChain: true // 是否让 AI 浏览器按应用名继续强制走 chainRegion
};

function cloneChainProxyUserConfig(value) {
  return JSON.parse(JSON.stringify(value));
}

function main(config) {
  config._azChainProxyUserConfig = {
    miyaCredentials: cloneChainProxyUserConfig(MIYA_CREDENTIALS),
    userOptions: cloneChainProxyUserConfig(USER_OPTIONS)
  };
  return config;
}
