// MiyaIP 凭证注入脚本
// 将 MiyaIP 代理凭证注入到 config._miya，供链式代理脚本读取。
//
// 使用方式：
//   1. 复制本文件并重命名为「MiyaIP 凭证.js」
//   2. 填入真实的用户名、密码和服务器地址
//   3. 在 Clash Party 覆写列表中启用，排序放在「DNS解析和域名嗅探.js」之后、
//      「家宽IP-链式代理.js」之前
function main(config) {
  config._miya = {
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
  return config;
}
