# Cloudflare Workers VLESS + Trojan 代理服务

## 📦 Release 说明

本 Release 包含两个预编译版本，可直接部署到 **Cloudflare Pages**：

### vls+tro-pages.zip（推荐）
- 包含 `_worker.js` — VLESS + Trojan 双协议代理
- 功能完整，支持自动故障转移和负载均衡
- 适用于大多数场景

### ss-pages.zip
- 包含 `shadowsocks.js` — Shadowsocks 单协议代理
- 轻量简洁，适合简单需求

## 🚀 快速部署

1. 下载对应压缩包并解压
2. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
3. 进入 **Workers & Pages** → **Create application** → **Create Worker**
4. 将解压后的 JS 文件内容粘贴到编辑器
5. 点击右上角 **Deploy**
6. 在 **Settings → Variables** 中配置环境变量

## ⚙️ 环境变量

| Variable Name | Default | Description |
|--------------|---------|-------------|
| `PASSWORD` | `123456` | Web page access password |
| `UUID` | Auto-generated | User UUID |
| `PROXYIP` | None | Proxy server IP |
| `SUB_PATH` | `link` | Subscription path |
| `DISABLE_TROJAN` | `false` | Disable Trojan protocol |

## 📝 Changelog

### v1.0.0 (2026-07-23)
- Initial release
- Optimized code structure, reduced ~45% size
- Fixed all Chinese comment encoding issues
- UUID dynamically generated
- CDN node list optimized
