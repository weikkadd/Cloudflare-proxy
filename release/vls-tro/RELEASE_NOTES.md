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

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PASSWORD` | `123456` | 主页访问密码 |
| `UUID` | 自动生成 | 用户 UUID |
| `PROXYIP` | 无 | 代理服务器 IP |
| `SUB_PATH` | `link` | 订阅路径 |
| `DISABLE_TROJAN` | `false` | 是否关闭 Trojan |

## 📝 更新日志

### v1.0.0 (2026-07-23)
- 初始 Release 版本
- 优化代码结构，减少约 45% 体积
- 修复所有中文注释乱码问题
- UUID 改为动态生成
- CDN 节点列表优化
