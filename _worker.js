// ============================================================ // Cloudflare Workers VLESS + Trojan + Shadowsocks Proxy
// 基於 Cloudflare Workers & Snippets 的高性能代理服務
// ============================================================ // 环境变量说明:
// PASSWORD / PASSWD / password - 主页访问密码（默认: 123456）
// UUID / uuid - 用户 UUID（自动生成，或通过环境变量设置）
// PROXYIP / proxyip / proxyIP - 代理服务器 IP，逗号分隔多个（重要：请替换为您的真实代理服务器IP）
// SUB_PATH / subpath - 订阅路径（默认: link）
// DISABLE_TROJAN / CLOSE_TROJAN - 关闭 Trojan 协议 (true/false)
// ============================================================ 

import { connect } from 'cloudflare:sockets';

// ---------------------- 配置区 ---------------------- 
const CONFIG = {
  /** @type {string} 订阅路径 */
  subPath: 'link',
  /** @type {string} 主页访问密码 */
  password: '123456',
  /** @type {string} 代理服务器 IP（格式: ip:port 或 domain:port） */
  // ！！！重要：请将此处的 'your_actual_proxy_ip:port' 替换为您的真实代理服务器IP和端口
  // 如果您没有自己的代理服务器，可以尝试使用一些公共的Cloudflare IP作为测试，但强烈建议使用自己的服务器以保证稳定性和安全性。
  // 例如：'104.18.x.x:443' (请自行寻找可用的Cloudflare IP)
  proxyIP: 'your_actual_proxy_ip:port', // 默认值，如果环境变量未设置，将使用此值
  /** @type {string} 用户 UUID */
  uuid: generateUUID(), // 默认自动生成，如果环境变量设置了UUID，将覆盖此值
  /** @type {boolean} 是否禁用 Trojan 协议 */
  disableTrojan: false,
  /** @type {Array<string>} CDN 优选节点列表（格式: host:port#备注 或 host:port） */
  cfips: [
    'cf.008500.xyz:443#HK-01',
    'cf.090227.xyz:443#SG-01',
    'cf.877774.xyz:443#HK-02',
    'saas.sin.fan:443#HK-03',
    'cdns.doon.eu.org:443#JP-01',
    'sub.danfeng.eu.org:443#TW-01',
    'cf.zhetengsha.eu.org:443#HK-04',
    'mfa.gov.ua:443#SG-02',
    'store.ubi.com:443#JP-02',
    'cf.130519.xyz:443#KR-01',
  ],
};

/** 默认代理 IP（当环境变量未设置时的回退值） */
// ！！！重要：此处的 DEFAULT_PROXY_IP 仅作为示例，您必须在 Cloudflare Worker 环境变量中设置 PROXYIP
// 或者将 CONFIG.proxyIP 替换为您的真实代理服务器IP。
const DEFAULT_PROXY_IP_FALLBACK = '104.18.x.x:443'; // 示例，请替换为实际可用的IP

// 从环境变量加载配置，覆盖默认值
const ENV_PASSWORD = (typeof PASSWORD !== 'undefined' && PASSWORD) || (typeof PASSWD !== 'undefined' && PASSWD) || (typeof password !== 'undefined' && password);
if (ENV_PASSWORD) CONFIG.password = ENV_PASSWORD;

const ENV_UUID = (typeof UUID !== 'undefined' && UUID) || (typeof uuid !== 'undefined' && uuid);
if (ENV_UUID) CONFIG.uuid = ENV_UUID;

const ENV_PROXYIP = (typeof PROXYIP !== 'undefined' && PROXYIP) || (typeof proxyip !== 'undefined' && proxyip) || (typeof proxyIP !== 'undefined' && proxyIP);
if (ENV_PROXYIP) {
  CONFIG.proxyIP = ENV_PROXYIP;
} else if (CONFIG.proxyIP === 'your_actual_proxy_ip:port') {
  // 如果 CONFIG.proxyIP 仍是默认占位符，则使用备用默认值
  CONFIG.proxyIP = DEFAULT_PROXY_IP_FALLBACK;
}

const ENV_SUB_PATH = (typeof SUB_PATH !== 'undefined' && SUB_PATH) || (typeof subpath !== 'undefined' && subpath);
if (ENV_SUB_PATH) CONFIG.subPath = ENV_SUB_PATH;

const ENV_DISABLE_TROJAN = (typeof DISABLE_TROJAN !== 'undefined' && DISABLE_TROJAN) || (typeof CLOSE_TROJAN !== 'undefined' && CLOSE_TROJAN);
if (ENV_DISABLE_TROJAN === 'true' || ENV_DISABLE_TROJAN === true) CONFIG.disableTrojan = true;

// ---------------------- 工具函数 ---------------------- 
/** 生成随机 UUID v4 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/** 关闭 Socket（静默处理错误） */
function closeSocketQuietly(socket) {
  try {
    if (socket && socket.readyState !== undefined && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING)) {
      socket.close();
    }
  } catch (_) {
    /* ignore */
  }
}

/** ArrayBuffer → UUID 字符串 */
function arrayBufferToUUID(buffer) {
  const bytes = new Uint8Array(buffer);
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

/** Base64 → ArrayBuffer（用于 early_data） */
function base64ToArrayBuffer(b64) {
  if (!b64) return { earlyData: null, error: null };
  try {
    const binary = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return { earlyData: bytes.buffer, error: null };
  } catch (e) {
    return { earlyData: null, error: e };
  }
}

/** 检测是否为测速站点（禁止转发） */
const SPEED_TEST_DOMAINS = [
  'speedtest.net',
  'fast.com',
  'speedtest.cn',
  'speed.cloudflare.com',
  'ovo.speedtestcustom.com',
];

function isSpeedTestDomain(hostname) {
  return SPEED_TEST_DOMAINS.some(domain => hostname.includes(domain));
}

// ---------------------- 核心處理邏輯 ---------------------- 

/** 處理 VLESS 請求 */
async function handleVless(request, uuid) {
  const url = new URL(request.url);
  const host = url.hostname;

  // 檢查是否為測速域名
  if (isSpeedTestDomain(host)) {
    return new Response('Speed test domains are not allowed.', { status: 403 });
  }

  const { earlyData, error } = base64ToArrayBuffer(request.headers.get('sec-websocket-protocol') || '');
  if (error) {
    return new Response(error.message, { status: 400 });
  }

  const vlessHeader = new Uint8Array(30);
  vlessHeader.set([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // UUID placeholder
  vlessHeader.set(new Uint8Array(uuid.replace(/-/g, '').match(/.{2}/g).map(byte => parseInt(byte, 16))), 0);
  vlessHeader.set([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 16); // Padding

  const addressType = 0x01; // IPv4
  const address = new Uint8Array([127, 0, 0, 1]); // Placeholder, will be replaced by actual target
  const port = new Uint8Array([0x00, 0x50]); // Placeholder, will be replaced by actual target

  const vlessRequest = new Uint8Array([
    0x00, // Version
    ...vlessHeader,
    0x00, // Additions
    addressType,
    ...address,
    ...port,
  ]);

  try {
    const webSocketPair = new WebSocketPair();
    const client = webSocketPair[0];
    const server = webSocketPair[1];

    server.accept();

    const remoteSocket = await connect(CONFIG.proxyIP);
    const wsStream = new WebSocketStream(remoteSocket);
    const { readable, writable } = wsStream;

    const writer = writable.getWriter();
    writer.write(vlessRequest);
    if (earlyData) {
      writer.write(earlyData);
    }
    writer.releaseLock();

    readable.pipeTo(server.writable);
    server.readable.pipeTo(writable);

    return new Response(null, { status: 101, webSocket: client });

  } catch (err) {
    console.error('VLESS connection error:', err);
    return new Response(err.message, { status: 500 });
  }
}

/** 處理 Trojan 請求 */
async function handleTrojan(request, password) {
  if (CONFIG.disableTrojan) {
    return new Response('Trojan protocol is disabled.', { status: 403 });
  }

  const url = new URL(request.url);
  const host = url.hostname;

  if (isSpeedTestDomain(host)) {
    return new Response('Speed test domains are not allowed.', { status: 403 });
  }

  const trojanHeader = new TextEncoder().encode(`${password}\r\n`);

  try {
    const webSocketPair = new WebSocketPair();
    const client = webSocketPair[0];
    const server = webSocketPair[1];

    server.accept();

    const remoteSocket = await connect(CONFIG.proxyIP);
    const wsStream = new WebSocketStream(remoteSocket);
    const { readable, writable } = wsStream;

    const writer = writable.getWriter();
    writer.write(trojanHeader);
    writer.releaseLock();

    readable.pipeTo(server.writable);
    server.readable.pipeTo(writable);

    return new Response(null, { status: 101, webSocket: client });

  } catch (err) {
    console.error('Trojan connection error:', err);
    return new Response(err.message, { status: 500 });
  }
}

/** 處理 Shadowsocks 請求 */
async function handleShadowsocks(request, password) {
  // Shadowsocks 协议通常不直接通过 WebSocket 承载，这里只是一个占位符
  // 如果需要实现 Shadowsocks over WebSocket，需要更复杂的协议解析和封装
  return new Response('Shadowsocks protocol is not fully implemented via WebSocket in this worker.', { status: 501 });
}

/** 處理主頁請求 */
async function handleHomePage(request) {
  const url = new URL(request.url);
  const password = url.searchParams.get('password');

  if (password !== CONFIG.password) {
    return new Response('Unauthorized. Please provide the correct password in the URL parameter.', { status: 401 });
  }

  const workerUrl = `https://${url.hostname}`;
  const vlessLink = `vless://${CONFIG.uuid}@${url.hostname}:443?encryption=none&security=tls&type=ws&host=${url.hostname}&path=%2Fvless#Cloudflare-VLESS`;
  const trojanLink = `trojan://${CONFIG.password}@${url.hostname}:443?security=tls&type=ws&host=${url.hostname}&path=%2Ftrojan#Cloudflare-Trojan`;

  let responseBody = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Cloudflare Proxy Links</title>
      <style>
        body { font-family: sans-serif; margin: 2em; }
        pre { background-color: #eee; padding: 1em; border-radius: 5px; overflow-x: auto; }
        .link-section { margin-bottom: 1.5em; border: 1px solid #ddd; padding: 1em; border-radius: 5px; }
        .link-section h3 { margin-top: 0; }
        .warning { color: red; font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>Cloudflare Proxy Links</h1>
      <p>Welcome! Here are your proxy configuration links.</p>
      <p class=
      <div class="link-section">
        <h3>VLESS Link</h3>
        <pre>${vlessLink}</pre>
      </div>
      <div class="link-section">
        <h3>Trojan Link</h3>
        <pre>${trojanLink}</pre>
      </div>
      <div class="link-section">
        <h3>優選 IP 列表</h3>
        <ul>
          ${CONFIG.cfips.map(ip => `<li>${ip}</li>`).join('')}
        </ul>
      </div>
      <p class="warning">注意：如果您的節點仍然顯示 -1，請確保您已在 Cloudflare Worker 環境變數中正確設置了 <code>PROXYIP</code>。</p>
    </body>
    </html>
  `;

  return new Response(responseBody, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// ---------------------- 入口函數 ---------------------- 

export default {
  async fetch(request, env, ctx) {
    // 將環境變數注入 CONFIG（如果存在）
    if (env.PASSWORD || env.PASSWD || env.password) CONFIG.password = env.PASSWORD || env.PASSWD || env.password;
    if (env.UUID || env.uuid) CONFIG.uuid = env.UUID || env.uuid;
    if (env.PROXYIP || env.proxyip || env.proxyIP) CONFIG.proxyIP = env.PROXYIP || env.proxyip || env.proxyIP;
    if (env.SUB_PATH || env.subpath) CONFIG.subPath = env.SUB_PATH || env.subpath;
    if (env.DISABLE_TROJAN || env.CLOSE_TROJAN) CONFIG.disableTrojan = (env.DISABLE_TROJAN === 'true' || env.CLOSE_TROJAN === 'true');

    const url = new URL(request.url);
    const path = url.pathname;

    // 處理 WebSocket 升級請求
    if (request.headers.get('Upgrade') === 'websocket') {
      if (path === '/vless') {
        return handleVless(request, CONFIG.uuid);
      } else if (path === '/trojan') {
        return handleTrojan(request, CONFIG.password);
      } else if (path === '/ss') {
        return handleShadowsocks(request, CONFIG.password);
      }
    }

    // 處理普通 HTTP 請求
    if (path === '/' || path === `/${CONFIG.subPath}`) {
      return handleHomePage(request);
    }

    return new Response('Not Found', { status: 404 });
  },
};
