// ============================================================
// Cloudflare Workers Shadowsocks Proxy (Pages 部署版)
// 基于 Cloudflare Pages 的 Shadowsocks 代理服务
// ============================================================
// 环境变量说明:
//   PASSWORD / PASSWD / password   - 主页访问密码（默认: 123456）
//   UUID / uuid                    - 用户 UUID（自动生成）
//   PROXYIP / proxyip / proxyIP    - 代理服务器 IP，逗号分隔多个
//   SUB_PATH / subpath             - 订阅路径（默认: link）
// ============================================================

import { connect } from 'cloudflare:sockets';

// ---------------------- 配置区 ----------------------

const CONFIG = {
	/** @type {string} 订阅路径 */
	subPath: 'link',

	/** @type {string} 节点 UUID（SS 密码） */
	uuid: generateUUID(),

	/** @type {string} 代理服务器 IP */
	proxyIP: '',

	/** @type {string} 主页访问密码 */
	password: '123456',

	/** @type {string} SS 路径验证（为空则使用 UUID） */
	ssPath: '',

	/** @type {Array<string>} CDN 优选节点列表 */
	cfips: [
		'cf.008500.xyz:443#HK-01',
		'cf.090227.xyz:443#SG-01',
		'cf.877774.xyz:443#HK-02',
		'saas.sin.fan:443#JP-01',
		'cdns.doon.eu.org:443#JP-02',
		'sub.danfeng.eu.org:443#TW-01',
		'cf.zhetengsha.eu.org:443#HK-03',
		'mfa.gov.ua:443#SG-02',
		'store.ubi.com:443#JP-03',
		'cf.130519.xyz:443#KR-01',
	],
};

const DEFAULT_PROXY_IP = 'proxy.xxxxxxxx.tk:50001';
const WS_OPEN = 1;
const WS_CLOSING = 2;

// ---------------------- 工具函数 ----------------------

function generateUUID() {
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
		const r = (Math.random() * 16) | 0;
		const v = c === 'x' ? r : (r & 0x3) | 0x8;
		return v.toString(16);
	});
}

function closeSocketQuietly(socket) {
	try {
		if (socket && socket.readyState !== undefined &&
			(socket.readyState === WS_OPEN || socket.readyState === WS_CLOSING)) {
			socket.close();
		}
	} catch (_) {}
}

function base64ToArrayBuffer(b64) {
	if (!b64) return { earlyData: null, error: null };
	try {
		const binary = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return { earlyData: bytes.buffer, error: null };
	} catch (e) { return { earlyData: null, error: e }; }
}

function parseProxyAddress(serverStr) {
	if (!serverStr) return null;
	serverStr = serverStr.trim();
	if (/^socks5?:\/\//.test(serverStr)) {
		try {
			const url = new URL(serverStr.replace(/^socks:\/\//, 'socks5://'));
			return { type: 'socks5', host: url.hostname, port: parseInt(url.port) || 1080, username: url.username ? decodeURIComponent(url.username) : '', password: url.password ? decodeURIComponent(url.password) : '' };
		} catch (_) { return null; }
	}
	if (/^https?:\/\//.test(serverStr)) {
		try {
			const url = new URL(serverStr);
			return { type: 'http', host: url.hostname, port: parseInt(url.port) || (serverStr.startsWith('https') ? 443 : 80), username: url.username ? decodeURIComponent(url.username) : '', password: url.password ? decodeURIComponent(url.password) : '' };
		} catch (_) { return null; }
	}
	if (serverStr.startsWith('[')) {
		const idx = serverStr.indexOf(']');
		if (idx > 0) {
			const host = serverStr.substring(1, idx);
			const rest = serverStr.substring(idx + 1);
			if (rest.startsWith(':')) { const p = parseInt(rest.substring(1), 10); if (!isNaN(p) && p >= 1 && p <= 65535) return { type: 'direct', host, port: p }; }
			return { type: 'direct', host, port: 443 };
		}
	}
	const lastColon = serverStr.lastIndexOf(':');
	if (lastColon > 0) {
		const host = serverStr.substring(0, lastColon);
		const port = parseInt(serverStr.substring(lastColon + 1), 10);
		if (!isNaN(port) && port >= 1 && port <= 65535) return { type: 'direct', host, port };
	}
	return { type: 'direct', host: serverStr, port: 443 };
}

function isSpeedTestDomain(hostname) {
	if (!hostname) return false;
	const h = hostname.toLowerCase();
	return ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com','ovo.speedtestcustom.com'].some(d => h === d || h.endsWith('.' + d));
}

// ---------------------- 连接辅助 ----------------------

async function connectDirect(address, port, initialData) {
	const sock = connect({ hostname: address, port });
	const writer = sock.writable.getWriter();
	await writer.write(initialData);
	writer.releaseLock();
	return sock;
}

async function connectViaSocks5(proxyCfg, targetHost, targetPort, initialData) {
	const { host, port, username, password } = proxyCfg;
	const socket = connect({ hostname: host, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	try {
		const hasAuth = !!(username && password);
		const authMethods = new Uint8Array(hasAuth ? 4 : 3);
		authMethods[0] = 5; authMethods[1] = hasAuth ? 2 : 1; authMethods[2] = 0;
		if (hasAuth) authMethods[3] = 2;
		await writer.write(authMethods);
		const methodResp = await reader.read();
		if (methodResp.done || methodResp.value.byteLength < 2) throw new Error('SOCKS5 method select failed');
		const method = new Uint8Array(methodResp.value)[1];
		if (method === 2) {
			if (!hasAuth) throw new Error('SOCKS5 requires auth');
			const ub = new TextEncoder().encode(username);
			const pb = new TextEncoder().encode(password);
			const ar = new Uint8Array(3 + ub.length + pb.length);
			ar[0] = 1; ar[1] = ub.length; ar.set(ub, 2); ar[2 + ub.length] = pb.length; ar.set(pb, 3 + ub.length);
			await writer.write(ar);
			const aResp = await reader.read();
			if (aResp.done || new Uint8Array(aResp.value)[1] !== 0) throw new Error('SOCKS5 auth failed');
		} else if (method !== 0) { throw new Error(`SOCKS5 unsupported auth: ${method}`); }
		const hb = new TextEncoder().encode(targetHost);
		const cr = new Uint8Array(7 + hb.length);
		cr[0] = 5; cr[1] = 1; cr[2] = 0; cr[3] = 3; cr[4] = hb.length; cr.set(hb, 5);
		new DataView(cr.buffer).setUint16(5 + hb.length, targetPort, false);
		await writer.write(cr);
		const cResp = await reader.read();
		if (cResp.done || new Uint8Array(cResp.value)[1] !== 0) throw new Error('SOCKS5 connect failed');
		await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (e) { writer.releaseLock(); reader.releaseLock(); throw e; }
}

async function connectViaHttp(proxyCfg, targetHost, targetPort, initialData) {
	const { host, port, username, password } = proxyCfg;
	const socket = connect({ hostname: host, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	try {
		const ah = (username && password) ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const req = [`CONNECT ${targetHost}:${targetPort} HTTP/1.1`, `Host: ${targetHost}:${targetPort}`, ah, 'User-Agent: Mozilla/5.0', 'Connection: keep-alive', '', ''].join('\r\n');
		await writer.write(new TextEncoder().encode(req));
		let buf = new Uint8Array(0), he = -1;
		for (let r = 0; r < 8192;) {
			const { done, value } = await reader.read();
			if (done) throw new Error('Connection closed');
			const nb = new Uint8Array(buf.length + value.length); nb.set(buf); nb.set(value, buf.length); buf = nb; r += value.length;
			for (let i = 0; i < buf.length - 3; i++) { if (buf[i] === 0x0d && buf[i+1] === 0x0a && buf[i+2] === 0x0d && buf[i+3] === 0x0a) { he = i + 4; break; } }
			if (he > 0) break;
		}
		if (he < 0) throw new Error('Invalid HTTP response');
		const sl = new TextDecoder().decode(buf.slice(0, he)).split('\r\n')[0];
		const m = sl.match(/HTTP\/\d\.\d\s+(\d+)/);
		if (!m) throw new Error(`Invalid response: ${sl}`);
		const code = parseInt(m[1]);
		if (code < 200 || code >= 300) throw new Error(`Connect failed: ${sl}`);
		await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (e) { try { writer.releaseLock(); } catch (_) {} try { reader.releaseLock(); } catch (_) {} try { socket.close(); } catch (_) {} throw e; }
}

// ---------------------- 流转发 ----------------------

function createWebSocketStream(socket, earlyDataHeader) {
	let cancelled = false;
	return new ReadableStream({
		start(controller) {
			socket.addEventListener('message', async (event) => {
				if (cancelled) return;
				let data = event.data;
				if (data instanceof Blob) data = await data.arrayBuffer();
				controller.enqueue(data);
			});
			socket.addEventListener('close', () => { if (!cancelled) { closeSocketQuietly(socket); controller.close(); } });
			socket.addEventListener('error', (err) => controller.error(err));
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) Promise.resolve().then(() => controller.error(error));
			else if (earlyData) Promise.resolve().then(() => { if (!cancelled) controller.enqueue(earlyData); });
		},
		cancel() { cancelled = true; closeSocketQuietly(socket); },
	});
}

function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
	let header = headerData, hasData = false;
	remoteSocket.readable.pipeTo(new WritableStream({
		async write(chunk) {
			hasData = true;
			if (webSocket.readyState !== WS_OPEN) throw new Error('WebSocket not open');
			if (header) { const resp = new Uint8Array(header.length + chunk.byteLength); resp.set(header, 0); resp.set(chunk, header.length); webSocket.send(resp.buffer); header = null; }
			else { webSocket.send(chunk); }
		},
		abort() {},
	})).catch(() => { closeSocketQuietly(webSocket); });
	if (!hasData && retryFunc) retryFunc();
}

async function forwardTCP(host, port, rawData, ws, respHeader, remoteWrapper, customProxyIP) {
	let proxyConfig = null, shouldUseProxy = false;
	if (customProxyIP) {
		proxyConfig = parseProxyAddress(customProxyIP);
		if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http')) shouldUseProxy = true;
		else if (!proxyConfig) proxyConfig = parseProxyAddress(CONFIG.proxyIP || DEFAULT_PROXY_IP) || { type: 'direct', host: DEFAULT_PROXY_IP, port: 443 };
	} else {
		proxyConfig = parseProxyAddress(CONFIG.proxyIP || DEFAULT_PROXY_IP) || { type: 'direct', host: DEFAULT_PROXY_IP, port: 443 };
		if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http') shouldUseProxy = true;
	}
	async function viaProxy() {
		let ns;
		if (proxyConfig.type === 'socks5') ns = await connectViaSocks5(proxyConfig, host, port, rawData);
		else if (proxyConfig.type === 'http') ns = await connectViaHttp(proxyConfig, host, port, rawData);
		else ns = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
		remoteWrapper.socket = ns;
		ns.closed?.catch(() => {}).finally(() => closeSocketQuietly(ws));
		connectStreams(ns, ws, respHeader, null);
	}
	if (shouldUseProxy) { await viaProxy(); }
	else {
		try { const s = await connectDirect(host, port, rawData); remoteWrapper.socket = s; connectStreams(s, ws, respHeader, viaProxy); }
		catch (_) { await viaProxy(); }
	}
}

// ---------------------- 协议处理 ----------------------

export default {
	async fetch(request, env, ctx) {
		// 加载环境变量
		if (env.PROXYIP || env.proxyip || env.proxyIP) {
			const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
			CONFIG.proxyIP = servers[0];
		}
		CONFIG.password = env.PASSWORD || env.PASSWD || env.password || CONFIG.password;
		CONFIG.subPath = env.SUB_PATH || env.subpath || CONFIG.subPath;
		CONFIG.uuid = env.UUID || env.uuid || CONFIG.uuid;
		if (CONFIG.subPath === 'link' || CONFIG.subPath === '') CONFIG.subPath = CONFIG.uuid;

		const url = new URL(request.url);
		const pathname = url.pathname;

		if (pathname.startsWith('/proxyip=')) {
			const pp = decodeURIComponent(pathname.substring(9)).trim();
			if (pp && !request.headers.get('Upgrade')) {
				CONFIG.proxyIP = pp;
				return new Response(`proxyIP set to: ${pp}`, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
			}
		}

		if (request.headers.get('Upgrade') === 'websocket') {
			const cpi = pathname.startsWith('/proxyip=') ? decodeURIComponent(pathname.substring(9)).trim() : url.searchParams.get('proxyip') || request.headers.get('proxyip');
			return handleSSRequest(request, cpi);
		}

		if (request.method === 'GET') {
			if (pathname === '/') return serveHomePage(request);
			const sp = CONFIG.ssPath || CONFIG.uuid;
			if (url.pathname.toLowerCase().includes(`/${sp.toLowerCase()}`)) return generateSubscription(url);
		}

		return new Response('Not Found', { status: 404 });
	},
};

async function handleSSRequest(request, customProxyIP) {
	const pair = new WebSocketPair();
	const [clientSock, serverSock] = [pair[0], pair[1]];
	serverSock.accept();
	serverSock.binaryType = 'arraybuffer';
	const remoteWrapper = { socket: null };
	const earlyData = request.headers.get('sec-websocket-protocol') || '';
	const readable = createWebSocketStream(serverSock, earlyData);

	readable.pipeTo(new WritableStream({
		async write(chunk) {
			if (remoteWrapper.socket) {
				const w = remoteWrapper.socket.writable.getWriter();
				await w.write(chunk); w.releaseLock();
				return;
			}
			if (chunk.byteLength < 4) throw new Error('Invalid packet size');
			const method = new Uint8Array(chunk.slice(0, 1))[0];
			const v = new Uint8Array(chunk.slice(1, 2))[0];
			if (v !== 1) throw new Error(`Invalid version: ${v}`);
			if (method !== 0 && method !== 1 && method !== 2 && method !== 3 && method !== 4 && method !== 5 && method !== 6 && method !== 7 && method !== 8 && method !== 9 && method !== 10 && method !== 11 && method !== 12 && method !== 13 && method !== 14 && method !== 15) throw new Error(`Invalid method: ${method}`);
			const addrIdx = 2;
			const atype = new Uint8Array(chunk.slice(addrIdx, addrIdx + 1))[0];
			let hostname = '', addrLen = 0;
			switch (atype) {
				case 1: hostname = [...new Uint8Array(chunk.slice(addrIdx + 1, addrIdx + 5))].join('.'); addrLen = 4; break;
				case 3: addrLen = new Uint8Array(chunk.slice(addrIdx + 1, addrIdx + 2))[0]; hostname = new TextDecoder().decode(chunk.slice(addrIdx + 2, addrIdx + 2 + addrLen)); break;
				case 4: { const parts = []; const dv = new DataView(chunk.slice(addrIdx + 1, addrIdx + 17)); for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16)); hostname = parts.join(':'); addrLen = 16; break; }
				default: throw new Error(`Invalid address type: ${atype}`);
			}
			const port = new DataView(chunk.slice(addrIdx + 1 + addrLen, addrIdx + 1 + addrLen + 2)).getUint16(0);
			if (isSpeedTestDomain(hostname)) throw new Error('Speedtest blocked');
			const rawData = chunk.slice(addrIdx + 1 + addrLen + 2);
			await forwardTCP(hostname, port, rawData, serverSock, null, remoteWrapper, customProxyIP);
		},
	})).catch(() => {});

	return new Response(null, { status: 101, webSocket: clientSock });
}

// ---------------------- 页面服务 ----------------------

function serveHomePage(request) {
	const host = request.headers.get('Host') || '';
	const baseUrl = `https://${host}`;
	const urlObj = new URL(request.url);
	const providedPassword = urlObj.searchParams.get('password');
	if (providedPassword) {
		if (providedPassword === CONFIG.password) return renderMainPage(host, baseUrl);
		return renderLoginPage(host, baseUrl, true);
	}
	return renderLoginPage(host, baseUrl, false);
}

function renderLoginPage(host, baseUrl, showError) {
	const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Shadowsocks - Login</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#7dd3ca,#a17ec4);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;overflow:hidden}.login-container{background:rgba(255,255,255,.95);backdrop-filter:blur(10px);border-radius:20px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,.1);max-width:400px;width:95%;text-align:center}.logo{margin-bottom:-20px;font-size:2.5rem}.title{font-size:1.8rem;margin-bottom:8px;color:#2d3748}.subtitle{color:#718096;margin-bottom:30px}.form-group{margin-bottom:20px;text-align:left}.form-label{display:block;margin-bottom:8px;font-weight:600;color:#4a5568}.form-input{width:100%;padding:12px 16px;border:2px solid #e2e8f0;border-radius:8px;font-size:1rem;transition:border-color .3s}.form-input:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.1)}.btn-login{width:100%;padding:12px;background:linear-gradient(135deg,#12cd9e,#a881d0);color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:all .3s}.btn-login:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.1)}.error-message{background:#fed7d7;color:#c53030;padding:12px;border-radius:8px;margin-bottom:20px;border-left:4px solid #e53e3e}.footer{margin-top:20px;color:#718096;font-size:.9rem}@media(max-width:480px){.login-container{padding:30px 20px}.title{font-size:1.5rem}}</style></head><body><div class="login-container"><div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo"></div><h1 class="title">Shadowsocks Service</h1><p class="subtitle">请输入密码以访问服务</p>${showError ? '<div class="error-message">密码错误，请重试</div>' : ''}<form onsubmit="handleLogin(event)"><div class="form-group"><input type="password" id="password" class="form-input" placeholder="请输入密码" required autofocus></div><button type="submit" class="btn-login">登录</button></form><div class="footer"><p>Powered by Cloudflare Workers</p></div></div><script>function handleLogin(e){e.preventDefault();const p=document.getElementById('password').value;const u=new URL(location.href);u.searchParams.set('password',p);location.href=u.toString()}</script></body></html>`;
	return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' } });
}

function renderMainPage(host, baseUrl) {
	const subUrl = `${baseUrl}/${CONFIG.ssPath || CONFIG.uuid}`;
	const clashUrl = `https://sublink.eooce.com/clash?config=${subUrl}`;
	const singboxUrl = `https://sublink.eooce.com/singbox?config=${subUrl}`;
	const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Shadowsocks Service</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#66ead7,#9461c8);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;overflow:hidden}.container{background:rgba(255,255,255,.95);backdrop-filter:blur(10px);border-radius:20px;padding:20px;box-shadow:0 20px 40px rgba(0,0,0,.1);max-width:800px;width:95%;max-height:90vh;text-align:center;overflow-y:auto;display:flex;flex-direction:column;position:relative}.logout-btn{position:fixed;top:20px;right:20px;background:#a7a0d8;color:#dc2929;border:none;border-radius:8px;padding:8px 16px;font-size:.9rem;font-weight:600;cursor:pointer;z-index:1000}.logout-btn:hover{background:#e0e0e0}.title{font-size:1.8rem;margin-bottom:8px;color:#2d3748}.subtitle{color:#718096;margin-bottom:15px;font-size:.95rem}.info-card{background:#f7fafc;border-radius:12px;padding:15px;margin:10px 0;border-left:3px solid #6ed8c9;flex:1;overflow-y:auto}.info-item{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #e2e8f0;font-size:.85rem}.info-item:last-child{border-bottom:none}.label{font-weight:600;color:#4a5568}.value{color:#14171d;font-family:'Courier New',monospace;background:#edf2f7;padding:4px 8px;border-radius:6px;font-size:.75rem;word-break:break-all}.btn-group{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin:15px 0}.btn{padding:10px 20px;border:none;border-radius:8px;font-size:.9rem;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block;transition:all .3s;min-width:100px}.btn-secondary{background:linear-gradient(45deg,#68e3d6,#906cc9);color:#001379}.btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.1)}.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:#48bb78;margin-right:8px;animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}.toast{position:fixed;top:20px;right:20px;background:#f4fcf7;border-left:4px solid #48bb78;border-radius:8px;padding:12px 16px;box-shadow:0 4px 12px rgba(0,0,0,.15);z-index:1000;opacity:0;transform:translateX(100%);transition:all .3s;max-width:300px}.toast.show{opacity:1;transform:translateX(0)}.footer{margin-top:10px;color:#718096;font-size:.9rem}.footer a{color:#667eea;text-decoration:none;margin:0 8px}@media(max-width:768px){.container{padding:15px}.btn-group{flex-direction:column;align-items:center}.btn{width:100%;max-width:180px}}</style></head><body><button onclick="logout()" class="logout-btn"><i class="fas fa-sign-out-alt"></i> 退出登录</button><div class="container"><div style="font-size:2rem;margin-bottom:-10px"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo"></div><h1 class="title">Shadowsocks Service</h1><p class="subtitle">基于 Cloudflare Workers 的高性能代理服务</p><div class="info-card"><div class="info-item"><span class="label">服务状态</span><span class="value"><span class="status-dot"></span>运行中</span></div><div class="info-item"><span class="label">主机地址</span><span class="value">${host}</span></div><div class="info-item"><span class="label">UUID/密码</span><span class="value">${CONFIG.uuid}</span></div><div class="info-item"><span class="label">订阅地址</span><span class="value">${subUrl}</span></div><div class="info-item"><span class="label">Clash 订阅</span><span class="value">${clashUrl}</span></div><div class="info-item"><span class="label">sing-box 订阅</span><span class="value">${singboxUrl}</span></div></div><div class="btn-group"><button onclick="copyText('${singboxUrl}','sing-box 订阅链接已复制')" class="btn btn-secondary">复制 sing-box</button><button onclick="copyText('${clashUrl}','Clash 订阅链接已复制')" class="btn btn-secondary">复制 Clash</button><button onclick="copyText('${subUrl}','订阅链接已复制')" class="btn btn-secondary">复制订阅</button></div><div class="footer"><a href="https://github.com/eooce/CF-Workers-VLESS" target="_blank">GitHub</a><a href="https://t.me/eooceu" target="_blank">Telegram</a></div></div><div id="toast" class="toast"><span id="toastMsg"></span></div><script>function copyText(url,msg){navigator.clipboard.writeText(url).then(()=>showToast(msg)).catch(()=>{const t=document.createElement('textarea');t.value=url;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showToast(msg)})}function showToast(m){const t=document.getElementById('toast');document.getElementById('toastMsg').textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1500)}function logout(){if(confirm('确定退出？')){const u=new URL(location.href);u.searchParams.delete('password');location.href=u.toString()}}</script></body></html>`;
	return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' } });
}

// ---------------------- 订阅生成 ----------------------

function generateSubscription(url) {
	const currentDomain = url.hostname;
	const nodes = CONFIG.cfips.map(cdnItem => {
		let host, port = 443, nodeName = '';
		const hashIdx = cdnItem.indexOf('#');
		if (hashIdx > 0) { nodeName = cdnItem.substring(hashIdx + 1); cdnItem = cdnItem.substring(0, hashIdx); }
		if (cdnItem.startsWith('[')) { const be = cdnItem.indexOf(']:'); if (be > 0) { host = cdnItem.substring(0, be + 1); port = parseInt(cdnItem.substring(be + 2)) || 443; } }
		else if (cdnItem.includes(':')) { const parts = cdnItem.split(':'); host = parts[0]; port = parseInt(parts[1]) || 443; }
		else { host = cdnItem; }
		const label = nodeName ? `${nodeName}-SS` : `CF-SS`;
		const encodedPath = encodeURIComponent(`/sub?ed=2560`);
		return `ss://${btoa(CONFIG.uuid)}@${host}:${port}?plugin=obfs-local;obfs=http;obfs-host=${currentDomain}&security=tls#${label}`;
	});
	const content = nodes.join('\n');
	return new Response(btoa(unescape(encodeURIComponent(content))), {
		headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate' },
	});
}
