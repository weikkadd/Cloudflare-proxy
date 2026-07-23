// ============================================================
// Cloudflare Workers VLESS + Trojan + Shadowsocks Proxy
// 基于 Cloudflare Workers & Snippets 的高性能代理服务
// ============================================================
// 环境变量说明:
//   PASSWORD / PASSWD / password   - 主页访问密码（默认: 123456）
//   UUID / uuid                    - 用户 UUID（自动生成）
//   PROXYIP / proxyip / proxyIP    - 代理服务器 IP，逗号分隔多个
//   SUB_PATH / subpath             - 订阅路径（默认: link）
//   DISABLE_TROJAN / CLOSE_TROJAN  - 关闭 Trojan 协议 (true/false)
// ============================================================

import { connect } from 'cloudflare:sockets';

// ---------------------- 配置区 ----------------------

const CONFIG = {
	/** @type {string} 订阅路径 */
	subPath: 'link',

	/** @type {string} 主页访问密码 */
	password: '123456',

	/** @type {string} 代理服务器 IP（格式: ip:port 或 domain:port） */
	proxyIP: '',

	/** @type {string} 用户 UUID */
	uuid: generateUUID(),

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
const DEFAULT_PROXY_IP = 'proxy.xxxxxxxx.tk:50001';

/** WebSocket 状态常量 */
const WS_OPEN = 1;
const WS_CLOSING = 2;

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
		if (socket && socket.readyState !== undefined &&
			(socket.readyState === WS_OPEN || socket.readyState === WS_CLOSING)) {
			socket.close();
		}
	} catch (_) { /* ignore */ }
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
	'speedtest.net', 'fast.com', 'speedtest.cn',
	'speed.cloudflare.com', 'ovo.speedtestcustom.com',
];

function isSpeedTestDomain(hostname) {
	if (!hostname) return false;
	const h = hostname.toLowerCase();
	return SPEED_TEST_DOMAINS.some(d => h === d || h.endsWith('.' + d));
}

/** SHA-224 哈希计算 */
async function sha224(text) {
	const encoder = new TextEncoder();
	const data = encoder.encode(text);
	const msgLen = data.length;
	const bitLen = msgLen * 8;
	const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
	const padded = new Uint8Array(paddedLen);
	padded.set(data);
	padded[msgLen] = 0x80;
	const view = new DataView(padded.buffer);
	view.setUint32(paddedLen - 4, bitLen, false);

	const K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	];

	let H = [
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
		0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
	];

	for (let chunk = 0; chunk < paddedLen; chunk += 64) {
		const W = new Uint32Array(64);
		const cv = new DataView(padded.buffer, chunk, 64);
		for (let i = 0; i < 16; i++) W[i] = cv.getUint32(i * 4, false);
		for (let i = 16; i < 64; i++) {
			const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
			const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
			W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
		}

		let [a, b, c, d, e, f, g, h] = H;
		for (let i = 0; i < 64; i++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ (~e & g);
			const t1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const t2 = (S0 + maj) >>> 0;
			h = g; g = f; f = e; e = (d + t1) >>> 0;
			d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		H[0] = (H[0] + a) >>> 0;
		H[1] = (H[1] + b) >>> 0;
		H[2] = (H[2] + c) >>> 0;
		H[3] = (H[3] + d) >>> 0;
		H[4] = (H[4] + e) >>> 0;
		H[5] = (H[5] + f) >>> 0;
		H[6] = (H[6] + g) >>> 0;
		H[7] = (H[7] + h) >>> 0;
	}

	return H.slice(0, 7).map(v =>
		((v >>> 24) & 0xff).toString(16).padStart(2, '0') +
		((v >>> 16) & 0xff).toString(16).padStart(2, '0') +
		((v >>> 8) & 0xff).toString(16).padStart(2, '0') +
		(v & 0xff).toString(16).padStart(2, '0')
	).join('');
}

function rotr(value, amount) {
	return (value >>> amount) | (value << (32 - amount));
}

// ---------------------- 代理地址解析 ----------------------

/**
 * 解析代理地址字符串
 * @param {string} serverStr - 代理地址（支持 socks5://, http://, 直接 IP:port）
 * @returns {{type:string, host:string, port:number, username?:string, password?:string}|null}
 */
function parseProxyAddress(serverStr) {
	if (!serverStr) return null;
	serverStr = serverStr.trim();

	// SOCKS5 代理
	if (/^socks5?:\/\//.test(serverStr)) {
		try {
			const url = new URL(serverStr.replace(/^socks:\/\//, 'socks5://'));
			return {
				type: 'socks5',
				host: url.hostname,
				port: parseInt(url.port) || 1080,
				username: url.username ? decodeURIComponent(url.username) : '',
				password: url.password ? decodeURIComponent(url.password) : '',
			};
		} catch (_) { return null; }
	}

	// HTTP/HTTPS 代理
	if (/^https?:\/\//.test(serverStr)) {
		try {
			const url = new URL(serverStr);
			return {
				type: 'http',
				host: url.hostname,
				port: parseInt(url.port) || (serverStr.startsWith('https') ? 443 : 80),
				username: url.username ? decodeURIComponent(url.username) : '',
				password: url.password ? decodeURIComponent(url.password) : '',
			};
		} catch (_) { return null; }
	}

	// IPv6 格式 [host]:port
	if (serverStr.startsWith('[')) {
		const idx = serverStr.indexOf(']');
		if (idx > 0) {
			const host = serverStr.substring(1, idx);
			const rest = serverStr.substring(idx + 1);
			if (rest.startsWith(':')) {
				const port = parseInt(rest.substring(1), 10);
				if (!isNaN(port) && port >= 1 && port <= 65535) return { type: 'direct', host, port };
			}
			return { type: 'direct', host, port: 443 };
		}
	}

	// 标准 host:port
	const lastColon = serverStr.lastIndexOf(':');
	if (lastColon > 0) {
		const host = serverStr.substring(0, lastColon);
		const port = parseInt(serverStr.substring(lastColon + 1), 10);
		if (!isNaN(port) && port >= 1 && port <= 65535) return { type: 'direct', host, port };
	}

	// 纯域名/IP（无端口）
	return { type: 'direct', host: serverStr, port: 443 };
}

// ---------------------- TCP 连接辅助 ----------------------

/** 直连目标主机 */
async function connectDirect(address, port, initialData) {
	const sock = connect({ hostname: address, port });
	const writer = sock.writable.getWriter();
	await writer.write(initialData);
	writer.releaseLock();
	return sock;
}

/** SOCKS5 代理连接 */
async function connectViaSocks5(proxyCfg, targetHost, targetPort, initialData) {
	const { host, port, username, password } = proxyCfg;
	const socket = connect({ hostname: host, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();

	try {
		// 认证方法请求
		const hasAuth = !!(username && password);
		const authMethods = new Uint8Array(hasAuth ? 4 : 3);
		authMethods[0] = 5;
		authMethods[1] = hasAuth ? 2 : 1;
		authMethods[2] = 0; // 无认证
		if (hasAuth) authMethods[3] = 2; // 用户名/密码认证
		await writer.write(authMethods);

		const methodResp = await reader.read();
		if (methodResp.done || methodResp.value.byteLength < 2) throw new Error('SOCKS5 method select failed');
		const method = new Uint8Array(methodResp.value)[1];

		if (method === 2) {
			// 用户名密码认证
			if (!hasAuth) throw new Error('SOCKS5 requires authentication');
			const userBytes = new TextEncoder().encode(username);
			const passBytes = new TextEncoder().encode(password);
			const authReq = new Uint8Array(3 + userBytes.length + passBytes.length);
			authReq[0] = 1; authReq[1] = userBytes.length;
			authReq.set(userBytes, 2);
			authReq[2 + userBytes.length] = passBytes.length;
			authReq.set(passBytes, 3 + userBytes.length);
			await writer.write(authReq);

			const authResp = await reader.read();
			if (authResp.done || new Uint8Array(authResp.value)[1] !== 0) throw new Error('SOCKS5 auth failed');
		} else if (method !== 0) {
			throw new Error(`SOCKS5 unsupported auth method: ${method}`);
		}

		// CONNECT 请求
		const hostBytes = new TextEncoder().encode(targetHost);
		const connReq = new Uint8Array(7 + hostBytes.length);
		connReq[0] = 5; connReq[1] = 1; connReq[2] = 0; connReq[3] = 3; // 域名
		connReq[4] = hostBytes.length;
		connReq.set(hostBytes, 5);
		new DataView(connReq.buffer).setUint16(5 + hostBytes.length, targetPort, false);
		await writer.write(connReq);

		const connResp = await reader.read();
		if (connResp.done || new Uint8Array(connResp.value)[1] !== 0) throw new Error('SOCKS5 connect failed');

		await writer.write(initialData);
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (error) {
		writer.releaseLock();
		reader.releaseLock();
		throw error;
	}
}

/** HTTP 代理连接（CONNECT 隧道） */
async function connectViaHttp(proxyCfg, targetHost, targetPort, initialData) {
	const { host, port, username, password } = proxyCfg;
	const socket = connect({ hostname: host, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();

	try {
		const authHeader = (username && password)
			? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';

		const request = [
			`CONNECT ${targetHost}:${targetPort} HTTP/1.1`,
			`Host: ${targetHost}:${targetPort}`,
			authHeader,
			`User-Agent: Mozilla/5.0`,
			`Connection: keep-alive`,
			'',
			'',
		].join('\r\n');

		await writer.write(new TextEncoder().encode(request));

		// 读取响应头
		let buf = new Uint8Array(0);
		let headerEnd = -1;
		for (let read = 0; read < 8192; ) {
			const { done, value } = await reader.read();
			if (done) throw new Error('Connection closed before response');
			const nb = new Uint8Array(buf.length + value.length);
			nb.set(buf); nb.set(value, buf.length);
			buf = nb; read += value.length;
			for (let i = 0; i < buf.length - 3; i++) {
				if (buf[i] === 0x0d && buf[i+1] === 0x0a && buf[i+2] === 0x0d && buf[i+3] === 0x0a) {
					headerEnd = i + 4; break;
				}
			}
			if (headerEnd > 0) break;
		}
		if (headerEnd < 0) throw new Error('Invalid HTTP response');

		const statusLine = new TextDecoder().decode(buf.slice(0, headerEnd)).split('\r\n')[0];
		const m = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
		if (!m) throw new Error(`Invalid response: ${statusLine}`);
		const code = parseInt(m[1]);
		if (code < 200 || code >= 300) throw new Error(`Connect failed: ${statusLine}`);

		await writer.write(initialData);
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock(); } catch (_) {}
		try { reader.releaseLock(); } catch (_) {}
		try { socket.close(); } catch (_) {}
		throw error;
	}
}

// ---------------------- 数据流转发 ----------------------

/** 创建 ReadableStream（从 WebSocket 读取数据） */
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
			socket.addEventListener('close', () => {
				if (!cancelled) { closeSocketQuietly(socket); controller.close(); }
			});
			socket.addEventListener('error', (err) => controller.error(err));

			// 处理 early_data (0-RTT)
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) Promise.resolve().then(() => controller.error(error));
			else if (earlyData) Promise.resolve().then(() => { if (!cancelled) controller.enqueue(earlyData); });
		},
		cancel() { cancelled = true; closeSocketQuietly(socket); },
	});
}

/** 双向流连接 */
function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
	let header = headerData, hasData = false;

	remoteSocket.readable.pipeTo(new WritableStream({
		async write(chunk) {
			hasData = true;
			if (webSocket.readyState !== WS_OPEN) throw new Error('WebSocket not open');
			if (header) {
				const resp = new Uint8Array(header.length + chunk.byteLength);
				resp.set(header, 0); resp.set(chunk, header.length);
				webSocket.send(resp.buffer);
				header = null;
			} else {
				webSocket.send(chunk);
			}
		},
		abort() {},
	})).catch(() => { closeSocketQuietly(webSocket); });

	if (!hasData && retryFunc) retryFunc();
}

/** 转发 TCP 流量到目标 */
async function forwardTCP(host, port, rawData, ws, respHeader, remoteWrapper, customProxyIP) {
	let proxyConfig = null;
	let shouldUseProxy = false;

	// 确定代理配置
	if (customProxyIP) {
		proxyConfig = parseProxyAddress(customProxyIP);
		if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http')) {
			shouldUseProxy = true;
		} else if (!proxyConfig) {
			proxyConfig = parseProxyAddress(CONFIG.proxyIP || DEFAULT_PROXY_IP) || { type: 'direct', host: DEFAULT_PROXY_IP, port: 443 };
		}
	} else {
		proxyConfig = parseProxyAddress(CONFIG.proxyIP || DEFAULT_PROXY_IP) || { type: 'direct', host: DEFAULT_PROXY_IP, port: 443 };
		if (proxyConfig.type === 'socks5' || proxyConfig.type === 'http') shouldUseProxy = true;
	}

	// 通过代理连接
	async function viaProxy() {
		let newSocket;
		if (proxyConfig.type === 'socks5') newSocket = await connectViaSocks5(proxyConfig, host, port, rawData);
		else if (proxyConfig.type === 'http') newSocket = await connectViaHttp(proxyConfig, host, port, rawData);
		else newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);

		remoteWrapper.socket = newSocket;
		newSocket.closed?.catch(() => {}).finally(() => closeSocketQuietly(ws));
		connectStreams(newSocket, ws, respHeader, null);
	}

	if (shouldUseProxy) {
		await viaProxy();
	} else {
		try {
			const sock = await connectDirect(host, port, rawData);
			remoteWrapper.socket = sock;
			connectStreams(sock, ws, respHeader, viaProxy);
		} catch (_) {
			await viaProxy();
		}
	}
}

/** UDP 转发（DNS 查询） */
async function forwardUDP(udpChunk, webSocket, respHeader) {
	try {
		const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();

		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WS_OPEN) {
					if (respHeader) {
						const resp = new Uint8Array(respHeader.length + chunk.byteLength);
						resp.set(respHeader, 0); resp.set(chunk, respHeader.length);
						webSocket.send(resp.buffer);
						respHeader = null;
					} else {
						webSocket.send(chunk);
					}
				}
			},
		}));
	} catch (_) { /* ignore UDP errors */ }
}

// ---------------------- 协议解析 ----------------------

/** VLESS 数据包头部解析 */
function parseVlessHeader(chunk, token) {
	if (chunk.byteLength < 24) return { error: 'Invalid packet size' };

	const version = new Uint8Array(chunk.slice(0, 1));
	const uuidHex = new Uint8Array(chunk.slice(1, 17));
	const clientUUID = arrayBufferToUUID(uuidHex);

	if (clientUUID !== token) return { error: 'Invalid UUID' };

	const optLen = new Uint8Array(chunk.slice(17, 18))[0];
	const cmdByte = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
	const isUDP = cmdByte === 2;
	if (cmdByte !== 1 && cmdByte !== 2) return { error: `Invalid command: ${cmdByte}` };

	const portIdx = 19 + optLen;
	const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);

	let addrIdx = portIdx + 2, addrLen = 0, hostname = '';
	const addrType = new Uint8Array(chunk.slice(addrIdx, addrIdx + 1))[0];

	switch (addrType) {
		case 1: // IPv4
			hostname = [...new Uint8Array(chunk.slice(addrIdx + 1, addrIdx + 5))].join('.');
			addrLen = 4; break;
		case 2: // Domain
			addrLen = new Uint8Array(chunk.slice(addrIdx + 1, addrIdx + 2))[0];
			hostname = new TextDecoder().decode(chunk.slice(addrIdx + 2, addrIdx + 2 + addrLen));
			break;
		case 3: // IPv6
			const parts = [];
			const dv = new DataView(chunk.slice(addrIdx + 1, addrIdx + 17));
			for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
			hostname = parts.join(':');
			addrLen = 16; break;
		default:
			return { error: `Invalid address type: ${addrType}` };
	}

	if (!hostname) return { error: 'Empty hostname' };

	return {
		error: null,
		isUDP,
		port,
		hostname,
		rawIndex: addrIdx + 1 + addrLen,
		version,
	};
}

/** Trojan 头部解析 */
async function parseTrojanHeader(chunk, passwordHash) {
	if (chunk.byteLength < 56) return { error: 'Invalid data size' };

	const crLfIndex = 56;
	if (new Uint8Array(chunk.slice(56, 57))[0] !== 0x0d || new Uint8Array(chunk.slice(57, 58))[0] !== 0x0a) {
		return { error: 'Invalid header format (missing CRLF)' };
	}

	const password = new TextDecoder().decode(chunk.slice(0, crLfIndex));
	if (password !== passwordHash) return { error: 'Invalid password' };

	const socks5Buf = chunk.slice(crLfIndex + 2);
	if (socks5Buf.byteLength < 6) return { error: 'Invalid SOCKS5 data' };

	const dv = new DataView(socks5Buf);
	const cmd = dv.getUint8(0);
	if (cmd !== 1) return { error: `Unsupported command: ${cmd}` };

	const atype = dv.getUint8(1);
	let address = '', addressLen = 0, addressIdx = 2;

	switch (atype) {
		case 1: // IPv4
			address = [...new Uint8Array(socks5Buf.slice(addressIdx, addressIdx + 4))].join('.');
			addressLen = 4; break;
		case 3: // Domain
			addressLen = new Uint8Array(socks5Buf.slice(addressIdx, addressIdx + 1))[0];
			address = new TextDecoder().decode(socks5Buf.slice(addressIdx + 1, addressIdx + 1 + addressLen));
			break;
		case 4: // IPv6
			const ipv6Parts = [];
			const ipv6Dv = new DataView(socks5Buf.slice(addressIdx, addressIdx + 16));
			for (let i = 0; i < 8; i++) ipv6Parts.push(ipv6Dv.getUint16(i * 2).toString(16));
			address = ipv6Parts.join(':');
			addressLen = 16; break;
		default:
			return { error: `Invalid address type: ${atype}` };
	}

	if (!address) return { error: 'Empty address' };

	const portRemote = dv.getUint16(addressIdx + addressLen);
	const rawClientData = socks5Buf.slice(addressIdx + addressLen + 4);

	return { error: null, address, port: portRemote, hostname: address, rawClientData };
}

// ---------------------- 主请求处理 ----------------------

/** 处理 VLESS/Trojan WebSocket 请求 */
async function handleProxyRequest(request, customProxyIP) {
	const pair = new WebSocketPair();
	const [clientSock, serverSock] = [pair[0], pair[1]];
	serverSock.accept();
	serverSock.binaryType = 'arraybuffer';

	const remoteWrapper = { socket: null };
	let isDNSQuery = false;
	let isTrojanMode = false;

	const earlyData = request.headers.get('sec-websocket-protocol') || '';
	const readable = createWebSocketStream(serverSock, earlyData);

	readable.pipeTo(new WritableStream({
		async write(chunk) {
			// UDP DNS 转发
			if (isDNSQuery) return forwardUDP(chunk, serverSock, null);

			// 已有连接则写入
			if (remoteWrapper.socket) {
				const w = remoteWrapper.socket.writable.getWriter();
				await w.write(chunk);
				w.releaseLock();
				return;
			}

			// 尝试 Trojan 协议
			if (!CONFIG.disableTrojan) {
				const trojanResult = await parseTrojanHeader(chunk, await sha224(CONFIG.uuid));
				if (!trojanResult.error) {
					isTrojanMode = true;
					if (isSpeedTestDomain(trojanResult.hostname)) throw new Error('Speedtest blocked');
					await forwardTCP(trojanResult.hostname, trojanResult.port, trojanResult.rawClientData, serverSock, null, remoteWrapper, customProxyIP);
					return;
				}
			}

			// VLESS 协议
			const result = parseVlessHeader(chunk, CONFIG.uuid);
			if (result.error) throw new Error(result.error);

			if (isSpeedTestDomain(result.hostname)) throw new Error('Speedtest blocked');
			if (result.isUDP) {
				if (result.port === 53) isDNSQuery = true;
				else throw new Error('UDP only supports DNS (port 53)');
			}

			const respHeader = new Uint8Array([result.version[0], 0]);
			const rawData = chunk.slice(result.rawIndex);
			if (isDNSQuery) return forwardUDP(rawData, serverSock, respHeader);

			await forwardTCP(result.hostname, result.port, rawData, serverSock, respHeader, remoteWrapper, customProxyIP);
		},
	})).catch(() => { /* pipe error */ });

	return new Response(null, { status: 101, webSocket: clientSock });
}

// ---------------------- HTTP 路由 ----------------------

export default {
	/**
	 * @param {Request} request
	 * @param {{ UUID?: string, uuid?: string, PROXYIP?: string, proxyip?: string, proxyIP?: string, PASSWORD?: string, PASSWD?: string, password?: string, SUB_PATH?: string, subpath?: string, DISABLE_TROJAN?: string, CLOSE_TROJAN?: string }} env
	 * @param {ExecutionContext} ctx
	 */
	async fetch(request, env, ctx) {
		// 加载环境变量
		loadEnv(env);

		const url = new URL(request.url);
		const pathname = url.pathname;

		// 从路径设置 proxyIP
		if (pathname.startsWith('/proxyip=')) {
			const pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
			if (pathProxyIP && !request.headers.get('Upgrade')) {
				CONFIG.proxyIP = pathProxyIP;
				return new Response(`proxyIP set to: ${pathProxyIP}`, {
					headers: { 'Content-Type': 'text/plain; charset=utf-8' },
				});
			}
		}

		// WebSocket 升级 → 代理请求
		if (request.headers.get('Upgrade') === 'websocket') {
			const customProxyIP = pathname.startsWith('/proxyip=')
				? decodeURIComponent(pathname.substring(9)).trim()
				: url.searchParams.get('proxyip') || request.headers.get('proxyip');
			return handleProxyRequest(request, customProxyIP);
		}

		// GET 请求
		if (request.method === 'GET') {
			if (pathname === '/') return serveHomePage(request);

			// 订阅链接
			const subPattern = `/${CONFIG.subPath}`;
			if (pathname.toLowerCase().includes(subPattern.toLowerCase())) {
				return generateSubscription(url);
			}
		}

		return new Response('Not Found', { status: 404 });
	},
};

/** 从 Cloudflare 环境变量加载配置 */
function loadEnv(env) {
	if (env.PROXYIP || env.proxyip || env.proxyIP) {
		const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
		CONFIG.proxyIP = servers[0];
	}
	CONFIG.password = env.PASSWORD || env.PASSWD || env.password || CONFIG.password;
	CONFIG.subPath = env.SUB_PATH || env.subpath || CONFIG.subPath;
	CONFIG.uuid = env.UUID || env.uuid || CONFIG.uuid;
	const dt = env.DISABLE_TROJAN || env.CLOSE_TROJAN;
	CONFIG.disableTrojan = dt === 'true' || dt === true;

	// 如果 subPath 是默认的 'link'，使用 UUID 作为路径
	if (CONFIG.subPath === 'link' || CONFIG.subPath === '') {
		CONFIG.subPath = CONFIG.uuid;
	}
}

/** 生成订阅链接（VLESS + Trojan） */
function generateSubscription(url) {
	const currentDomain = url.hostname;
	const vlessHeader = 'vless';
	const trojanHeader = 'trojan';

	const nodes = CONFIG.cfips.map(cdnItem => {
		let host, port = 443, nodeName = '';
		const hashIdx = cdnItem.indexOf('#');
		if (hashIdx > 0) {
			nodeName = cdnItem.substring(hashIdx + 1);
			cdnItem = cdnItem.substring(0, hashIdx);
		}
		if (cdnItem.startsWith('[')) {
			const bracketEnd = cdnItem.indexOf(']:');
			if (bracketEnd > 0) {
				host = cdnItem.substring(0, bracketEnd + 1);
				port = parseInt(cdnItem.substring(bracketEnd + 2)) || 443;
			}
		} else if (cdnItem.includes(':')) {
			const parts = cdnItem.split(':');
			host = parts[0];
			port = parseInt(parts[1]) || 443;
		} else {
			host = cdnItem;
		}

		const label = nodeName ? `${nodeName}-${vlessHeader}` : `CF-${vlessHeader}`;
		const encodedPath = encodeURIComponent('/?ed=2560');
		return `${vlessHeader}://${CONFIG.uuid}@${host}:${port}?encryption=none&security=tls&sni=${currentDomain}&fp=firefox&allowInsecure=0&type=ws&host=${currentDomain}&path=${encodedPath}#${label}`;
	});

	// Trojan 节点
	if (!CONFIG.disableTrojan) {
		nodes.push(...CONFIG.cfips.map(cdnItem => {
			let host, port = 443, nodeName = '';
			const hashIdx = cdnItem.indexOf('#');
			if (hashIdx > 0) { nodeName = cdnItem.substring(hashIdx + 1); cdnItem = cdnItem.substring(0, hashIdx); }
			if (cdnItem.startsWith('[')) {
				const bracketEnd = cdnItem.indexOf(']:');
				if (bracketEnd > 0) { host = cdnItem.substring(0, bracketEnd + 1); port = parseInt(cdnItem.substring(bracketEnd + 2)) || 443; }
			} else if (cdnItem.includes(':')) {
				const parts = cdnItem.split(':'); host = parts[0]; port = parseInt(parts[1]) || 443;
			} else { host = cdnItem; }

			const label = nodeName ? `${nodeName}-${trojanHeader}` : `CF-${trojanHeader}`;
			const encodedPath = encodeURIComponent('/?ed=2560');
			return `${trojanHeader}://${CONFIG.uuid}@${host}:${port}?security=tls&sni=${currentDomain}&fp=firefox&allowInsecure=0&type=ws&host=${currentDomain}&path=${encodedPath}#${label}`;
		}));
	}

	const content = nodes.join('\n');
	return new Response(btoa(unescape(encodeURIComponent(content))), {
		headers: {
			'Content-Type': 'text/plain; charset=utf-8',
			'Cache-Control': 'no-store, no-cache, must-revalidate',
		},
	});
}

// ---------------------- 页面服务 ----------------------

/** 首页路由 */
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

/** 登录页面 */
function renderLoginPage(host, baseUrl, showError) {
	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Workers Service - Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#7dd3ca,#a17ec4);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;overflow:hidden}
.login-container{background:rgba(255,255,255,.95);backdrop-filter:blur(10px);border-radius:20px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,.1);max-width:400px;width:95%;text-align:center}
.logo{margin-bottom:-20px;font-size:2.5rem}
.title{font-size:1.8rem;margin-bottom:8px;color:#2d3748}
.subtitle{color:#718096;margin-bottom:30px}
.form-group{margin-bottom:20px;text-align:left}
.form-label{display:block;margin-bottom:8px;font-weight:600;color:#4a5568}
.form-input{width:100%;padding:12px 16px;border:2px solid #e2e8f0;border-radius:8px;font-size:1rem;transition:border-color .3s}
.form-input:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.1)}
.btn-login{width:100%;padding:12px;background:linear-gradient(135deg,#12cd9e,#a881d0);color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:all .3s}
.btn-login:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.1)}
.error-message{background:#fed7d7;color:#c53030;padding:12px;border-radius:8px;margin-bottom:20px;border-left:4px solid #e53e3e}
.footer{margin-top:20px;color:#718096;font-size:.9rem}
@media(max-width:480px){.login-container{padding:30px 20px}.title{font-size:1.5rem}}
</style>
</head>
<body>
<div class="login-container">
<div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo"></div>
<h1 class="title">Workers Service</h1>
<p class="subtitle">请输入密码以访问服务</p>
${showError ? '<div class="error-message">密码错误，请重试</div>' : ''}
<form onsubmit="handleLogin(event)">
<div class="form-group">
<input type="password" id="password" class="form-input" placeholder="请输入密码" required autofocus>
</div>
<button type="submit" class="btn-login">登录</button>
</form>
<div class="footer"><p>Powered by Cloudflare Workers</p></div>
</div>
<script>function handleLogin(e){e.preventDefault();const p=document.getElementById('password').value;const u=new URL(location.href);u.searchParams.set('password',p);location.href=u.toString()}</script>
</body>
</html>`;
	return new Response(html, {
		status: 200,
		headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' },
	});
}

/** 主页内容（验证通过后） */
function renderMainPage(host, baseUrl) {
	const subUrl = `${baseUrl}/${CONFIG.subPath}`;
	const clashUrl = `https://sublink.eooce.com/clash?config=${subUrl}`;
	const singboxUrl = `https://sublink.eooce.com/singbox?config=${subUrl}`;

	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Workers Service</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#66ead7,#9461c8);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;overflow:hidden}
.container{background:rgba(255,255,255,.95);backdrop-filter:blur(10px);border-radius:20px;padding:20px;box-shadow:0 20px 40px rgba(0,0,0,.1);max-width:800px;width:95%;max-height:90vh;text-align:center;overflow-y:auto;display:flex;flex-direction:column;position:relative}
.logout-btn{position:fixed;top:20px;right:20px;background:#a7a0d8;color:#dc2929;border:none;border-radius:8px;padding:8px 16px;font-size:.9rem;font-weight:600;cursor:pointer;z-index:1000}
.logout-btn:hover{background:#e0e0e0}
.logo{margin-bottom:-10px;font-size:2rem}
.title{font-size:1.8rem;margin-bottom:8px;color:#2d3748}
.subtitle{color:#718096;margin-bottom:15px;font-size:.95rem}
.info-card{background:#f7fafc;border-radius:12px;padding:15px;margin:10px 0;border-left:3px solid #6ed8c9;flex:1;overflow-y:auto}
.info-item{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #e2e8f0;font-size:.85rem}
.info-item:last-child{border-bottom:none}
.label{font-weight:600;color:#4a5568}
.value{color:#14171d;font-family:'Courier New',monospace;background:#edf2f7;padding:4px 8px;border-radius:6px;font-size:.75rem;word-break:break-all}
.btn-group{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin:15px 0}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:.9rem;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block;transition:all .3s;min-width:100px}
.btn-primary{background:linear-gradient(45deg,#667eea,#764ba2);color:#fff}
.btn-secondary{background:linear-gradient(45deg,#68e3d6,#906cc9);color:#001379}
.btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.1)}
.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:#48bb78;margin-right:8px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.toast{position:fixed;top:20px;right:20px;background:#f4fcf7;border-left:4px solid #48bb78;border-radius:8px;padding:12px 16px;box-shadow:0 4px 12px rgba(0,0,0,.15);z-index:1000;opacity:0;transform:translateX(100%);transition:all .3s;max-width:300px}
.toast.show{opacity:1;transform:translateX(0)}
.footer{margin-top:10px;color:#718096;font-size:.9rem}
.footer a{color:#667eea;text-decoration:none;margin:0 8px}
@media(max-width:768px){.container{padding:15px}.btn-group{flex-direction:column;align-items:center}.btn{width:100%;max-width:180px}}
</style>
</head>
<body>
<button onclick="logout()" class="logout-btn"><i class="fas fa-sign-out-alt"></i> 退出登录</button>
<div class="container">
<div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo"></div>
<h1 class="title">Workers Service</h1>
<p class="subtitle">基于 Cloudflare Workers 的高性能代理服务 (VLESS + Trojan)</p>
<div class="info-card">
<div class="info-item"><span class="label">服务状态</span><span class="value"><span class="status-dot"></span>运行中</span></div>
<div class="info-item"><span class="label">主机地址</span><span class="value">${host}</span></div>
<div class="info-item"><span class="label">UUID</span><span class="value">${CONFIG.uuid}</span></div>
<div class="info-item"><span class="label">V2rayN 订阅</span><span class="value">${subUrl}</span></div>
<div class="info-item"><span class="label">Clash 订阅</span><span class="value">${clashUrl}</span></div>
<div class="info-item"><span class="label">sing-box 订阅</span><span class="value">${singboxUrl}</span></div>
</div>
<div class="btn-group">
<button onclick="copyText('${singboxUrl}','sing-box 订阅链接已复制')" class="btn btn-secondary">复制 sing-box</button>
<button onclick="copyText('${clashUrl}','Clash 订阅链接已复制')" class="btn btn-secondary">复制 Clash</button>
<button onclick="copyText('${subUrl}','V2rayN 订阅链接已复制')" class="btn btn-secondary">复制 V2rayN</button>
</div>
<div class="footer">
<a href="https://github.com/eooce/CF-Workers-VLESS" target="_blank">GitHub</a>
<a href="https://t.me/eooceu" target="_blank">Telegram</a>
</div>
</div>
<div id="toast" class="toast"><span id="toastMsg"></span></div>
<script>
function copyText(url,msg){navigator.clipboard.writeText(url).then(()=>showToast(msg)).catch(()=>{const t=document.createElement('textarea');t.value=url;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showToast(msg)})}
function showToast(m){const t=document.getElementById('toast');document.getElementById('toastMsg').textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1500)}
function logout(){if(confirm('确定退出？')){const u=new URL(location.href);u.searchParams.delete('password');location.href=u.toString()}}
</script>
</body>
</html>`;
	return new Response(html, {
		status: 200,
		headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' },
	});
}
