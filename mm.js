// 相关环境变量(都是可选的)
// SUB_PATH | subpath  订阅路径
// PROXYIP | proxyip   代理IP
// UUID | AUTH | uuid  UUID

import { connect } from 'cloudflare:sockets';

let subPath = 'sub';     // 订阅路径,不修改将使用uuid作为订阅路径
let password = '123456';  // 主页密码，建议修改或添加PASSWORD环境变量
let serverPool = ['13.230.34.30'];  // proxyIP
let yourUUID = '5dc15e15-f285-4a9d-959b-0e4fbdd77b63'; // UUID，建议修改或添加环境便量

let cfip = [ // cfip
	'ip.sb', 'time.is', 'skk.moe', 'www.visa.com.tw', 'www.visa.com.hk', 'www.visa.com.sg',
	'cf.090227.xyz','cf.877774.xyz', 'cdns.doon.eu.org', 'cf.zhetengsha.eu.org'
]; 

let dnsResolver = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=';

// parse server address and port
function parseServerAddress(serverStr) {
	const defaultPort = 443; 
	let hostname = serverStr.trim();
	let port = defaultPort;
	
	if (hostname.includes('.tp')) {
		const portMatch = hostname.match(/\.tp(\d+)\./);
		if (portMatch) {
			port = parseInt(portMatch[1]);
		}
	} else if (hostname.includes('[') && hostname.includes(']:')) {
		port = parseInt(hostname.split(']:')[1]);
		hostname = hostname.split(']:')[0] + ']';
	} else if (hostname.includes(':')) {
		const parts = hostname.split(':');
		port = parseInt(parts[parts.length - 1]);
		hostname = parts.slice(0, -1).join(':');
	}
	
	return {
		hostname: hostname,
		port: port
	};
}

// resolve hostname to IP address
async function resolveHostname(hostname) {
	// if hostname is IP address, return directly
	if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(hostname)) {
		return hostname;
	}
	
	try {
		// use Cloudflare Workers's DNS over HTTPS to resolve hostname
		const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
			headers: {
				'Accept': 'application/dns-json'
			}
		});
		
		if (dnsResponse.ok) {
			const dnsData = await dnsResponse.json();
			if (dnsData.Answer && dnsData.Answer.length > 0) {
				// return first A record
				return dnsData.Answer[0].data;
			}
		}
		
		// if DNS resolution failed, return original hostname to connect function
		console.warn(`DNS resolution failed for ${hostname}, using original hostname`);
		return hostname;
	} catch (error) {
		console.warn(`DNS resolution error for ${hostname}:`, error);
		return hostname;
	}
}

// try to connect server with failover
async function connectWithFailover() {
	const validServers = serverPool.filter(server => server && server.trim() !== '');
	const allServers = [...validServers, 'Kr.tp50000.netlib.re'];
	let lastError = null;
	
	for (let i = 0; i < allServers.length; i++) {
		try {
			const serverStr = allServers[i];
			const { hostname, port } = parseServerAddress(serverStr);
			const resolvedHostname = await resolveHostname(hostname);
			
			// console.log(`try to connect ${i + 1}/${allServers.length}: ${serverStr} -> ${resolvedHostname}:${port}`);
			
			const socket = await connect({
				hostname: resolvedHostname,
				port: port,
			});
			
			// console.log(`connect success: ${resolvedHostname}:${port}`);
			return {
				socket,
				server: {
					hostname: resolvedHostname,
					port: port,
					original: serverStr
				}
			};
		} catch (error) {
			// console.warn(`connect ${allServers[i]} faild:`, error.message);
			lastError = error;

			continue;
		}
	}
	
	throw new Error(`All servers connect failed: ${lastError?.message || 'Unknown error'}`);
}

function obfuscateUserAgent() {
	const userAgents = [
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
	];
	return userAgents[Math.floor(Math.random() * userAgents.length)];
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, AUTH: string, uuid: string, PROXYIP: string, PASSWORD: string, PASSWD: string, password: string, proxyip: string, proxyIP: string, DNS_RESOLVER: string, SUB_PATH: string, subpath: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {

			if (subPath === 'link' || subPath === '') {
				subPath = yourUUID;
			}

			if (env.PROXYIP || env.proxyip || env.proxyIP) {
				const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
				serverPool = servers;
			}
			password = env.PASSWORD || env.PASSWD || env.password || password;
            subPath = env.SUB_PATH || env.subpath || subPath;
			yourUUID = env.UUID || env.uuid || env.AUTH || yourUUID;
			dnsResolver = env.DNS_RESOLVER || dnsResolver;
			const upgradeHeader = request.headers.get('Upgrade');
				const url = new URL(request.url);
			
			if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
				return await VLOverWSHandler(request);
			} else {
				// Handle HTTP requests
				switch (url.pathname) {
					case '/':
						return getSubscription(request);
					case `/${subPath}`:
						return getSubscription(request);
					case '/info':
						return new Response(JSON.stringify(request.cf, null, 4), {
							status: 200,
							headers: {
								"Content-Type": "application/json;charset=utf-8",
							},
						});
					case '/connect': // for test connect to cf socket
						const [hostname, port] = ['cloudflare.com', '80'];
						console.log(`Connecting to ${hostname}:${port}...`);

						try {
							const socket = await connect({
								hostname: hostname,
								port: parseInt(port, 10),
							});

							const writer = socket.writable.getWriter();

							try {
								await writer.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: ' + hostname + '\r\n\r\n'));
							} catch (writeError) {
								writer.releaseLock();
								await socket.close();
								return new Response(writeError.message, { status: 500 });
							}

							writer.releaseLock();

							const reader = socket.readable.getReader();
							let value;

							try {
								const result = await reader.read();
								value = result.value;
							} catch (readError) {
								await reader.releaseLock();
								await socket.close();
								return new Response(readError.message, { status: 500 });
							}

							await reader.releaseLock();
							await socket.close();

							return new Response(new TextDecoder().decode(value), { status: 200 });
						} catch (connectError) {
							return new Response(connectError.message, { status: 500 });
						}
						
					default:
						const randomSites = cfip.length > 0 ? cfip : [
							'ip.sb', 'time.is', 'www.apple.com', 'skk.moe',
							'www.visa.com.tw', 'www.github.com', 'www.ups.com',
							'www.tesla.com', 'www.microsoft.com', 'www.amazon.com'
						];
						const randomSite = randomSites[Math.floor(Math.random() * randomSites.length)];
						
						const Url = new URL(`https://${randomSite}${url.pathname}${url.search}`);
						
						const headers = new Headers(request.headers);
						headers.set('User-Agent', obfuscateUserAgent());
						headers.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
						headers.set('Accept-Language', 'zh-CN,zh;q=0.9,en;q=0.8');
						headers.set('Accept-Encoding', 'gzip, deflate, br');
						headers.set('DNT', '1');
						headers.set('Connection', 'keep-alive');
						headers.set('Upgrade-Insecure-Requests', '1');
						headers.set('Host', randomSite);
						
						const UrlRequest = new Request(Url, {
							method: request.method,
							headers: headers,
							body: request.body
						});
						
						try {
							const response = await fetch(UrlRequest);
							return response;
						} catch (error) {
							return new Response('Service Unavailable', { status: 502 });
						}
				}
			}
		} catch (err) {
			return new Response('Internal Server Error', {
				status: 500,
				headers: {
					'Content-Type': 'text/plain;charset=utf-8',
				},
			});
		}
	},
};

/**
 * 
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function VLOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	webSocket.accept();

	const log = () => {};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			try {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
					
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
				}
				} catch (writeError) {
					controller.error(writeError);
				}

			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				VLVersion = new Uint8Array([0, 0]),
				isUDP,
			} = await processVLHeader(chunk, yourUUID);
			if (hasError) {
				throw new Error(message);
			}
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
			} else {
				throw new Error('only enable for DNS which is port 53');
			}
			}
			const VLResponseHeader = new Uint8Array([VLVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, VLResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, VLResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

/**
 *
 * @param {any} remoteSocket 
 * @param {string} addressRemote 
 * @param {number} portRemote 
 * @param {Uint8Array} rawClientData 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket
 * @param {Uint8Array} VLResponseHeader 
 * @param {function} log 
 * @returns {Promise<void>}
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, VLResponseHeader, log,) {
	async function connectAndWrite(address, port) {
		try {
			/** @type {import("@cloudflare/workers-types").Socket} */
			const tcpSocket = connect({
				hostname: address,
				port: port,
			});
			remoteSocket.value = tcpSocket;
			
			const writer = tcpSocket.writable.getWriter();
			await writer.write(rawClientData); 
			writer.releaseLock();
			return tcpSocket;
		} catch (connectError) {
			throw connectError;
		}
	}

	async function retry() {
		try {
			// use sequential failover mechanism to connect server
			const { socket: tcpSocket, server } = await connectWithFailover();
			remoteSocket.value = tcpSocket;
			
			const writer = tcpSocket.writable.getWriter();
			await writer.write(rawClientData);
			writer.releaseLock();
			
			tcpSocket.closed.catch(error => {
				safeCloseWebSocket(webSocket);
			}).finally(() => {
				safeCloseWebSocket(webSocket);
			});
			remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
		} catch (retryError) {
			console.error('All servers connect failed:', retryError.message);
			safeCloseWebSocket(webSocket);
		}
	}

	try {
		// first try to connect to target address directly
		const tcpSocket = await connectAndWrite(addressRemote, portRemote);
		remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, retry, log);
	} catch (connectError) {
		console.log(`direct connect failed, try to use failover: ${addressRemote}:${portRemote}`);
		retry();
	}
}

/**
 * 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer
 * @param {string} earlyDataHeader 
 * @param {(info: string)=> void} log 
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			}
			);
			webSocketServer.addEventListener('error', (err) => {
				controller.error(err);
			}
			);
			// for ws 0rtt
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {

		},
		cancel(reason) {
			if (readableStreamCancel) {
				return;
			}
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;

}

/**
 * 
 * @param { ArrayBuffer} VLBuffer 
 * @param {string} yourUUID 
 * @returns 
 */
async function processVLHeader(
	VLBuffer,
	yourUUID
) {
	if (VLBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}
	const version = new Uint8Array(VLBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(VLBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);

	const ids = yourUUID.includes(',') ? yourUUID.split(",") : [yourUUID];

	// Check id against local list
	isValidUser = ids.some(yourUUID => slicedBufferString === yourUUID.trim());

	// ID validation completed

	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(VLBuffer.slice(17, 18))[0];

	const command = new Uint8Array(
		VLBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	if (command === 1) {
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		VLBuffer.slice(addressIndex, addressIndex + 1)
	);

	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				VLBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		VLVersion: version,
		isUDP,
	};
}


/**
 * 
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} VLResponseHeader 
 * @param {(() => Promise<void>) | null} retry
 * @param {*} log 
 */
async function remoteSocketToWS(remoteSocket, webSocket, VLResponseHeader, retry, log) {
	/** @type {ArrayBuffer | null} */
	let VLHeader = VLResponseHeader;
	let hasIncomingData = false; 
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 * 
				 * @param {Uint8Array} chunk 
				 * @param {*} controller 
				 */
				async write(chunk, controller) {
					try {
					hasIncomingData = true;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
							return;
						}

						
						if (VLHeader) {
							webSocket.send(await new Blob([VLHeader, chunk]).arrayBuffer());
							VLHeader = null;
					} else {
						webSocket.send(chunk);
						}
					} catch (sendError) {
						controller.error(sendError);
					}
				},
				close() {
					// Remote connection closed
				},
				abort(reason) {
					// Connection aborted
				},
			})
		)
		.catch((error) => {
			safeCloseWebSocket(webSocket);
		});

	if (hasIncomingData === false && retry) {
		retry();
	}
}

/**
 * 
 * @param {string} base64Str 
 * @returns 
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}

/**
 * @param {string} id 
 */
function isValidAUTH(id) {
	const idRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return idRegex.test(id);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * @param {import("@cloudflare/workers-types").WebSocket} socket
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		// WebSocket close error
	}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
	const id = unsafeStringify(arr, offset);
	if (!isValidAUTH(id)) {
		throw TypeError("Stringified id is invalid");
	}
	return id;
}

/**
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} VLResponseHeader 
 * @param {(string)=> void} log 
 */
async function handleUDPOutBound(webSocket, VLResponseHeader, log) {

	let isVLHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {
		}
	});

	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch(dnsResolver,
				{
					method: 'POST',
					headers: {
						'content-type': 'application/dns-message',
					},
					body: chunk,
				})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				if (isVLHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([VLResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVLHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		// DNS UDP error
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 * 
		 * @param {Uint8Array} chunk 
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

/**
 * @param {string} yourUUID 
 * @param {string | null} url
 * @returns {string}
 */
function getVLConfig(yourUUID, url) {
	const wsPath = '/?ed=2560';
	const encodedPath = encodeURIComponent(wsPath);
	const addresses = Array.isArray(cfip) ? cfip : [cfip];
	const header = 'v-l-e-s-s';
	const configs = addresses.map(addr => `${header}://${yourUUID}@${addr}:443?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${encodedPath}#Workers-service`);
	return configs.join('\n').replace(new RegExp(header, 'g'), 'v' + 'l' + 'e' + 's' + 's');
}

/**
 * @param {import("@cloudflare/workers-types").Request} request
 * @returns {Response}
 */
function getSubscription(request) {
	const url = request.headers.get('Host');
	
	const VLUrl = getVLConfig(yourUUID, url);
	const content = btoa(VLUrl);
	
	return new Response(content, {
		status: 200,
		headers: {
			'Content-Type': 'text/plain;charset=utf-8',
			'Cache-Control': 'no-cache, no-store, must-revalidate',
		},
	});
}
