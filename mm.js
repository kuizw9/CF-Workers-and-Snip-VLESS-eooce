// _worker.js - 完整版：硬編碼 3 個 UUID，不依賴環境變數
import { connect } from 'cloudflare:sockets';

// === 相关环境变量(都是可选的) ===
let subPath = 'link'; // 订阅路径,不修改将使用第一个UUID作为订阅路径
let password = '123456'; // 主页密码，建议修改
let serverPool = ['13.230.34.30:443']; // proxyIP
// === 硬編碼 3 個 UUID（不再從 env.UUID 讀取）===
const UUID_LIST = [
  '5dc15e15-f285-4a9d-959b-0e4fbdd77b65',
  '5dc15e15-f285-4a9d-959b-0e4fbdd77b64',
  '5dc15e15-f285-4a9d-959b-0e4fbdd77b63'
];
let yourUUID = UUID_LIST[0]; // 預設第一個 UUID
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
  return { hostname, port };
}

// resolve hostname to IP address
async function resolveHostname(hostname) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(hostname)) {
    return hostname;
  }
  try {
    const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    if (dnsResponse.ok) {
      const dnsData = await dnsResponse.json();
      if (dnsData.Answer && dnsData.Answer.length > 0) {
        return dnsData.Answer[0].data;
      }
    }
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
      const socket = await connect({ hostname: resolvedHostname, port });
      return { socket, server: { hostname: resolvedHostname, port, original: serverStr } };
    } catch (error) {
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
  async fetch(request, env, ctx) {
    try {
      // 仍支援環境變數覆蓋（可選）
      if (env.PROXYIP || env.proxyip || env.proxyIP) {
        const servers = (env.PROXYIP || env.proxyip || env.proxyIP).split(',').map(s => s.trim());
        serverPool = servers;
      }
      password = env.PASSWORD || env.PASSWD || env.password || password;
      subPath = env.SUB_PATH || env.subpath || subPath;
      // 優先使用環境變數 UUID（若有），否則用硬編碼
      if (env.UUID || env.uuid || env.AUTH) {
        yourUUID = env.UUID || env.uuid || env.AUTH;
      } else {
        yourUUID = UUID_LIST.join(','); // 合併為字串
      }
      dnsResolver = env.DNS_RESOLVER || dnsResolver;

      const upgradeHeader = request.headers.get('Upgrade');
      const url = new URL(request.url);

      if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        return await VLOverWSHandler(request);
      } else {
        switch (url.pathname) {
          case '/':
            return getHomePage(request);
          case `/${subPath}`:
            return getSubscription(request);
          case '/info':
            return new Response(JSON.stringify(request.cf, null, 4), {
              status: 200,
              headers: { "Content-Type": "application/json;charset=utf-8" }
            });
          case '/connect':
            const [hostname, port] = ['cloudflare.com', '80'];
            try {
              const socket = await connect({ hostname, port: parseInt(port, 10) });
              const writer = socket.writable.getWriter();
              try {
                await writer.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: ' + hostname + '\r\n\r\n'));
              } catch { writer.releaseLock(); await socket.close(); return new Response('Write error', { status: 500 }); }
              writer.releaseLock();
              const reader = socket.readable.getReader();
              let value;
              try {
                const result = await reader.read();
                value = result.value;
              } catch { await reader.releaseLock(); await socket.close(); return new Response('Read error', { status: 500 }); }
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
        headers: { 'Content-Type': 'text/plain;charset=utf-8' }
      });
    }
  },
};

async function VLOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  const log = () => {};
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      try {
        if (isDns && udpStreamWrite) {
          return udpStreamWrite(chunk);
        }
        if (remoteSocketWapper.value) {
          const writer = remoteSocketWapper.value.writable.getWriter();
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
    close() { log(`readableWebSocketStream is close`); },
    abort(reason) { log(`readableWebSocketStream is abort`, JSON.stringify(reason)); },
  })).catch((err) => {
    log('readableWebSocketStream pipeTo error', err);
  });

  return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, VLResponseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const { socket: tcpSocket } = await connectWithFailover();
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    tcpSocket.closed.catch(error => safeCloseWebSocket(webSocket)).finally(() => safeCloseWebSocket(webSocket));
    remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, null, log);
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, VLResponseHeader, retry, log);
  } catch (connectError) {
    console.log(`direct connect failed, try to use failover: ${addressRemote}:${portRemote}`);
    retry();
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => controller.error(err));
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) return;
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}

// === 關鍵修改：支援硬編碼多 UUID ===
async function processVLHeader(VLBuffer, yourUUID) {
  if (VLBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }

  const version = new Uint8Array(VLBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;

  const slicedBuffer = new Uint8Array(VLBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  // 支援多 UUID：從字串或陣列中解析，自動去橫線
  let ids = [];
  if (Array.isArray(yourUUID)) {
    ids = yourUUID.map(id => id.replace(/-/g, ''));
  } else {
    ids = yourUUID.split(",").map(s => s.trim().replace(/-/g, ''));
  }

  isValidUser = ids.some(id => slicedBufferString === id);

  if (!isValidUser) {
    return { hasError: true, message: 'invalid user' };
  }

  const optLength = new Uint8Array(VLBuffer.slice(17, 18))[0];
  const command = new Uint8Array(VLBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `command ${command} is not support, command 01-tcp,02-udp,03-mux` };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = VLBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(VLBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2:
      addressLength = new Uint8Array(VLBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(VLBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: `invild addressType is ${addressType}` };
  }

  if (!addressValue) {
    return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };
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

async function remoteSocketToWS(remoteSocket, webSocket, VLResponseHeader, retry, log) {
  let VLHeader = VLResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(new WritableStream({
    start() {},
    async write(chunk, controller) {
      try {
        hasIncomingData = true;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          controller.error('webSocket.readyState is not open');
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
    close() {},
    abort(reason) {},
  })).catch(() => safeCloseWebSocket(webSocket));

  if (hasIncomingData === false && retry) retry();
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, c => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidAUTH(id) {
  const idRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return idRegex.test(id);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
          byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
          byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
          byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
          byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
  const id = unsafeStringify(arr, offset);
  if (!isValidAUTH(id)) throw TypeError("Stringified id is invalid");
  return id;
}

async function handleUDPOutBound(webSocket, VLResponseHeader, log) {
  let isVLHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {}
  });

  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch(dnsResolver, {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message' },
        body: chunk,
      });
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
  })).catch(() => {});

  const writer = transformStream.writable.getWriter();
  return { write(chunk) { writer.write(chunk); } };
}

function getVLConfig(yourUUID, url) {
  const wsPath = '/?ed=2560';
  const encodedPath = encodeURIComponent(wsPath);
  const addresses = Array.isArray(cfip) ? cfip : [cfip];
  const header = 'v-l-e-s-s';
  let configs = [];
  if (yourUUID.includes(',')) {
    const uuids = yourUUID.split(',').map(s => s.trim());
    uuids.forEach(uuid => {
      addresses.forEach(addr => {
        configs.push(`${header}://${uuid}@${addr}:443?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${encodedPath}#Workers-service`);
      });
    });
  } else {
    addresses.forEach(addr => {
      configs.push(`${header}://${yourUUID}@${addr}:443?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${encodedPath}#Workers-service`);
    });
  }
  return configs.join('\n').replace(new RegExp(header, 'g'), 'vless');
}

function getHomePage(request) {
  const url = request.headers.get('Host');
  const baseUrl = `https://${url}`;
  const urlObj = new URL(request.url);
  const providedPassword = urlObj.searchParams.get('password');
  if (providedPassword) {
    if (providedPassword === password) {
      return getMainPageContent(url, baseUrl);
    } else {
      return getLoginPage(url, baseUrl, true);
    }
  }
  return getLoginPage(url, baseUrl, false);
}

function getLoginPage(url, baseUrl, showError = false) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service - 登录</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; align-items: center; justify-content: center; color: #333; }
        .login-container { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; padding: 40px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); max-width: 400px; width: 95%; text-align: center; }
        .logo { font-size: 3rem; margin-bottom: 20px; background: linear-gradient(45deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .title { font-size: 1.8rem; margin-bottom: 8px; color: #2d3748; }
        .subtitle { color: #718096; margin-bottom: 30px; font-size: 1rem; }
        .form-group { margin-bottom: 20px; text-align: left; }
        .form-label { display: block; margin-bottom: 8px; font-weight: 600; color: #4a5568; }
        .form-input { width: 100%; padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1rem; transition: border-color 0.3s ease; background: #fff; }
        .form-input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        .btn-login { width: 100%; padding: 12px 20px; background: linear-gradient(45deg, #667eea, #764ba2); color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.3s ease; }
        .btn-login:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1); }
        .error-message { background: #fed7d7; color: #c53030; padding: 12px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #e53e3e; }
        .footer { margin-top: 20px; color: #718096; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">Lock</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">请输入密码以访问服务</p>
        ${showError ? '<div class="error-message">密码错误，请重试</div>' : ''}
        <form onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="password" class="form-label">密码</label>
                <input type="password" id="password" name="password" class="form-input" placeholder="请输入密码" required autofocus>
            </div>
            <button type="submit" class="btn-login">登录</button>
        </form>
        <div class="footer">
            <p>Powered by eooce <a href="https://t.me/eooceu" target="_blank" style="color: #007bff; text-decoration: none;">Join Telegram group</a></p>
        </div>
    </div>
    <script>
        function handleLogin(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const currentUrl = new URL(window.location);
            currentUrl.searchParams.set('password', password);
            window.location.href = currentUrl.toString();
        }
    </script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' }
  });
}

function getMainPageContent(url, baseUrl) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workers Service</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; align-items: center; justify-content: center; color: #333; }
        .container { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; padding: 20px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); max-width: 800px; width: 95%; max-height: 90vh; text-align: center; overflow-y: auto; }
        .logout-btn { position: fixed; top: 20px; right: 20px; background: #f5f5f5; color: #ff6b6b; border: none; border-radius: 8px; padding: 8px 16px; font-size: 0.9rem; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px; }
        .logout-btn:hover { background: #e0e0e0; }
        .logo { font-size: 2.5rem; margin-bottom: 10px; background: linear-gradient(45deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .title { font-size: 1.8rem; margin-bottom: 8px; color: #2d3748; }
        .subtitle { color: #718096; margin-bottom: 15px; font-size: 1rem; }
        .info-card { background: #f7fafc; border-radius: 12px; padding: 15px; margin: 10px 0; border-left: 4px solid #667eea; }
        .info-item { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; }
        .info-item:last-child { border-bottom: none; }
        .label { font-weight: 600; color: #4a5568; }
        .value { color: #1a202c; font-family: 'Courier New', monospace; background: #edf2f7; padding: 4px 8px; border-radius: 6px; font-size: 0.8rem; }
        .button-group { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; margin: 15px 0; }
        .btn { padding: 10px 20px; border: none; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; min-width: 100px; background: linear-gradient(45deg, #667eea, #764ba2); color: white; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1); }
        .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #48bb78; margin-right: 8px; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .footer { margin-top: 10px; color: #718096; font-size: 1rem; }
        .footer-links { display: flex; gap: 15px; flex-wrap: wrap; justify-content: center; }
        .footer-link { color: #667eea; text-decoration: none; display: flex; align-items: center; gap: 6px; font-weight: 500; }
    </style>
</head>
<body>
    <button onclick="logout()" class="logout-btn">
        <i class="fas fa-sign-out-alt"></i> 退出登录
    </button>
    <div class="container">
        <div class="logo">Rocket</div>
        <h1 class="title">Workers Service</h1>
        <p class="subtitle">基于 Cloudflare Workers 的高性能网络服务</p>
        <div class="info-card">
            <div class="info-item">
                <span class="label">服务状态</span>
                <span class="value"><span class="status"></span>运行中</span>
            </div>
            <div class="info-item">
                <span class="label">主机地址</span>
                <span class="value">${url}</span>
            </div>
            <div class="info-item">
                <span class="label">UUID</span>
                <span class="value">${UUID_LIST.join('<br>')}</span>
            </div>
            <div class="info-item">
                <span class="label">base64订阅地址</span>
                <span class="value">${baseUrl}/${subPath}</span>
            </div>
            <div class="info-item">
                <span class="label">Clash订阅地址</span>
                <span class="value">https://sublink.eooce.com/clash?config=${baseUrl}/${subPath}</span>
            </div>
            <div class="info-item">
                <span class="label">singbox订阅地址</span>
                <span class="value">https://sublink.eooce.com/singbox?config=${baseUrl}/${subPath}</span>
            </div>
        </div>
        <div class="button-group">
            <button onclick="copySingboxSubscription()" class="btn">复制singbox订阅链接</button>
            <button onclick="copyClashSubscription()" class="btn">复制Clash订阅链接</button>
            <button onclick="copySubscription()" class="btn">复制base64订阅链接</button>
        </div>
        <div class="footer">
            <div class="footer-links">
                <a href="https://github.com/eooce/CF-Workers-VLESS" target="_blank" class="footer-link">
                    <svg class="github-icon" viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                    </svg> GitHub
                </a>
                <a href="https://t.me/eooceu" target="_blank" class="footer-link">Telegram Join Telegram group</a>
            </div>
        </div>
    </div>
    <script>
        function showToast(message) {
            const existingToast = document.querySelector('.toast');
            if (existingToast) existingToast.remove();
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.innerHTML = '<div class="toast-icon">Check</div><div class="toast-message">' + message + '</div>';
            toast.style.cssText = 'position:fixed;top:20px;right:20px;background:#d1fae5;border-left:4px solid #10b981;padding:12px 16px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15);display:flex;gap:10px;z-index:1000;opacity:0;transform:translateX(100%);transition:all 0.3s ease;max-width:300px;';
            document.body.appendChild(toast);
            setTimeout(() => toast.style.opacity = '1'; toast.style.transform = 'translateX(0)';, 10);
            setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(100%)'; setTimeout(() => toast.remove(), 300); }, 1500);
        }
        function copySubscription() { navigator.clipboard.writeText('${baseUrl}/${subPath}').then(() => showToast('base64订阅链接已复制！')); }
        function copyClashSubscription() { navigator.clipboard.writeText('https://sublink.eooce.com/clash?config=${baseUrl}/${subPath}').then(() => showToast('Clash订阅链接已复制！')); }
        function copySingboxSubscription() { navigator.clipboard.writeText('https://sublink.eooce.com/singbox?config=${baseUrl}/${subPath}').then(() => showToast('singbox订阅链接已复制！')); }
        function logout() { if (confirm('确定要退出登录吗？')) { const u = new URL(window.location); u.searchParams.delete('password'); window.location.href = u; } }
    </script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' }
  });
}

function getSubscription(request) {
  const url = request.headers.get('Host');
  const VLUrl = getVLConfig(yourUUID, url);
  const content = btoa(VLUrl);
  return new Response(content, {
    status: 200,
    headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-cache, no-store, must-revalidate' }
  });
}
