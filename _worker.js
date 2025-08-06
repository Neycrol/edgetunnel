import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIPs = [];
let path = '/?ed=2560';
let addressesapi = [];
let RproxyIP = 'false';
let allowInsecure = '&allowInsecure=1';
let SCV = 'true';

export default {
    async fetch(request, env, ctx) {
        try {
            userID = env.UUID || userID;
            if (!userID) {
                return new Response('请设置你的UUID变量', { status: 404 });
            }

            if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
            proxyIPs = await 整理优选列表(addressesapi);

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);

            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                const hostName = request.headers.get('Host');
                const pathname = url.pathname;

                if (pathname === `/${userID}`) {
                    const content = await 生成本地订阅(hostName, userID);
                    return new Response(content, {
                        status: 200,
                        headers: {
                            "Content-Type": "text/plain;charset=utf-8",
                        }
                    });
                } else {
                    return new Response('无效路径', { status: 404 });
                }
            }

            return await 维列斯OverWSHandler(request);
        } catch (err) {
            return new Response(err.toString());
        }
    },
};

async function 维列斯OverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const { hasError, message, addressType, portRemote = 443, addressRemote = '', rawDataIndex, 维列斯Version = new Uint8Array([0, 0]), isUDP } = process维列斯Header(chunk, userID);
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '}`;
            if (hasError) {
                throw new Error(message);
            }

            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                } else {
                    throw new Error('UDP 代理仅对 DNS（53 端口）启用');
                }
            }

            const 维列斯ResponseHeader = new Uint8Array([维列斯Version[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, 维列斯ResponseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }

            log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
            handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log);
        },
        close() {
            log(`readableWebSocketStream 已关闭`);
        },
        abort(reason) {
            log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream 管道错误', err);
    });

    return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log) {
    async function connectAndWrite(address, port) {
        log(`连接到 ${address}:${port}`);
        if (isIPv6(address) && !address.startsWith('[') && !address.endsWith(']')) {
            address = `[${address}]`;
        }
        const tcpSocket = connect({ hostname: address, port: port });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        const proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)] || addressRemote;
        tcpSocket = await connectAndWrite(proxyIP, portRemote);
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, null, log);
    }

    let tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
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
                if (!readableStreamCancel) controller.close();
            });
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket 服务器错误');
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        cancel(reason) {
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

function process维列斯Header(维列斯Buffer, userID) {
    if (维列斯Buffer.byteLength < 24) {
        return { hasError: true, message: 'invalid data' };
    }
    const version = new Uint8Array(维列斯Buffer.slice(0, 1));
    const userIDArray = new Uint8Array(维列斯Buffer.slice(1, 17));
    const userIDString = stringify(userIDArray);
    if (userIDString !== userID) {
        return { hasError: true, message: `invalid user ${userIDArray}` };
    }
    const optLength = new Uint8Array(维列斯Buffer.slice(17, 18))[0];
    const command = new Uint8Array(维列斯Buffer.slice(18 + optLength, 19 + optLength))[0];
    let isUDP = false;
    if (command === 1) {
        // TCP
    } else if (command === 2) {
        isUDP = true;
    } else {
        return { hasError: true, message: `command ${command} not supported` };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = 维列斯Buffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(维列斯Buffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(维列斯Buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `invalid addressType ${addressType}` };
    }
    if (!addressValue) {
        return { hasError: true, message: `addressValue empty, addressType ${addressType}` };
    }
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        维列斯Version: version,
        isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, 维列斯ResponseHeader, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk) {
            hasIncomingData = true;
            if (webSocket.readyState !== 1) return;
            webSocket.send(chunk);
        },
        close() {
            log(`remoteSocket.readable closed`);
        },
        abort(reason) {
            console.error(`remoteSocket.readable abort`, reason);
        },
    })).catch((error) => {
        console.error(`remoteSocketToWS error`, error);
        safeCloseWebSocket(webSocket);
    });
    if (!hasIncomingData && retry) {
        retry();
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: undefined, error: null };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
        socket.close();
    }
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
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw TypeError(`生成的 UUID 不符合规范 ${uuid}`);
    }
    return uuid;
}

async function 整理优选列表(api) {
    if (!api || api.length === 0) return [];
    let newapi = "";
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    try {
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: { 'User-Agent': 'CF-Workers-edgetunnel/cmliu' },
            signal: controller.signal
        }).then(res => res.ok ? res.text() : Promise.reject())));
        for (const [index, response] of responses.entries()) {
            if (response.status === 'fulfilled') {
                const content = await response.value;
                const lines = content.split(/\r?\n/);
                let remark = '';
                let testPort = '443';
                if (lines[0].split(',').length > 3) {
                    const idMatch = api[index].match(/id=([^&]*)/);
                    if (idMatch) remark = idMatch[1];
                    const portMatch = api[index].match(/port=([^&]*)/);
                    if (portMatch) testPort = portMatch[1];
                    for (let i = 1; i < lines.length; i++) {
                        let col = lines[i].split(',')[0];
                        if (col) {
                            if (isIPv6(col) && !col.startsWith('[') && !col.endsWith(']')) {
                                col = `[${col}]`;
                            }
                            newapi += `${col}:${testPort}${remark ? `#${remark}` : ''}\n`;
                        }
                    }
                } else {
                    newapi += content + '\n';
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        clearTimeout(timeout);
    }
    return await 整理(newapi);
}

async function 整理(content) {
    content = content.replace(/[ |"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (content.startsWith(',')) content = content.slice(1);
    if (content.endsWith(',')) content = content.slice(0, -1);
    return content.split(',');
}

function isIPv6(address) {
    return address.includes(':') && /^[0-9a-fA-F:]+$/.test(address);
}

function parseAddress(addressStr) {
    if (addressStr.startsWith('[')) {
        const match = addressStr.match(/\[([^\]]+)\]:(\d+)(#.*)?$/);
        if (match) {
            return { address: match[1], port: match[2], remark: match[3] ? match[3].slice(1) : '' };
        }
    }

    if (addressStr.includes(':') && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(addressStr)) {
        if (addressStr.includes('#')) {
            const [ip, remark] = addressStr.split('#', 2);
            return { address: ip, port: '443', remark };
        }
        return { address: addressStr, port: '443', remark: '' };
    }

    let address = addressStr;
    let port = '443';
    let remark = '';

    if (address.includes('#')) {
        [address, remark] = address.split('#', 2);
    }

    if (address.includes(':')) {
        const [addr, prt] = address.split(':');
        address = addr;
        port = prt;
    }

    return { address, port, remark };
}

async function 生成本地订阅(host, UUID) {
    const addresses = await 整理优选列表(addressesapi);
    const uniqueAddresses = [...new Set(addresses)];
    const responseBody = uniqueAddresses.map(addrStr => {
        const { address, port, remark } = parseAddress(addrStr);
        let addressid = remark || address;
        let finalAddress = address;
        if (isIPv6(finalAddress) && !finalAddress.startsWith('[') && !finalAddress.endsWith(']')) {
            finalAddress = `[${finalAddress}]`;
        }
        const 协议类型 = 'vless';
        return `${协议类型}://${UUID}@${finalAddress}:${port}?encryption=none&security=tls&sni=${host}&fp=random&type=ws&host=${host}&path=${encodeURIComponent(path)}${allowInsecure}#${encodeURIComponent(addressid)}`;
    }).join('\n');
    return btoa(responseBody);
}
