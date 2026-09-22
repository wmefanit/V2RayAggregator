'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;
const url = require('url');
const zlib = require('zlib');

const CONFIG_FILE = process.argv[2] || process.env.SOURCES_FILE || './sub/all_sources.json';
const OUT_DIR = './dist';
const TCP_CONCURRENCY = parseInt(process.env.TCP_CONCURRENCY || '1200', 10);
const L7_CONCURRENCY = parseInt(process.env.L7_CONCURRENCY || '800', 10);
const DNS_CONCURRENCY = parseInt(process.env.DNS_CONCURRENCY || '300', 10);
const TCP_TIMEOUT_MS = parseInt(process.env.TCP_TIMEOUT_MS || '2000', 10);
const L7_TIMEOUT_MS = parseInt(process.env.L7_TIMEOUT_MS || '2500', 10);
const DNS_TIMEOUT_MS = parseInt(process.env.DNS_TIMEOUT_MS || '4000', 10);
const MAX_CANDIDATES = parseInt(process.env.MAX_CANDIDATES || '0', 10);
const CHUNK_SIZE = parseInt(process.env.CHUNK_SIZE || '20000', 10);

// ---------- 离线 ASN 库：真实 IP -> 国家/ASN/运营商 ----------
let ASN_TABLE = [];
function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function loadAsnTable(file = './data/ip2asn-v4.tsv.gz') {
  try {
    const buf = zlib.gunzipSync(fs.readFileSync(file));
    for (const line of buf.toString('utf8').trim().split('\n')) {
      const p = line.split('\t');
      if (p.length >= 5) ASN_TABLE.push({ start: ipToInt(p[0]), end: ipToInt(p[1]), asn: p[2], country: p[3], org: p[4] });
    }
    console.log(`离线 ASN 库加载完成: ${ASN_TABLE.length} 条`);
  } catch (e) {
    console.log('ASN 库缺失，国家归属回退备注解析');
  }
}
function lookupAsn(ip) {
  if (!ASN_TABLE.length || !ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return null;
  const target = ipToInt(ip);
  let low = 0, high = ASN_TABLE.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const r = ASN_TABLE[mid];
    if (target >= r.start && target <= r.end) {
      return { country: r.country === 'None' ? '' : r.country, asn: r.asn === '0' ? '' : 'AS' + r.asn, org: r.org };
    }
    if (target < r.start) high = mid - 1; else low = mid + 1;
  }
  return null;
}

// ---------- 网络工具 ----------
function fetchText(targetUrl, timeoutMs = 25000, redirects = 3) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const client = targetUrl.startsWith('https') ? https : http;
    try {
      const req = client.get(targetUrl, { timeout: timeoutMs, headers: { 'User-Agent': 'v2rayN/6.23 ClashMeta/v1.18.0' } }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
          res.resume();
          return fetchText(new url.URL(res.headers.location, targetUrl).toString(), timeoutMs, redirects - 1).then(done);
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => done(Buffer.concat(chunks).toString('utf8')));
      });
      req.on('error', () => done(''));
      req.on('timeout', () => { req.destroy(); done(''); });
    } catch (e) { return done(''); }
  });
}

function resolveA(host) {
  return Promise.race([
    dns.resolve4(host).then((ips) => (Array.isArray(ips) && ips[0]) || null).catch(() => null),
    new Promise((r) => setTimeout(() => r(null), DNS_TIMEOUT_MS)),
  ]);
}

function maybeBase64Decode(text) {
  const t = text.trim();
  if (!t || t.includes('://') || t.includes(':')) return text;
  for (const enc of ['base64', 'base64url']) {
    try {
      const d = Buffer.from(t, enc).toString('utf8');
      if (d.includes('://') || d.includes(':')) return d;
    } catch (e) {}
  }
  return text;
}

const IP_PORT_REGEX = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/;

function extractAllCandidates(text, defaultType = 'http') {
  const list = [];
  for (const raw of maybeBase64Decode(text).replace(/\r/g, '').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    if (/^(vmess|vless|trojan|ss|ssr|socks5|socks4|http|https):\/\//i.test(line)) { list.push(line); continue; }
    const m = line.match(IP_PORT_REGEX);
    if (m) {
      const port = parseInt(m[2], 10);
      if (port > 0 && port < 65536) list.push(`${defaultType}://${m[1]}:${port}`);
    }
  }
  return list;
}

function parseHostPort(link) {
  try {
    const proto = link.slice(0, link.indexOf('://')).toLowerCase();
    if (proto === 'vmess') {
      const j = JSON.parse(Buffer.from(link.slice(8).split('#')[0], 'base64').toString('utf8'));
      const host = String(j.add || ''), port = parseInt(j.port, 10);
      return host && port ? { host, port, proto, remark: j.ps || '' } : null;
    }
    if (proto === 'ssr') {
      const dec = Buffer.from(link.slice(6), 'base64').toString('utf8');
      const p = dec.split('/')[0].split(':');
      const host = p[0], port = parseInt(p[1], 10);
      return host && port ? { host, port, proto, remark: '' } : null;
    }
    const noScheme = link.slice(link.indexOf('://') + 3);
    const hashIdx = noScheme.indexOf('#');
    const remark = hashIdx >= 0 ? decodeURIComponent(noScheme.slice(hashIdx + 1)) : '';
    const body = (hashIdx >= 0 ? noScheme.slice(0, hashIdx) : noScheme).split('?')[0];
    let hostPort = body;
    if (body.includes('@')) hostPort = body.slice(body.lastIndexOf('@') + 1);
    else if (proto === 'ss') {
      const dec = Buffer.from(body, 'base64').toString('utf8');
      if (dec.includes('@')) hostPort = dec.slice(dec.lastIndexOf('@') + 1);
    }
    const i = hostPort.lastIndexOf(':');
    if (i <= 0) return null;
    const host = hostPort.slice(0, i).replace(/^[\[\]]/g, '');
    const port = parseInt(hostPort.slice(i + 1), 10);
    return host && port ? { host, port, proto, remark } : null;
  } catch (e) { return null; }
}

const FLAG_MAP = [['\uD83C\uDDEF\uD83C\uDDF5', 'JP'], ['\uD83C\uDDFA\uD83C\uDDF8', 'US'], ['\uD83C\uDDED\uD83C\uDDF0', 'HK'],
  ['\uD83C\uDDF8\uD83C\uDDEC', 'SG'], ['\uD83C\uDDF9\uD83C\uDDFC', 'TW'], ['\uD83C\uDDF0\uD83C\uDDF7', 'KR'],
  ['\uD83C\uDDEC\uD83C\uDDE7', 'GB'], ['\uD83C\uDDE9\uD83C\uDDEA', 'DE'], ['\uD83C\uDDE8\uD83C\uDDE6', 'CA'],
  ['\uD83C\uDDEB\uD83C\uDDF7', 'FR'], ['\uD83C\uDDF3\uD83C\uDDF1', 'NL'], ['\uD83C\uDDF7\uD83C\uDDFA', 'RU']];
const CN_NAME_MAP = [[/日本|东京|大阪/, 'JP'], [/香港/, 'HK'], [/美国|洛杉矶|硅谷|西雅图/, 'US'], [/新加坡|狮城/, 'SG'],
  [/台湾|台北/, 'TW'], [/韩国|首尔/, 'KR'], [/德国|法兰克福/, 'DE'], [/英国|伦敦/, 'GB']];
function countryFromRemark(remark) {
  if (!remark) return '';
  for (const [flag, code] of FLAG_MAP) if (remark.includes(flag)) return code;
  const m = remark.match(/(?:^|[\s\[(\-_])(HK|TW|JP|US|SG|KR|UK|GB|DE|CA|FR|RU|IN|AU|NL|SE|IT|ES|BR|ID|MY|VN|TH|TR|PH)(?=$|[\s\])_\-])/i);
  if (m) return m[1].toUpperCase() === 'UK' ? 'GB' : m[1].toUpperCase();
  for (const [re, code] of CN_NAME_MAP) if (re.test(remark)) return code;
  return '';
}

// 仅标记 CDN ASN（不删除任何 TCP 存活节点，避免误杀 SNI/Host 转发型 Xray 代理）
const PURE_CDN_ORG_REGEX = /^(CLOUDFLARENET|CLOUDFLARESPECTRUM|FASTLY|AKAMAI-AS|AKAMAI-ASN1|EDGECAST|IMPERVA|INCAPSULA)/i;
function isCdnOrg(org) {
  return !!(org && PURE_CDN_ORG_REGEX.test(org));
}

// ---------- 原生 L7 轻量级真实验活 (带硬超时熔断 + 粘包/分片健壮处理) ----------
function withHardTimeout(promise, timeoutMs) {
  let timer = null;
  const timeoutPromise = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
  });
  return Promise.race([
    promise.finally(() => { if (timer) clearTimeout(timer); }),
    timeoutPromise
  ]);
}

function probeL7HttpRaw(ip, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (e) {}
      resolve(ok ? Date.now() - start : null);
    };
    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.once('close', () => finish(false));

    sock.connect(port, ip, () => {
      const req = 'GET http://cp.cloudflare.com/generate_204 HTTP/1.1\r\n' +
                  'Host: cp.cloudflare.com\r\n' +
                  'User-Agent: curl/8.5.0\r\n' +
                  'Proxy-Connection: close\r\n' +
                  'Connection: close\r\n\r\n';
      sock.write(req);
    });

    let buf = '';
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.includes('204 No Content') || buf.includes('HTTP/1.1 204') || buf.includes('HTTP/1.0 204')) {
        finish(true);
      } else if (buf.length > 2000 || buf.includes('400 Bad Request') || buf.includes('403 Forbidden') || buf.includes('502 Bad Gateway')) {
        finish(false);
      }
    });
  });
}

function probeL7HttpsRaw(ip, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const start = Date.now();
    let done = false;
    let sock = null;
    const finish = (ok, plainFallback) => {
      if (done) return;
      done = true;
      try { if (sock) sock.destroy(); } catch (e) {}
      resolve({ ok, ms: ok ? Date.now() - start : null, plainFallback });
    };
    try {
      sock = tls.connect({ host: ip, port, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        sock.write('GET http://cp.cloudflare.com/generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n');
      });
    } catch (e) {
      return finish(false, true);
    }
    let buf = '';
    sock.on('timeout', () => finish(false, false));
    sock.on('error', () => finish(false, true));
    sock.on('close', () => finish(false, false));
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.includes('204 No Content') || buf.includes('HTTP/1.1 204') || buf.includes('HTTP/1.0 204')) {
        finish(true, false);
      } else if (buf.length > 2000) {
        finish(false, false);
      }
    });
  });
}

function probeL7Socks5Raw(ip, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    let stage = 1;
    let stageBuf = Buffer.alloc(0);
    let httpBuf = '';

    const finish = (ok) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (e) {}
      resolve(ok ? Date.now() - start : null);
    };

    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.once('close', () => finish(false));

    sock.connect(port, ip, () => {
      sock.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    sock.on('data', (chunk) => {
      if (stage === 1) {
        stageBuf = Buffer.concat([stageBuf, chunk]);
        if (stageBuf.length < 2) return;
        if (stageBuf[0] === 0x05 && stageBuf[1] === 0x00) {
          stage = 2;
          stageBuf = stageBuf.slice(2);
          const host = Buffer.from('cp.cloudflare.com', 'ascii');
          const req = Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]),
            host,
            Buffer.from([0x00, 0x50]),
          ]);
          sock.write(req);
        } else {
          return finish(false);
        }
      }

      if (stage === 2) {
        if (chunk.length > 0 && stageBuf.length === 0) {
          stageBuf = Buffer.concat([stageBuf, chunk]);
        }
        if (stageBuf.length < 4) return;
        if (stageBuf[0] !== 0x05 || stageBuf[1] !== 0x00) {
          return finish(false);
        }

        const atyp = stageBuf[3];
        let replyLen = 0;
        if (atyp === 0x01) {
          replyLen = 4 + 4 + 2; // IPv4: 10B
        } else if (atyp === 0x03) {
          if (stageBuf.length < 5) return;
          replyLen = 4 + 1 + stageBuf[4] + 2; // Domain
        } else if (atyp === 0x04) {
          replyLen = 4 + 16 + 2; // IPv6: 22B
        } else {
          return finish(false);
        }

        if (stageBuf.length < replyLen) return;

        const extraData = stageBuf.slice(replyLen);
        stage = 3;
        stageBuf = Buffer.alloc(0);
        sock.write('GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n');
        if (extraData.length > 0) {
          httpBuf += extraData.toString('utf8');
          if (httpBuf.includes('204 No Content') || httpBuf.includes('HTTP/1.1 204') || httpBuf.includes('HTTP/1.0 204')) {
            return finish(true);
          }
        }
        return;
      }

      if (stage === 3) {
        httpBuf += chunk.toString('utf8');
        if (httpBuf.includes('204 No Content') || httpBuf.includes('HTTP/1.1 204') || httpBuf.includes('HTTP/1.0 204')) {
          finish(true);
        } else if (httpBuf.length > 2000 || httpBuf.includes('400 Bad Request') || httpBuf.includes('403 Forbidden') || httpBuf.includes('502 Bad Gateway')) {
          finish(false);
        }
      }
    });
  });
}

function probeL7Socks4Raw(ip, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    let stage = 1;
    let stageBuf = Buffer.alloc(0);
    let httpBuf = '';

    const finish = (ok) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (e) {}
      resolve(ok ? Date.now() - start : null);
    };

    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.once('close', () => finish(false));

    sock.connect(port, ip, () => {
      const host = Buffer.from('cp.cloudflare.com', 'ascii');
      const req = Buffer.concat([
        Buffer.from([0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00]),
        host,
        Buffer.from([0x00]),
      ]);
      sock.write(req);
    });

    sock.on('data', (chunk) => {
      if (stage === 1) {
        stageBuf = Buffer.concat([stageBuf, chunk]);
        if (stageBuf.length < 8) return;
        if (stageBuf[0] !== 0x00 || stageBuf[1] !== 0x5a) {
          return finish(false);
        }
        const extraData = stageBuf.slice(8);
        stage = 2;
        stageBuf = Buffer.alloc(0);
        sock.write('GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n');
        if (extraData.length > 0) {
          httpBuf += extraData.toString('utf8');
          if (httpBuf.includes('204 No Content') || httpBuf.includes('HTTP/1.1 204') || httpBuf.includes('HTTP/1.0 204')) {
            return finish(true);
          }
        }
        return;
      }

      if (stage === 2) {
        httpBuf += chunk.toString('utf8');
        if (httpBuf.includes('204 No Content') || httpBuf.includes('HTTP/1.1 204') || httpBuf.includes('HTTP/1.0 204')) {
          finish(true);
        } else if (httpBuf.length > 2000 || httpBuf.includes('400 Bad Request') || httpBuf.includes('403 Forbidden') || httpBuf.includes('502 Bad Gateway')) {
          finish(false);
        }
      }
    });
  });
}

async function probeL7(proto, ip, port) {
  const p = (proto || '').toLowerCase();
  if (p === 'http') {
    const ms = await withHardTimeout(probeL7HttpRaw(ip, port, L7_TIMEOUT_MS), L7_TIMEOUT_MS + 500);
    return ms !== null ? { okMs: ms, scheme: 'http' } : null;
  }
  if (p === 'https') {
    const r = await withHardTimeout(probeL7HttpsRaw(ip, port, L7_TIMEOUT_MS), L7_TIMEOUT_MS + 500);
    if (r && r.ok) return { okMs: r.ms, scheme: 'https' };
    if (r && r.plainFallback) {
      const ms = await withHardTimeout(probeL7HttpRaw(ip, port, L7_TIMEOUT_MS), L7_TIMEOUT_MS + 500);
      if (ms !== null) return { okMs: ms, scheme: 'http' };
    }
    return null;
  }
  if (p === 'socks5') {
    const ms = await withHardTimeout(probeL7Socks5Raw(ip, port, L7_TIMEOUT_MS), L7_TIMEOUT_MS + 500);
    return ms !== null ? { okMs: ms, scheme: 'socks5' } : null;
  }
  if (p === 'socks4') {
    const ms = await withHardTimeout(probeL7Socks4Raw(ip, port, L7_TIMEOUT_MS), L7_TIMEOUT_MS + 500);
    return ms !== null ? { okMs: ms, scheme: 'socks4' } : null;
  }
  return null;
}

function tcpProbeOnce(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (e) {}
      resolve(ok ? Date.now() - start : null);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, ip);
  });
}

async function tcpProbe(ip, port) {
  return await tcpProbeOnce(ip, port, TCP_TIMEOUT_MS);
}

async function runPool(items, worker, concurrency) {
  const results = new Array(items.length);
  let idx = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = idx++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(runners);
  return results;
}

function roundRobinSample(perSourceLists, cap) {
  const cursors = perSourceLists.map(() => 0);
  const seen = new Set();
  const out = [];
  let progressed = true;
  while (progressed) {
    progressed = false;
    for (let i = 0; i < perSourceLists.length; i++) {
      const arr = perSourceLists[i];
      while (cursors[i] < arr.length) {
        const v = arr[cursors[i]++];
        progressed = true;
        if (!seen.has(v)) { seen.add(v); out.push(v); break; }
      }
      if (cap > 0 && out.length >= cap) return out;
    }
  }
  return out;
}

async function main() {
  const t0 = Date.now();
  console.log(`=== [1/4] 读取源配置: ${CONFIG_FILE} ===`);
  if (!fs.existsSync(CONFIG_FILE)) { console.error(`错误: ${CONFIG_FILE} 不存在`); process.exit(1); }
  const catalog = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  loadAsnTable();

  const taskUrls = [];
  for (const src of (catalog.sources || [])) {
    if (src.enabled === false) continue;
    for (const u of (src.urls || [])) {
      if (u.url) taskUrls.push({ name: src.name, type: u.type || 'http', url: u.url });
    }
  }
  console.log(`待抓取 URL 数: ${taskUrls.length}`);

  const perSource = await runPool(taskUrls, async (t) => {
    const cands = extractAllCandidates(await fetchText(t.url), t.type);
    console.log(`  - [${t.name}] (${t.type}) -> ${cands.length} 条`);
    return cands;
  }, 10);

  const rawList = roundRobinSample(perSource, MAX_CANDIDATES);
  const totalFetched = perSource.reduce((s, a) => s + a.length, 0);
  console.log(`\n抓取总量 ${totalFetched} 条，去重后候选 ${rawList.length} 条` + (MAX_CANDIDATES > 0 ? ` (上限 ${MAX_CANDIDATES})` : ' (全量无上限)'));

  console.log(`\n=== [2/4] 启动 ${TCP_CONCURRENCY} 高并发分块拨测 (块大小: ${CHUNK_SIZE}, 超时: ${TCP_TIMEOUT_MS}ms) ===`);
  const alive = [];
  let parsedTotal = 0, probeTotal = 0, dnsMs = 0, tcpMs = 0, cdnMarked = 0;
  let parseFailed = 0, dnsFailed = 0, tcpFailed = 0;
  let tcpT0 = 0;

  for (let off = 0; off < rawList.length; off += CHUNK_SIZE) {
    const chunk = rawList.slice(off, off + CHUNK_SIZE);
    const parsed = [];
    for (const link of chunk) {
      const ep = parseHostPort(link);
      if (ep && ep.port > 0 && ep.port < 65536) parsed.push({ link, ep });
      else parseFailed++;
    }
    parsedTotal += parsed.length;

    const dnsT0 = Date.now();
    const domains = Array.from(new Set(parsed.filter(x => !net.isIP(x.ep.host)).map(x => x.ep.host)));
    const dnsCache = new Map();
    if (domains.length > 0) {
      await runPool(domains, async (d) => { dnsCache.set(d, await resolveA(d)); }, DNS_CONCURRENCY);
    }
    dnsMs += Date.now() - dnsT0;

    const tasks = [];
    for (const x of parsed) {
      const ip = net.isIP(x.ep.host) ? x.ep.host : dnsCache.get(x.ep.host);
      if (ip) tasks.push({ ...x, ip });
      else dnsFailed++;
    }
    probeTotal += tasks.length;
    tcpT0 = Date.now();

    const probed = await runPool(tasks, async (item) => {
      const geo = lookupAsn(item.ip);
      const org = geo ? geo.org : '';
      // 不丢弃任何 TCP 存活节点：CDN ASN 仅打标，避免漏掉借 CDN 转发的 Xray 代理
      const rtt = await tcpProbe(item.ip, item.ep.port);
      if (rtt !== null) {
        return {
          link: item.link,
          proto: item.ep.proto,
          host: item.ep.host,
          ip: item.ip,
          port: item.ep.port,
          remark: item.ep.remark,
          country: (geo && geo.country) || countryFromRemark(item.ep.remark) || 'OTHER',
          asn: geo ? geo.asn : '',
          org: org,
          country_source: geo && geo.country ? 'asn_db' : 'remark',
          rtt_ms: rtt,
          cdn_edge: isCdnOrg(org),
        };
      }
      return null;
    }, TCP_CONCURRENCY);

    let aliveAdded = 0;
    for (const p of probed) {
      if (p) {
        alive.push(p);
        aliveAdded++;
        if (p.cdn_edge) cdnMarked++;
      }
    }
    tcpFailed += tasks.length - aliveAdded;
    tcpMs += Date.now() - tcpT0;

    const progress = Math.min(off + CHUNK_SIZE, rawList.length);
    const elapsed = Math.round((Date.now() - t0) / 1000);
    const speed = Math.round(probeTotal / Math.max(1, elapsed));
    console.log(`  进度: ${progress} / ${rawList.length} | 累计存活: ${alive.length} | 速率: ~${speed} 端点/秒`);
  }

  const l4Sec = Math.round((Date.now() - t0) / 1000);
  const sumCheck = parseFailed + dnsFailed + tcpFailed + alive.length;
  console.log(`\nL4 探活完成: TCP存活 ${alive.length} / 待探测 ${probeTotal} (耗时: ${l4Sec}s)`);
  console.log(`  计数守恒校验: 去重候选 ${rawList.length} = 解析失败 ${parseFailed} + DNS失败 ${dnsFailed} + TCP不通 ${tcpFailed} + TCP存活 ${alive.length} (合计 ${sumCheck}) → ${sumCheck === rawList.length ? '100% 守恒' : '存在未计漏检!'}`);
  console.log(`  阶段耗时拆解: DNS=${(dnsMs/1000).toFixed(1)}s  TCP=${(tcpMs/1000).toFixed(1)}s  CDN边缘标记=${cdnMarked} 个 (未删除)`);
  alive.sort((a, b) => a.rtt_ms - b.rtt_ms);

  // === [2.5/4] 对全量 TCP 存活节点做小字节 204 协议通断 (不做带宽测速) ===
  console.log(`\n=== [2.5/4] 启动 ${L7_CONCURRENCY} 并发对全量 ${alive.length} 个存活节点做 204 协议通断 ===`);
  const l7T0 = Date.now();
  const l7Verified = [];
  let l7Attempted = 0, l7Passed = 0, l7Failed = 0;

  await runPool(alive, async (item) => {
    const p = (item.proto || '').toLowerCase();
    if (p === 'http' || p === 'https' || p === 'socks5' || p === 'socks4') {
      l7Attempted++;
      const r = await probeL7(p, item.ip, item.port);
      if (r !== null) {
        item.verification = 'l7_204';
        item.l7_rtt_ms = r.okMs; // 记录 DNS+TCP+204 回传业务延迟
        if (p === 'https' && r.scheme === 'http') {
          item.link = item.link.replace(/^https:\/\//, 'http://');
          item.proto = 'http';
        }
        l7Passed++;
        l7Verified.push(item);
      } else {
        // 204 不通的节点仍保留在全量 TCP 存活池中（绝不物理删除，标记 tcp_only）
        item.verification = 'tcp_only';
        l7Failed++;
      }
    } else {
      // Xray 协议（vless/vmess/trojan/ss）云端仅能确认 TCP 可达；全部保留在 xray_alive 待本地 strictprobe 精验
      item.verification = 'tcp_only';
    }
  }, L7_CONCURRENCY);

  // L7 验证池按真实 204 响应延迟升序严格排序
  l7Verified.sort((a, b) => (a.l7_rtt_ms || 9999) - (b.l7_rtt_ms || 9999));
  const l7Sec = Math.round((Date.now() - l7T0) / 1000);
  console.log(`  协议通断完成: 尝试 ${l7Attempted} 个直接代理，${l7Passed} 个通过 204 (不通 ${l7Failed})，耗时 ${l7Sec}s`);

  console.log('\n=== [3/4] 导出分层结构化产物 ===');
  fs.rmSync(OUT_DIR, { recursive: true, force: true });
  fs.mkdirSync(path.join(OUT_DIR, 'by_country'), { recursive: true });
  fs.mkdirSync(path.join(OUT_DIR, 'by_protocol'), { recursive: true });

  const countryMap = {}, protoMap = {};
  for (const n of alive) {
    (countryMap[n.country] = countryMap[n.country] || []).push(n.link);
    (protoMap[n.proto] = protoMap[n.proto] || []).push(n.link);
  }

  // 1. 全量多出口池 (包含全部 TCP 存活节点，一个不丢)
  fs.writeFileSync('all_exit.json', JSON.stringify(alive, null, 2));
  fs.writeFileSync('all_exit.txt', alive.map(n => n.link).join('\n'));
  fs.writeFileSync('all_exit_base64.txt', Buffer.from(alive.map(n => n.link).join('\n')).toString('base64'));
  fs.writeFileSync('all_exit_meta.txt', alive.map(n =>
    `[${n.country || 'XX'}|${n.asn || '-'}|${n.rtt_ms}ms|${n.verification || 'tcp_only'}] ${n.link}`).join('\n'));

  // 2. 全量 L7 验活池 (HTTP/SOCKS 协议 100% 确认通断)
  fs.writeFileSync('all_l7_verified.txt', l7Verified.map(n => n.link).join('\n'));
  fs.writeFileSync('all_l7_verified_meta.json', JSON.stringify(l7Verified.map(n => ({
    link: n.link, proto: n.proto, ip: n.ip, port: n.port, country: n.country,
    tcp_rtt_ms: n.rtt_ms, l7_rtt_ms: n.l7_rtt_ms, verification: 'l7_204'
  })), null, 2));

  // 3. Xray 待验池 (云端已确认为 TCP 存活的 Xray 节点，供本地快速精验)
  const XRAY_PROTOS = new Set(['vless', 'vmess', 'trojan', 'ss', 'ssr']);
  const xrayAlive = alive.filter(n => XRAY_PROTOS.has((n.proto || '').toLowerCase()));
  fs.writeFileSync('xray_alive.txt', xrayAlive.map(n => n.link).join('\n'));
  fs.writeFileSync('xray_alive_meta.json', JSON.stringify(xrayAlive.map(n => ({
    link: n.link, proto: n.proto, ip: n.ip, port: n.port, country: n.country,
    tcp_rtt_ms: n.rtt_ms, verification: 'tcp_only'
  })), null, 2));

  // 4. 高速推荐池 (仅限 100% 通过 204 验证的节点，按延迟排序，不再混入未验证 Xray 节点)
  const topFast = l7Verified.slice(0, 500);
  fs.writeFileSync('high_speed.txt', topFast.map(n => n.link).join('\n'));
  fs.writeFileSync('high_speed_meta.json', JSON.stringify(topFast.map(n => ({
    link: n.link, proto: n.proto, ip: n.ip, port: n.port, country: n.country,
    tcp_rtt_ms: n.rtt_ms, l7_rtt_ms: n.l7_rtt_ms, verification: 'l7_204'
  })), null, 2));
  fs.writeFileSync('Eternity.txt', topFast.map(n => n.link).join('\n'));
  fs.writeFileSync('Eternity', Buffer.from(topFast.map(n => n.link).join('\n')).toString('base64'));

  // 5. 国别与协议分流
  for (const [c, links] of Object.entries(countryMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_country', `${c.toLowerCase()}.txt`), links.join('\n'));
  }
  for (const [p, links] of Object.entries(protoMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_protocol', `${p.toLowerCase()}.txt`), links.join('\n'));
  }

  // 6. 总体报告
  const summary = {
    updated_at: new Date().toISOString(),
    total_fetched_raw: totalFetched,
    deduped_candidates: rawList.length,
    parse_failed: parseFailed,
    dns_failed: dnsFailed,
    tcp_failed: tcpFailed,
    tcp_alive_nodes: alive.length,
    l7_verified_nodes: l7Verified.length,
    xray_alive_nodes: xrayAlive.length,
    high_speed_nodes: topFast.length,
    conservation_check: sumCheck === rawList.length ? 'CONSERVED' : 'MISMATCH',
    countries: Object.fromEntries(Object.entries(countryMap).map(([k, v]) => [k, v.length])),
    protocols: Object.fromEntries(Object.entries(protoMap).map(([k, v]) => [k, v.length])),
    elapsed_seconds: Math.round((Date.now() - t0) / 1000),
  };
  fs.writeFileSync('summary.json', JSON.stringify(summary, null, 2));

  console.log('🎉 分层产物导出完成：');
  console.log(`- all_exit.txt: ${alive.length} 节点 (全量 TCP 存活池)`);
  console.log(`- all_l7_verified.txt: ${l7Verified.length} 节点 (全量 L7 204 已验活池)`);
  console.log(`- xray_alive.txt: ${xrayAlive.length} 节点 (Xray TCP 存活待本地精验池)`);
  console.log(`- high_speed.txt: ${topFast.length} 节点 (Top 500 低延迟已验活推荐池)`);
  console.log(`- dist/by_country/: ${Object.keys(countryMap).length} 个国家地区分流`);
  console.log(`- dist/by_protocol/: ${Object.keys(protoMap).length} 个协议分流`);
  console.log(`- summary.json: 统计摘要报告 (守恒校验: ${summary.conservation_check})`);
}

main().catch((e) => { console.error(e); process.exit(1); });
