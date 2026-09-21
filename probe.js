'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const net = require('net');
const dns = require('dns').promises;
const url = require('url');
const zlib = require('zlib');

const CONFIG_FILE = process.argv[2] || process.env.SOURCES_FILE || './sub/sample_sources.json';
const OUT_DIR = './dist';
const TCP_CONCURRENCY = parseInt(process.env.TCP_CONCURRENCY || '500', 10);
const DNS_CONCURRENCY = parseInt(process.env.DNS_CONCURRENCY || '200', 10);
const TCP_TIMEOUT_MS = parseInt(process.env.TCP_TIMEOUT_MS || '2000', 10);
const DNS_TIMEOUT_MS = parseInt(process.env.DNS_TIMEOUT_MS || '5000', 10);
// 0 = 不限制（全量）；>0 时按源轮询均匀采样，保证样本代表性
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
function fetchText(targetUrl, timeoutMs = 15000, redirects = 3) {
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

// c-ares 纯异步解析，避免 dns.lookup 走 libuv 4 线程池卡死
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

// 备注兜底国家识别（仅当 ASN 库无记录时使用）
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

function tcpProbe(ip, port) {
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
    sock.setTimeout(TCP_TIMEOUT_MS);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, ip);
  });
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

// 按源轮询均匀采样，避免"从头截断"导致协议/地区分布失真
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
  }, 8);

  const rawList = roundRobinSample(perSource, MAX_CANDIDATES);
  const totalFetched = perSource.reduce((s, a) => s + a.length, 0);
  console.log(`\n抓取总量 ${totalFetched} 条，去重采样后候选 ${rawList.length} 条` + (MAX_CANDIDATES > 0 ? ` (上限 ${MAX_CANDIDATES})` : ''));

  console.log('\n=== [2/4] 解析端点 + 分块 DNS 预解析 + TCP 探活 ===');
  const alive = [];
  let parsedTotal = 0, probeTotal = 0;
  for (let off = 0; off < rawList.length; off += CHUNK_SIZE) {
    const chunk = rawList.slice(off, off + CHUNK_SIZE);
    const parsed = [];
    for (const link of chunk) {
      const ep = parseHostPort(link);
      if (ep && ep.port > 0 && ep.port < 65536) parsed.push({ link, ep });
    }
    parsedTotal += parsed.length;

    const domains = Array.from(new Set(parsed.filter(x => !net.isIP(x.ep.host)).map(x => x.ep.host)));
    const dnsCache = new Map();
    await runPool(domains, async (d) => { dnsCache.set(d, await resolveA(d)); }, DNS_CONCURRENCY);

    const tasks = parsed.map(x => ({ ...x, ip: net.isIP(x.ep.host) ? x.ep.host : dnsCache.get(x.ep.host) })).filter(x => x.ip);
    probeTotal += tasks.length;

    const probed = await runPool(tasks, async (item) => {
      const rtt = await tcpProbe(item.ip, item.ep.port);
      if (rtt !== null) {
        const geo = lookupAsn(item.ip);
        return {
          link: item.link,
          proto: item.ep.proto,
          host: item.ep.host,
          ip: item.ip,
          port: item.ep.port,
          remark: item.ep.remark,
          country: (geo && geo.country) || countryFromRemark(item.ep.remark) || 'OTHER',
          asn: geo ? geo.asn : '',
          org: geo ? geo.org : '',
          country_source: geo && geo.country ? 'asn_db' : 'remark',
          rtt_ms: rtt,
        };
      }
      return null;
    }, TCP_CONCURRENCY);

    for (const p of probed) if (p) alive.push(p);
    console.log(`  分块进度: ${Math.min(off + CHUNK_SIZE, rawList.length)} / ${rawList.length} (累计存活: ${alive.length})`);
  }

  console.log(`\n探活完成: 存活可用数 ${alive.length} / ${probeTotal} (耗时: ${Math.round((Date.now() - t0) / 1000)}s)`);
  alive.sort((a, b) => a.rtt_ms - b.rtt_ms);

  console.log('\n=== [3/4] 导出多场景结构化分流订阅 ===');
  fs.rmSync(OUT_DIR, { recursive: true, force: true });
  fs.mkdirSync(path.join(OUT_DIR, 'by_country'), { recursive: true });
  fs.mkdirSync(path.join(OUT_DIR, 'by_protocol'), { recursive: true });

  const countryMap = {}, protoMap = {};
  for (const n of alive) {
    (countryMap[n.country] = countryMap[n.country] || []).push(n.link);
    (protoMap[n.proto] = protoMap[n.proto] || []).push(n.link);
  }

  // 1. 全量多出口池
  fs.writeFileSync('all_exit.json', JSON.stringify(alive, null, 2));
  fs.writeFileSync('all_exit.txt', alive.map(n => n.link).join('\n'));
  fs.writeFileSync('all_exit_base64.txt', Buffer.from(alive.map(n => n.link).join('\n')).toString('base64'));
  fs.writeFileSync('all_exit_meta.txt', alive.map(n =>
    `[${n.country || 'XX'}|${n.asn || '-'}|${n.rtt_ms}ms] ${n.link}`).join('\n'));

  // 2. 低延迟优质池 (Top 200)
  const topFast = alive.slice(0, 200);
  fs.writeFileSync('high_speed.txt', topFast.map(n => n.link).join('\n'));
  fs.writeFileSync('Eternity.txt', topFast.map(n => n.link).join('\n'));
  fs.writeFileSync('Eternity', Buffer.from(topFast.map(n => n.link).join('\n')).toString('base64'));

  // 3. 国别分流
  for (const [c, links] of Object.entries(countryMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_country', `${c.toLowerCase()}.txt`), links.join('\n'));
  }

  // 4. 协议分流
  for (const [p, links] of Object.entries(protoMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_protocol', `${p.toLowerCase()}.txt`), links.join('\n'));
  }

  // 5. 总体报告
  const summary = {
    updated_at: new Date().toISOString(),
    total_fetched_raw: totalFetched,
    sampled_candidates: rawList.length,
    valid_endpoints: parsedTotal,
    dns_resolved_and_probed: probeTotal,
    alive_nodes: alive.length,
    top_fast_nodes: topFast.length,
    countries: Object.fromEntries(Object.entries(countryMap).map(([k, v]) => [k, v.length])),
    protocols: Object.fromEntries(Object.entries(protoMap).map(([k, v]) => [k, v.length])),
    elapsed_seconds: Math.round((Date.now() - t0) / 1000),
  };
  fs.writeFileSync('summary.json', JSON.stringify(summary, null, 2));

  console.log('🎉 订阅产物导出完成：');
  console.log(`- all_exit.txt / all_exit_meta.txt: ${alive.length} 节点 (全量多出口池，含国家/ASN/RTT 元数据)`);
  console.log(`- high_speed.txt / Eternity.txt: ${topFast.length} 节点 (低延迟精选池)`);
  console.log(`- dist/by_country/: ${Object.keys(countryMap).length} 个国家地区分流`);
  console.log(`- dist/by_protocol/: ${Object.keys(protoMap).length} 个协议分流`);
  console.log(`- summary.json: 统计摘要报告`);
}

main().catch((e) => { console.error(e); process.exit(1); });
