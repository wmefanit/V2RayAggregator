'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const net = require('net');
const dns = require('dns').promises;
const url = require('url');

const CONFIG_FILE = process.argv[2] || process.env.SOURCES_FILE || './sub/sample_sources.json';
const OUT_DIR = './dist';
const TCP_CONCURRENCY = parseInt(process.env.TCP_CONCURRENCY || '500', 10);
const DNS_CONCURRENCY = parseInt(process.env.DNS_CONCURRENCY || '200', 10);
const DNS_TIMEOUT_MS = parseInt(process.env.DNS_TIMEOUT_MS || '5000', 10);
const TCP_TIMEOUT_MS = parseInt(process.env.TCP_TIMEOUT_MS || '2000', 10);
// 0 = 不限制；小样本验证用上限控制规模
const MAX_PER_SOURCE = parseInt(process.env.MAX_PER_SOURCE || '0', 10);
const MAX_CANDIDATES = parseInt(process.env.MAX_CANDIDATES || '0', 10);

// 用 c-ares（dns.resolve4）纯异步解析，避免 dns.lookup 走 libuv 4 线程池卡死
function resolveA(host) {
  return Promise.race([
    dns.resolve4(host).then((ips) => (Array.isArray(ips) && ips[0]) || null).catch(() => null),
    new Promise((r) => setTimeout(() => r(null), DNS_TIMEOUT_MS)),
  ]);
}

function fetchText(targetUrl, timeoutMs = 15000, redirects = 3) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const client = targetUrl.startsWith('https') ? https : http;
    try {
      const req = client.get(targetUrl, { timeout: timeoutMs, headers: { 'User-Agent': 'v2rayN/6.23 ClashMeta/v1.18.0' } }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
          res.resume();
          const next = new url.URL(res.headers.location, targetUrl).toString();
          return fetchText(next, timeoutMs, redirects - 1).then(done);
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
  const lines = maybeBase64Decode(text).split(/[\r\n]+/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    if (/^(vmess|vless|trojan|ss|ssr|socks5|socks4|http|https):\/\//i.test(line)) {
      list.push(line);
      continue;
    }

    const m = line.match(IP_PORT_REGEX);
    if (m) {
      const port = parseInt(m[2], 10);
      if (port > 0 && port < 65536) {
        list.push(`${defaultType}://${m[1]}:${port}`);
      }
    }
  }
  return list;
}

function parseHostPort(link) {
  try {
    const proto = link.slice(0, link.indexOf('://')).toLowerCase();
    if (proto === 'vmess') {
      const b64 = link.slice(8).split('#')[0];
      const j = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
      const host = String(j.add || '');
      const port = parseInt(j.port, 10);
      return host && port ? { host, port, proto, remark: j.ps || '' } : null;
    }
    if (proto === 'ssr') {
      const dec = Buffer.from(link.slice(6), 'base64').toString('utf8');
      const [hp] = dec.split('/');
      const p = hp.split(':');
      const host = p[0], port = parseInt(p[1], 10);
      return host && port ? { host, port, proto, remark: '' } : null;
    }
    const noScheme = link.slice(link.indexOf('://') + 3);
    const hashIdx = noScheme.indexOf('#');
    const remark = hashIdx >= 0 ? decodeURIComponent(noScheme.slice(hashIdx + 1)) : '';
    const body = (hashIdx >= 0 ? noScheme.slice(0, hashIdx) : noScheme).split('?')[0];

    let hostPort = body;
    if (body.includes('@')) {
      hostPort = body.slice(body.lastIndexOf('@') + 1);
    } else if (proto === 'ss') {
      const dec = Buffer.from(body, 'base64').toString('utf8');
      if (dec.includes('@')) hostPort = dec.slice(dec.lastIndexOf('@') + 1);
    }
    const i = hostPort.lastIndexOf(':');
    if (i <= 0) return null;
    const host = hostPort.slice(0, i).replace(/^[\[\]]/g, '');
    const port = parseInt(hostPort.slice(i + 1), 10);
    return host && port ? { host, port, proto, remark } : null;
  } catch (e) {
    return null;
  }
}

const COUNTRY_REGEX = /(HK|TW|JP|US|SG|KR|UK|GB|DE|CA|FR|RU|IN|AU|NL|SE|IT|ES|BR|ID|MY|VN|TH|TR|PH)/i;

function extractCountry(remark, host) {
  const m = (remark || '').match(COUNTRY_REGEX);
  if (m) {
    let c = m[1].toUpperCase();
    if (c === 'UK') c = 'GB';
    return c;
  }
  return 'OTHER';
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

async function main() {
  const t0 = Date.now();
  console.log(`=== [1/4] 读取源配置: ${CONFIG_FILE} ===`);

  if (!fs.existsSync(CONFIG_FILE)) {
    console.error(`错误: ${CONFIG_FILE} 不存在`);
    process.exit(1);
  }

  const catalog = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  const taskUrls = [];
  for (const src of (catalog.sources || [])) {
    if (src.enabled === false) continue;
    for (const u of (src.urls || [])) {
      if (u.url) {
        taskUrls.push({ name: src.name, parser: src.parser, type: u.type || 'http', url: u.url });
      }
    }
  }

  console.log(`待抓取任务数: ${taskUrls.length}`);
  const fetched = await runPool(taskUrls, async (t) => {
    const txt = await fetchText(t.url);
    let cands = extractAllCandidates(txt, t.type);
    const rawCount = cands.length;
    if (MAX_PER_SOURCE > 0 && cands.length > MAX_PER_SOURCE) {
      cands = cands.slice(0, MAX_PER_SOURCE);
    }
    console.log(`  - [${t.name}] (${t.type}) -> 抓取到 ${rawCount} 条` + (cands.length !== rawCount ? `，采样取 ${cands.length}` : ''));
    return cands;
  }, 8);

  const rawList = Array.from(new Set(fetched.flat()));
  console.log(`去重后候选总数: ${rawList.length}`);

  console.log('\n=== [2/4] 解析端点与批量异步 DNS 预解析 ===');
  let parsed = [];
  for (const link of rawList) {
    const ep = parseHostPort(link);
    if (ep && ep.port > 0 && ep.port < 65536) {
      parsed.push({ link, ep });
    }
  }
  console.log(`有效格式端点: ${parsed.length} / ${rawList.length}`);
  if (MAX_CANDIDATES > 0 && parsed.length > MAX_CANDIDATES) {
    console.log(`按 MAX_CANDIDATES=${MAX_CANDIDATES} 截断（原始 ${parsed.length}）`);
    parsed = parsed.slice(0, MAX_CANDIDATES);
  }

  const domainSet = new Set();
  for (const item of parsed) {
    if (!net.isIP(item.ep.host)) domainSet.add(item.ep.host);
  }
  console.log(`其中独立域名: ${domainSet.size}`);

  // 并发纯异步 DNS 预解析（c-ares）
  const dnsCache = new Map();
  const domains = Array.from(domainSet);
  const dnsStart = Date.now();
  await runPool(domains, async (d) => {
    const ip = await resolveA(d);
    dnsCache.set(d, ip);
  }, DNS_CONCURRENCY);
  const resolvedCount = Array.from(dnsCache.values()).filter(Boolean).length;
  console.log(`DNS 预解析完成: ${resolvedCount} / ${domains.length} (耗时 ${Math.round((Date.now() - dnsStart) / 1000)}s)`);

  console.log(`\n=== [3/4] 启动 ${TCP_CONCURRENCY} 并发 IP 直接拨测探活 ===`);
  const probeTasks = parsed.map(item => {
    const ip = net.isIP(item.ep.host) ? item.ep.host : dnsCache.get(item.ep.host);
    return { ...item, targetIP: ip };
  }).filter(item => Boolean(item.targetIP));

  console.log(`进入探活队列数: ${probeTasks.length}`);

  let checkedCount = 0;
  const probed = await runPool(probeTasks, async (item) => {
    const rtt = await tcpProbe(item.targetIP, item.ep.port);
    checkedCount++;
    if (checkedCount % 5000 === 0 || checkedCount === probeTasks.length) {
      console.log(`  探活进度: ${checkedCount} / ${probeTasks.length} ...`);
    }
    if (rtt !== null) {
      return {
        link: item.link,
        proto: item.ep.proto,
        host: item.ep.host,
        ip: item.targetIP,
        port: item.ep.port,
        remark: item.ep.remark,
        country: extractCountry(item.ep.remark, item.ep.host),
        rtt_ms: rtt
      };
    }
    return null;
  }, TCP_CONCURRENCY);

  const alive = probed.filter(Boolean);
  console.log(`\n探活完成: 存活可用数 ${alive.length} / ${probeTasks.length} (耗时: ${Math.round((Date.now() - t0) / 1000)}s)`);

  alive.sort((a, b) => a.rtt_ms - b.rtt_ms);

  console.log('\n=== [4/4] 导出多场景结构化分流订阅 ===');
  fs.mkdirSync(path.join(OUT_DIR, 'by_country'), { recursive: true });
  fs.mkdirSync(path.join(OUT_DIR, 'by_protocol'), { recursive: true });

  const countryMap = {};
  const protoMap = {};
  for (const n of alive) {
    countryMap[n.country] = countryMap[n.country] || [];
    countryMap[n.country].push(n.link);

    protoMap[n.proto] = protoMap[n.proto] || [];
    protoMap[n.proto].push(n.link);
  }

  // 1. 全量存活多出口池
  fs.writeFileSync('all_exit.json', JSON.stringify(alive, null, 2));
  fs.writeFileSync('all_exit.txt', alive.map(n => n.link).join('\n'));
  fs.writeFileSync('all_exit_base64.txt', Buffer.from(alive.map(n => n.link).join('\n')).toString('base64'));

  // 2. 低延迟优质池 (Top 100)
  const topFast = alive.slice(0, 100);
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
    total_raw_candidates: rawList.length,
    valid_endpoints: parsed.length,
    dns_resolved: probeTasks.length,
    alive_nodes: alive.length,
    top_fast_nodes: topFast.length,
    countries: Object.fromEntries(Object.entries(countryMap).map(([k, v]) => [k, v.length])),
    protocols: Object.fromEntries(Object.entries(protoMap).map(([k, v]) => [k, v.length])),
    elapsed_seconds: Math.round((Date.now() - t0) / 1000)
  };
  fs.writeFileSync('summary.json', JSON.stringify(summary, null, 2));

  console.log('🎉 订阅产物导出完成：');
  console.log(`- all_exit.txt: ${alive.length} 节点 (全量多出口备选池)`);
  console.log(`- high_speed.txt: ${topFast.length} 节点 (低延迟精选池)`);
  console.log(`- dist/by_country/: ${Object.keys(countryMap).length} 个国家地区分流`);
  console.log(`- dist/by_protocol/: ${Object.keys(protoMap).length} 个协议分流`);
  console.log(`- summary.json: 统计摘要报告`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
