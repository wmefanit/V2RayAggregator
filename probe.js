'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const net = require('net');
const url = require('url');

const ALL_SOURCES_PATH = process.argv[2] || process.env.SOURCES_FILE || './sub/sample_sources.json';
const OUT_DIR = './dist';
const TCP_CONCURRENCY = 1000;
const TCP_TIMEOUT_MS = 2000;

function fetchText(targetUrl, timeoutMs = 15000, redirects = 3) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const client = targetUrl.startsWith('https') ? https : http;
    let req;
    try {
      req = client.get(targetUrl, { timeout: timeoutMs, headers: { 'User-Agent': 'v2rayN/6.23 ClashMeta/v1.18.0' } }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
          res.resume();
          const next = new url.URL(res.headers.location, targetUrl).toString();
          return fetchText(next, timeoutMs, redirects - 1).then(done);
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => done(Buffer.concat(chunks).toString('utf8')));
      });
    } catch (e) { return done(''); }
    req.on('error', () => done(''));
    req.on('timeout', () => { req.destroy(); done(''); });
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

// 支持提取 IP:Port 以及各类代理 URL
const IP_PORT_REGEX = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/;

function extractAllCandidates(text, defaultType = 'http') {
  const list = [];
  const lines = maybeBase64Decode(text).split(/[\r\n]+/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    // 1. 协议 URL (vmess, ss, trojan, vless, socks5, http)
    if (/^(vmess|vless|trojan|ss|ssr|socks5|socks4|http|https):\/\//i.test(line)) {
      list.push(line);
      continue;
    }

    // 2. 纯 IP:Port 格式 (如 1.2.3.4:8080)
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

function tcpProbe(host, port) {
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
    sock.connect(port, host);
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
  console.log('=== [1/3] 云端全量抓取 62 个数据源 (124 条 URL 规则) ===');

  const catalog = JSON.parse(fs.readFileSync(ALL_SOURCES_PATH, 'utf8'));
  const taskUrls = [];
  for (const src of (catalog.sources || [])) {
    if (src.enabled === false) continue;
    for (const u of (src.urls || [])) {
      if (u.url) {
        taskUrls.push({ name: src.name, parser: src.parser, type: u.type || 'http', url: u.url });
      }
    }
  }

  console.log(`有效待抓取 URL 任务数: ${taskUrls.length}`);

  const fetched = await runPool(taskUrls, async (t) => {
    const txt = await fetchText(t.url);
    const cands = extractAllCandidates(txt, t.type);
    console.log(`  - [${t.name}] (${t.type}) -> ${cands.length} 候选`);
    return cands;
  }, 16);

  const rawSet = new Set(fetched.flat());
  const rawList = Array.from(rawSet);
  console.log(`\n🎉 百万池去重后全量候选总数: ${rawList.length}`);

  console.log(`\n=== [2/3] 全量端点解析与 ${TCP_CONCURRENCY} 并发云端探活 ===`);
  const parsed = [];
  for (const link of rawList) {
    const ep = parseHostPort(link);
    if (ep && ep.port > 0 && ep.port < 65536) {
      parsed.push({ link, ep });
    }
  }
  console.log(`可有效拨号端点数: ${parsed.length} / ${rawList.length}`);

  let checkedCount = 0;
  const probed = await runPool(parsed, async (item) => {
    const rtt = await tcpProbe(item.ep.host, item.ep.port);
    checkedCount++;
    if (checkedCount % 20000 === 0) {
      console.log(`  已拨号: ${checkedCount} / ${parsed.length} ...`);
    }
    if (rtt !== null) {
      return {
        link: item.link,
        proto: item.ep.proto,
        host: item.ep.host,
        port: item.ep.port,
        remark: item.ep.remark,
        country: extractCountry(item.ep.remark, item.ep.host),
        rtt_ms: rtt
      };
    }
    return null;
  }, TCP_CONCURRENCY);

  const alive = probed.filter(Boolean);
  console.log(`\n探活完成: 存活可用节点数 ${alive.length} / ${parsed.length} (耗时: ${Math.round((Date.now() - t0) / 1000)}s)`);

  alive.sort((a, b) => a.rtt_ms - b.rtt_ms);

  console.log('\n=== [3/3] 产出多维度百万级清洗订阅 ===');
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

  // 1. 全量多出口存活池
  fs.writeFileSync('all_exit.json', JSON.stringify(alive, null, 2));
  fs.writeFileSync('all_exit.txt', alive.map(n => n.link).join('\n'));
  fs.writeFileSync('all_exit_base64.txt', Buffer.from(alive.map(n => n.link).join('\n')).toString('base64'));

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

  // 5. 总体报表
  const summary = {
    updated_at: new Date().toISOString(),
    total_raw_candidates: rawList.length,
    valid_endpoints: parsed.length,
    alive_nodes: alive.length,
    top_fast_nodes: topFast.length,
    countries: Object.fromEntries(Object.entries(countryMap).map(([k, v]) => [k, v.length])),
    protocols: Object.fromEntries(Object.entries(protoMap).map(([k, v]) => [k, v.length])),
    elapsed_seconds: Math.round((Date.now() - t0) / 1000)
  };
  fs.writeFileSync('summary.json', JSON.stringify(summary, null, 2));

  console.log('🎉 百万池云端清洗完成！');
  console.log(`- all_exit.txt: ${alive.length} 节点 (全量多出口池)`);
  console.log(`- high_speed.txt: ${topFast.length} 节点 (低延迟精选)`);
  console.log(`- dist/by_country/: ${Object.keys(countryMap).length} 个国家地区分流`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
