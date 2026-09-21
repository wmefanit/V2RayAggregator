'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const net = require('net');
const url = require('url');

const SUB_LIST_PATH = './sub/sub_list.json';
const OUT_DIR = './dist';
const TCP_CONCURRENCY = 500;
const TCP_TIMEOUT_MS = 2500;

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
  if (!t || t.includes('://')) return text;
  for (const enc of ['base64', 'base64url']) {
    try {
      const d = Buffer.from(t, enc).toString('utf8');
      if (d.includes('://')) return d;
    } catch (e) {}
  }
  return text;
}

function extractLinks(text) {
  const out = [];
  for (const raw of maybeBase64Decode(text).split(/[\r\n]+/)) {
    const line = raw.trim();
    if (/^(vmess|vless|trojan|ss|ssr):\/\//i.test(line)) {
      out.push(line);
    }
  }
  return out;
}

function parseEndpoint(link) {
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
  console.log('=== [1/3] 抓取并合并 18 个订阅源 ===');

  if (!fs.existsSync(SUB_LIST_PATH)) {
    console.error('sub_list.json 不存在');
    process.exit(1);
  }

  const subList = JSON.parse(fs.readFileSync(SUB_LIST_PATH, 'utf8')).filter(s => s.enabled && s.url);
  const fetched = await runPool(subList, async (s) => {
    const txt = await fetchText(s.url);
    const links = extractLinks(txt);
    console.log(`  - ${s.remarks}: 抓取到 ${links.length} 个节点`);
    return links;
  }, 8);

  const rawLinks = Array.from(new Set(fetched.flat()));
  console.log(`\n全网抓取去重后节点总数: ${rawLinks.length}`);

  console.log(`\n=== [2/3] 端点解析与 ${TCP_CONCURRENCY} 并发 TCP 拨号探活 ===`);
  const parsed = rawLinks.map(l => ({ link: l, ep: parseEndpoint(l) })).filter(x => x.ep && x.ep.port > 0 && x.ep.port < 65536);
  console.log(`成功提取端点: ${parsed.length} / ${rawLinks.length}`);

  let checkedCount = 0;
  const probed = await runPool(parsed, async (item) => {
    const rtt = await tcpProbe(item.ep.host, item.ep.port);
    checkedCount++;
    if (checkedCount % 5000 === 0) {
      console.log(`  探活进度: ${checkedCount} / ${parsed.length} ...`);
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
  console.log(`\n探活完成: 存活可用节点 ${alive.length} / ${parsed.length} (耗时: ${Math.round((Date.now() - t0) / 1000)}s)`);

  // 按 RTT 排序
  alive.sort((a, b) => a.rtt_ms - b.rtt_ms);

  console.log('\n=== [3/3] 生成多场景分流订阅产物 ===');
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

  // 1. 全量存活多出口池 (按国家与延迟结构化)
  fs.writeFileSync('all_exit.json', JSON.stringify(alive, null, 2));
  fs.writeFileSync('all_exit.txt', alive.map(n => n.link).join('\n'));
  fs.writeFileSync('all_exit_base64.txt', Buffer.from(alive.map(n => n.link).join('\n')).toString('base64'));

  // 2. 高质量/低延迟精选池 (Top 100)
  const topFast = alive.slice(0, 100);
  fs.writeFileSync('high_speed.txt', topFast.map(n => n.link).join('\n'));
  fs.writeFileSync('Eternity.txt', topFast.map(n => n.link).join('\n'));
  fs.writeFileSync('Eternity', Buffer.from(topFast.map(n => n.link).join('\n')).toString('base64'));

  // 3. 国别分流订阅
  for (const [c, links] of Object.entries(countryMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_country', `${c.toLowerCase()}.txt`), links.join('\n'));
  }

  // 4. 协议分流订阅
  for (const [p, links] of Object.entries(protoMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_protocol', `${p.toLowerCase()}.txt`), links.join('\n'));
  }

  // 5. 总体健康报告
  const summary = {
    updated_at: new Date().toISOString(),
    total_raw_nodes: rawLinks.length,
    valid_endpoints: parsed.length,
    alive_nodes: alive.length,
    top_fast_nodes: topFast.length,
    countries: Object.fromEntries(Object.entries(countryMap).map(([k, v]) => [k, v.length])),
    protocols: Object.fromEntries(Object.entries(protoMap).map(([k, v]) => [k, v.length])),
    elapsed_seconds: Math.round((Date.now() - t0) / 1000)
  };
  fs.writeFileSync('summary.json', JSON.stringify(summary, null, 2));

  console.log('🎉 全部订阅产物生成完毕！');
  console.log(`- all_exit.txt: ${alive.length} 节点 (全量多出口备选池)`);
  console.log(`- high_speed.txt / Eternity.txt: ${topFast.length} 节点 (低延迟精选池)`);
  console.log(`- dist/by_country/: ${Object.keys(countryMap).length} 个国家地区分流`);
  console.log(`- dist/by_protocol/: ${Object.keys(protoMap).length} 个协议分流`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
