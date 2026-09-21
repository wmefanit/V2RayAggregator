#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { execSync, spawn } = require('child_process');

const SUB_LIST_PATH = './sub/sub_list.json';
const OUT_DIR = './dist';

// 工具：安全 HTTP GET
function fetchText(url, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(fetchText(res.headers.location, timeoutMs));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', () => resolve(''));
    req.on('timeout', () => { req.destroy(); resolve(''); });
  });
}

// 解码订阅文本中的节点
function decodeNodes(rawText) {
  const nodes = [];
  if (!rawText) return nodes;
  
  // 尝试 base64 解码
  let text = rawText.trim();
  if (!text.includes('://') && text.length > 20) {
    try {
      const decoded = Buffer.from(text, 'base64').toString('utf8');
      if (decoded.includes('://')) text = decoded;
    } catch(e) {}
  }

  const lines = text.split(/[\r\n]+/);
  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    if (line.startsWith('vmess://') || line.startsWith('vless://') || 
        line.startsWith('trojan://') || line.startsWith('ss://') || 
        line.startsWith('ssr://')) {
      nodes.push(line);
    }
  }
  return nodes;
}

// 提取节点协议和备注名称
function parseNodeInfo(link) {
  const proto = link.split('://')[0];
  let remark = '';
  try {
    if (proto === 'vmess') {
      const b64 = link.slice(8);
      const json = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
      remark = json.ps || json.add || '';
    } else {
      const hashIdx = link.indexOf('#');
      if (hashIdx !== -1) {
        remark = decodeURIComponent(link.slice(hashIdx + 1));
      }
    }
  } catch(e) {}
  return { proto, remark, link };
}

async function main() {
  console.log('=== [1/4] 读取并抓取所有订阅源 ===');
  if (!fs.existsSync(SUB_LIST_PATH)) {
    console.error('sub_list.json 不存在');
    process.exit(1);
  }

  const subList = JSON.parse(fs.readFileSync(SUB_LIST_PATH, 'utf8'));
  const allNodes = new Set();
  
  for (const item of subList) {
    if (!item.enabled || !item.url) continue;
    console.log(`抓取: ${item.remarks || item.url}`);
    const content = await fetchText(item.url);
    const nodes = decodeNodes(content);
    console.log(`  -> 获得 ${nodes.length} 个节点`);
    nodes.forEach(n => allNodes.add(n));
  }

  const nodeList = Array.from(allNodes).map(parseNodeInfo);
  console.log(`\n去重后节点总数: ${nodeList.length}`);

  // 写入待清洗原始全量清单
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.mkdirSync(path.join(OUT_DIR, 'by_country'), { recursive: true });
  fs.mkdirSync(path.join(OUT_DIR, 'by_protocol'), { recursive: true });

  fs.writeFileSync(path.join(OUT_DIR, 'raw_nodes.txt'), Array.from(allNodes).join('\n'));

  console.log('\n=== [2/4] 调用 subconverter 转为统一 clash 格式供测活 ===');
  // 利用 subconverter 本地服务批量转成 YAML 测活配置
  // subconverter 启动检查
  try {
    execSync('wget -q -O subconverter.tar.gz https://github.com/tindy2013/subconverter/releases/download/v0.7.2/subconverter_linux64.tar.gz && tar -zxf subconverter.tar.gz');
    execSync('chmod +x subconverter/subconverter && nohup ./subconverter/subconverter > /dev/null 2>&1 &');
    await new Promise(r => setTimeout(r, 2000));
  } catch(e) {
    console.log('subconverter 初始化:', e.message);
  }

  console.log('\n=== [3/4] 运行并发探针 (测活 + 出口 + 测速) ===');
  // 运行 LiteSpeedTest（配置为测出口 + ping + 测速）
  try {
    execSync('wget -q -O lite.gz https://github.com/xxf098/LiteSpeedTest/releases/download/v0.14.1/lite-linux-amd64-v0.14.1.gz && gzip -df lite.gz && chmod +x lite');
    
    // 生成包含全部节点的本地订阅文件
    const subMergePath = './sub/sub_merge.txt';
    fs.mkdirSync('./sub', { recursive: true });
    fs.writeFileSync(subMergePath, Array.from(allNodes).join('\n'));

    // 生成测速配置 (限制单节点超时 5s, 64并发快速出结果)
    const liteCfg = {
      group: "Aggregator",
      speedtestMode: "all",
      pingMethod: "googleping",
      sortMethod: "rspeed",
      concurrency: 32,
      testMode: 2,
      subscription: "",
      timeout: 5,
      language: "en",
      fontSize: 24,
      unique: true
    };
    fs.writeFileSync('lite_config.json', JSON.stringify(liteCfg, null, 2));

    console.log('启动 LiteSpeedTest 并发测验...');
    execSync('curl -s "http://127.0.0.1:25500/sub?target=clash&url=http://127.0.0.1:8000/sub/sub_merge.txt" -o clash_temp.yml 2>/dev/null || true');
    
    // 本地起简易静态服务供 subconverter 拉取
    const fileServer = http.createServer((req, res) => {
      res.end(Array.from(allNodes).join('\n'));
    }).listen(8000);

    execSync('curl -s "http://127.0.0.1:25500/sub?target=clash&url=http://127.0.0.1:8000/nodes" -o clash_all.yml');
    fileServer.close();

    console.log('执行测活与带宽压测...');
    try {
      execSync('./lite --config ./lite_config.json --test ./clash_all.yml > speedtest.log 2>&1', { timeout: 480000 });
    } catch(e) {
      console.log('测速完成或部分超时，继续提取已生成数据');
    }
  } catch(e) {
    console.error('测活执行警告:', e.message);
  }

  console.log('\n=== [4/4] 结构化多视图分流导出 ===');
  let testedNodes = [];
  if (fs.existsSync('out.json')) {
    try {
      const outData = JSON.parse(fs.readFileSync('out.json', 'utf8'));
      testedNodes = outData.nodes || [];
    } catch(e) {}
  }

  console.log(`测活结果总数: ${testedNodes.length}`);
  const aliveNodes = testedNodes.filter(n => n.ping > 0 || n.avg_speed > 0);
  console.log(`存活可用节点数: ${aliveNodes.length}`);

  // 1. 全量存活多出口池 (按国家/ASN 聚类)
  const countryMap = {};
  const protoMap = {};
  const multiExitList = [];
  const highSpeedList = [];

  // 按平均速度排序
  aliveNodes.sort((a, b) => (b.avg_speed || 0) - (a.avg_speed || 0));

  for (const n of aliveNodes) {
    const link = n.link;
    if (!link) continue;

    // 解析国家代码 (从 remarks/name 中提取 emoji 或国家简写，如 🇯🇵 JP, 🇺🇸 US)
    let country = 'OTHER';
    const match = (n.remarks || '').match(/([A-Z]{2})[-_\s]|(HK|TW|JP|US|SG|KR|UK|DE|CA|FR|RU|IN)/i);
    if (match) country = (match[1] || match[2]).toUpperCase();

    const item = {
      id: n.id,
      protocol: n.protocol,
      remarks: n.remarks,
      country: country,
      ping_ms: n.ping,
      avg_speed_mb: +(n.avg_speed * 0.00000095367432).toFixed(2),
      max_speed_mb: +(n.max_speed * 0.00000095367432).toFixed(2),
      link: link
    };

    multiExitList.push(item);

    if (item.avg_speed_mb > 1.0) {
      highSpeedList.push(item);
    }

    if (!countryMap[country]) countryMap[country] = [];
    countryMap[country].push(link);

    const proto = n.protocol || 'other';
    if (!protoMap[proto]) protoMap[proto] = [];
    protoMap[proto].push(link);
  }

  // 写入全量多出口 JSON & TXT
  fs.writeFileSync('./all_exit.json', JSON.stringify(multiExitList, null, 2));
  fs.writeFileSync('./all_exit.txt', multiExitList.map(n => n.link).join('\n'));
  fs.writeFileSync('./all_exit_base64.txt', Buffer.from(multiExitList.map(n => n.link).join('\n')).toString('base64'));

  // 写入高带宽精选池
  const topHighSpeed = (highSpeedList.length >= 20 ? highSpeedList : multiExitList.slice(0, 50));
  fs.writeFileSync('./Eternity.txt', topHighSpeed.map(n => n.link).join('\n'));
  fs.writeFileSync('./Eternity', Buffer.from(topHighSpeed.map(n => n.link).join('\n')).toString('base64'));

  // 写入国别分流订阅
  for (const [c, links] of Object.entries(countryMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_country', `${c.toLowerCase()}.txt`), links.join('\n'));
  }

  // 写入协议分流
  for (const [p, links] of Object.entries(protoMap)) {
    fs.writeFileSync(path.join(OUT_DIR, 'by_protocol', `${p.toLowerCase()}.txt`), links.join('\n'));
  }

  // 写入运行总报表
  const summary = {
    updated_at: new Date().toISOString(),
    total_raw_nodes: nodeList.length,
    alive_nodes: aliveNodes.length,
    high_speed_nodes: highSpeedList.length,
    countries: Object.keys(countryMap).map(c => ({ country: c, count: countryMap[c].length })),
    protocols: Object.keys(protoMap).map(p => ({ protocol: p, count: protoMap[p].length }))
  };
  fs.writeFileSync('./summary.json', JSON.stringify(summary, null, 2));

  console.log('\n🎉 产物导出完成：');
  console.log(`- all_exit.json (全量多出口池: ${multiExitList.length} 节点)`);
  console.log(`- Eternity.txt (高带宽精选池: ${topHighSpeed.length} 节点)`);
  console.log(`- by_country/ (${Object.keys(countryMap).length} 个国家地区分流)`);
  console.log(`- summary.json (画像概览报告)`);
}

main().catch(console.error);
