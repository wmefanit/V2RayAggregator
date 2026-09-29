'use strict';

// 源级漏斗统计（纯函数，便于单测）：
// - fetched 按 URL 任务累加（perSource 与 taskUrls 等长）
// - deduped/sampled/exclusive 来自去重采样表 rawList
// - tcp_alive / l7_verified / xray_verified 按节点携带的全部 sources 归因（共享节点归属每个源）
function buildSourceStats(entryNames, taskUrls, perSource, rawList, alive, l7Verified, xrayVerified) {
  const sourceStats = {};
  for (const name of entryNames) {
    sourceStats[name] = { fetched: 0, deduped: 0, tcp_alive: 0, l7_verified: 0, xray_verified: 0, sampled: 0, exclusive: 0 };
  }
  for (let i = 0; i < taskUrls.length; i++) {
    const sName = taskUrls[i].name;
    if (sourceStats[sName]) sourceStats[sName].fetched += (perSource[i] || []).length;
  }
  for (const item of rawList) {
    const sset = (item.sources && item.sources.length) ? item.sources : [item.source || 'unknown'];
    const excl = sset.length === 1;
    for (const s of sset) {
      if (sourceStats[s]) {
        sourceStats[s].deduped++;
        sourceStats[s].sampled++;
        if (excl) sourceStats[s].exclusive++;
      }
    }
  }
  const incStats = (list, key) => {
    for (const n of list) {
      const sset = (n.sources && n.sources.length) ? n.sources : [n.source || 'unknown'];
      for (const s of sset) {
        if (sourceStats[s]) sourceStats[s][key]++;
      }
    }
  };
  incStats(alive, 'tcp_alive');
  incStats(l7Verified, 'l7_verified');
  incStats(xrayVerified, 'xray_verified');
  return sourceStats;
}

module.exports = { buildSourceStats };