'use strict';
const assert = require('assert');
const { buildSourceStats } = require('./source_stats');

// 构造：A 独有节点 1，A/B 共享节点 1，B 独有节点 1（来自 roundRobin 语义）
const taskUrls = [{ name: 'A', type: 'http' }, { name: 'B', type: 'http' }];
const perSource = [[{}, {}, {}], [{}, {}, {}]]; // fetched: A=3, B=3（多 URL 累加）
const rawList = [
  { source: 'A', sources: ['A'] },
  { source: 'A', sources: ['A', 'B'] }, // 共享
  { source: 'B', sources: ['B'] },
];
const alive = [
  { source: 'A', sources: ['A'] },
  { source: 'A', sources: ['A', 'B'] }, // 共享节点必须同时计入 A、B
];
const l7Verified = [{ source: 'A', sources: ['A', 'B'] }];
const xrayVerified = [{ source: 'B', sources: ['B'] }];

const st = buildSourceStats(['A', 'B', 'C'], taskUrls, perSource, rawList, alive, l7Verified, xrayVerified);

assert.strictEqual(st.A.fetched, 3, 'A fetched');
assert.strictEqual(st.B.fetched, 3, 'B fetched');
assert.strictEqual(st.C.fetched, 0, 'C fetched (disabled/absent url)');

// 共享节点归因到所有来源，不只首源
assert.strictEqual(st.A.tcp_alive, 2, 'A tcp_alive: own + shared');
assert.strictEqual(st.B.tcp_alive, 1, 'B tcp_alive: shared only');
assert.strictEqual(st.A.l7_verified, 1, 'A l7 via shared attribution');
assert.strictEqual(st.B.l7_verified, 1, 'B l7 via shared attribution');
assert.strictEqual(st.B.xray_verified, 1, 'B xray');

// dedup/sampled/exclusive 与旧口径一致
assert.strictEqual(st.A.deduped, 2, 'A deduped');
assert.strictEqual(st.B.deduped, 2, 'B deduped');
assert.strictEqual(st.A.exclusive, 1, 'A exclusive');
assert.strictEqual(st.B.exclusive, 1, 'B exclusive');

// 无 sources 字段的旧数据回退到首 source，不崩溃
const legacy = buildSourceStats(['A'], [{ name: 'A' }], [[{}]], [{ source: 'A' }], [{ source: 'A' }], [], []);
assert.strictEqual(legacy.A.tcp_alive, 1, 'legacy fallback');
assert.strictEqual(legacy.A.fetched, 1, 'legacy fetched');

console.log('source_stats.test.js PASS');
