'use strict';

const assert = require('assert');
const {
  matchThreatActor,
  countMalwareFilesFromDisposalTabs,
  hasMaliciousEntity,
  buildDisposalTabsRequestBody,
  extractGptSubResultFromResponse,
  buildIncidentGptTableRequestBody,
  THREAT_ACTOR_NAMES
} = require('../src/mssw_client');

// Test matchThreatActor
assert.strictEqual(matchThreatActor(''), '', '空字符串不匹配');
assert.strictEqual(matchThreatActor('银狐'), '银狐', '精确匹配银狐');
assert.strictEqual(matchThreatActor('系统检测到银狐木马活动'), '银狐', '包含匹配银狐');
assert.strictEqual(matchThreatActor('勒索病毒攻击'), '勒索', '包含匹配勒索');
assert.strictEqual(matchThreatActor('cobaltstrike回连'), 'cobaltstrike', '匹配 cobaltstrike');
assert.strictEqual(matchThreatActor('未知威胁'), '', '未知威胁不匹配');

// Test countMalwareFilesFromDisposalTabs
const noMalware = countMalwareFilesFromDisposalTabs({
  data: {
    entities: [
      { threatLevelDesc: '未知' },
      { threatLevelDesc: '安全' }
    ]
  }
});
assert.strictEqual(noMalware, 0, '无恶意文件');

const hasMalware = countMalwareFilesFromDisposalTabs({
  data: {
    entities: [
      { threatLevelDesc: '未知' },
      { threatLevelDesc: '恶意' },
      { threatLevelDesc: '恶意软件' }
    ]
  }
});
assert.strictEqual(hasMalware, 2, '两个恶意文件');

const emptyResponse = countMalwareFilesFromDisposalTabs({});
assert.strictEqual(emptyResponse, 0, '空响应');

const nullResponse = countMalwareFilesFromDisposalTabs(null);
assert.strictEqual(nullResponse, 0, 'null 响应');

// Test extractGptSubResultFromResponse
const hasResult = extractGptSubResultFromResponse({
  data: {
    list: [
      {
        gpt_sub_result: {
          original_value: '500',
          render_value: '银狐'
        }
      }
    ]
  }
});
assert.strictEqual(hasResult, '银狐', '提取 render_value');

const emptyResult = extractGptSubResultFromResponse({
  data: {
    list: [
      {
        gpt_sub_result: {
          original_value: '500',
          render_value: ''
        }
      }
    ]
  }
});
assert.strictEqual(emptyResult, '', '空 render_value');

const noList = extractGptSubResultFromResponse({ data: {} });
assert.strictEqual(noList, '', '无 list');

// Test buildIncidentGptTableRequestBody
const body = buildIncidentGptTableRequestBody({
  offset: 0,
  limit: 20,
  startTimeMs: 1700000000000,
  endTimeMs: 1705000000000,
  customerId: '67262236'
});
assert.strictEqual(body.limit, 20, 'limit');
assert.strictEqual(body.offset, 0, 'offset');
assert.deepStrictEqual(body.filters.company_ids, ['67262236'], 'company_ids');
assert.deepStrictEqual(body.filters.end_time, [1700000000000, 1705000000000], 'end_time range');
assert.strictEqual(body.filters.customer_type, 'single_customer', 'customer_type');

// Verify THREAT_ACTOR_NAMES is an array with expected values
assert.ok(Array.isArray(THREAT_ACTOR_NAMES), 'THREAT_ACTOR_NAMES is array');
assert.ok(THREAT_ACTOR_NAMES.includes('银狐'), 'THREAT_ACTOR_NAMES includes 银狐');
assert.ok(THREAT_ACTOR_NAMES.includes('勒索'), 'THREAT_ACTOR_NAMES includes 勒索');

// Test buildDisposalTabsRequestBody
const fileBody = buildDisposalTabsRequestBody('FILE');
assert.strictEqual(fileBody.type, 'FILE', 'FILE body type');
assert.strictEqual(fileBody.pageNum, 1, 'FILE body pageNum');

const ipBody = buildDisposalTabsRequestBody('IP');
assert.strictEqual(ipBody.type, 'IP', 'IP body type');

const dnsBody = buildDisposalTabsRequestBody('DNS');
assert.strictEqual(dnsBody.type, 'DNS', 'DNS body type');

const defaultBody = buildDisposalTabsRequestBody();
assert.strictEqual(defaultBody.type, 'FILE', 'default body type');

// Test hasMaliciousEntity
assert.strictEqual(hasMaliciousEntity({
  data: { entities: [{ threatLevelDesc: '未知' }, { threatLevelDesc: '安全' }] }
}), false, '无恶意实体');

assert.strictEqual(hasMaliciousEntity({
  data: { entities: [{ threatLevelDesc: '未知' }, { threatLevelDesc: '恶意' }] }
}), true, '有恶意实体');

assert.strictEqual(hasMaliciousEntity({
  data: { entities: [{ threatLevelDesc: '恶意软件' }] }
}), true, '恶意软件包含恶意');

assert.strictEqual(hasMaliciousEntity({ data: {} }), false, '空 data');
assert.strictEqual(hasMaliciousEntity(null), false, 'null 参数');

console.log('yunying_alert_stats.test.js passed');
