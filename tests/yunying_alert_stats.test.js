'use strict';

const assert = require('assert');
const {
  buildAlertThreatClassRequestBody,
  summarizeGptYunyingAlertRows,
  summarizeAlertThreatClassRows
} = require('../src/xdr_asset_client');

const gptSummary = summarizeGptYunyingAlertRows([
  {
    gptResult: { originalValue: 120, renderValue: '病毒木马活动' },
    hostIp: { originalValue: '10.5.40.62', renderValue: '10.5.40.62' }
  },
  {
    gptResult: { originalValue: 120, renderValue: '病毒木马活动' },
    hostIp: { originalValue: '10.5.40.62', renderValue: '10.5.40.62' }
  },
  {
    gptResult: { originalValue: 121, renderValue: '主机失陷活动' },
    hostIp: { originalValue: '10.5.40.63', renderValue: '10.5.40.63' }
  },
  {
    gptResult: { originalValue: 122, renderValue: '其他类型' },
    hostIp: { originalValue: '10.5.40.64', renderValue: '10.5.40.64' }
  }
]);

const alertSummary = summarizeAlertThreatClassRows([
  {
    threatClass: { originalValue: 30, renderValue: '漏洞攻击' },
    hostIp: { originalValue: '10.5.40.65', renderValue: '10.5.40.65' }
  },
  {
    threatClass: { originalValue: 90, renderValue: '网站攻击' },
    hostIp: { originalValue: '10.5.40.66', renderValue: '10.5.40.66' }
  }
]);

assert.strictEqual(gptSummary.virusFiles.total, 2);
assert.deepStrictEqual(gptSummary.virusFiles.hostIps, ['10.5.40.62']);
assert.strictEqual(gptSummary.virusFiles.records.length, 2);
assert.strictEqual(gptSummary.virusFiles.records[0].hostIp.originalValue, '10.5.40.62');
assert.strictEqual(gptSummary.c2ExternalLink.total, 1);
assert.deepStrictEqual(gptSummary.c2ExternalLink.hostIps, ['10.5.40.63']);
assert.strictEqual(gptSummary.c2ExternalLink.records[0].gptResult.renderValue, '主机失陷活动');
assert.strictEqual(gptSummary.exploitAttacks.total, 0);
assert.strictEqual(gptSummary.webAttacks.total, 0);

assert.strictEqual(alertSummary.exploitAttacks.total, 1);
assert.deepStrictEqual(alertSummary.exploitAttacks.hostIps, ['10.5.40.65']);
assert.strictEqual(alertSummary.exploitAttacks.records[0].threatClass.renderValue, '漏洞攻击');
assert.strictEqual(alertSummary.webAttacks.total, 1);
assert.deepStrictEqual(alertSummary.webAttacks.hostIps, ['10.5.40.66']);
assert.strictEqual(alertSummary.webAttacks.records[0].threatClass.renderValue, '网站攻击');

const requestBody = buildAlertThreatClassRequestBody({ begin: 1779206400, end: 1781798399, pageNum: 1, pageSize: 10 });
assert.strictEqual(requestBody.spl.mappedSpl, 'filter 是否关联事件  in { "已关联" } | filter 告警一级分类  in { "网站攻击", "漏洞攻击" }');
assert.strictEqual(requestBody.spl.extensionParams.frontRender[0].field, 'incidentRelated');
assert.strictEqual(requestBody.spl.extensionParams.frontRender[0].valueText, '已关联');
assert.strictEqual(requestBody.spl.extensionParams.frontRender[1].field, 'threatClass');
assert.strictEqual(requestBody.spl.extensionParams.frontRender[1].valueText, '网站攻击, 漏洞攻击');

console.log('yunying_alert_stats.test.js passed');
