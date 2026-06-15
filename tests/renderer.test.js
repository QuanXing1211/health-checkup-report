'use strict';

const assert = require('assert');
const { renderTemplate } = require('../src/template_renderer');
const { buildMockReportData } = require('../src/mock_data');

const data = buildMockReportData({
  customer: '测试客户',
  start: '2026-05-01',
  end: '2026-05-31'
});

const html = renderTemplate(`
<html><head><meta name="report-data-mode" content="mock"><title>首次安全体检报告 - 示例科技有限公司</title></head>
<body>
<h1>首次安全体检报告</h1>
<p>示例科技有限公司 · 2026-01-01 ~ 2026-03-31</p>
<p>{{ report.customerName }}</p>
<div data-field="assets.total">0</div>
<div data-section="assets.summary"></div>
<table><tbody data-repeat="riskOverview.keyRisks"></tbody></table>
</body></html>
`, data);

assert(html.includes('<meta name="report-data-mode" content="generated">'));
assert(html.includes('<title>首次安全体检报告 - 测试客户</title>'));
assert(html.includes('测试客户 · 2026-05-01 ~ 2026-05-31'));
assert(html.includes('<p>测试客户</p>'));
assert(html.includes('<div data-field="assets.total">520</div>'));
assert(html.includes('【资产统计】台账资产520个'));
assert(html.includes('<tbody data-repeat="riskOverview.keyRisks"><tr><td>【威胁运营】大量病毒文件、C2外联事件</td>'));
assert(html.includes('window.SECURITY_REPORT_DATA='));

console.log('renderer.test.js passed');
