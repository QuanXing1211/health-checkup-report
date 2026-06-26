'use strict';

const assert = require('assert');
const { renderTemplate } = require('../src/template_renderer');
const data = {
  projectBackground: {
    title: '首次安全体检报告',
    customerName: '测试客户',
    customerId: null,
    startDate: '2026-05-01',
    endDate: '2026-05-31',
    generatedAt: '2026-05-31T00:00:00.000Z'
  },
  assetLedger: {
    manage_asset: 520,
    core_asset: 88,
    ready_to_outbound: 7,
    typeDistribution: [],
    protectionDistribution: [],
    internetExposureDistribution: []
  },
  riskOverview: {
    securityLogTotal: 1250000,
    alertTotal: 3200,
    totalEvents: 177,
    closedEvents: 12,
    containedEvents: 72,
    alertReductionRate: 0.97,
    closeRate: 7,
    yunyingAlertStats: {
      c2VirusTotal: 10,
      webVulnTotal: 5,
      virusFiles: {
        total: 4,
        hostIps: ['10.5.40.62'],
        records: []
      },
      c2ExternalLink: {
        total: 6,
        hostIps: ['10.5.40.63', '10.5.40.64'],
        records: []
      },
      exploitAttacks: {
        total: 2,
        hostIps: ['10.5.40.65'],
        records: []
      },
      webAttacks: {
        total: 3,
        hostIps: ['10.5.40.66'],
        records: []
      }
    },
    keyRisks: [
      {
        risk: '【威胁运营】大量病毒文件、C2外联事件',
        description: 'desc',
        impact: 'impact',
        strategy: ['s1'],
        status: ['t1']
      }
    ]
  },
  riskDetails: {
    totalEvents: 86,
    severeEvents: 8,
    highEvents: 28,
    uniqueAssetCount: 12,
    closedEvents: 68,
    containedEvents: 72,
    processingEvents: 18,
    closeRate: 79
  }
};

const html = renderTemplate(`
<html><head><meta name="report-data-mode" content="mock"><title>首次安全体检报告 - 示例科技有限公司</title></head>
<body>
<h1>首次安全体检报告</h1>
<p>示例科技有限公司 · 2026-01-01 ~ 2026-03-31</p>
<p>{{ projectBackground.customerName }}</p>
<div data-field="assetLedger.manage_asset">0</div>
<div data-field="assetLedger.core_asset">0</div>
<div data-field="assetLedger.ready_to_outbound">0</div>
<p>XDR接收安全日志数 <span data-field="riskOverview.securityLogTotal">0</span> 条；有效告警数 <span data-field="riskOverview.alertTotal">0</span> 条；有效安全事件数 <span data-field="riskOverview.totalEvents">0</span> 起；处置闭环数 <span data-field="riskOverview.closedEvents">0</span> 起；总计遏制 <span data-field="riskOverview.containedEvents">0</span> 起；告警消减率 <span data-field="riskOverview.alertReductionRate">0</span>%；事件闭环率 <span data-field="riskOverview.closeRate">0</span>%。</p>
<p>总接入组件数 <b data-field="ops.devices-v">0</b> 个 · 深信服 <b data-field="ops.sangfor-v">0</b></p>
<p>GPT 运营告警中，C2外联&病毒文件共 <span data-field="riskOverview.yunyingAlertStats.c2VirusTotal">0</span> 起（病毒文件 <span data-field="riskOverview.yunyingAlertStats.virusFiles.total">0</span> 起，C2外联 <span data-field="riskOverview.yunyingAlertStats.c2ExternalLink.total">0</span> 起）；Web攻击&Web漏洞共 <span data-field="riskOverview.yunyingAlertStats.webVulnTotal">0</span> 起（Web攻击 <span data-field="riskOverview.yunyingAlertStats.webAttacks.total">0</span> 起，Web漏洞 <span data-field="riskOverview.yunyingAlertStats.exploitAttacks.total">0</span> 起）。</p>
<p>严重事件 <span data-field="riskDetails.severeEvents">0</span> 起，高危事件 <span data-field="riskDetails.highEvents">0</span> 起，已闭环 <span data-field="riskDetails.closedEvents">0</span> 起，已遏制 <span data-field="riskDetails.containedEvents">0</span> 起，处置中 <span data-field="riskDetails.processingEvents">0</span> 起（闭环率：<span data-field="riskDetails.closeRate">0</span>%）。</p>
<p>事件遏制 <span data-field="riskDetails.containedEvents">0</span> 起；</p>
<div data-section="assetLedger.summary"></div>
<p>涉及到的资产数 <span data-field="riskDetails.uniqueAssetCount">0</span> 个</p>
<table><tbody data-repeat="riskOverview.keyRisks"></tbody></table>
</body></html>
`, data);

assert(html.includes('<meta name="report-data-mode" content="generated">'));
assert(html.includes('<title>首次安全体检报告 - 测试客户</title>'));
assert(html.includes('测试客户 · 2026-05-01 ~ 2026-05-31'));
assert(html.includes('<p>测试客户</p>'));
assert(html.includes('<div data-field="assetLedger.manage_asset">520</div>'));
assert(html.includes('<div data-field="assetLedger.core_asset">88</div>'));
assert(html.includes('<div data-field="assetLedger.ready_to_outbound">7</div>'));
assert(html.includes('XDR接收安全日志数 <span data-field="riskOverview.securityLogTotal">1250000</span> 条；有效告警数 <span data-field="riskOverview.alertTotal">3200</span> 条；有效安全事件数 <span data-field="riskOverview.totalEvents">177</span> 起；处置闭环数 <span data-field="riskOverview.closedEvents">12</span> 起；总计遏制 <span data-field="riskOverview.containedEvents">72</span> 起；告警消减率 <span data-field="riskOverview.alertReductionRate">0.97</span>%；事件闭环率 <span data-field="riskOverview.closeRate">7</span>%。'));
assert(html.includes('总接入组件数 <b data-field="ops.devices-v">0</b> 个 · 深信服 <b data-field="ops.sangfor-v">0</b>'));
assert(html.includes('GPT 运营告警中，C2外联&病毒文件共 <span data-field="riskOverview.yunyingAlertStats.c2VirusTotal">10</span> 起（病毒文件 <span data-field="riskOverview.yunyingAlertStats.virusFiles.total">4</span> 起，C2外联 <span data-field="riskOverview.yunyingAlertStats.c2ExternalLink.total">6</span> 起）；Web攻击&Web漏洞共 <span data-field="riskOverview.yunyingAlertStats.webVulnTotal">5</span> 起（Web攻击 <span data-field="riskOverview.yunyingAlertStats.webAttacks.total">3</span> 起，Web漏洞 <span data-field="riskOverview.yunyingAlertStats.exploitAttacks.total">2</span> 起）。'));
assert(html.includes('严重事件 <span data-field="riskDetails.severeEvents">8</span> 起，高危事件 <span data-field="riskDetails.highEvents">28</span> 起，已闭环 <span data-field="riskDetails.closedEvents">68</span> 起，已遏制 <span data-field="riskDetails.containedEvents">72</span> 起，处置中 <span data-field="riskDetails.processingEvents">18</span> 起（闭环率：<span data-field="riskDetails.closeRate">79</span>%）。'));
assert(html.includes('事件遏制 <span data-field="riskDetails.containedEvents">72</span> 起；'));
assert(html.includes('【资产统计】台账资产520个，核心资产88个，7天内即将退库7个'));
assert(html.includes('涉及到的资产数 <span data-field="riskDetails.uniqueAssetCount">12</span> 个'));
assert(html.includes('<tbody data-repeat="riskOverview.keyRisks"><tr><td>【威胁运营】大量病毒文件、C2外联事件</td>'));
assert(html.includes('window.SECURITY_REPORT_DATA='));

console.log('renderer.test.js passed');
