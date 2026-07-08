#!/usr/bin/env node
'use strict';

const fs = require('fs/promises');
const path = require('path');
const { renderReportToFile } = require('../src/template_renderer');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT_DIR = path.join(ROOT, 'output');
const TEMPLATE_PATH = path.join(ROOT, 'security-report-preview.html');

async function main() {
  const richMockPath = path.join(OUTPUT_DIR, 'mock-full-report-data-rich.json');
  const richMock = await readJson(richMockPath);
  const zeroReportData = buildZeroReportData(richMock);

  const zeroJsonPath = path.join(OUTPUT_DIR, 'mock-zero-report-data.json');
  await writeJson(zeroJsonPath, zeroReportData);

  const renderResult = await renderReportToFile({
    templatePath: TEMPLATE_PATH,
    outputDir: path.join(OUTPUT_DIR, 'mock-zero-preview'),
    reportData: zeroReportData
  });

  console.log(JSON.stringify({
    ok: true,
    reportDataPath: zeroJsonPath,
    htmlPath: renderResult.html_path
  }, null, 2));
}

function buildZeroReportData(source) {
  const zero = zeroValue(source);

  zero.projectBackground = zero.projectBackground || {};
  zero.projectBackground.title = '';
  zero.projectBackground.customerName = '';
  zero.projectBackground.customerId = '';
  zero.projectBackground.startDate = '';
  zero.projectBackground.endDate = '';
  zero.projectBackground.generatedAt = '';

  zero.assetLedger = zero.assetLedger || {};
  zero.assetLedger.typeDistribution = namedZeroList(['服务器', '终端', '其他']);
  zero.assetLedger.protectionDistribution = namedZeroList(['在线', '离线', '已禁用', '已降级', '未防护']);
  zero.assetLedger.internetExposureDistribution = namedZeroList(['服务器', '终端', '其他']);

  zero.riskOverview = zero.riskOverview || {};
  zero.riskOverview.coreBusinessSystemRanking = ['', '', ''];
  zero.riskOverview.topRiskAssets = [];
  zero.riskOverview.incidentGptStats = zero.riskOverview.incidentGptStats || {};
  zero.riskOverview.incidentGptStats.hostCompromise = zero.riskOverview.incidentGptStats.hostCompromise || {};
  zero.riskOverview.incidentGptStats.virusTrojan = zero.riskOverview.incidentGptStats.virusTrojan || {};
  zero.riskOverview.incidentGptStats.threatActorStats = [
    { name: '', count: 0 },
    { name: '', count: 0 }
  ];
  zero.riskOverview.incidentGptStats.nonAesCoveredAssets = ['', ''];
  zero.riskOverview.incidentGptStats.unlabeledAssets = ['', ''];
  zero.riskOverview.incidentGptStats.confirmedIncidentIds = [];
  zero.riskOverview.incidentGptStats.c2ConnectionExamples = [];
  zero.riskOverview.incidentGptStats.virusTrojanExamples = [];

  zero.riskDetails = zero.riskDetails || {};
  zero.riskDetails.highRiskIncidentExamples = {
    vulnExploits: [],
    viruses: [],
    c2Connections: []
  };
  zero.riskDetails.businessSystemEventDistribution = [];
  zero.riskDetails.eventTypeDistribution = [];

  zero.summary = zero.summary || {};
  zero.summary.internet = zero.summary.internet || {};
  zero.summary.intranet = zero.summary.intranet || {};

  zero.key_risks = zero.key_risks || {};
  zero.key_risks.vuln = zero.key_risks.vuln || {};
  zero.key_risks.weak_pwd = zero.key_risks.weak_pwd || {};
  zero.key_risks.exposure = zero.key_risks.exposure || {};

  zero.internet = zero.internet || {};
  zero.internet.exposure = zero.internet.exposure || {};
  zero.internet.exposure.dist = namedZeroList([
    '资产总表',
    '根域名',
    '子域名',
    'IP C段',
    '端口表',
    'WEB资产',
    '非WEB资产',
    '登录入口（0）',
    '网络&安全设备',
    '公有云资产',
    'SSL证书',
    '公众号&小程序资产（0）',
    'APP资产（0）'
  ]);
  zero.internet.exposure.web_top5 = [];
  zero.internet.exposure.nonweb_top5 = [];
  zero.internet.exposure.stack_rows = [];
  zero.internet.vuln = zero.internet.vuln || {};
  zero.internet.vuln.top_rows = [];
  zero.internet.weak_pwd = zero.internet.weak_pwd || {};
  zero.internet.weak_pwd.asset_rows = [];

  zero.intranet = zero.intranet || {};
  zero.intranet.vuln = zero.intranet.vuln || {};
  zero.intranet.vuln.biz_top_rows = [];
  zero.intranet.vuln.asset_top_rows = [];
  zero.intranet.weak_pwd = zero.intranet.weak_pwd || {};
  zero.intranet.weak_pwd.biz_rows = [];
  zero.intranet.weak_pwd.asset_rows = [];

  zero.protection_effectiveness = zero.protection_effectiveness || {};
  zero.protection_effectiveness.without_aes_asset_stats = zero.protection_effectiveness.without_aes_asset_stats || {};
  zero.protection_effectiveness.without_aes_asset_stats.hide_hint = false;
  zero.protection_effectiveness.policy_stats = zero.protection_effectiveness.policy_stats || {};
  zero.protection_effectiveness.policy_stats.abnormal_by_dev_type = {};
  zero.protection_effectiveness.policy_stats.by_device = [];
  zero.protection_effectiveness.policy_stats.policy_check_example = [];

  return zero;
}

function zeroValue(value) {
  if (typeof value === 'number') {
    return 0;
  }
  if (typeof value === 'string') {
    return '';
  }
  if (typeof value === 'boolean') {
    return false;
  }
  if (Array.isArray(value)) {
    return [];
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      out[key] = zeroValue(nested);
    }
    return out;
  }
  return value == null ? '' : value;
}

function namedZeroList(names) {
  return names.map((name) => ({ name, value: 0 }));
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

async function writeJson(filePath, data) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
