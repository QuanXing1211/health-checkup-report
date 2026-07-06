#!/usr/bin/env node
'use strict';

const fs = require('fs/promises');
const path = require('path');
const { renderReportToFile } = require('../src/template_renderer');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT_DIR = path.join(ROOT, 'output');
const TEMPLATE_PATH = path.join(ROOT, 'security-report-preview.html');

async function main() {
  const reportDataSample = await readJsonIfExists(path.join(OUTPUT_DIR, 'report-data.json'));
  const existingMockSample = await readJsonIfExists(path.join(OUTPUT_DIR, 'mock-full-report-data.json'));
  const branch1Report = await readJsonIfExists(path.join(ROOT, 'tmp', 'branch1', 'branch1-report.json'));
  const xdrAssetSummary = await readJsonIfExists(path.join(OUTPUT_DIR, 'xdr-asset-summary.json'));
  const deviceSnapshot = await readJsonIfExists(path.join(ROOT, 'tmp', 'device.json'));

  const reportData = buildRichReportData({
    existingMockSample,
    reportDataSample,
    branch1Report,
    xdrAssetSummary
  });

  const auditPayload = buildAuditPayload({
    reportData,
    branch1Report,
    xdrAssetSummary,
    deviceSnapshot,
    existingMockSample,
    reportDataSample
  });

  const richReportPath = path.join(OUTPUT_DIR, 'mock-full-report-data-rich.json');
  const auditPath = path.join(OUTPUT_DIR, 'mock-full-audit.json');

  await writeJson(richReportPath, reportData);
  await writeJson(auditPath, auditPayload);

  const renderResult = await renderReportToFile({
    templatePath: TEMPLATE_PATH,
    outputDir: path.join(OUTPUT_DIR, 'mock-full-preview'),
    reportData
  });

  console.log(JSON.stringify({
    ok: true,
    reportDataPath: richReportPath,
    auditPath,
    htmlPath: renderResult.html_path
  }, null, 2));
}

function buildRichReportData(input) {
  let reportData = deepMerge({}, input.existingMockSample || {});
  reportData = deepMerge(reportData, input.reportDataSample || {});

  if (input.xdrAssetSummary) {
    reportData = deepMerge(reportData, {
      projectBackground: input.xdrAssetSummary.projectBackground || {},
      assetLedger: input.xdrAssetSummary.assetLedger || {},
      riskOverview: input.xdrAssetSummary.riskOverview || {},
      riskDetails: input.xdrAssetSummary.riskDetails || {}
    });
  }

  if (input.branch1Report && input.branch1Report.reportPatch) {
    reportData = deepMerge(reportData, {
      scoring: input.branch1Report.reportPatch.scoring || {},
      protection_effectiveness: input.branch1Report.reportPatch.protection_effectiveness || {}
    });
  }

  reportData = normalizeReportData(reportData);
  enrichReportData(reportData);
  return reportData;
}

function normalizeReportData(reportData) {
  const normalized = deepMerge({}, reportData || {});

  normalized.projectBackground = normalized.projectBackground || {};
  normalized.assetLedger = normalized.assetLedger || {};
  normalized.riskOverview = normalized.riskOverview || {};
  normalized.riskDetails = normalized.riskDetails || {};
  normalized.summary = normalized.summary || {};
  normalized.key_risks = normalized.key_risks || {};
  normalized.risk_detail = normalized.risk_detail || {};
  normalized.internet = normalized.internet || {};
  normalized.intranet = normalized.intranet || {};
  normalized.scoring = normalized.scoring || {};
  normalized.protection_effectiveness = normalized.protection_effectiveness || {};

  normalized.projectBackground.title = normalized.projectBackground.title || '安全体检报告';
  normalized.projectBackground.customerName = normalized.projectBackground.customerName || '测试001';
  normalized.projectBackground.customerId = normalized.projectBackground.customerId || 'mock-company-001';
  normalized.projectBackground.startDate = normalized.projectBackground.startDate || '2026-06-01';
  normalized.projectBackground.endDate = normalized.projectBackground.endDate || '2026-06-30';
  normalized.projectBackground.generatedAt = normalized.projectBackground.generatedAt || '2026-07-06T00:00:00.000Z';

  normalized.riskOverview.incidentGptStats = normalized.riskOverview.incidentGptStats || {};
  normalized.riskOverview.incidentGptStats.hostCompromise = normalized.riskOverview.incidentGptStats.hostCompromise || {};
  normalized.riskOverview.incidentGptStats.virusTrojan = normalized.riskOverview.incidentGptStats.virusTrojan || {};
  normalized.riskOverview.exploitStats = normalized.riskOverview.exploitStats || {};
  normalized.riskOverview.topRiskAssets = arrayOrEmpty(normalized.riskOverview.topRiskAssets);
  normalized.riskOverview.coreBusinessSystemRanking = arrayOrEmpty(normalized.riskOverview.coreBusinessSystemRanking);

  normalized.riskDetails.highRiskIncidentExamples = normalized.riskDetails.highRiskIncidentExamples || {};
  normalized.riskDetails.highRiskIncidentExamples.vulnExploits = arrayOrEmpty(normalized.riskDetails.highRiskIncidentExamples.vulnExploits);
  normalized.riskDetails.highRiskIncidentExamples.viruses = arrayOrEmpty(normalized.riskDetails.highRiskIncidentExamples.viruses);
  normalized.riskDetails.highRiskIncidentExamples.c2Connections = arrayOrEmpty(normalized.riskDetails.highRiskIncidentExamples.c2Connections);

  normalized.protection_effectiveness.without_aes_asset_stats = normalized.protection_effectiveness.without_aes_asset_stats || {};
  normalized.protection_effectiveness.policy_stats = normalized.protection_effectiveness.policy_stats || {};
  normalized.protection_effectiveness.policy_stats.by_device = arrayOrEmpty(normalized.protection_effectiveness.policy_stats.by_device);
  normalized.protection_effectiveness.policy_stats.policy_check_example = arrayOrEmpty(normalized.protection_effectiveness.policy_stats.policy_check_example);

  if (!normalized.appendix || typeof normalized.appendix !== 'object') {
    normalized.appendix = {};
  }
  if (!normalized.appendix.businessSystemRanking || typeof normalized.appendix.businessSystemRanking !== 'object') {
    normalized.appendix.businessSystemRanking = {};
  }

  if (!normalized.appendix.businessSystemRanking.coreBusinessSystemRanking.length) {
    normalized.appendix.businessSystemRanking.coreBusinessSystemRanking = arrayOrEmpty(normalized.riskOverview.coreBusinessSystemRanking);
  }
  if (!normalized.appendix.businessSystemRanking.maxRiskSystem) {
    normalized.appendix.businessSystemRanking.maxRiskSystem = normalized.riskOverview.maxRiskSystem || null;
  }
  if (normalized.appendix.businessSystemRanking.securityRiskTotal === undefined) {
    normalized.appendix.businessSystemRanking.securityRiskTotal = Number(normalized.riskOverview.securityRiskTotal || 0);
  }
  if (normalized.appendix.businessSystemRanking.highAndAboveRiskCount === undefined) {
    normalized.appendix.businessSystemRanking.highAndAboveRiskCount = Number(normalized.riskOverview.highAndAboveRiskCount || 0);
  }

  return normalized;
}

function enrichReportData(reportData) {
  reportData.assetLedger.typeDistribution = ensureArrayObjects(
    reportData.assetLedger.typeDistribution,
    [
      { name: '服务器', value: 284 },
      { name: '终端', value: 106 },
      { name: '其他', value: 4777 }
    ]
  );
  reportData.assetLedger.protectionDistribution = ensureArrayObjects(
    reportData.assetLedger.protectionDistribution,
    [
      { name: '在线', value: 837 },
      { name: '离线', value: 549 },
      { name: '已禁用', value: 1 },
      { name: '已降级', value: 2 },
      { name: '未防护', value: 6 }
    ]
  );
  reportData.assetLedger.internetExposureDistribution = ensureArrayObjects(
    reportData.assetLedger.internetExposureDistribution,
    [
      { name: '服务器', value: 156 },
      { name: '终端', value: 99 },
      { name: '其他', value: 699 }
    ]
  );

  reportData.riskOverview.securityRiskTotal = positiveNumberOr(reportData.riskOverview.securityRiskTotal, 1422);
  reportData.riskOverview.highAndAboveRiskCount = positiveNumberOr(reportData.riskOverview.highAndAboveRiskCount, 850);
  reportData.riskOverview.riskBusinessCount = positiveNumberOr(reportData.riskOverview.riskBusinessCount, 9);
  reportData.riskOverview.riskAssetCount = positiveNumberOr(reportData.riskOverview.riskAssetCount, 146);
  reportData.riskOverview.affectedAssetCount = positiveNumberOr(reportData.riskOverview.affectedAssetCount, 73);
  reportData.riskOverview.devices = positiveNumberOr(reportData.riskOverview.devices, 202);
  reportData.riskOverview.closeRate = positiveNumberOr(reportData.riskOverview.closeRate, 61);
  reportData.riskOverview.closedEvents = positiveNumberOr(reportData.riskOverview.closedEvents, 239);
  reportData.riskOverview.containedEvents = positiveNumberOr(reportData.riskOverview.containedEvents, 88);
  reportData.riskOverview.totalEvents = positiveNumberOr(reportData.riskOverview.totalEvents, 391);

  reportData.riskOverview.coreBusinessSystemRanking = ensurePrimitiveArray(
    reportData.riskOverview.coreBusinessSystemRanking,
    ['OA系统', 'ERP系统', '邮件系统', 'Web门户', 'VPN系统']
  );
  reportData.riskOverview.maxRiskSystem = reportData.riskOverview.maxRiskSystem || 'OA系统';

  const incidentGptStats = reportData.riskOverview.incidentGptStats;
  incidentGptStats.total = positiveNumberOr(incidentGptStats.total, 5);
  incidentGptStats.hostCompromise.total = positiveNumberOr(incidentGptStats.hostCompromise.total, 2);
  incidentGptStats.hostCompromise.confirmedIncidentIds = ensurePrimitiveArray(
    incidentGptStats.hostCompromise.confirmedIncidentIds,
    ['incident-c2-001', 'incident-c2-002']
  );
  incidentGptStats.virusTrojan.total = positiveNumberOr(incidentGptStats.virusTrojan.total, 3);
  incidentGptStats.virusTrojan.confirmedIncidentIds = ensurePrimitiveArray(
    incidentGptStats.virusTrojan.confirmedIncidentIds,
    ['incident-virus-001', 'incident-virus-002', 'incident-virus-003']
  );
  incidentGptStats.threatActorStats = ensureArrayObjects(
    incidentGptStats.threatActorStats,
    [
      { name: '银狐', count: 3 },
      { name: '勒索', count: 2 }
    ]
  );
  incidentGptStats.virusAttackAsset = incidentGptStats.virusAttackAsset || '10.128.160.200';
  incidentGptStats.nonAesCoveredAssets = ensurePrimitiveArray(
    incidentGptStats.nonAesCoveredAssets,
    ['10.128.160.200', '10.128.165.10']
  );
  incidentGptStats.unlabeledAssets = ensurePrimitiveArray(
    incidentGptStats.unlabeledAssets,
    ['10.128.165.151', '10.128.165.53']
  );
  incidentGptStats.c2ConnectionExamples = ensureArrayObjects(
    incidentGptStats.c2ConnectionExamples,
    [
      {
        ioc: 'malicious-c2.example',
        affectedAsset: '10.128.165.151',
        lastOccurredAt: '2026-06-19 09:21:55',
        disposalStatus: '处置中'
      },
      {
        ioc: '198.51.100.77',
        affectedAsset: '10.128.165.53',
        lastOccurredAt: '2026-06-22 17:03:11',
        disposalStatus: '已遏制'
      }
    ]
  );
  incidentGptStats.virusTrojanExamples = ensureArrayObjects(
    incidentGptStats.virusTrojanExamples,
    [
      {
        md5: 'e3b0c44298fc1c149afbf4c8996fb924',
        affectedAsset: '10.128.160.200',
        lastOccurredAt: '2026-06-18 13:05:09',
        disposalStatus: '处置完成'
      },
      {
        md5: '9d5ed678fe57bcca610140957afab571',
        affectedAsset: '10.128.160.83',
        lastOccurredAt: '2026-06-20 18:42:00',
        disposalStatus: '处置中'
      }
    ]
  );

  reportData.riskOverview.exploitStats.total = positiveNumberOr(reportData.riskOverview.exploitStats.total, 22);
  reportData.riskOverview.exploitStats.highRiskAsset = reportData.riskOverview.exploitStats.highRiskAsset || '10.248.38.136';
  reportData.riskOverview.exploitStats.attackSuccessCount = positiveNumberOr(reportData.riskOverview.exploitStats.attackSuccessCount, 7);
  reportData.riskOverview.exploitStats.incidentIds = ensurePrimitiveArray(
    reportData.riskOverview.exploitStats.incidentIds,
    ['incident-exp-001', 'incident-exp-002', 'incident-exp-003']
  );

  reportData.riskOverview.topRiskAssets = mergeArrayObjects(
    reportData.riskOverview.topRiskAssets,
    [
      buildTopRiskAsset('10.128.165.151', '已托管', 'OA系统', 1179, [
        '漏洞风险 1179 项，其中高危及以上 642 项',
        '最近 30 天发生 2 起 C2 外联事件',
        '该资产尚未标注责任人',
        '该资产已纳入重点加固范围'
      ]),
      buildTopRiskAsset('10.128.165.53', '已托管', 'ERP系统', 814, [
        '漏洞风险 814 项，其中高危及以上 401 项',
        '最近 30 天发生 1 起病毒木马事件',
        '该资产尚未安装aES',
        '建议优先执行补丁与终端防护加固'
      ]),
      buildTopRiskAsset('10.128.160.200', '已托管', '邮件系统', 236, [
        '漏洞风险 236 项，其中高危及以上 88 项',
        '检测到病毒投递行为与可疑外联',
        '该资产长期暴露在邮件投递链路上'
      ]),
      buildTopRiskAsset('192.168.30.190', '未托管', 'Web门户', 129, [
        '互联网暴露面风险集中在 Web 服务与弱口令',
        '存在未纳管资产，建议先补纳管再修复'
      ]),
      buildTopRiskAsset('10.128.160.83', '已托管', 'VPN系统', 72, [
        '高危漏洞与账号暴露风险并存',
        '建议优先完成身份认证与边界加固'
      ])
    ],
    'ip'
  );

  reportData.riskOverview.keyRisks = ensureArrayObjects(
    reportData.riskOverview.keyRisks,
    [
      {
        risk: '【威胁运营】病毒木马与 C2 外联事件',
        description: '检测到多个终端存在恶意样本落地与外联行为。',
        impact: '可能导致主机失陷、横向移动与核心系统进一步暴露。',
        strategy: ['优先处置已确认病毒样本', '补齐 aES 覆盖', '核查责任人归属'],
        status: ['2 起已遏制', '3 起处置中']
      },
      {
        risk: '【漏洞风险】核心业务系统高危漏洞集中',
        description: 'OA、ERP、邮件系统存在较多高危及以上漏洞。',
        impact: '攻击者可能借助公开利用链直接获取系统权限。',
        strategy: ['优先修复互联网暴露资产', '建立分批补丁窗口'],
        status: ['高危及以上 850 项', '重点资产 5 台']
      }
    ]
  );

  reportData.riskDetails.securityLogTotal = positiveNumberOr(reportData.riskDetails.securityLogTotal, reportData.riskOverview.securityLogTotal);
  reportData.riskDetails.alertTotal = positiveNumberOr(reportData.riskDetails.alertTotal, reportData.riskOverview.alertTotal);
  reportData.riskDetails.alertReductionRate = numberOr(reportData.riskDetails.alertReductionRate, reportData.riskOverview.alertReductionRate);
  reportData.riskDetails.totalEvents = positiveNumberOr(reportData.riskDetails.totalEvents, reportData.riskOverview.totalEvents);
  reportData.riskDetails.severeEvents = positiveNumberOr(reportData.riskDetails.severeEvents, 18);
  reportData.riskDetails.highEvents = positiveNumberOr(reportData.riskDetails.highEvents, 73);
  reportData.riskDetails.closedEvents = positiveNumberOr(reportData.riskDetails.closedEvents, reportData.riskOverview.closedEvents);
  reportData.riskDetails.containedEvents = positiveNumberOr(reportData.riskDetails.containedEvents, reportData.riskOverview.containedEvents);
  reportData.riskDetails.processingEvents = positiveNumberOr(reportData.riskDetails.processingEvents, 64);
  reportData.riskDetails.closeRate = positiveNumberOr(reportData.riskDetails.closeRate, reportData.riskOverview.closeRate);
  reportData.riskDetails.uniqueAssetCount = positiveNumberOr(reportData.riskDetails.uniqueAssetCount, reportData.riskOverview.affectedAssetCount);
  reportData.riskDetails.managedAssetEvents = positiveNumberOr(reportData.riskDetails.managedAssetEvents, 280);
  reportData.riskDetails.managedAssetContainedEvents = positiveNumberOr(reportData.riskDetails.managedAssetContainedEvents, 88);
  reportData.riskDetails.managedAssetDisposedEvents = positiveNumberOr(reportData.riskDetails.managedAssetDisposedEvents, 176);
  reportData.riskDetails.managedEventCloseRate = positiveNumberOr(reportData.riskDetails.managedEventCloseRate, 63);
  reportData.riskDetails.managedAssetCount = positiveNumberOr(reportData.riskDetails.managedAssetCount, 200);
  reportData.riskDetails.managedAvgResponseTime = positiveNumberOr(reportData.riskDetails.managedAvgResponseTime, 47);
  reportData.riskDetails.topEventType = reportData.riskDetails.topEventType || '恶意文件检出';
  reportData.riskDetails.top3BusinessSystems = reportData.riskDetails.top3BusinessSystems || 'OA系统、ERP系统、邮件系统';
  reportData.riskDetails.businessSystemEventDistribution = ensureArrayObjects(
    reportData.riskDetails.businessSystemEventDistribution,
    [
      { name: 'OA系统', value: 96 },
      { name: 'ERP系统', value: 74 },
      { name: '邮件系统', value: 52 },
      { name: 'Web门户', value: 31 },
      { name: 'VPN系统', value: 27 }
    ]
  );
  reportData.riskDetails.eventTypeDistribution = ensureArrayObjects(
    reportData.riskDetails.eventTypeDistribution,
    [
      { name: '恶意文件检出', value: 121 },
      { name: '漏洞利用', value: 87 },
      { name: '可疑外联', value: 68 },
      { name: '弱口令攻击', value: 43 },
      { name: '账号异常', value: 29 },
      { name: '其他', value: 43 }
    ]
  );

  reportData.riskDetails.highRiskIncidentExamples.vulnExploits = ensureArrayObjects(
    reportData.riskDetails.highRiskIncidentExamples.vulnExploits,
    [
      {
        eventName: '利用漏洞获取 Linux 用户信息',
        affectedAsset: '10.248.38.136',
        lastOccurredAt: '2026-06-09 20:43:16',
        disposalStatus: '处置中'
      },
      {
        eventName: 'Spring 组件远程利用尝试',
        affectedAsset: '10.128.165.151',
        lastOccurredAt: '2026-06-17 11:25:40',
        disposalStatus: '已遏制'
      }
    ]
  );
  reportData.riskDetails.highRiskIncidentExamples.viruses = ensureArrayObjects(
    reportData.riskDetails.highRiskIncidentExamples.viruses,
    [
      {
        md5: '44d88612fea8a8f36de82e1278abb02f',
        affectedAsset: '10.128.160.200',
        lastOccurredAt: '2026-06-18 13:05:09',
        disposalStatus: '处置完成'
      },
      {
        md5: '098f6bcd4621d373cade4e832627b4f6',
        affectedAsset: '10.128.160.83',
        lastOccurredAt: '2026-06-20 18:42:00',
        disposalStatus: '处置中'
      }
    ]
  );
  reportData.riskDetails.highRiskIncidentExamples.c2Connections = ensureArrayObjects(
    reportData.riskDetails.highRiskIncidentExamples.c2Connections,
    [
      {
        ioc: 'malicious-c2.example',
        affectedAsset: '10.128.165.151',
        lastOccurredAt: '2026-06-19 09:21:55',
        disposalStatus: '处置中'
      },
      {
        ioc: '198.51.100.77',
        affectedAsset: '10.128.165.53',
        lastOccurredAt: '2026-06-22 17:03:11',
        disposalStatus: '已遏制'
      }
    ]
  );

  reportData.protection_effectiveness.without_aes_asset_stats.ips =
    reportData.protection_effectiveness.without_aes_asset_stats.ips || '10.128.160.200、10.128.165.10';
  reportData.protection_effectiveness.without_aes_asset_stats.total =
    numberOr(reportData.protection_effectiveness.without_aes_asset_stats.total, 3);
  if (reportData.protection_effectiveness.without_aes_asset_stats.hide_hint === undefined) {
    reportData.protection_effectiveness.without_aes_asset_stats.hide_hint = false;
  }

  const policyStats = reportData.protection_effectiveness.policy_stats;
  policyStats.total = positiveNumberOr(policyStats.total, 12);
  policyStats.abnormal_count = positiveNumberOr(policyStats.abnormal_count, 4);
  policyStats.abnormal_by_dev_type = ensureObject(policyStats.abnormal_by_dev_type, {
    aES: 2,
    AF: 1,
    SIP: 1
  });
  policyStats.abnormal_by_dev_type_text = policyStats.abnormal_by_dev_type_text || 'aES 2项，AF 1项，SIP 1项';
  policyStats.abnormal_by_dev_type_bracket = policyStats.abnormal_by_dev_type_bracket || '（aES 2项，AF 1项，SIP 1项）';
  policyStats.abnormal_component_count = positiveNumberOr(policyStats.abnormal_component_count, 3);
  policyStats.total_component_count = positiveNumberOr(policyStats.total_component_count, 9);
  policyStats.by_device = ensureArrayObjects(
    policyStats.by_device,
    [
      {
        dev_name: 'EDR-核心区-01',
        dev_type: 'aES',
        check_count: 5,
        abnormal_count: 2
      },
      {
        dev_name: 'AF-出口边界-01',
        dev_type: 'AF',
        check_count: 4,
        abnormal_count: 1
      },
      {
        dev_name: 'SIP-汇聚-01',
        dev_type: 'SIP',
        check_count: 3,
        abnormal_count: 1
      }
    ]
  );
  policyStats.policy_check_example = ensureArrayObjects(
    policyStats.policy_check_example,
    [
      {
        dev_name: 'EDR-核心区-01',
        dev_type: 'aES',
        name: '终端防护策略',
        policy_status: '策略获取失败',
        description: '无法拉取终端防护策略最新配置。',
        risk_desc: '可能存在高危样本拦截规则缺失。'
      },
      {
        dev_name: 'AF-出口边界-01',
        dev_type: 'AF',
        name: '边界访问控制',
        policy_status: '未启用',
        description: '出口方向关键拦截策略未生效。',
        risk_desc: '可能导致恶意连接与暴露服务未被阻断。'
      }
    ]
  );
}

function buildAuditPayload(input) {
  const branch1Report = input.branch1Report || {
    reportPatch: {
      scoring: input.reportData.scoring,
      protection_effectiveness: input.reportData.protection_effectiveness
    },
    artifacts: {
      policyJsonPath: path.join(ROOT, '分支1', 'report', 'tmp', 'policy_check.json'),
      policyExcelPath: path.join(ROOT, '分支1', 'report', '策略检查清单.xlsx')
    }
  };

  return {
    generatedAt: new Date().toISOString(),
    auditedJsonOutputs: [
      {
        logicalName: 'report-data',
        defaultPath: path.join(ROOT, 'output', 'report-data.json'),
        role: '最终 HTML 渲染输入',
        presentInWorkspace: Boolean(input.reportDataSample)
      },
      {
        logicalName: 'xdr-asset-summary',
        defaultPath: path.join(ROOT, 'output', 'xdr-asset-summary.json'),
        role: '资产总览中间 JSON',
        presentInWorkspace: Boolean(input.xdrAssetSummary)
      },
      {
        logicalName: 'branch1-report',
        defaultPath: path.join(ROOT, 'tmp', 'branch1', 'branch1-report.json'),
        role: '分支1评分与防护成效补丁',
        presentInWorkspace: Boolean(input.branch1Report)
      },
      {
        logicalName: 'device-snapshot',
        defaultPath: path.join(ROOT, 'tmp', 'device.json'),
        role: '设备接口快照',
        presentInWorkspace: Boolean(input.deviceSnapshot)
      },
      {
        logicalName: 'policy-check',
        defaultPath: path.join(ROOT, '分支1', 'report', 'tmp', 'policy_check.json'),
        role: '策略检查原始 JSON',
        presentInWorkspace: false
      },
      {
        logicalName: 'scoring-result',
        defaultPath: path.join(ROOT, '分支1', 'report', 'scoring_result.json'),
        role: '评分脚本输出',
        presentInWorkspace: false
      },
      {
        logicalName: 'protection-effectiveness',
        defaultPath: path.join(ROOT, '分支1', 'report', 'protection_effectiveness.json'),
        role: '防护成效脚本输出',
        presentInWorkspace: false
      }
    ],
    reportData: input.reportData,
    xdrAssetSummary: input.xdrAssetSummary || {
      projectBackground: input.reportData.projectBackground,
      assetLedger: input.reportData.assetLedger,
      riskOverview: {
        incidentGptStats: input.reportData.riskOverview.incidentGptStats,
        securityLogTotal: input.reportData.riskOverview.securityLogTotal,
        alertTotal: input.reportData.riskOverview.alertTotal,
        alertReductionRate: input.reportData.riskOverview.alertReductionRate,
        closeRate: input.reportData.riskOverview.closeRate
      },
      riskDetails: {
        securityLogTotal: input.reportData.riskDetails.securityLogTotal,
        alertTotal: input.reportData.riskDetails.alertTotal,
        alertReductionRate: input.reportData.riskDetails.alertReductionRate,
        closeRate: input.reportData.riskDetails.closeRate,
        highRiskIncidentExamples: input.reportData.riskDetails.highRiskIncidentExamples
      }
    },
    branch1Report,
    deviceSnapshot: input.deviceSnapshot || buildMockDeviceSnapshot(input.reportData),
    sourceFiles: {
      existingMockSample: Boolean(input.existingMockSample),
      reportDataSample: Boolean(input.reportDataSample),
      branch1ReportSample: Boolean(input.branch1Report),
      xdrAssetSummarySample: Boolean(input.xdrAssetSummary),
      deviceSnapshotSample: Boolean(input.deviceSnapshot)
    }
  };
}

function buildMockDeviceSnapshot(reportData) {
  return {
    data: {
      total: Number(reportData.riskDetails.sangfor || 0) + Number(reportData.riskDetails.third || 0),
      summary: {
        af: Number(reportData.riskDetails.af || 0),
        aes: Number(reportData.riskDetails.aes || 0),
        sip: Number(reportData.riskDetails.sip || 0),
        sta: Number(reportData.riskDetails.sta || 0),
        other_sf: Number(reportData.riskDetails.other_sf || 0),
        third: Number(reportData.riskDetails.third || 0)
      }
    },
    mock: true
  };
}

function buildTopRiskAsset(ip, managedStatus, businessSystem, riskCount, detailLines) {
  return {
    ip,
    managedStatus,
    businessSystem,
    riskCount,
    detailLines: ensurePrimitiveArray(detailLines, []),
    riskDetails: {
      detailLines: ensurePrimitiveArray(detailLines, [])
    }
  };
}

function ensureArrayObjects(current, fallback) {
  return Array.isArray(current) && current.length ? current : fallback;
}

function ensurePrimitiveArray(current, fallback) {
  return Array.isArray(current) && current.length ? current : fallback;
}

function ensureObject(current, fallback) {
  if (current && typeof current === 'object' && !Array.isArray(current) && Object.keys(current).length) {
    return current;
  }
  return fallback;
}

function mergeArrayObjects(current, fallback, keyField) {
  if (!Array.isArray(current) || !current.length) {
    return fallback;
  }

  const fallbackMap = new Map(
    fallback
      .filter((item) => item && item[keyField] !== undefined)
      .map((item) => [item[keyField], item])
  );

  return current.map((item, index) => {
    const matched = item && item[keyField] !== undefined
      ? fallbackMap.get(item[keyField])
      : fallback[index];
    return matched ? deepMerge(matched, item) : item;
  });
}

function arrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

function numberOr(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function positiveNumberOr(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function deepMerge(base, patch) {
  if (!isPlainObject(base) || !isPlainObject(patch)) {
    return cloneValue(patch);
  }

  const merged = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    merged[key] = isPlainObject(value) && isPlainObject(merged[key])
      ? deepMerge(merged[key], value)
      : cloneValue(value);
  }
  return merged;
}

function cloneValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => cloneValue(item));
  }
  if (isPlainObject(value)) {
    const cloned = {};
    for (const [key, nested] of Object.entries(value)) {
      cloned[key] = cloneValue(nested);
    }
    return cloned;
  }
  return value;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

async function readJsonIfExists(filePath) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function writeJson(filePath, data) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
