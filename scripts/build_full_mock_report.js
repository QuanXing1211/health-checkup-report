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
  const branch1Data = await readJsonIfExists(path.join(ROOT, '分支1', 'report', 'data.json'));
  const scoringResult = await readJsonIfExists(path.join(ROOT, '分支1', 'report', 'scoring_result.json'));
  const protectionEffectiveness = await readJsonIfExists(path.join(ROOT, '分支1', 'report', 'protection_effectiveness.json'));
  const policyCheck = await readJsonIfExists(path.join(ROOT, '分支1', 'report', 'tmp', 'policy_check.json'));
  const xdrAssetSummary = await readJsonIfExists(path.join(OUTPUT_DIR, 'xdr-asset-summary.json'));
  const deviceSnapshot = await readJsonIfExists(path.join(ROOT, 'tmp', 'device.json'));

  const reportData = buildRichReportData({
    existingMockSample,
    reportDataSample,
    branch1Report,
    branch1Data,
    scoringResult,
    protectionEffectiveness,
    xdrAssetSummary
  });

  const auditPayload = buildAuditPayload({
    reportData,
    branch1Report,
    branch1Data,
    scoringResult,
    protectionEffectiveness,
    policyCheck,
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
  reportData = deepMerge(reportData, input.branch1Data || {});

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

  if (input.scoringResult) {
    reportData = deepMerge(reportData, {
      scoring: input.scoringResult
    });
  }

  if (input.protectionEffectiveness) {
    reportData = deepMerge(reportData, {
      protection_effectiveness: input.protectionEffectiveness
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
  reportData.riskOverview.affectedAssetCount = positiveNumberOr(reportData.riskOverview.affectedAssetCount, 0);
  reportData.riskOverview.devices = positiveNumberOr(reportData.riskOverview.devices, 202);
  reportData.riskOverview.closeRate = positiveNumberOr(reportData.riskOverview.closeRate, 61);
  reportData.riskOverview.closedEvents = positiveNumberOr(reportData.riskOverview.closedEvents, 239);
  reportData.riskOverview.containedAlerts = positiveNumberOr(reportData.riskOverview.containedAlerts, 88);
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
  incidentGptStats.virusAttackAssetEmpty = !incidentGptStats.virusAttackAsset;
  incidentGptStats.nonAesCoveredAssets = ensurePrimitiveArray(
    incidentGptStats.nonAesCoveredAssets,
    ['10.128.160.200', '10.128.165.10', '10.128.165.20']
  );
  incidentGptStats.nonAesCoveredAssetsHideHint = incidentGptStats.nonAesCoveredAssetsHideHint ?? false;
  incidentGptStats.nonAesCoveredAssetsAllInstalledHide = incidentGptStats.nonAesCoveredAssetsAllInstalledHide ?? true;
  incidentGptStats.nonAesCoveredAssetsIps = incidentGptStats.nonAesCoveredAssetsIps || incidentGptStats.nonAesCoveredAssets.filter(Boolean).join('、');
  incidentGptStats.unlabeledAssets = ensurePrimitiveArray(
    incidentGptStats.unlabeledAssets,
    ['10.128.165.151', '10.128.165.53']
  );
  incidentGptStats.unlabeledAssetsHideHint = incidentGptStats.unlabeledAssetsHideHint ?? false;
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
      buildTopRiskAsset('10.128.165.151', 'OA系统', 1179, [
        '漏洞风险 1179 项，其中高危及以上 642 项',
        '最近 30 天发生 2 起 C2 外联事件',
        '该资产尚未标注责任人',
        '该资产已纳入重点加固范围'
      ]),
      buildTopRiskAsset('10.128.165.53', 'ERP系统', 814, [
        '漏洞风险 814 项，其中高危及以上 401 项',
        '最近 30 天发生 1 起病毒木马事件',
        '该资产尚未安装EDR',
        '建议优先执行补丁与终端防护加固'
      ]),
      buildTopRiskAsset('10.128.160.200', '邮件系统', 236, [
        '漏洞风险 236 项，其中高危及以上 88 项',
        '检测到病毒投递行为与可疑外联',
        '该资产长期暴露在邮件投递链路上'
      ]),
      buildTopRiskAsset('192.168.30.190', 'Web门户', 129, [
        '互联网暴露面风险集中在 Web 服务与弱口令',
        '存在未纳管资产，建议先补纳管再修复'
      ]),
      buildTopRiskAsset('10.128.160.83', 'VPN系统', 72, [
        '高危漏洞与账号暴露风险并存',
        '建议优先完成身份认证与边界加固'
      ])
    ],
    'ip'
  );

  reportData.riskDetails.securityLogTotal = positiveNumberOr(reportData.riskDetails.securityLogTotal, reportData.riskOverview.securityLogTotal);
  reportData.riskDetails.alertTotal = positiveNumberOr(reportData.riskDetails.alertTotal, reportData.riskOverview.alertTotal);
  reportData.riskDetails.alertReductionRate = numberOr(reportData.riskDetails.alertReductionRate, reportData.riskOverview.alertReductionRate);
  reportData.riskDetails.totalEvents = positiveNumberOr(reportData.riskDetails.totalEvents, reportData.riskOverview.totalEvents);
  reportData.riskDetails.severeEvents = positiveNumberOr(reportData.riskDetails.severeEvents, 18);
  reportData.riskDetails.highEvents = positiveNumberOr(reportData.riskDetails.highEvents, 73);
  reportData.riskDetails.closedEvents = positiveNumberOr(reportData.riskDetails.closedEvents, reportData.riskOverview.closedEvents);
  reportData.riskDetails.containedAlerts = positiveNumberOr(reportData.riskDetails.containedAlerts, reportData.riskOverview.containedAlerts);
  reportData.riskDetails.processingEvents = positiveNumberOr(reportData.riskDetails.processingEvents, 64);
  reportData.riskDetails.closeRate = positiveNumberOr(reportData.riskDetails.closeRate, reportData.riskOverview.closeRate);
  reportData.riskDetails.uniqueAssetCount = positiveNumberOr(reportData.riskDetails.uniqueAssetCount, reportData.riskOverview.affectedAssetCount);
  reportData.riskDetails.AvgResponseTime = positiveNumberOr(reportData.riskDetails.AvgResponseTime, 42);
  reportData.riskDetails.managedAssetCount = positiveNumberOr(reportData.riskDetails.managedAssetCount, 200);
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
  const scoringResult = input.scoringResult || buildMockScoringResult(input.reportData);
  const protectionEffectiveness = input.protectionEffectiveness || buildMockProtectionEffectiveness(input.reportData);
  const branch1Data = input.branch1Data || buildMockBranch1Data({
    reportData: input.reportData,
    scoringResult,
    protectionEffectiveness
  });
  const policyCheck = input.policyCheck || buildMockPolicyCheck(protectionEffectiveness);
  const xdrAssetSummary = input.xdrAssetSummary || buildMockXdrAssetSummary(input.reportData);
  const deviceSnapshot = input.deviceSnapshot || buildMockDeviceSnapshot(input.reportData);
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
  const sourceJsonExamples = {
    reportData: input.reportData,
    xdrAssetSummary,
    branch1Report,
    branch1Data,
    scoringResult,
    protectionEffectiveness,
    policyCheck,
    deviceSnapshot
  };
  const fieldCoverage = buildFieldCoverage(sourceJsonExamples, input.reportData);

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
        presentInWorkspace: Boolean(input.policyCheck)
      },
      {
        logicalName: 'scoring-result',
        defaultPath: path.join(ROOT, '分支1', 'report', 'scoring_result.json'),
        role: '评分脚本输出',
        presentInWorkspace: Boolean(input.scoringResult)
      },
      {
        logicalName: 'protection-effectiveness',
        defaultPath: path.join(ROOT, '分支1', 'report', 'protection_effectiveness.json'),
        role: '防护成效脚本输出',
        presentInWorkspace: Boolean(input.protectionEffectiveness)
      },
      {
        logicalName: 'branch1-data',
        defaultPath: path.join(ROOT, '分支1', 'report', 'data.json'),
        role: '分支1聚合数据样例',
        presentInWorkspace: Boolean(input.branch1Data)
      }
    ],
    fieldCoverage,
    reportData: input.reportData,
    xdrAssetSummary,
    branch1Report,
    branch1Data,
    scoringResult,
    protectionEffectiveness,
    policyCheck,
    deviceSnapshot,
    sourceJsonExamples,
    sourceFiles: {
      existingMockSample: Boolean(input.existingMockSample),
      reportDataSample: Boolean(input.reportDataSample),
      branch1ReportSample: Boolean(input.branch1Report),
      branch1DataSample: Boolean(input.branch1Data),
      scoringResultSample: Boolean(input.scoringResult),
      protectionEffectivenessSample: Boolean(input.protectionEffectiveness),
      policyCheckSample: Boolean(input.policyCheck),
      xdrAssetSummarySample: Boolean(input.xdrAssetSummary),
      deviceSnapshotSample: Boolean(input.deviceSnapshot)
    }
  };
}

function buildMockXdrAssetSummary(reportData) {
  return {
    projectBackground: reportData.projectBackground,
    assetLedger: reportData.assetLedger,
    riskOverview: {
      incidentGptStats: reportData.riskOverview.incidentGptStats,
      securityLogTotal: reportData.riskOverview.securityLogTotal,
      alertTotal: reportData.riskOverview.alertTotal,
      alertReductionRate: reportData.riskOverview.alertReductionRate,
      closeRate: reportData.riskOverview.closeRate
    },
    riskDetails: {
      securityLogTotal: reportData.riskDetails.securityLogTotal,
      alertTotal: reportData.riskDetails.alertTotal,
      alertReductionRate: reportData.riskDetails.alertReductionRate,
      closeRate: reportData.riskDetails.closeRate,
      highRiskIncidentExamples: reportData.riskDetails.highRiskIncidentExamples
    }
  };
}

function buildMockScoringResult(reportData) {
  const scoring = reportData.scoring || {};
  return {
    total_score: numberOr(scoring.total_score, 72.4),
    L1: ensureObject(scoring.L1, {
      '资产防护得分': 74.2,
      '日常运营得分': 70.6
    }),
    L2: ensureObject(scoring.L2, {
      '托管资产得分': 88.5,
      '组件检测得分': 69.4,
      '事件得分': 76.8,
      '勒索风险得分': 54.1
    }),
    L3: ensureObject(scoring.L3, {
      '服务器得分': 81.3,
      '终端得分': 65.7,
      '服务器权重': 0.6,
      '终端权重': 0.4,
      '设备离线得分': 72.0,
      '策略隐患得分': 61.0,
      '漏洞得分': 68.0,
      '端口得分': 63.0,
      '弱密码基础分': 70.0,
      '脆弱性事件分': 75.0,
      '弱密码得分': 58.0
    }),
    data_summary: ensureObject(scoring.data_summary, {
      asset: {
        server: { both_coverage: 42, client_only: 8, net_only: 5, no_coverage: 3, total: 58 },
        pc: { both_coverage: 86, client_only: 12, net_only: 7, no_coverage: 9, total: 114 },
        all_assets: 172,
        device: { activated_count: 171, offline_count: 12, total: 183 }
      },
      event: {
        server_events: { critical: 3, high: 8, medium: 19, low: 12 },
        pc_events: { critical: 5, high: 14, medium: 21, low: 9 },
        total_events: 91
      },
      weak_pwd_event: {
        weak_pwd_server_events: { critical: 0, high: 2, medium: 4, low: 1 },
        weak_pwd_pc_events: { critical: 1, high: 3, medium: 5, low: 2 },
        total_weak_pwd_events: 18
      },
      vuln: { urgent_count: 24, fast_count: 61, suggest_count: 37, total_vulns: 122 },
      weak_pwd: { high_count: 11, middle_count: 9, low_count: 7, unknown_count: 4, total_weak_pwd: 31 },
      port: { risk_port_count: 128, total_ports: 416 },
      policy: {
        check_cnt: 12,
        risk_cnt: 4,
        policy_status_summary: { '策略获取失败': 2, '正常': 7, '异常': 3 },
        risk_status_summary: { '存在风险': 4, '无风险': 8 }
      }
    }),
    weights_used: ensureObject(scoring.weights_used, {
      DEFAULT_ASSETS_RATIO: 0.6,
      ASSETS_RATIO: 0.4,
      COMPONENTS_RATIO: 0.6,
      EVENTS_RATIO: 0.6,
      VULNERABILITIES_RATIO: 0.4,
      SERVER_RATIO: 0.75,
      PC_SCORE: 0.25,
      DEVICE_K: 0.5,
      POLICY_K: 0.5,
      VULNERABILITY_K: 0.5,
      WEAK_PASSWORD_K: 0.25,
      PORT_K: 0.25,
      WEAK_PASSWORD_BASE_K: 1,
      SERVER_MAJOR_EVENT_K: 10,
      SERVER_GENERAL_EVENT_K: 7.5,
      SERVER_OTHER_EVENT_K: 5,
      SERVER_MAJOR_THREAT_K: 2.5,
      PC_MAJOR_EVENT_K: 5,
      PC_GENERAL_EVENT_K: 3.75,
      PC_OTHER_EVENT_K: 2.5,
      PC_MAJOR_THREAT_K: 1.25,
      AGENT_FIX_VULN_K: 15,
      FAST_FIX_VULN_K: 7.5,
      SUGGEST_FIX_VULN_K: 1,
      RISK_PORT_K: 20,
      HIGH_LEVEL_WEAKPWD_K: 20,
      MIDDLE_LEVEL_WEAKPWD_K: 10,
      LOW_LEVEL_WEAKPWD_K: 5,
      UNKNOWN_LEVEL_WEAKPWD_K: 2
    })
  };
}

function buildMockProtectionEffectiveness(reportData) {
  return ensureObject(reportData.protection_effectiveness, {
    without_aes_asset_stats: {
      ips: '10.128.160.200、10.128.165.10、192.168.30.190',
      total: 3,
      hide_hint: false
    },
    policy_stats: {
      total: 12,
      abnormal_count: 4,
      abnormal_by_dev_type: {
        EDR: 2,
        AF: 1,
        SIP: 1
      },
      abnormal_by_dev_type_text: 'EDR 2 个，AF 1 个，SIP 1 个',
      abnormal_by_dev_type_bracket: '（EDR 2 个，AF 1 个，SIP 1 个）',
      abnormal_component_count: 3,
      total_component_count: 9,
      by_device: [
        { dev_name: 'EDR-核心区-01', dev_type: 'EDR', check_count: 5, abnormal_count: 2 },
        { dev_name: 'AF-出口边界-01', dev_type: 'AF', check_count: 4, abnormal_count: 1 },
        { dev_name: 'SIP-汇聚-01', dev_type: 'SIP', check_count: 3, abnormal_count: 1 }
      ],
      policy_check_example: [
        {
          dev_id: 154258,
          dev_name: 'EDR-核心区-01',
          name: 'Linux SSH暴力破解检测-处置方式',
          policy_type: 'EDR_LINUX_ANTI_BFA_SSH_HANDLE',
          policy_status: '策略获取失败',
          description: '当前策略获取失败，请人工检查该设备策略情况。',
          latest_time: ['2026-06-20 10:00:00'],
          event_time: ['2026-05-25 15:18:50'],
          risk_desc: '风险描述举例',
          dev_type: 'EDR',
          risk_status: 'at_risk',
          handle_status: 'generated'
        }
      ]
    }
  });
}

function buildMockPolicyCheck(protectionEffectiveness) {
  const examples = Array.isArray(
    protectionEffectiveness
    && protectionEffectiveness.policy_stats
    && protectionEffectiveness.policy_stats.policy_check_example
  )
    ? protectionEffectiveness.policy_stats.policy_check_example
    : [];

  if (examples.length) {
    return cloneValue(examples);
  }

  return [
    {
      dev_id: 154258,
      dev_name: 'EDR-核心区-01',
      name: 'Linux SSH暴力破解检测-处置方式',
      policy_type: 'EDR_LINUX_ANTI_BFA_SSH_HANDLE',
      policy_status: '策略获取失败',
      description: '当前策略获取失败，请人工检查该设备策略情况。',
      latest_time: ['2026-06-20 10:00:00'],
      event_time: ['2026-05-25 15:18:50'],
      risk_desc: '风险描述举例',
      dev_type: 'EDR',
      risk_status: 'at_risk',
      handle_status: 'generated'
    }
  ];
}

function buildMockBranch1Data(input) {
  return {
    ...cloneValue(input.reportData),
    scoring: cloneValue(input.scoringResult),
    protection_effectiveness: cloneValue(input.protectionEffectiveness),
    without_aes_asset_stats: cloneValue(input.protectionEffectiveness.without_aes_asset_stats),
    policy_stats: cloneValue(input.protectionEffectiveness.policy_stats)
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

function buildFieldCoverage(sourceJsonExamples, reportData) {
  const sourcePathSet = new Set();
  const reportPathSet = new Set();

  for (const sample of Object.values(sourceJsonExamples)) {
    collectJsonPaths(sample, '', sourcePathSet);
  }
  collectJsonPaths(reportData, '', reportPathSet);

  return {
    sourceJsonPathCount: sourcePathSet.size,
    reportDataPathCount: reportPathSet.size,
    reportDataMissingPaths: [...sourcePathSet].filter((item) => !reportPathSet.has(item)).sort()
  };
}

function collectJsonPaths(value, prefix, output) {
  if (Array.isArray(value)) {
    output.add(`${prefix}[]`);
    value.forEach((item) => collectJsonPaths(item, `${prefix}[]`, output));
    return;
  }

  if (!isPlainObject(value)) {
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const next = prefix ? `${prefix}.${key}` : key;
    output.add(next);
    collectJsonPaths(nested, next, output);
  }
}

function buildTopRiskAsset(ip, businessSystem, riskCount, detailLines) {
  return {
    ip,
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
