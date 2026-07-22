'use strict';

const { fetchMsswAssetOverview, fetchSecurityCheckReportStats, calculateAttackOverview, readMsswCookieInfo } = require('./mssw_client');

async function collectReportData(input) {
  if (input.msswCookiePath) {
    logInfo(input.logger, '使用 MSSW 主链路生成报告资产台账');
    const baseData = buildBaseReportData(input);
    const overviewData = await fetchMsswAssetOverview({
      logger: input.logger,
      projectBackground: {
        customerName: input.customer || '',
        customerId: input.customerId || null,
        startDate: input.start || '',
        endDate: input.end || ''
      },
      msswCookiePath: input.msswCookiePath,
      xdrCookiePath: input.xdrCookiePath,
      msswBaseUrl: input.msswBaseUrl,
      customerId: input.customerId,
      incidentFilePath: input.incidentFilePath,
      assetFilePath: input.assetFilePath,
      exploitIncidentIds: input.exploitIncidentIds
    });

    let merged = deepMerge(baseData, overviewData);
    // core_asset 改为由 Excel 资产表统计提供，不查接口
    merged.assetLedger.core_asset = 0;
    merged = applyAssetStatusStats(merged, input.assetStatusStats);
    merged = applyIncidentStatusStats(merged, input.incidentStatusStats);
    merged = await applyAttackOverview(merged, input);
    return merged;
  }

  logInfo(input.logger, '使用基础数据生成报告（跳过资产台账 API）');
  const baseData = buildBaseReportData(input);
  let merged = applyAssetStatusStats(baseData, input.assetStatusStats);
  merged = applyIncidentStatusStats(merged, input.incidentStatusStats);
  return merged;
}

/**
 * 调用安全体检报告统计接口，计算攻击态势总览数据并合并到 reportData.attackOverview。
 * 失败不阻断主流程，仅在日志中提示。
 */
async function applyAttackOverview(reportData, input) {
  const merged = { ...reportData };
  merged.attackOverview = buildEmptyAttackOverview();

  if (!input.msswCookiePath || !input.customerId || !input.start || !input.end) {
    logInfo(input.logger, '跳过攻击态势接口查询: 缺少 msswCookiePath/customerId/start/end');
    return merged;
  }

  try {
    const cookieInfo = await readMsswCookieInfo(input.msswCookiePath);
    const stats = await fetchSecurityCheckReportStats(
      cookieInfo,
      input.msswBaseUrl,
      input.customerId,
      input.customer,
      input.start,
      input.end
    );

    if (!stats) {
      logInfo(input.logger, '攻击态势接口返回空数据: 报告范围可能不在近 31 天内');
      return merged;
    }

    const overview = calculateAttackOverview(stats);
    if (overview) {
      merged.attackOverview = overview;
      logInfo(input.logger, `攻击态势数据已合并: total=${overview.total_attack_count}, dailyAvg=${overview.daily_avg}, night=${overview.night_attack_count}, ratio=${overview.night_ratio}%, days=${overview.trend_dates.length}`);
    }
  } catch (error) {
    logInfo(input.logger, `攻击态势接口调用失败（不影响主流程）: ${error.message}`);
  }

  return merged;
}

function buildEmptyAttackOverview() {
  return {
    total_attack_count: 0,
    night_attack_count: 0,
    workday_attack_count: 0,
    daily_avg: 0,
    night_ratio: '0',
    trend_dates: [],
    trend_values: [],
    error: ''
  };
}

function logInfo(logger, message) {
  if (typeof logger === 'function') {
    logger(message);
  }
}

function applyIncidentStatusStats(reportData, stats) {
  const existingRiskDetails = reportData && reportData.riskDetails ? reportData.riskDetails : {};

  // 如果 stats 没有显式提供消减率，但有事件总数和告警总数，则自动计算
  const hasExplicitAlertReduction = stats && stats.alertReductionRate !== undefined && stats.alertReductionRate !== null;
  let computedAlertReductionRate;
  if (hasExplicitAlertReduction) {
    computedAlertReductionRate = Number(stats.alertReductionRate);
  } else {
    const totalEvts = Number(stats && stats.totalEvents || 0);
    const alertTot = Number(existingRiskDetails.alertTotal || 0);
    if (alertTot > 0 && totalEvts > 0) {
      computedAlertReductionRate = Number((((alertTot - totalEvts) / alertTot) * 100).toFixed(2));
    } else {
      computedAlertReductionRate = existingRiskDetails.alertReductionRate || 0;
    }
  }

  const merged = stats ? deepMerge(reportData, {
    riskDetails: {
      totalEvents: Number(stats.totalEvents || 0),
      severeEvents: Number(stats.severeEvents || 0),
      highEvents: Number(stats.highEvents || 0),
      closedEvents: Number(stats.closedEvents || 0),
      containedEvents: Number(stats.containedEvents || 0),
      processingEvents: Number(stats.processingEvents || 0),
      closeRate: Number(stats.closeRate || 0),
      alertReductionRate: computedAlertReductionRate,
      uniqueAssetCount: Number(stats.uniqueAssetCount || 0)
    }
  }) : reportData;

  if (merged && merged.riskOverview && merged.riskDetails) {
    merged.riskOverview.closeRate = merged.riskDetails.closeRate;
    merged.riskOverview.closedEvents = merged.riskDetails.closedEvents;
    merged.riskOverview.containedEvents = merged.riskDetails.containedEvents;
    merged.riskOverview.totalEvents = merged.riskDetails.totalEvents;
    merged.riskOverview.alertReductionRate = merged.riskDetails.alertReductionRate;
    merged.riskOverview.affectedAssetCount = merged.riskDetails.uniqueAssetCount;
  }

  // === ABCDE 派生计算（2 节风险总览总结文案）===
  // C = 威胁预防风险总数（5 项求和，全部来自 2 节图右侧"威胁预防"面板）
  const internetRiskPorts = Number((merged.summary && merged.summary.internet && merged.summary.internet.exposure && merged.summary.internet.exposure.risk_ports) || 0);
  const internetVulnTotal = Number((merged.summary && merged.summary.internet && merged.summary.internet.vuln && merged.summary.internet.vuln.total) || 0);
  const internetWeakPwdTotal = Number((merged.summary && merged.summary.internet && merged.summary.internet.weak_pwd && merged.summary.internet.weak_pwd.total) || 0);
  const intranetVulnTotal = Number((merged.summary && merged.summary.intranet && merged.summary.intranet.vuln && merged.summary.intranet.vuln.total) || 0);
  const intranetWeakPwdTotal = Number((merged.summary && merged.summary.intranet && merged.summary.intranet.weak_pwd && merged.summary.intranet.weak_pwd.total) || 0);
  const threatPreventionRiskCount = internetRiskPorts + internetVulnTotal + internetWeakPwdTotal + intranetVulnTotal + intranetWeakPwdTotal;

  // M = 组件策略检查风险项
  const policyAbnormalCount = Number((merged.protection_effectiveness && merged.protection_effectiveness.policy_stats && merged.protection_effectiveness.policy_stats.abnormal_count) || 0);

  // A = B + C + M
  const totalRiskCount = Number(merged.riskOverview.totalEvents || 0) + threatPreventionRiskCount + policyAbnormalCount;

  if (merged.riskOverview) {
    merged.riskOverview.threatPreventionRiskCount = threatPreventionRiskCount;
    merged.riskOverview.totalRiskCount = totalRiskCount;
  }

  return merged;
}

function applyAssetStatusStats(reportData, stats) {
  if (!stats) {
    return reportData;
  }

  const merged = deepMerge(reportData, {
    assetLedger: {
      core_asset: Number(stats.core_asset || 0),
      core_managed_asset: Number(stats.core_managed_asset || 0),
      manage_asset: Number(stats.manage_asset || 0),
      typeDistribution: Array.isArray(stats.typeDistribution) ? stats.typeDistribution : [],
      protectionDistribution: Array.isArray(stats.protectionDistribution) ? stats.protectionDistribution : [],
      internetExposureTotal: Number(stats.internetExposureTotal || 0),
      internetExposureDistribution: Array.isArray(stats.internetExposureDistribution) ? stats.internetExposureDistribution : []
    }
  });

  if (merged && merged.assetLedger) {
    merged.assetLedger.assetTotal = Number(stats.assetTotal || stats.manage_asset || 0);
  }

  return merged;
}

function buildBaseReportData(input) {
  return {
    projectBackground: {
      customerName: input.customer,
      startDate: input.start,
      endDate: input.end
    },
    assetLedger: {},
    riskOverview: {},
    riskDetails: {}
  };
}

function deepMerge(base, patch) {
  if (!isPlainObject(base) || !isPlainObject(patch)) {
    return patch;
  }

  const merged = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    merged[key] = isPlainObject(value) && isPlainObject(merged[key])
      ? deepMerge(merged[key], value)
      : value;
  }
  return merged;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

module.exports = {
  collectReportData
};
