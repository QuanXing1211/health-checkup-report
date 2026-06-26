'use strict';

const { fetchXdrAssetOverview } = require('./xdr_asset_client');

async function collectReportData(input) {
  if (input.xdrCookiePath) {
    logInfo(input.logger, '使用 XDR 数据生成报告资产台账');
    const baseData = buildBaseReportData(input);
    const xdrData = await fetchXdrAssetOverview(input.xdrCookiePath, {
      logger: input.logger,
      projectBackground: {
        customerName: input.customer || '',
        customerId: input.customerId || null,
        startDate: input.start || '',
        endDate: input.end || ''
      }
    });

    let merged = deepMerge(baseData, xdrData);
    merged = applyAssetStatusStats(merged, input.assetStatusStats);
    merged = applyIncidentStatusStats(merged, input.incidentStatusStats);
    return merged;
  }

  throw new Error('Real data source requires --xdr-cookie-path.');
}

function logInfo(logger, message) {
  if (typeof logger === 'function') {
    logger(message);
  }
}

function applyIncidentStatusStats(reportData, stats) {
  const existingRiskDetails = reportData && reportData.riskDetails ? reportData.riskDetails : {};
  const merged = stats ? deepMerge(reportData, {
    riskDetails: {
      totalEvents: Number(stats.totalEvents || 0),
      severeEvents: Number(stats.severeEvents || 0),
      highEvents: Number(stats.highEvents || 0),
      closedEvents: Number(stats.closedEvents || 0),
      containedEvents: Number(stats.containedEvents || 0),
      processingEvents: Number(stats.processingEvents || 0),
      closeRate: Number(stats.closeRate || 0),
      alertReductionRate: Number(
        stats.alertReductionRate !== undefined && stats.alertReductionRate !== null
          ? stats.alertReductionRate
          : existingRiskDetails.alertReductionRate || 0
      ),
      uniqueAssetCount: Number(stats.uniqueAssetCount || 0)
    }
  }) : reportData;

  if (merged && merged.riskOverview && merged.riskDetails) {
    merged.riskOverview.closeRate = merged.riskDetails.closeRate;
    merged.riskOverview.closedEvents = merged.riskDetails.closedEvents;
    merged.riskOverview.containedEvents = merged.riskDetails.containedEvents;
    merged.riskOverview.totalEvents = merged.riskDetails.totalEvents;
    merged.riskOverview.alertReductionRate = merged.riskDetails.alertReductionRate;
  }

  return merged;
}

function applyAssetStatusStats(reportData, stats) {
  if (!stats) {
    return reportData;
  }

  const merged = deepMerge(reportData, {
    assetLedger: {
      manage_asset: Number(stats.manage_asset || stats.assetTotal || 0),
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
      title: '首次安全体检报告',
      customerName: input.customer,
      customerId: input.customerId || null,
      startDate: input.start,
      endDate: input.end,
      generatedAt: new Date().toISOString()
    },
    assetLedger: {},
    riskOverview: {},
    riskDetails: {},
    appendix: {}
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
