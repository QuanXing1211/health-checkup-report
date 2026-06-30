#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs/promises');
const { parseArgs, requireArgs } = require('./src/args');
const { collectReportData } = require('./src/data_client');
const { summarizeAssetTable } = require('./src/asset_excel_stats');
const { summarizeIncidentStatus, extractExploitStats, extractVulnExploitExamples, summarizeManagedAssetIncidents, extractIncidentTypeStats } = require('./src/incident_excel_stats');
const { exportXdrAssetList, exportXdrIncidentList, exportXdrDeviceList, exportMsswIncidentList, exportMsswAssetList, exportMsswDeviceList, findMsswCustomerIdByName, fetchDefaultProjectTimeRange, fetchXdrAssetOverview, readXdrCookieInfo, readMsswCookieInfo, resolveWorkingXdrBaseUrl, collectDeviceCategoryCounts, collectMsswDeviceCategoryCounts, parseLocalDate } = require('./src/xdr_asset_client');
const { renderReportToFile } = require('./src/template_renderer');

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));
  const logger = createLogger(options);
  const emitJson = options.json === true || options.json === 'true';

  if (command === 'help' || options.help) {
    printHelp();
    return;
  }

  const reportGeneratedAt = new Date();

  // 统一查一次 customerId（只接受 --customer 自动查）
  let customerId = '';
  let msswCookie = null;
  if (options['mssw-cookie-path'] && options.customer) {
    try {
      msswCookie = await readMsswCookieInfo(options['mssw-cookie-path']);
      customerId = await findMsswCustomerIdByName(msswCookie, options['mssw-base-url'], options.customer);
      logger(`已自动获取 company_id: ${customerId}`);
    } catch (err) {
      logger(`自动查询 company_id 失败: ${err.message}`);
    }
  }

  // 设备表导出
  if (options['mssw-cookie-path']) {
    await exportMsswDeviceList({
      msswCookiePath: options['mssw-cookie-path'],
      msswBaseUrl: options['mssw-base-url'],
      customerId,
      logger
    });
  } else if (options['xdr-cookie-path']) {
    await exportXdrDeviceList({
      xdrCookiePath: options['xdr-cookie-path'],
      xdrBaseUrl: options['xdr-base-url'],
      logger
    });
  }

  if (command && command !== 'generate') {
    if (command === 'xdr-asset-export') {
      const result = await exportXdrAssetList({
        xdrCookiePath: options['xdr-cookie-path'],
        downloadDir: options['download-dir'],
        timeoutMs: options['timeout-ms'] ? Number(options['timeout-ms']) : undefined,
        logger
      });
      outputResult(result, emitJson, logger, `XDR 资产表已导出: ${result.filePath}`);
      return;
    }

    if (command === 'mssw-asset-export') {
      requireArgs(options, ['mssw-cookie-path', 'customer-id']);
      const result = await exportMsswAssetList({
        msswCookiePath: options['mssw-cookie-path'],
        msswBaseUrl: options['mssw-base-url'],
        downloadDir: options['download-dir'],
        customerId: options['customer-id'],
        logger
      });
      outputResult(result, emitJson, logger, `MSSW 资产表已导出: ${result.filePath}`);
      return;
    }

    if (command === 'xdr-incident-export') {
      const result = await exportXdrIncidentList({
        xdrCookiePath: options['xdr-cookie-path'],
        downloadDir: options['download-dir'],
        start: options.start,
        end: options.end,
        timeoutMs: options['timeout-ms'] ? Number(options['timeout-ms']) : undefined,
        pollIntervalMs: options['poll-interval-ms'] ? Number(options['poll-interval-ms']) : undefined,
        logger
      });
      outputResult(result, emitJson, logger, `XDR 事件表已导出: ${result.filePath}`);
      return;
    }

    if (command === 'xdr-asset-summary') {
      const root = __dirname;
      const end = options.end || formatLocalDate(new Date());
      const result = await fetchXdrAssetOverview(options['xdr-cookie-path'], {
        logger,
        projectBackground: {
          customerName: options.customer || '',
          customerId: options['customer-id'] || null,
          startDate: options.start || '',
          endDate: end
        }
      });
      const outputJson = options['output-json'] || path.join(root, 'output', 'xdr-asset-summary.json');
      const merged = await mergeJsonFile(outputJson, result);
      outputResult(merged, emitJson, logger, `XDR 资产台账统计已更新: ${outputJson}`);
      return;
    }

    throw new Error(`Unsupported command: ${command}`);
  }

  requireArgs(options, ['customer']);

  const effectiveTimeRange = await resolveEffectiveTimeRange({
    options,
    customerId,
    msswCookie,
    reportGeneratedAt,
    logger
  });

  const root = __dirname;
  const templatePath = options.template || path.join(root, 'security-report-preview.html');
  const outputDir = options['output-dir'] || path.join(root, 'output');

  logger(`开始生成: ${options.customer} ${effectiveTimeRange.start} ~ ${effectiveTimeRange.end}`);

  const xdrExports = await exportConfiguredXdrTables({
    xdrCookiePath: options['xdr-cookie-path'],
    msswCookiePath: options['mssw-cookie-path'],
    downloadDir: options['download-dir'],
    start: effectiveTimeRange.start,
    end: effectiveTimeRange.end,
    xdrTables: options['xdr-tables'],
    customerId,
    timeoutMs: options['timeout-ms'] ? Number(options['timeout-ms']) : undefined,
    pollIntervalMs: options['poll-interval-ms'] ? Number(options['poll-interval-ms']) : undefined,
    logger
  });
  if (Object.keys(xdrExports).length) {
    logger(`XDR 导出完成: ${Object.keys(xdrExports).join(', ')}`);
  } else {
    logger('跳过 XDR 导出');
  }

  const assetStatusStats = await summarizeExportedAssetStatus(xdrExports, logger);
  const incidentStatusStats = await summarizeExportedIncidentStatus(xdrExports, logger);

  // 从事件表提取漏洞利用统计（不阻断主流程）
  let exploitStats = null;
  let vulnExploitExamples = [];
  const incidentFilePath = xdrExports && xdrExports.incident ? xdrExports.incident.filePath : '';
  if (incidentFilePath) {
    try {
      exploitStats = await extractExploitStats(incidentFilePath);
      logger(`漏洞利用事件统计: 共 ${exploitStats.total} 起, 攻击成功 ${exploitStats.attackSuccessCount} 次, 影响资产 ${exploitStats.highRiskAsset || '无'}`);
    } catch (error) {
      logger(`提取漏洞利用事件统计失败（不影响主流程）: ${error.message}`);
    }

    try {
      const exploitExamples = await extractVulnExploitExamples(incidentFilePath, exploitStats ? exploitStats.incidentIds : []);
      vulnExploitExamples = Array.isArray(exploitExamples.vulnExploits) ? exploitExamples.vulnExploits : [];
      logger(`漏洞利用事件举例已提取: ${vulnExploitExamples.length} 条`);
    } catch (error) {
      logger(`提取漏洞利用事件举例失败（不影响主流程）: ${error.message}`);
    }
  }

  // 从资产表和事件表提取托管资产安全事件统计（不阻断主流程）
  const assetFilePath = xdrExports && xdrExports.asset ? xdrExports.asset.filePath : '';
  let managedAssetIncidentStats = null;
  if (assetFilePath && incidentFilePath) {
    try {
      managedAssetIncidentStats = await summarizeManagedAssetIncidents(assetFilePath, incidentFilePath);
      logger(`托管资产事件统计: 共 ${managedAssetIncidentStats.managedAssetEvents} 起事件, 涉及 ${managedAssetIncidentStats.managedAssetCount} 个托管资产, 已遏制 ${managedAssetIncidentStats.managedAssetContainedEvents} 起, 处置完成 ${managedAssetIncidentStats.managedAssetDisposedEvents} 起, 闭环率 ${managedAssetIncidentStats.managedEventCloseRate}%`);
    } catch (error) {
      logger(`托管资产事件统计失败（不影响主流程）: ${error.message}`);
    }
  }

  const reportData = await collectReportData({
    customer: options.customer,
    customerId,
    start: effectiveTimeRange.start,
    end: effectiveTimeRange.end,
    xdrCookiePath: options['xdr-cookie-path'],
    msswCookiePath: options['mssw-cookie-path'],
    msswBaseUrl: options['mssw-base-url'],
    assetStatusStats,
    incidentStatusStats,
    incidentFilePath: xdrExports.incident ? xdrExports.incident.filePath : undefined,
    assetFilePath: xdrExports.asset ? xdrExports.asset.filePath : undefined,
    logger
  });

  // 合并漏洞利用统计到报告数据
  if (exploitStats) {
    reportData.riskOverview.exploitStats = exploitStats;
    logger(`漏洞利用数据已合并: total=${exploitStats.total}, attackSuccessCount=${exploitStats.attackSuccessCount}`);
  }

  if (!reportData.riskDetails.highRiskIncidentExamples || typeof reportData.riskDetails.highRiskIncidentExamples !== 'object') {
    reportData.riskDetails.highRiskIncidentExamples = {};
  }
  reportData.riskDetails.highRiskIncidentExamples.vulnExploits = vulnExploitExamples;

  // 合并托管资产事件统计到报告数据（始终写入默认值，有数据时覆盖）
  Object.assign(reportData.riskDetails, {
    managedAssetEvents: 0,
    managedAssetContainedEvents: 0,
    managedAssetDisposedEvents: 0,
    managedEventCloseRate: 0,
    managedAssetCount: 0,
    managedAvgResponseTime: 0,
    topEventType: '',
    top3BusinessSystems: '',
    businessSystemEventDistribution: []
  });
  if (managedAssetIncidentStats) {
    Object.assign(reportData.riskDetails, {
      managedAssetEvents: managedAssetIncidentStats.managedAssetEvents,
      managedAssetContainedEvents: managedAssetIncidentStats.managedAssetContainedEvents,
      managedAssetDisposedEvents: managedAssetIncidentStats.managedAssetDisposedEvents,
      managedEventCloseRate: managedAssetIncidentStats.managedEventCloseRate,
      managedAssetCount: managedAssetIncidentStats.managedAssetCount,
      managedAvgResponseTime: managedAssetIncidentStats.managedAvgResponseTime,
      topEventType: managedAssetIncidentStats.topEventType,
      top3BusinessSystems: managedAssetIncidentStats.top3BusinessSystems,
      businessSystemEventDistribution: managedAssetIncidentStats.businessSystemEventDistribution
    });
    logger(`托管资产事件数据已合并: events=${managedAssetIncidentStats.managedAssetEvents}, contained=${managedAssetIncidentStats.managedAssetContainedEvents}, disposed=${managedAssetIncidentStats.managedAssetDisposedEvents}, closeRate=${managedAssetIncidentStats.managedEventCloseRate}%, avgResponseTime=${managedAssetIncidentStats.managedAvgResponseTime}分钟`);
    logger(`最多类型事件: ${managedAssetIncidentStats.topEventType}`);
    logger(`TOP3业务系统: ${managedAssetIncidentStats.top3BusinessSystems}`);
    logger(`业务系统安全事件分布: ${JSON.stringify(managedAssetIncidentStats.businessSystemEventDistribution)}`);
  }

  // 从事件表独立计算安全事件类型分布（不依赖资产表）
  if (incidentFilePath) {
    try {
      const incidentTypeStats = await extractIncidentTypeStats(incidentFilePath);
      reportData.riskDetails.topEventType = incidentTypeStats.topEventType;
      reportData.riskDetails.eventTypeDistribution = incidentTypeStats.eventTypeDistribution;
      logger(`安全事件类型分布已计算: topEventType=${incidentTypeStats.topEventType}`);
    } catch (error) {
      logger(`提取安全事件类型分布失败（不影响主流程）: ${error.message}`);
    }
  }

  // 事件类型分布超过 5 项时才在末尾补充"其他"（取值 = 总事件数 - 已有类型事件数之和）
  const dist = reportData.riskDetails.eventTypeDistribution;
  if (Array.isArray(dist) && dist.length >= 5) {
    const sum = dist.reduce((acc, item) => acc + (item.value || 0), 0);
    const otherValue = (reportData.riskDetails.totalEvents || 0) - sum;
    dist.push({ name: '其他', value: otherValue >= 0 ? otherValue : 0 });
    logger(`事件类型分布已补充"其他": ${otherValue} 起`);
  }

  if (options['xdr-cookie-path']) {
    let cookieInfo, resolved;
    try {
      cookieInfo = await readXdrCookieInfo(options['xdr-cookie-path']);
      resolved = await resolveWorkingXdrBaseUrl(cookieInfo, options['xdr-base-url'], logger);
    } catch (error) {
      logger(`初始化 XDR 连接失败: ${error.message}`);
    }

    if (cookieInfo && resolved) {
      try {
        logger('正在查询设备分类数量...');
        const deviceCounts = await collectDeviceCategoryCounts(cookieInfo, resolved.xdrBaseUrl, logger);
        reportData.riskDetails = Object.assign(reportData.riskDetails || {}, deviceCounts);
        reportData.riskOverview = Object.assign(reportData.riskOverview || {}, {
          devices: deviceCounts.devices
        });
        logger(`设备总数: ${deviceCounts.devices}, AF: ${deviceCounts.af}, AES: ${deviceCounts.aes}, SIP: ${deviceCounts.sip}, STA: ${deviceCounts.sta}`);
      } catch (error) {
        logger(`获取设备分类数量失败: ${error.message}，将跳过设备分类统计`);
      }
    }
  }

  if (options['mssw-cookie-path']) {
    try {
      const loadedMsswCookie = msswCookie || await readMsswCookieInfo(options['mssw-cookie-path']);
      logger(`MSSW Cookie 已加载: ${loadedMsswCookie.resolvedPath}`);

      // 通过 MSSW 接口查询设备分类数量
      try {
        logger('正在通过 MSSW 查询设备分类数量...');
        const deviceCounts = await collectMsswDeviceCategoryCounts(
          loadedMsswCookie,
          options['mssw-base-url'],
          customerId,
          logger
        );
        reportData.riskDetails = Object.assign(reportData.riskDetails || {}, deviceCounts);
        reportData.riskOverview = Object.assign(reportData.riskOverview || {}, {
          devices: deviceCounts.devices
        });
        logger(`MSSW 设备总数: ${deviceCounts.devices}，深信服: ${deviceCounts.sangfor}（AF: ${deviceCounts.af}, AES: ${deviceCounts.aes}, SIP: ${deviceCounts.sip}, STA: ${deviceCounts.sta}, 其他: ${deviceCounts.other_sf}），第三方: ${deviceCounts.third}`);
      } catch (error) {
        logger(`通过 MSSW 获取设备分类数量失败: ${error.message}，将跳过设备分类统计`);
      }
    } catch (error) {
      logger(`加载 MSSW Cookie 失败: ${error.message}`);
    }
  }

  const reportDataJsonPath = options['output-json'] || path.join(outputDir, 'report-data.json');
  await writeJsonFile(reportDataJsonPath, reportData);
  logger(`数据已写入: ${reportDataJsonPath}`);

  const result = await renderReportToFile({
    templatePath,
    outputDir,
    reportData
  });
  logger(`HTML 已生成: ${result.html_path || result.filePath || ''}`);

  outputResult({
    ...result,
    xdrExports
  }, emitJson, logger, `完成: ${result.html_path || result.filePath || ''}`);
}

function printHelp() {
  console.log(`Usage:
  node health_report.js --customer "客户名" [--start YYYY-MM-DD --end YYYY-MM-DD] [options]

Options:
  --customer <name>              Customer name (用于自动查询 company_id)
  --start <YYYY-MM-DD>           Optional report start date
  --end <YYYY-MM-DD>             Optional report end date
  --xdr-cookie-path <path>       XDR cookie file path
  --mssw-cookie-path <path>      MSSW cookie file path (pre.soar.sangfor.com)
  --xdr-tables <names>           Optional XDR export tables, default asset,incident
  --download-dir <path>          Optional XDR download directory override
  --output-json <path>           Optional report data JSON path, default output/report-data.json
  --json                         Print full JSON result to stdout
  --timeout-ms <ms>              Optional wait timeout for XDR download
  --poll-interval-ms <ms>        Optional XDR event export polling interval
  --template <path>              HTML template path
  --output-dir <path>            Output directory
`);
}

async function exportConfiguredXdrTables(options) {
  if (!options.xdrCookiePath && !options.msswCookiePath) {
    return {};
  }

  const tables = parseXdrTables(options.xdrTables);
  logWith(options.logger, `准备导出表格: ${tables.join(', ')}`);
  const results = {};
  for (const table of tables) {
    if (table === 'asset') {
      // TODO: 资产表接口暂不通，恢复时取消下面注释即可
      // if (options.msswCookiePath) {
      //   logWith(options.logger, '开始处理表格: asset (MSSW)');
      //   results.asset = await exportMsswAssetList({
      //     msswCookiePath: options.msswCookiePath,
      //     msswBaseUrl: options.msswBaseUrl,
      //     downloadDir: options.downloadDir,
      //     customerId: options.customerId,
      //     logger: options.logger
      //   });
      // } else if (options.xdrCookiePath) {
      //   logWith(options.logger, '开始处理表格: asset (XDR)');
      //   results.asset = await exportXdrAssetList({
      //     xdrCookiePath: options.xdrCookiePath,
      //     downloadDir: options.downloadDir,
      //     timeoutMs: options.timeoutMs,
      //     logger: options.logger
      //   });
      // } else {
      //   logWith(options.logger, '跳过 asset 导出: 需要 --mssw-cookie-path 或 --xdr-cookie-path');
      // }
      logWith(options.logger, '跳过 asset 导出: 资产表接口暂不通');
      continue;
    }

    if (table === 'incident') {
      if (options.msswCookiePath) {
        logWith(options.logger, '开始处理表格: incident (MSSW)');
        results.incident = await exportMsswIncidentList({
          msswCookiePath: options.msswCookiePath,
          downloadDir: options.downloadDir,
          start: options.start,
          end: options.end,
          customerId: options.customerId,
          timeoutMs: options.timeoutMs,
          pollIntervalMs: options.pollIntervalMs,
          logger: options.logger
        });
      } else if (options.xdrCookiePath) {
        logWith(options.logger, '开始处理表格: incident (XDR)');
        results.incident = await exportXdrIncidentList({
          xdrCookiePath: options.xdrCookiePath,
          downloadDir: options.downloadDir,
          start: options.start,
          end: options.end,
          timeoutMs: options.timeoutMs,
          pollIntervalMs: options.pollIntervalMs,
          logger: options.logger
        });
      } else {
        logWith(options.logger, '跳过 incident 导出: 需要 --mssw-cookie-path 或 --xdr-cookie-path');
      }
      continue;
    }

    throw new Error(`Unsupported export table: ${table}`);
  }

  return results;
}

function createLogger(options = {}) {
  if (options.quiet === true || options.quiet === 'true') {
    return () => {};
  }

  return (message) => {
    console.error(message);
  };
}

function outputResult(result, emitJson, logger, summary) {
  if (emitJson) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (summary) {
    logger(summary);
  }
}

function logWith(logger, message) {
  if (typeof logger === 'function') {
    logger(message);
  }
}

async function summarizeExportedIncidentStatus(xdrExports, logger) {
  const incidentFilePath = xdrExports && xdrExports.incident ? xdrExports.incident.filePath : '';
  if (!incidentFilePath) {
    return null;
  }

  logWith(logger, `开始统计事件表处置状态: ${incidentFilePath}`);
  const stats = await summarizeIncidentStatus(incidentFilePath);
  if (Number(xdrExports.incident.totalEvents) > 0) {
    stats.totalEvents = Number(xdrExports.incident.totalEvents);
    stats.closeRate = stats.totalEvents ? Math.round((stats.closedEvents / stats.totalEvents) * 100) : 0;
  }
  logWith(logger, `事件表统计完成: 事件数 ${stats.totalEvents} 起，严重 ${stats.severeEvents} 起，高危 ${stats.highEvents} 起，涉及到的资产数 ${stats.uniqueAssetCount} 个，已闭环 ${stats.closedEvents} 起，已遏制 ${stats.containedEvents} 起，处置中 ${stats.processingEvents} 起，闭环率 ${stats.closeRate}%`);
  return stats;
}

async function summarizeExportedAssetStatus(xdrExports, logger) {
  const assetFilePath = xdrExports && xdrExports.asset ? xdrExports.asset.filePath : '';
  if (!assetFilePath) {
    return null;
  }

  logWith(logger, `开始统计资产表: ${assetFilePath}`);
  const stats = await summarizeAssetTable(assetFilePath);
  const getCount = (name) => {
    const item = Array.isArray(stats && stats.typeDistribution)
      ? stats.typeDistribution.find((entry) => entry && entry.name === name)
      : null;
    return item ? Number(item.value || 0) : 0;
  };
  logWith(
    logger,
    `资产表统计完成: 资产总数 ${stats.assetTotal} 个，服务器 ${getCount('服务器')} 个，终端 ${getCount('终端')} 个，暴露资产 ${Number(stats.internetExposureTotal || 0)} 个`
  );
  return stats;
}

function parseXdrTables(value) {
  const raw = value || 'asset,incident';
  return String(raw)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

async function writeJsonFile(filePath, data) {
  const resolvedPath = path.resolve(filePath);
  await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
  await fs.writeFile(resolvedPath, JSON.stringify(data, null, 2), 'utf8');
}

function formatLocalDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

async function resolveEffectiveTimeRange({ options, customerId, msswCookie, reportGeneratedAt, logger }) {
  const hasStart = options.start !== undefined && options.start !== null && String(options.start).trim() !== '';
  const hasEnd = options.end !== undefined && options.end !== null && String(options.end).trim() !== '';

  if (hasStart !== hasEnd) {
    throw new Error('时间参数必须同时传入 --start 和 --end，或两者都不传');
  }

  if (hasStart && hasEnd) {
    validateDateRange(options.start, options.end);
    return {
      start: String(options.start).trim(),
      end: String(options.end).trim(),
      source: 'cli'
    };
  }

  if (!options['mssw-cookie-path']) {
    throw new Error('未传 --start/--end 时，需要提供 --mssw-cookie-path 以自动推导默认时间范围');
  }

  const resolvedCookie = msswCookie || await readMsswCookieInfo(options['mssw-cookie-path']);
  const resolvedCustomerId = String(customerId || options['customer-id'] || '').trim();
  if (!resolvedCustomerId) {
    throw new Error('未传时间时需要先解析出 company_id，请检查 --customer 是否能匹配，或手动传 --customer-id');
  }

  const timeRange = await fetchDefaultProjectTimeRange(
    resolvedCookie,
    options['mssw-base-url'],
    resolvedCustomerId,
    reportGeneratedAt
  );
  validateDateRange(timeRange.start, timeRange.end);
  logger(`已自动推导时间范围: ${timeRange.start} ~ ${timeRange.end}`);
  return {
    ...timeRange,
    source: 'mssw-project-service'
  };
}

function validateDateRange(start, end) {
  const begin = parseLocalDate(start, false);
  const finish = parseLocalDate(end, true);

  if (!begin || !finish) {
    throw new Error('时间参数无效，请使用 YYYY-MM-DD');
  }
  if (begin > finish) {
    throw new Error('时间范围无效: --start 不能晚于 --end');
  }
}

async function mergeJsonFile(filePath, patch) {
  let existing = {};
  try {
    existing = JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }

  const merged = deepMerge(existing, patch);
  delete merged.report;
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(merged, null, 2), 'utf8');
  return merged;
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

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
