#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs/promises');
const { parseArgs, requireArgs } = require('./src/args');
const { collectReportData } = require('./src/data_client');
const { summarizeAssetTable } = require('./src/asset_excel_stats');
const { summarizeIncidentStatus, extractExploitStats, extractVulnExploitExamples, summarizeManagedAssetIncidents, extractIncidentTypeStats, summarizeTopRiskAssetDetails } = require('./src/incident_excel_stats');
const { exportMsswIncidentList, exportMsswAssetList, exportMsswDeviceList, findMsswCustomerIdByName, fetchDefaultProjectTimeRange, readXdrCookieInfo, readMsswCookieInfo, collectMsswDeviceCategoryCounts, parseLocalDate } = require('./src/mssw_client');
const { collectPreventionTableExports, getTmpExportDir } = require('./src/prevention_exports');
const { calculatePreventionData } = require('./src/prevention_data');
const { rankBusinessSystems } = require('./src/business_system_ranking');
const { calculateRiskAssetCount } = require('./src/risk_asset_count');
const { runBranch1ReportStage, mergeBranch1ReportPatch, exportBranch1Word, getDefaultDeviceJsonPath } = require('./src/branch1_adapter');
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

  if (command && command !== 'generate') {
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

    throw new Error(`Unsupported command: ${command}`);
  }

  requireArgs(options, ['customer', 'mssw-cookie-path', 'xdr-cookie-path']);

  await readXdrCookieInfo(options['xdr-cookie-path']);

  await exportMsswDeviceList({
    msswCookiePath: options['mssw-cookie-path'],
    msswBaseUrl: options['mssw-base-url'],
    customerId,
    logger
  });

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
  let branch1Result = null;
  let preventionTables = null;

  logger(`开始生成: ${options.customer} ${effectiveTimeRange.start} ~ ${effectiveTimeRange.end}`);

  const tableExports = await exportConfiguredXdrTables({
    xdrCookiePath: options['xdr-cookie-path'],
    msswCookiePath: options['mssw-cookie-path'],
    downloadDir: options['download-dir'],
    start: effectiveTimeRange.start,
    end: effectiveTimeRange.end,
    xdrTables: options['xdr-tables'],
    customerId,
    assetIds: [],
    timeoutMs: options['timeout-ms'] ? Number(options['timeout-ms']) : undefined,
    pollIntervalMs: options['poll-interval-ms'] ? Number(options['poll-interval-ms']) : undefined,
    logger
  });
  if (Object.keys(tableExports).length) {
    logger(`MSSW 导表完成: ${Object.keys(tableExports).join(', ')}`);
  } else {
    logger('跳过 MSSW 导表');
  }

  const assetStatusStats = await summarizeExportedAssetStatus(tableExports, logger);
  const incidentStatusStats = await summarizeExportedIncidentStatus(tableExports, logger);

  // 从事件表提取漏洞利用统计（不阻断主流程）
  let exploitStats = null;
  let vulnExploitExamples = [];
  const incidentFilePath = await resolveIncidentFilePath(options, tableExports);
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
  const resolvedAssetFilePath = await resolveAssetFilePath({
    options,
    xdrExports,
    logger
  });
  const assetFilePath = resolvedAssetFilePath;
  let managedAssetIncidentStats = null;
  if (assetFilePath && incidentFilePath) {
    try {
      managedAssetIncidentStats = await summarizeManagedAssetIncidents(assetFilePath, incidentFilePath);
      logger(`托管资产事件统计: 共 ${managedAssetIncidentStats.managedAssetEvents} 起事件, 涉及 ${managedAssetIncidentStats.managedAssetCount} 个托管资产, 已遏制 ${managedAssetIncidentStats.managedAssetContainedEvents} 起, 处置完成 ${managedAssetIncidentStats.managedAssetDisposedEvents} 起, 闭环率 ${managedAssetIncidentStats.managedEventCloseRate}%`);
    } catch (error) {
      logger(`托管资产事件统计失败（不影响主流程）: ${error.message}`);
    }
  }

  let reportData = await collectReportData({
    customer: options.customer,
    customerId,
    start: effectiveTimeRange.start,
    end: effectiveTimeRange.end,
    xdrCookiePath: options['xdr-cookie-path'],
    msswCookiePath: options['mssw-cookie-path'],
    msswBaseUrl: options['mssw-base-url'],
    assetStatusStats,
    incidentStatusStats,
    incidentFilePath: incidentFilePath || undefined,
    assetFilePath: resolvedAssetFilePath || undefined,
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

  const preventionEnabled = await shouldRunPreventionStage(options, xdrExports);
  if (preventionEnabled) {
    if (!incidentFilePath) {
      throw new Error('威胁预防数据计算失败: 缺少事件表，请检查本次事件表导出结果');
    }
    if (!resolvedAssetFilePath) {
      throw new Error('威胁预防数据计算失败: 缺少资产表，请先准备 tmp/exports 中可用的资产表');
    }

    logger('开始准备威胁预防所需表格...');
    preventionTables = await collectPreventionTableExports({
      customer: options.customer,
      start: effectiveTimeRange.start,
      end: effectiveTimeRange.end,
      soarCookiePath: options['cookie-path'],
      msswCookiePath: options['mssw-cookie-path'],
      outputDir: getTmpExportDir(),
      logger
    });
    logger(`威胁预防表格已就绪: weakpwd=${preventionTables.weakpwd.filePath}, vuln=${preventionTables.vuln.filePath}, exposure=${preventionTables.exposure.filePath}`);

    const preventionData = await calculatePreventionData({
      assetPath: resolvedAssetFilePath,
      incidentPath: incidentFilePath,
      weakpwdPath: preventionTables.weakpwd.filePath,
      vulnPath: preventionTables.vuln.filePath,
      exposurePath: preventionTables.exposure.filePath
    });
    Object.assign(reportData, preventionData);
    logger('威胁预防 JSON 已合并到 report-data');

    branch1Result = await runBranch1ReportStage({
      customer: options.customer,
      companyId: customerId,
      start: effectiveTimeRange.start,
      end: effectiveTimeRange.end,
      assetPath: resolvedAssetFilePath,
      incidentPath: incidentFilePath,
      weakpwdPath: preventionTables.weakpwd.filePath,
      vulnPath: preventionTables.vuln.filePath,
      exposurePath: preventionTables.exposure.filePath,
      devicePath: getDefaultDeviceJsonPath(),
      soarCookiePath: options['cookie-path'],
      outputDir: path.join(root, 'tmp', 'branch1')
    });
    reportData = mergeBranch1ReportPatch(reportData, branch1Result.reportPatch);
    logger('分支1 JSON 已合并到 report-data');

    const archivedFiles = await archiveRiskListFiles({
      root,
      incidentPath: incidentFilePath,
      assetPath: resolvedAssetFilePath,
      exposurePath: preventionTables.exposure.filePath,
      weakpwdPath: preventionTables.weakpwd.filePath,
      vulnPath: preventionTables.vuln.filePath,
      logger
    });
    if (xdrExports.incident) {
      xdrExports.incident.filePath = archivedFiles.incidentPath;
    }
    if (xdrExports.asset) {
      xdrExports.asset.filePath = archivedFiles.assetPath;
    }
    preventionTables.exposure.filePath = archivedFiles.exposurePath;
    preventionTables.weakpwd.filePath = archivedFiles.weakpwdPath;
    preventionTables.vuln.filePath = archivedFiles.vulnPath;

    const businessSystemRanking = await rankBusinessSystems({
      eventsPath: archivedFiles.incidentPath,
      weakpwdPath: archivedFiles.weakpwdPath,
      vulnPath: archivedFiles.vulnPath,
      exposurePath: archivedFiles.exposurePath,
      assetPath: archivedFiles.assetPath,
      logger
    });
    reportData.riskOverview = Object.assign({}, reportData.riskOverview || {}, {
      coreBusinessSystemRanking: Array.isArray(businessSystemRanking.coreBusinessSystemRanking)
        ? businessSystemRanking.coreBusinessSystemRanking
        : [],
      maxRiskSystem: businessSystemRanking.maxRiskSystem || null,
      securityRiskTotal: Number(businessSystemRanking.securityRiskTotal || 0),
      highAndAboveRiskCount: Number(businessSystemRanking.highAndAboveRiskCount || 0)
    });
    logger('业务系统排序数据已在 5 个风险清单落盘后合并到 riskOverview');

    const riskAssetStats = await calculateRiskAssetCount({
      eventPath: archivedFiles.incidentPath,
      assetPath: archivedFiles.assetPath,
      weakPasswordPath: archivedFiles.weakpwdPath,
      vulnerabilityPath: archivedFiles.vulnPath,
      exposurePath: archivedFiles.exposurePath
    });
    let topRiskAssets = Array.isArray(riskAssetStats.riskAssetTop5)
      ? riskAssetStats.riskAssetTop5
      : [];
    if (topRiskAssets.length) {
      try {
        const incidentGptStats = reportData.riskOverview && reportData.riskOverview.incidentGptStats
          ? reportData.riskOverview.incidentGptStats
          : {};
        const topRiskAssetDetails = await summarizeTopRiskAssetDetails({
          incidentExcelPath: archivedFiles.incidentPath,
          assetExcelPath: archivedFiles.assetPath,
          weakPasswordExcelPath: archivedFiles.weakpwdPath,
          vulnerabilityExcelPath: archivedFiles.vulnPath,
          exposureExcelPath: archivedFiles.exposurePath,
          topAssets: topRiskAssets,
          c2Ids: incidentGptStats.hostCompromise && Array.isArray(incidentGptStats.hostCompromise.confirmedIncidentIds)
            ? incidentGptStats.hostCompromise.confirmedIncidentIds
            : [],
          virusIds: incidentGptStats.virusTrojan && Array.isArray(incidentGptStats.virusTrojan.confirmedIncidentIds)
            ? incidentGptStats.virusTrojan.confirmedIncidentIds
            : [],
          exploitIds: exploitStats && Array.isArray(exploitStats.incidentIds) ? exploitStats.incidentIds : []
        });
        const detailMap = topRiskAssetDetails.assets || {};
        topRiskAssets = topRiskAssets.map((asset) => {
          const detail = detailMap[asset.ip] || null;
          return detail
            ? {
              ...asset,
              riskDetails: detail,
              detailLines: Array.isArray(detail.detailLines) ? detail.detailLines : []
            }
            : asset;
        });
        logger('风险资产 TOP5 风险详情已按事件表和资产表补齐');
      } catch (error) {
        logger(`统计风险资产 TOP5 风险详情失败（不影响主流程）: ${error.message}`);
      }
    }

    reportData.riskOverview = Object.assign({}, reportData.riskOverview || {}, {
      riskAssetCount: Number(riskAssetStats.affectedAssetCount || 0),
      riskBusinessCount: Number(riskAssetStats.riskBusinessCount || 0),
      topRiskAssets
    });
    logger(`风险总览统计已更新: 风险业务数 ${reportData.riskOverview.riskBusinessCount} 个，风险资产数 ${reportData.riskOverview.riskAssetCount} 个（按风险清单五表综合统计）`);
  } else {
    logger('跳过威胁预防数据准备: 未提供相关运行上下文');
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

  let wordExport = null;
  if (branch1Result) {
    wordExport = await exportBranch1Word({
      htmlPath: result.html_path || result.filePath || '',
      wordPath: replaceExtension(result.html_path || result.filePath || '', '.docx')
    });
    logger(`Word 已生成: ${wordExport.wordPath}`);
  }

  outputResult({
    ...result,
    xdrExports,
    word_path: wordExport ? wordExport.wordPath : null,
    branch1Artifacts: branch1Result
      ? {
        ...branch1Result.artifacts,
        wordPath: wordExport ? wordExport.wordPath : null
      }
      : null
  }, emitJson, logger, `完成: ${result.html_path || result.filePath || ''}`);
}

function printHelp() {
  console.log(`Usage:
  node health_report.js --customer "客户名" [--start YYYY-MM-DD --end YYYY-MM-DD] [options]

Options:
  --customer <name>              Customer name (用于自动查询 company_id)
  --mssw-cookie-path <path>      Required for generate and MSSW data flow
  --xdr-cookie-path <path>       Required for generate, currently only validated/pass-through
  --start <YYYY-MM-DD>           Optional report start date
  --end <YYYY-MM-DD>             Optional report end date
  --cookie-path <path>           SOAR cookie file path (soar.sangfor.com.cn)
  --xdr-tables <names>           Optional MSSW export tables, default asset,incident
  --download-dir <path>          Optional export directory override
  --output-json <path>           Optional report data JSON path, default output/report-data.json
  --json                         Print full JSON result to stdout
  --timeout-ms <ms>              Optional wait timeout for MSSW export download
  --poll-interval-ms <ms>        Optional MSSW event export polling interval
  --template <path>              HTML template path
  --output-dir <path>            Output directory
`);
}

async function exportConfiguredXdrTables(options) {
  if (!options.msswCookiePath) {
    return {};
  }

  const tables = parseXdrTables(options.xdrTables);
  logWith(options.logger, `准备导出表格: ${tables.join(', ')}`);
  const results = {};
  for (const table of tables) {
    if (table === 'asset') {
      logWith(options.logger, '开始处理表格: asset (MSSW)');
      results.asset = await exportMsswAssetList({
        msswCookiePath: options.msswCookiePath,
        msswBaseUrl: options.msswBaseUrl,
        downloadDir: options.downloadDir,
        customerId: options.customerId,
        assetIds: options.assetIds || [],
        logger: options.logger
      });
      continue;
    }

    if (table === 'incident') {
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

async function archiveRiskListFiles(options) {
  const riskListDir = path.join(options.root, '安全体检报告', '风险清单');
  await fs.mkdir(riskListDir, { recursive: true });

  const mappings = [
    ['incidentPath', '安全事件表.xlsx'],
    ['assetPath', '资产清单.xlsx'],
    ['exposurePath', '暴露面清单.xlsx'],
    ['weakpwdPath', '弱口令清单.xlsx'],
    ['vulnPath', '漏洞清单.xlsx']
  ];
  const archived = {};

  for (const [key, filename] of mappings) {
    const sourcePath = options[key];
    if (!sourcePath) {
      throw new Error(`归档风险清单失败: 缺少 ${key}`);
    }

    const targetPath = path.join(riskListDir, filename);
    archived[key] = await moveOrReplaceFile(sourcePath, targetPath);
    logWith(options.logger, `风险清单已归档: ${archived[key]}`);
  }

  return archived;
}

async function moveOrReplaceFile(sourcePath, targetPath) {
  const resolvedSource = path.resolve(sourcePath);
  const resolvedTarget = path.resolve(targetPath);
  if (samePath(resolvedSource, resolvedTarget)) {
    return resolvedTarget;
  }

  await fs.mkdir(path.dirname(resolvedTarget), { recursive: true });
  await fs.rm(resolvedTarget, { force: true });

  try {
    await fs.rename(resolvedSource, resolvedTarget);
  } catch (error) {
    if (!isCrossDeviceError(error)) {
      throw error;
    }
    await fs.copyFile(resolvedSource, resolvedTarget);
    await fs.rm(resolvedSource, { force: true });
  }

  return resolvedTarget;
}

function samePath(left, right) {
  return path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase();
}

function isCrossDeviceError(error) {
  return Boolean(error) && (error.code === 'EXDEV' || error.code === 'EPERM');
}

function formatLocalDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function replaceExtension(filePath, extension) {
  const parsed = path.parse(filePath);
  return path.join(parsed.dir, `${parsed.name}${extension}`);
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

async function shouldRunPreventionStage(options, xdrExports) {
  return Boolean(
    options['cookie-path']
    || (options['mssw-cookie-path'] && await resolveIncidentFilePath(options, xdrExports))
  );
}

async function resolveIncidentFilePath(options, xdrExports) {
  const exportedPath = xdrExports && xdrExports.incident ? xdrExports.incident.filePath : '';
  if (exportedPath) {
    return exportedPath;
  }

  return findLatestWorkbook(getTmpExportDir(), /incident|事件/i);
}

async function resolveAssetFilePath({ options, xdrExports, logger }) {
  const exportedPath = xdrExports && xdrExports.asset ? xdrExports.asset.filePath : '';
  if (exportedPath) {
    return exportedPath;
  }

  const discovered = await findLatestWorkbook(getTmpExportDir(), /asset|资产/i);
  if (discovered) {
    logger(`已从 tmp/exports 自动使用资产表: ${discovered}`);
    return discovered;
  }

  return '';
}

async function findLatestWorkbook(directory, pattern) {
  try {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    const candidates = entries
      .filter((entry) => entry.isFile() && /\.xlsx$/i.test(entry.name))
      .filter((entry) => pattern.test(entry.name))
      .map((entry) => path.join(directory, entry.name));

    if (!candidates.length) {
      return '';
    }

    const withStat = await Promise.all(candidates.map(async (filePath) => ({
      filePath,
      stat: await fs.stat(filePath)
    })));
    withStat.sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs);
    return withStat[0].filePath;
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return '';
    }
    throw error;
  }
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
