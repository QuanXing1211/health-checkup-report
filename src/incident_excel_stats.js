'use strict';

const { execFile } = require('child_process');
const path = require('path');

async function summarizeIncidentStatus(excelPath) {
  if (!excelPath) {
    return null;
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'incident_status_stats.py');
  const stdout = await execPython(scriptPath, excelPath);
  const parsed = JSON.parse(stdout);

  return {
    totalEvents: Number(parsed.totalEvents || 0),
    severeEvents: Number(parsed.severeEvents || 0),
    highEvents: Number(parsed.highEvents || 0),
    closedEvents: Number(parsed.closedEvents || 0),
    containedEvents: Number(parsed.containedEvents || 0),
    processingEvents: Number(parsed.processingEvents || 0),
    closeRate: Number(parsed.closeRate || 0),
    uniqueAssetCount: Number(parsed.uniqueAssetCount || 0)
  };
}

function execPythonWithArgs(scriptPath, args, label) {
  return new Promise((resolve, reject) => {
    execFile('python', [scriptPath, ...args], {
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 1024 * 1024,
      env: Object.assign({}, process.env, { PYTHONIOENCODING: 'utf-8' })
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${label}: ${stderr || error.message}`));
        return;
      }

      resolve(stdout.trim());
    });
  });
}

function execPython(scriptPath, excelPath) {
  return execPythonWithArgs(scriptPath, [excelPath], '事件表统计失败');
}

async function removeIncidentRows(excelPath, incidentIds) {
  if (!excelPath || !Array.isArray(incidentIds) || !incidentIds.length) {
    return { removed: 0, message: '没有需要移除的行' };
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'remove_incident_rows.py');
  const idsJson = JSON.stringify(incidentIds);
  // 在 Windows 上传递长 JSON 参数时需要用双引号包裹
  const stdout = await execPythonWithArgs(scriptPath, [excelPath, idsJson], '移除误报事件失败');
  const parsed = JSON.parse(stdout);

  return {
    removed: Number(parsed.removed || 0),
    totalBefore: Number(parsed.total_before || 0),
    totalAfter: Number(parsed.total_after || 0),
    message: parsed.message || ''
  };
}

async function parseIncidentGptStats(excelPath) {
  if (!excelPath) {
    return null;
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'incident_gpt_stats.py');
  const stdout = await execPythonWithArgs(scriptPath, [excelPath], '事件表 GPT 研判结论读取失败');
  const parsed = JSON.parse(stdout);

  return {
    hostCompromiseIds: Array.isArray(parsed.hostCompromiseIds) ? parsed.hostCompromiseIds : [],
    virusTrojanIds: Array.isArray(parsed.virusTrojanIds) ? parsed.virusTrojanIds : [],
    gptSubResultMap: parsed.gptSubResultMap && typeof parsed.gptSubResultMap === 'object' ? parsed.gptSubResultMap : {}
  };
}

async function extractIncidentAssetInfo(incidentExcelPath, assetExcelPath, confirmedIds, virusIds) {
  if (!incidentExcelPath || !Array.isArray(confirmedIds) || !Array.isArray(virusIds)) {
    return {
      virusAttackAsset: '',
      nonAesCoveredAssets: [],
      unlabeledAssets: []
    };
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'extract_incident_asset_info.py');
  const args = [
    incidentExcelPath,
    assetExcelPath || '',
    JSON.stringify(confirmedIds),
    JSON.stringify(virusIds)
  ];
  const stdout = await execPythonWithArgs(scriptPath, args, '提取事件资产信息失败');
  return JSON.parse(stdout);
}

async function summarizeManagedAssetIncidents(assetExcelPath, incidentExcelPath) {
  if (!assetExcelPath || !incidentExcelPath) {
    return {
      managedAssetEvents: 0,
      managedAssetContainedEvents: 0,
      managedAssetDisposedEvents: 0,
      managedEventCloseRate: 0,
      managedAssetCount: 0,
      topEventType: '',
      top3BusinessSystems: []
    };
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'managed_asset_incident_stats.py');
  const stdout = await execPythonWithArgs(scriptPath, [assetExcelPath, incidentExcelPath], '托管资产事件统计失败');
  const parsed = JSON.parse(stdout);

  return {
    managedAssetEvents: Number(parsed.managedAssetEvents || 0),
    managedAssetContainedEvents: Number(parsed.managedAssetContainedEvents || 0),
    managedAssetDisposedEvents: Number(parsed.managedAssetDisposedEvents || 0),
    managedEventCloseRate: Number(parsed.managedEventCloseRate || 0),
    managedAssetCount: Number(parsed.managedAssetCount || 0),
    topEventType: String(parsed.topEventType || ''),
    top3BusinessSystems: Array.isArray(parsed.top3BusinessSystems) ? parsed.top3BusinessSystems : []
  };
}

async function extractExploitStats(incidentExcelPath) {
  if (!incidentExcelPath) {
    return {
      total: 0,
      highRiskAsset: '',
      attackSuccessCount: 0
    };
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'extract_exploit_stats.py');
  const stdout = await execPythonWithArgs(scriptPath, [incidentExcelPath], '提取漏洞利用统计失败');
  const parsed = JSON.parse(stdout);

  if (parsed.error) {
    throw new Error(parsed.error);
  }

  return {
    total: Number(parsed.total || 0),
    highRiskAsset: String(parsed.highRiskAsset || ''),
    attackSuccessCount: Number(parsed.attackSuccessCount || 0)
  };
}

async function extractIncidentTypeStats(incidentExcelPath) {
  if (!incidentExcelPath) {
    return {
      topEventType: '',
      eventTypeDistribution: []
    };
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'incident_type_stats.py');
  const stdout = await execPythonWithArgs(scriptPath, [incidentExcelPath], '提取事件类型分布失败');
  const parsed = JSON.parse(stdout);

  if (parsed.error) {
    throw new Error(parsed.error);
  }

  return {
    topEventType: String(parsed.topEventType || ''),
    eventTypeDistribution: Array.isArray(parsed.eventTypeDistribution) ? parsed.eventTypeDistribution : []
  };
}

module.exports = {
  summarizeIncidentStatus,
  removeIncidentRows,
  parseIncidentGptStats,
  extractIncidentAssetInfo,
  summarizeManagedAssetIncidents,
  extractExploitStats,
  extractIncidentTypeStats
};
