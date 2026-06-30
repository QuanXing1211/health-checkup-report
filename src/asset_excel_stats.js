'use strict';

const { execFile } = require('child_process');
const path = require('path');

async function summarizeAssetTable(excelPath) {
  if (!excelPath) {
    return null;
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'asset_table_stats.py');
  const stdout = await execPython(scriptPath, excelPath);
  const parsed = JSON.parse(stdout);
  const assetTotal = Number(parsed.assetTotal || 0);

  return {
    assetTotal,
    manage_asset: assetTotal,
    typeDistribution: toNameValueList(parsed.typeDistribution, [
      ['服务器', 'server'],
      ['终端', 'terminal'],
      ['其他', 'other']
    ]),
    protectionDistribution: toNameValueList(parsed.protectionDistribution, [
      ['在线', '在线'],
      ['离线', '离线'],
      ['已禁用', '已禁用'],
      ['已降级', '已降级'],
      ['未安装', '未安装']
    ]),
    internetExposureTotal: Number(parsed.internetExposureTotal || 0),
    internetExposureDistribution: toNameValueList(parsed.internetExposureDistribution, [
      ['服务器', 'server'],
      ['终端', 'terminal'],
      ['其他', 'other']
    ])
  };
}

function toNameValueList(source, items) {
  const data = source && typeof source === 'object' ? source : {};
  return items.map(([name, key]) => ({
    name,
    value: Number(data[key] || 0)
  }));
}

function execPython(scriptPath, excelPath) {
  return new Promise((resolve, reject) => {
    execFile('python', [scriptPath, excelPath], {
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 1024 * 1024
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`资产表统计失败: ${stderr || error.message}`));
        return;
      }

      resolve(stdout.trim());
    });
  });
}

module.exports = {
  summarizeAssetTable
};
