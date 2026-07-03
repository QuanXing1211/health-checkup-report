'use strict';

const { execFile } = require('child_process');
const path = require('path');

function defaultTmpExportPath(filename) {
  return path.join(path.resolve(__dirname, '..'), 'tmp', 'exports', filename);
}

async function calculateRiskAssetCount(options = {}) {
  const scriptPath = path.join(__dirname, '..', 'scripts', 'risk_asset_count.py');
  const args = [
    options.eventPath || defaultTmpExportPath('事件表.xlsx'),
    options.weakPasswordPath
      || 'C:\\Users\\xupai\\.openclaw\\workspace\\skills\\health-checkup-report\\output\\mock-business-system-ranking\\弱口令清单_mock.xlsx',
    options.vulnerabilityPath
      || 'C:\\Users\\xupai\\.openclaw\\workspace\\skills\\health-checkup-report\\output\\mock-business-system-ranking\\漏洞清单_mock.xlsx',
    options.exposurePath
      || 'C:\\Users\\xupai\\.openclaw\\workspace\\skills\\health-checkup-report\\output\\mock-business-system-ranking\\暴露面清单_mock.xlsx',
    options.assetPath
      || 'C:\\Users\\xupai\\.openclaw\\workspace\\skills\\health-checkup-report\\output\\mock-business-system-ranking\\Asset_Export__mock.xlsx'
  ];

  return new Promise((resolve, reject) => {
    execFile('python', [scriptPath, ...args], {
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 1024 * 1024,
      env: Object.assign({}, process.env, { PYTHONIOENCODING: 'utf-8' })
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`计算风险资产数失败: ${stderr || error.message}`));
        return;
      }

      try {
        resolve(JSON.parse(stdout.trim()));
      } catch (parseError) {
        reject(new Error(`解析风险资产数结果失败: ${parseError.message}`));
      }
    });
  });
}

module.exports = {
  calculateRiskAssetCount,
  defaultTmpExportPath
};
