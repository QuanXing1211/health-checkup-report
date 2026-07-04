'use strict';

const { execFile } = require('child_process');
const path = require('path');
const { encodePath } = require('./path_helper');

async function calculateRiskAssetCount(options = {}) {
  const scriptPath = path.join(__dirname, '..', 'scripts', 'risk_asset_count.py');
  const tmpDir = path.join(path.resolve(__dirname, '..'), 'tmp', 'exports');
  const args = [
    encodePath(options.eventPath || path.join(tmpDir, '安全事件表.xlsx')),
    encodePath(options.weakPasswordPath || path.join(tmpDir, '弱口令清单_mock.xlsx')),
    encodePath(options.vulnerabilityPath || path.join(tmpDir, '漏洞清单_mock.xlsx')),
    encodePath(options.exposurePath || path.join(tmpDir, '暴露面清单_mock.xlsx')),
    encodePath(options.assetPath || path.join(tmpDir, '资产清单.xlsx'))
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
  calculateRiskAssetCount
};
