'use strict';

const { execFile } = require('child_process');
const path = require('path');
const { encodePath } = require('./path_helper');

/**
 * 调用 Python 脚本执行业务系统风险排名
 *
 * @param {object} [options]
 * @param {string} [options.eventsPath]   安全事件表路径
 * @param {string} [options.weakpwdPath]  弱口令清单路径
 * @param {string} [options.vulnPath]     漏洞清单路径
 * @param {string} [options.exposurePath] 暴露面清单路径
 * @param {string} [options.assetPath]    资产清单路径
 * @param {function} [options.logger]     日志函数
 * @returns {Promise<{top5: Array, fullRanking: Array, summary: object}>}
 */
async function rankBusinessSystems(options = {}) {
  const scriptPath = path.join(__dirname, '..', 'scripts', 'business_system_ranking.py');
  const logger = options.logger || (() => {});

  const args = [];
  if (options.eventsPath && options.weakpwdPath && options.vulnPath && options.exposurePath && options.assetPath) {
    args.push(
      encodePath(options.eventsPath),
      encodePath(options.weakpwdPath),
      encodePath(options.vulnPath),
      encodePath(options.exposurePath),
      encodePath(options.assetPath)
    );
  }

  logger('[业务系统排名] 开始...');
  const stdout = await execPython(scriptPath, args, logger);
  const parsed = JSON.parse(stdout);
  const systemCount = Array.isArray(parsed.coreBusinessSystemRanking) ? parsed.coreBusinessSystemRanking.length : 0;
  const totalRisks = Number(parsed.securityRiskTotal || 0);
  logger(`[业务系统排名] 完成: ${systemCount} 个系统, ${totalRisks} 条风险`);
  return parsed;
}

function execPython(scriptPath, args, logger) {
  return new Promise((resolve, reject) => {
    const child = execFile('python', [scriptPath, ...args], {
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 1024 * 1024
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`业务系统排名失败: ${error.message}`));
        return;
      }
      resolve(stdout.trim());
    });

    if (child.stderr) {
      child.stderr.on('data', (data) => {
        const lines = String(data).trim();
        if (lines) {
          lines.split('\n').forEach((line) => logger(line));
        }
      });
    }
  });
}

module.exports = {
  rankBusinessSystems
};
