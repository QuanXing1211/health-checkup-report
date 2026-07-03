'use strict';

const assert = require('assert');
const path = require('path');
const { rankBusinessSystems } = require('../src/business_system_ranking');

async function main() {
  const baseDir = path.join(__dirname, '..', 'output', 'mock-business-system-ranking');
  const result = await rankBusinessSystems({
    eventsPath: path.join(baseDir, '测试客户_事件跟踪表_mock.xlsx'),
    weakpwdPath: path.join(baseDir, '弱口令清单_mock.xlsx'),
    vulnPath: path.join(baseDir, '漏洞清单_mock.xlsx'),
    exposurePath: path.join(baseDir, '暴露面清单_mock.xlsx'),
    assetPath: path.join(baseDir, 'Asset_Export__mock.xlsx'),
    logger: () => {}
  });

  assert(Array.isArray(result.coreBusinessSystemRanking));
  assert.strictEqual(typeof result.securityRiskTotal, 'number');
  assert.strictEqual(typeof result.highAndAboveRiskCount, 'number');
  assert(
    result.maxRiskSystem === null
    || typeof result.maxRiskSystem === 'string'
  );

  console.log('business_system_ranking.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
