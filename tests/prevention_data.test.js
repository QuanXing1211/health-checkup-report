'use strict';

const assert = require('assert');
const path = require('path');
const { calculatePreventionData } = require('../src/prevention_data');

async function main() {
  const baseDir = path.join(__dirname, '..', 'output', 'mock-business-system-ranking');
  const result = await calculatePreventionData({
    assetPath: path.join(baseDir, 'Asset_Export__mock.xlsx'),
    incidentPath: path.join(baseDir, '测试客户_事件跟踪表_mock.xlsx'),
    weakpwdPath: path.join(baseDir, '弱口令清单_mock.xlsx'),
    vulnPath: path.join(baseDir, '漏洞清单_mock.xlsx'),
    exposurePath: path.join(baseDir, '暴露面清单_mock.xlsx')
  });

  assert(result.summary && result.summary.internet && result.summary.intranet);
  assert(result.key_risks && result.key_risks.vuln && result.key_risks.weak_pwd && result.key_risks.exposure);
  assert(result.risk_detail && result.risk_detail.internet && result.risk_detail.intranet);
  assert(result.internet && result.internet.exposure && result.internet.vuln && result.internet.weak_pwd);
  assert(result.intranet && result.intranet.vuln && result.intranet.weak_pwd);
  assert.strictEqual(typeof result.internet.exposure.risk_asset_count, 'number');
  assert(Array.isArray(result.internet.exposure.dist));
  assert(Array.isArray(result.intranet.vuln.biz_top_rows));

  console.log('prevention_data.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
