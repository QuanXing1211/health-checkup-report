'use strict';

const assert = require('assert');
const path = require('path');
const { calculateRiskAssetCount } = require('../src/risk_asset_count');

async function main() {
  const baseDir = path.join(__dirname, '..', 'output', 'mock-business-system-ranking');
  const result = await calculateRiskAssetCount({
    eventPath: path.join(baseDir, '测试客户_事件跟踪表_mock.xlsx'),
    weakPasswordPath: path.join(baseDir, '弱口令清单_mock.xlsx'),
    vulnerabilityPath: path.join(baseDir, '漏洞清单_mock.xlsx'),
    exposurePath: path.join(baseDir, '暴露面清单_mock.xlsx'),
    assetPath: path.join(baseDir, 'Asset_Export__mock.xlsx')
  });

  assert.strictEqual(result.affectedAssetCount, 6);
  assert.strictEqual(result.riskBusinessCount, 3);
  assert.strictEqual(result.top1BusinessSystem, '支付网关');
  assert.deepStrictEqual(result.riskAssetTop5, [
    {
      ip: '10.10.1.11',
      managedStatus: '已托管',
      businessSystem: '支付网关',
      riskCount: 2
    },
    {
      ip: '10.10.1.10',
      managedStatus: '已托管',
      businessSystem: '支付网关',
      riskCount: 1
    },
    {
      ip: '10.10.2.20',
      managedStatus: '已托管',
      businessSystem: '电商平台',
      riskCount: 3
    },
    {
      ip: '10.10.2.21',
      managedStatus: '未托管',
      businessSystem: '电商平台',
      riskCount: 2
    },
    {
      ip: '10.10.3.31',
      managedStatus: '未托管',
      businessSystem: 'OA系统',
      riskCount: 2
    }
  ]);

  console.log('risk_asset_count.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
