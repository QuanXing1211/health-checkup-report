'use strict';

const assert = require('assert');
const path = require('path');

async function main() {
  const xdrClientPath = path.resolve(__dirname, '..', 'src', 'xdr_asset_client.js');
  require.cache[xdrClientPath] = {
    id: xdrClientPath,
    filename: xdrClientPath,
    loaded: true,
    exports: {
      fetchXdrAssetOverview: async () => ({
        assetLedger: {
          core_asset: 12,
          ready_to_outbound: 3,
        },
        riskOverview: {
          securityLogTotal: 1250000,
          alertTotal: 3200,
          alertReductionRate: 0.97,
          closeRate: 97,
          yunyingAlertStats: {
            c2VirusTotal: 5,
            webVulnTotal: 5,
            virusFiles: {
              total: 2,
              hostIps: ['10.5.40.62'],
              records: [
                {
                  hostIp: { originalValue: '10.5.40.62', renderValue: '10.5.40.62' },
                  threatClass: { originalValue: 120, renderValue: '病毒木马活动' },
                  gptResult: { originalValue: 120, renderValue: '病毒木马活动' }
                }
              ]
            },
            c2ExternalLink: {
              total: 3,
              hostIps: ['10.5.40.63', '10.5.40.64'],
              records: [
                {
                  hostIp: { originalValue: '10.5.40.63', renderValue: '10.5.40.63' },
                  threatClass: { originalValue: 121, renderValue: '主机失陷活动' },
                  gptResult: { originalValue: 121, renderValue: '主机失陷活动' }
                }
              ]
            },
            exploitAttacks: {
              total: 1,
              hostIps: ['10.5.40.65'],
              records: [
                {
                  hostIp: { originalValue: '10.5.40.65', renderValue: '10.5.40.65' },
                  threatClass: { originalValue: 30, renderValue: '漏洞攻击' },
                  gptResult: { originalValue: 122, renderValue: '其他类型' }
                }
              ]
            },
            webAttacks: {
              total: 4,
              hostIps: ['10.5.40.66'],
              records: [
                {
                  hostIp: { originalValue: '10.5.40.66', renderValue: '10.5.40.66' },
                  threatClass: { originalValue: 90, renderValue: '网站攻击' },
                  gptResult: { originalValue: 122, renderValue: '其他类型' }
                }
              ]
            }
          }
        },
        projectBackground: {
          customerName: '测试客户',
          startDate: '2026-06-01',
          endDate: '2026-06-16'
        },
        riskDetails: {
          alertReductionRate: 0.97
        },
        appendix: {}
      })
    }
  };

  const { collectReportData } = require('../src/data_client');
  const data = await collectReportData({
    customer: '测试客户',
    start: '2026-06-01',
    end: '2026-06-16',
    xdrCookiePath: 'fake-cookie.txt',
    assetStatusStats: {
      assetTotal: 555,
      manage_asset: 555,
      typeDistribution: [
        { name: '服务器', value: 115 },
        { name: '终端', value: 36 },
        { name: '其他', value: 404 }
      ],
      protectionDistribution: [
        { name: '在线', value: 400 },
        { name: '离线', value: 100 },
        { name: '已禁用', value: 20 },
        { name: '已降级', value: 10 },
        { name: '未安装', value: 25 }
      ],
      internetExposureTotal: 18,
      internetExposureDistribution: [
        { name: '服务器', value: 6 },
        { name: '终端', value: 4 },
        { name: '其他', value: 8 }
      ]
    },
    incidentStatusStats: {
      totalEvents: 177,
      closedEvents: 12,
      containedEvents: 5,
      processingEvents: 3,
      closeRate: 7
    },
    logger: () => {}
  });

  assert.strictEqual(data.projectBackground.customerName, '测试客户');
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data, 'report'), false);
  assert.strictEqual(data.assetLedger.manage_asset, 555);
  assert.strictEqual(data.assetLedger.core_asset, 12);
  assert.strictEqual(data.assetLedger.ready_to_outbound, 3);
  assert.strictEqual(data.assetLedger.assetTotal, 555);
  assert.strictEqual(data.assetLedger.internetExposureTotal, 18);
  assert.strictEqual(data.assetLedger.typeDistribution[0].value, 115);
  assert.strictEqual(data.assetLedger.protectionDistribution[4].name, '未安装');
  assert.strictEqual(data.assetLedger.internetExposureDistribution[2].value, 8);
  assert.strictEqual(data.riskOverview.securityLogTotal, 1250000);
  assert.strictEqual(data.riskOverview.alertTotal, 3200);
  assert.strictEqual(data.riskOverview.alertReductionRate, 0.97);
  assert.strictEqual(data.riskOverview.totalEvents, 177);
  assert.strictEqual(data.riskOverview.closedEvents, 12);
  assert.strictEqual(data.riskOverview.containedEvents, 5);
  assert.strictEqual(data.riskOverview.closeRate, 7);
  assert.strictEqual(data.riskOverview.yunyingAlertStats.c2VirusTotal, 5);
  assert.strictEqual(data.riskOverview.yunyingAlertStats.webVulnTotal, 5);
  assert.strictEqual(data.riskOverview.yunyingAlertStats.virusFiles.total, 2);
  assert.strictEqual(data.riskOverview.yunyingAlertStats.virusFiles.hostIps[0], '10.5.40.62');
  assert.strictEqual(data.riskOverview.yunyingAlertStats.c2ExternalLink.total, 3);
  assert.strictEqual(data.riskOverview.yunyingAlertStats.c2ExternalLink.hostIps[1], '10.5.40.64');
  assert.strictEqual(data.riskOverview.yunyingAlertStats.exploitAttacks.total, 1);
  assert.strictEqual(data.riskOverview.yunyingAlertStats.exploitAttacks.hostIps[0], '10.5.40.65');
  assert.strictEqual(data.riskOverview.yunyingAlertStats.webAttacks.total, 4);
  assert.strictEqual(data.riskOverview.yunyingAlertStats.webAttacks.hostIps[0], '10.5.40.66');
  assert.strictEqual(data.riskDetails.totalEvents, 177);
  assert.strictEqual(data.riskDetails.alertReductionRate, 0.97);
  assert.strictEqual(data.riskDetails.severeEvents, 0);
  assert.strictEqual(data.riskDetails.highEvents, 0);
  assert.strictEqual(data.riskDetails.closedEvents, 12);
  assert.strictEqual(data.riskDetails.containedEvents, 5);
  assert.strictEqual(data.riskDetails.processingEvents, 3);
  assert.strictEqual(data.riskDetails.closeRate, 7);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data, 'ops'), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data, 'risks'), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data.riskOverview, 'keyRisks'), false);

  console.log('data_client.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
