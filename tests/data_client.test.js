'use strict';

const assert = require('assert');

async function main() {
  const xdrClientPath = require.resolve('../src/xdr_asset_client');
  const originalCacheEntry = require.cache[xdrClientPath];
  const fetchCalls = [];

  try {
    require.cache[xdrClientPath] = {
      id: xdrClientPath,
      filename: xdrClientPath,
      loaded: true,
      exports: {
        fetchMsswAssetOverview: async (options) => {
          fetchCalls.push({ options });
          return ({
        assetLedger: {
          ready_to_outbound: 3,
        },
        riskOverview: {
          securityLogTotal: 1250000,
          alertTotal: 3200,
          alertReductionRate: 0.97,
          closeRate: 97,
          incidentGptStats: {
            total: 5,
            hostCompromise: {
              total: 2,
              confirmedIncidentIds: ['incident-aaa', 'incident-bbb']
            },
            virusTrojan: {
              total: 3,
              confirmedIncidentIds: ['incident-ccc', 'incident-ddd', 'incident-eee']
            },
            threatActorStats: [
              { name: '银狐', count: 2 },
              { name: '勒索', count: 1 }
            ]
          }
        },
        projectBackground: {
          customerName: '测试客户',
          startDate: '2026-06-01',
          endDate: '2026-06-16'
        },
        riskDetails: {
          alertReductionRate: 0.97,
          highRiskIncidentExamples: {
            vulnExploits: [
              {
                incidentId: 'inc-001',
                eventName: '利用漏洞获取Linux用户信息',
                affectedAsset: '10.0.0.7',
                lastOccurredAt: '2026-06-26 10:22:31',
                disposalStatus: '处置完成'
              }
            ],
            viruses: [
              {
                incidentId: 'incident-ccc',
                md5: 'b7e1…4f9a',
                affectedAsset: '10.0.0.9',
                lastOccurredAt: '2026-06-27 10:22:31',
                disposalStatus: '已遏制'
              }
            ],
            c2Connections: [
              {
                incidentId: 'incident-aaa',
                ioc: '1.1.1.2、bad.example.com',
                affectedAsset: '10.0.0.8',
                lastOccurredAt: '2026-06-28 10:22:31',
                disposalStatus: '处置中'
              }
            ]
          }
        },
        appendix: {}
      });
        }
    }
  };

  const { collectReportData } = require('../src/data_client');
  const data = await collectReportData({
    customer: '测试客户',
    start: '2026-06-01',
    end: '2026-06-16',
    xdrCookiePath: 'fake-cookie.txt',
    msswCookiePath: 'fake-mssw-cookie.txt',
    msswBaseUrl: 'pre.soar.sangfor.com',
    customerId: 'company-001',
    incidentFilePath: 'incident.xlsx',
    assetFilePath: 'asset.xlsx',
    assetStatusStats: {
      assetTotal: 555,
      manage_asset: 555,
      core_asset: 12,
      core_managed_asset: 8,
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
        { name: '未防护', value: 25 }
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
      closeRate: 7,
      uniqueAssetCount: 42
    },
    logger: () => {}
  });

  assert.strictEqual(data.projectBackground.customerName, '测试客户');
  assert.strictEqual(fetchCalls.length, 1);
  assert.strictEqual(fetchCalls[0].options.msswCookiePath, 'fake-mssw-cookie.txt');
  assert.strictEqual(fetchCalls[0].options.msswBaseUrl, 'pre.soar.sangfor.com');
  assert.strictEqual(fetchCalls[0].options.customerId, 'company-001');
  assert.strictEqual(fetchCalls[0].options.incidentFilePath, 'incident.xlsx');
  assert.strictEqual(fetchCalls[0].options.assetFilePath, 'asset.xlsx');
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data, 'report'), false);
  assert.strictEqual(data.assetLedger.manage_asset, 555);
  assert.strictEqual(data.assetLedger.core_asset, 12);
  assert.strictEqual(data.assetLedger.core_managed_asset, 8);
  assert.strictEqual(data.assetLedger.ready_to_outbound, 3);
  assert.strictEqual(data.assetLedger.assetTotal, 555);
  assert.strictEqual(data.assetLedger.internetExposureTotal, 18);
  assert.strictEqual(data.assetLedger.typeDistribution[0].value, 115);
  assert.strictEqual(data.assetLedger.protectionDistribution[4].name, '未防护');
  assert.strictEqual(data.assetLedger.internetExposureDistribution[2].value, 8);
  assert.strictEqual(data.riskOverview.securityLogTotal, 1250000);
  assert.strictEqual(data.riskOverview.alertTotal, 3200);
  assert.strictEqual(data.riskOverview.alertReductionRate, 0.97);
  assert.strictEqual(data.riskOverview.totalEvents, 177);
  assert.strictEqual(data.riskOverview.closedEvents, 12);
  assert.strictEqual(data.riskOverview.containedEvents, 5);
  assert.strictEqual(data.riskOverview.closeRate, 7);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data.riskOverview, 'affectedAssetCount'), false);
  assert.strictEqual(data.riskOverview.incidentGptStats.hostCompromise.total, 2);
  assert.strictEqual(data.riskOverview.incidentGptStats.virusTrojan.total, 3);
  assert.strictEqual(data.riskOverview.incidentGptStats.threatActorStats[0].name, '银狐');
  assert.strictEqual(data.riskOverview.incidentGptStats.threatActorStats[0].count, 2);
  assert.strictEqual(data.riskOverview.incidentGptStats.threatActorStats[1].name, '勒索');
  assert.strictEqual(data.riskOverview.incidentGptStats.threatActorStats[1].count, 1);
  assert.strictEqual(data.riskDetails.totalEvents, 177);
  assert.strictEqual(data.riskDetails.alertReductionRate, 0.97);
  assert.strictEqual(data.riskDetails.severeEvents, 0);
  assert.strictEqual(data.riskDetails.highEvents, 0);
  assert.strictEqual(data.riskDetails.closedEvents, 12);
  assert.strictEqual(data.riskDetails.containedEvents, 5);
  assert.strictEqual(data.riskDetails.processingEvents, 3);
  assert.strictEqual(data.riskDetails.closeRate, 7);
  assert.strictEqual(data.riskDetails.uniqueAssetCount, 42);
  assert.strictEqual(data.riskDetails.highRiskIncidentExamples.vulnExploits.length, 1);
  assert.strictEqual(data.riskDetails.highRiskIncidentExamples.vulnExploits[0].eventName, '利用漏洞获取Linux用户信息');
  assert.strictEqual(data.riskDetails.highRiskIncidentExamples.viruses.length, 1);
  assert.strictEqual(data.riskDetails.highRiskIncidentExamples.viruses[0].md5, 'b7e1…4f9a');
  assert.strictEqual(data.riskDetails.highRiskIncidentExamples.c2Connections.length, 1);
  assert.strictEqual(data.riskDetails.highRiskIncidentExamples.c2Connections[0].ioc, '1.1.1.2、bad.example.com');
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data, 'ops'), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data, 'risks'), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(data.riskOverview, 'keyRisks'), false);

  console.log('data_client.test.js passed');
  } finally {
    if (originalCacheEntry) {
      require.cache[xdrClientPath] = originalCacheEntry;
    } else {
      delete require.cache[xdrClientPath];
    }
  }
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
