'use strict';

function buildMockReportData(input) {
  return {
    report: {
      title: '首次安全体检报告',
      customerName: input.customer,
      customerId: input.customerId || null,
      startDate: input.start,
      endDate: input.end,
      generatedAt: new Date().toISOString(),
      grade: '中'
    },
    assets: {
      total: 520,
      core: 86,
      retire: 12,
      review: 8,
      typeDistribution: [
        { name: '服务器', value: 312 },
        { name: '终端', value: 156 },
        { name: '其他', value: 52 }
      ],
      protectionDistribution: [
        { name: '在线', value: 498 },
        { name: '离线', value: 22 },
        { name: '已禁用', value: 6 },
        { name: '已降级', value: 4 },
        { name: '未防护', value: 18 }
      ]
    },
    ops: {
      devices: 28,
      sangfor: 22,
      logReduce: 74,
      alertReduce: 97,
      severe: 8,
      high: 28
    },
    risks: {
      total: 47,
      highVulns: 42,
      keySystems: ['OA 系统', 'MES 系统', 'ERP 系统'],
      topSystem: 'OA 系统',
      topSystemHighRisks: 18,
      keyRisks: []
    }
  };
}

module.exports = {
  buildMockReportData
};

