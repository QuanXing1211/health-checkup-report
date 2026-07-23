#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const template = fs.readFileSync(path.join(ROOT, 'security-report-preview.html'), 'utf8');

// 构建6位数的 mock JSON，保证总数也是六位数
const mockData = {
  assetLedger: {
    assetTotal: 999999,
    internetExposureTotal: 123456,
    typeDistribution: [
      { name: '服务器', value: 500000 },
      { name: '终端', value: 400000 },
      { name: '其他', value: 99999 }
    ],
    protectionDistribution: [
      { name: '在线', value: 700000 },
      { name: '离线', value: 200000 },
      { name: '已禁用', value: 50000 },
      { name: '已降级', value: 30000 },
      { name: '未防护资产', value: 19999 }
    ],
    internetExposureDistribution: [
      { name: '服务器', value: 80000 },
      { name: '终端', value: 30000 },
      { name: '其他', value: 13456 }
    ]
  },
  riskDetails: {
    eventDistributionSectionHide: false,
    eventTypeDistribution: [
      { name: '漏洞利用攻击', value: 350000 },
      { name: '暴力破解尝试', value: 280000 },
      { name: '恶意软件感染', value: 180000 },
      { name: '钓鱼/社会工程', value: 95000 },
      { name: 'C2通信行为', value: 55000 },
      { name: '其它', value: 39999 }
    ],
    businessSystemEventDistribution: [
      { name: 'OA系统', value: 180000, highRisk: 45000 },
      { name: 'VPN系统', value: 160000, highRisk: 38000 },
      { name: 'ERP系统', value: 140000, highRisk: 32000 },
      { name: '邮件系统', value: 120000, highRisk: 28000 },
      { name: 'MES系统', value: 100000, highRisk: 22000 },
      { name: '其它', value: 299999, highRisk: 55000 }
    ],
    topEventType: '漏洞利用攻击',
    top3BusinessSystems: 'OA系统、VPN系统、其它'
  },
  riskOverview: {
    securityRiskTotal: 888888,
    highAndAboveRiskCount: 123456,
    riskBusinessCount: 99,
    riskAssetCount: 999999,
    affectedAssetCount: 0
  }
};

const jsonStr = JSON.stringify(mockData);

// 仿照 template_renderer.js 的 injectReportData：在 </head> 前注入
const injection = '<script>window.SECURITY_REPORT_DATA=' + jsonStr + ';</script>\n</head>';
const injected = template.replace('</head>', injection);

const outPath = path.join(ROOT, 'output', 'six-digit-preview.html');
fs.writeFileSync(outPath, injected, 'utf8');
console.log('Written:', outPath);
