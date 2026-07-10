#!/usr/bin/env node
'use strict';

const fs = require('fs/promises');
const path = require('path');
const { renderReportToFile } = require('../src/template_renderer');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT_DIR = path.join(ROOT, 'output');
const TEMPLATE_PATH = path.join(ROOT, 'security-report-preview.html');

async function main() {
  const basePath = path.join(OUTPUT_DIR, 'mock-full-report-data-rich.json');
  const base = await readJson(basePath);

  // 构建"只有深信服设备 AF + AES"的 mock 数据
  const mockData = deepMerge({}, base);

  // 客户信息
  mockData.projectBackground = mockData.projectBackground || {};
  mockData.projectBackground.customerName = '深信服AF+AES测试';
  mockData.projectBackground.startDate = '2026-06-01';
  mockData.projectBackground.endDate = '2026-06-30';

  // 设备数据: 只有 AF 和 AES
  mockData.riskDetails = mockData.riskDetails || {};
  mockData.riskDetails.devices = 8;        // 安全设备总数 = af + aes
  mockData.riskDetails.sangfor = 8;        // 深信服设备 = af + aes
  mockData.riskDetails.af = 5;             // AF: 5台
  mockData.riskDetails.aes = 3;            // aES: 3台
  mockData.riskDetails.sip = 0;            // SIP: 0 → 应隐藏
  mockData.riskDetails.sta = 0;            // STA: 0 → 应隐藏
  mockData.riskDetails.other_sf = 0;       // 其它: 0 → 应隐藏
  mockData.riskDetails.third = 0;          // 第三方: 0 → 应隐藏

  // 同步 riskOverview 的设备字段
  mockData.riskOverview = mockData.riskOverview || {};
  mockData.riskOverview.devices = 8;

  // 保留其他数据不变（事件、风险等保持原样）

  const jsonPath = path.join(OUTPUT_DIR, 'mock-af-aes-only.json');
  await writeJson(jsonPath, mockData);
  console.log(`JSON 已写入: ${jsonPath}`);

  const renderResult = await renderReportToFile({
    templatePath: TEMPLATE_PATH,
    outputDir: path.join(OUTPUT_DIR, 'mock-af-aes-preview'),
    reportData: mockData
  });

  console.log(JSON.stringify({
    ok: true,
    reportDataPath: jsonPath,
    htmlPath: renderResult.html_path,
    deviceData: {
      devices: mockData.riskDetails.devices,
      sangfor: mockData.riskDetails.sangfor,
      af: mockData.riskDetails.af,
      aes: mockData.riskDetails.aes,
      sip: mockData.riskDetails.sip,
      sta: mockData.riskDetails.sta,
      other_sf: mockData.riskDetails.other_sf,
      third: mockData.riskDetails.third
    }
  }, null, 2));
}

function deepMerge(base, patch) {
  if (!isPlainObject(base) || !isPlainObject(patch)) return patch;
  const merged = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    merged[key] = isPlainObject(value) && isPlainObject(merged[key])
      ? deepMerge(merged[key], value)
      : value;
  }
  return merged;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

async function writeJson(filePath, data) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
