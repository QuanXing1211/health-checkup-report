'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { summarizeAssetTable } = require('../src/asset_excel_stats');

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-report-'));
  const excelPath = path.join(tmpDir, 'asset.xlsx');

  const pythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["资产导出", "", "", "", ""])',
    'ws.append(["序号", "资产名称", "资产类型", "agent状态", "互联网暴露"])',
    'ws.append([1, "A", "服务器", 1, "yes"])',
    'ws.append([2, "B", "终端", 0, "no"])',
    'ws.append([3, "C", "数据库", 2, "yes"])',
    'ws.append([4, "D", "服务器", 3, "no"])',
    'ws.append([5, "E", "终端", None, "yes"])',
    'ws.append([None, None, None, None, None])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', pythonCode, excelPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const stats = await summarizeAssetTable(excelPath);

  assert.strictEqual(stats.assetTotal, 5);
  assert.strictEqual(stats.manage_asset, 5);
  assert.deepStrictEqual(stats.typeDistribution, [
    { name: '服务器', value: 2 },
    { name: '终端', value: 2 },
    { name: '其他', value: 1 }
  ]);
  assert.deepStrictEqual(stats.protectionDistribution, [
    { name: '在线', value: 1 },
    { name: '离线', value: 1 },
    { name: '已禁用', value: 1 },
    { name: '已降级', value: 1 },
    { name: '未防护资产', value: 1 }
  ]);
  assert.strictEqual(stats.internetExposureTotal, 3);
  assert.deepStrictEqual(stats.internetExposureDistribution, [
    { name: '服务器', value: 1 },
    { name: '终端', value: 1 },
    { name: '其他', value: 1 }
  ]);

  console.log('asset_excel_stats.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
