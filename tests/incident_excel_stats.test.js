'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { summarizeIncidentStatus, extractExploitStats, summarizeManagedAssetIncidents } = require('../src/incident_excel_stats');

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-report-'));
  const excelPath = path.join(tmpDir, 'incident.xlsx');

  const pythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["等级", "处置状态", "影响资产", "安全事件一级分类"])',
    'ws.append(["严重", "处置完成", "10.5.40.62(未归类组)", "漏洞利用"])',
    'ws.append(["高危", "已遏制", "10.5.40.63(未归类组)", "病毒木马"])',
    'ws.append(["高危", "处置中", "10.5.40.62(未归类组)", "漏洞利用"])',
    'ws.append(["中危", "处置完成", "192.168.1.10(未归类组)", "Web攻击"])',
    'ws.append(["低危", "处置完成", "172.16.0.8(组B)", "暴力破解"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', pythonCode, excelPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const stats = await summarizeIncidentStatus(excelPath);

  assert.strictEqual(stats.totalEvents, 5);
  assert.strictEqual(stats.severeEvents, 1);
  assert.strictEqual(stats.highEvents, 2);
  assert.strictEqual(stats.closedEvents, 3);
  assert.strictEqual(stats.containedEvents, 1);
  assert.strictEqual(stats.processingEvents, 1);
  assert.strictEqual(stats.closeRate, 60);
  assert.strictEqual(stats.uniqueAssetCount, 4);

  // === Test extractExploitStats ===
  const exploitExcelPath = path.join(tmpDir, 'exploit-test.xlsx');
  const exploitPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["事件ID", "安全事件一级分类", "影响资产", "攻击状态"])',
    'ws.append(["inc-001", "漏洞利用", "10.5.40.62(未归类组)", "成功"])',
    'ws.append(["inc-002", "漏洞利用", "10.5.40.63(未归类组)", "成功"])',
    'ws.append(["inc-003", "漏洞利用", "10.5.40.64(未归类组)", "失败"])',
    'ws.append(["inc-004", "漏洞利用", "10.5.40.65(未归类组)", "成功"])',
    'ws.append(["inc-005", "病毒木马", "10.5.40.66(未归类组)", "成功"])',
    'ws.append(["inc-006", "Web攻击", "10.5.40.67(未归类组)", "失败"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', exploitPythonCode, exploitExcelPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const exploitStats = await extractExploitStats(exploitExcelPath);

  assert.strictEqual(exploitStats.total, 4, '漏洞利用事件总数应为 4');
  assert.strictEqual(exploitStats.attackSuccessCount, 3, '攻击成功次数应为 3');
  assert.strictEqual(exploitStats.highRiskAsset, '10.5.40.62(未归类组)', '高危漏洞资产应为第一个事件的影响资产');

  // Test with empty excelPath
  const emptyStats = await extractExploitStats(null);
  assert.strictEqual(emptyStats.total, 0);
  assert.strictEqual(emptyStats.highRiskAsset, '');
  assert.strictEqual(emptyStats.attackSuccessCount, 0);

  // === Test summarizeManagedAssetIncidents ===
  const assetExcelPath = path.join(tmpDir, 'managed_asset.xlsx');
  const assetPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["资产表"])',
    'ws.append(["IP地址", "资产名称", "托管状态", "所属业务"])',
    'ws.append(["10.5.40.62", "服务器A", "已托管", "OA系统"])',
    'ws.append(["10.5.40.63", "服务器B", "已托管", "ERP系统"])',
    'ws.append(["192.168.1.10", "服务器C", "未托管", "VPN系统"])',
    'ws.append(["172.16.0.8", "服务器D", "已托管", "邮件系统"])',
    'ws.append(["10.5.40.64", "服务器E", "未托管", "数据库"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', assetPythonCode, assetExcelPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const managedStats = await summarizeManagedAssetIncidents(assetExcelPath, excelPath);

  // Events 1,2,3,5 involve managed assets; event 4 (192.168.1.10) is unmanaged
  assert.strictEqual(managedStats.managedAssetEvents, 4, '托管资产事件数应为 4（事件1,2,3,5）');
  assert.strictEqual(managedStats.managedAssetContainedEvents, 1, '已遏制事件数应为 1（事件2）');
  assert.strictEqual(managedStats.managedAssetDisposedEvents, 2, '处置完成事件数应为 2（事件1,5）');
  assert.strictEqual(managedStats.managedAssetCount, 3, '托管资产IP数应为 3（10.5.40.62, 10.5.40.63, 172.16.0.8）');
  assert.strictEqual(managedStats.managedEventCloseRate, 50, '闭环率应为 50%');

  // 最多类型事件 TOP1
  assert.strictEqual(typeof managedStats.topEventType, 'string', 'topEventType 应为字符串');
  assert.strictEqual(managedStats.topEventType, '漏洞利用', '最多事件类型应为 漏洞利用');

  // TOP3 业务系统安全事件分布
  assert.ok(Array.isArray(managedStats.top3BusinessSystems), 'top3BusinessSystems 应为数组');
  assert.strictEqual(managedStats.top3BusinessSystems.length, 3, '应有3个业务系统');
  assert.strictEqual(managedStats.top3BusinessSystems[0].name, 'OA系统', 'TOP1 应为OA系统');
  assert.strictEqual(managedStats.top3BusinessSystems[0].value, 2, 'OA系统应有2起事件');

  // Test with empty paths
  const emptyManagedStats = await summarizeManagedAssetIncidents(null, null);
  assert.strictEqual(emptyManagedStats.managedAssetEvents, 0);
  assert.strictEqual(emptyManagedStats.managedAssetContainedEvents, 0);
  assert.strictEqual(emptyManagedStats.managedAssetDisposedEvents, 0);
  assert.strictEqual(emptyManagedStats.managedEventCloseRate, 0);
  assert.strictEqual(emptyManagedStats.managedAssetCount, 0);
  assert.strictEqual(emptyManagedStats.topEventType, '', '空数据时 topEventType 应为空字符串');
  assert.ok(Array.isArray(emptyManagedStats.top3BusinessSystems), '空数据时 top3BusinessSystems 应为数组');
  assert.strictEqual(emptyManagedStats.top3BusinessSystems.length, 0, '空数据时 top3BusinessSystems 应为空');

  console.log('incident_excel_stats.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
