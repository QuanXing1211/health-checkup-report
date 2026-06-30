'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { summarizeIncidentStatus, extractExploitStats, extractC2ConnectionExamples, extractVirusTrojanExamples, extractVulnExploitExamples, summarizeManagedAssetIncidents } = require('../src/incident_excel_stats');

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-report-'));
  const excelPath = path.join(tmpDir, 'incident.xlsx');

  const pythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["等级", "处置状态", "影响资产", "安全事件一级分类", "响应时间"])',
    'ws.append(["严重", "处置完成", "10.5.40.62(未归类组)", "漏洞利用", "30分钟"])',
    'ws.append(["高危", "已遏制", "10.5.40.63(未归类组)", "病毒木马", ""])',
    'ws.append(["高危", "处置中", "10.5.40.62(未归类组)", "漏洞利用", ""])',
    'ws.append(["中危", "处置完成", "192.168.1.10(未归类组)", "Web攻击", "20分钟"])',
    'ws.append(["低危", "处置完成", "172.16.0.8(组B)", "暴力破解", "45"])',
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
  assert.deepStrictEqual(exploitStats.incidentIds, ['inc-001', 'inc-002', 'inc-003', 'inc-004'], '应按事件表顺序保留漏洞利用事件 ID');

  // Test with empty excelPath
  const emptyStats = await extractExploitStats(null);
  assert.strictEqual(emptyStats.total, 0);
  assert.strictEqual(emptyStats.highRiskAsset, '');
  assert.strictEqual(emptyStats.attackSuccessCount, 0);
  assert.deepStrictEqual(emptyStats.incidentIds, []);

  const vulnExamples = await extractVulnExploitExamples(exploitExcelPath, ['inc-001', 'inc-002', 'inc-003', 'inc-004']);
  assert.ok(Array.isArray(vulnExamples.vulnExploits), 'vulnExploits 应为数组');
  assert.strictEqual(vulnExamples.vulnExploits.length, 4, '应按传入 incidentIds 提取漏洞利用事件举例');
  assert.strictEqual(vulnExamples.vulnExploits[0].incidentId, 'inc-001');

  // === Test extractC2ConnectionExamples ===
  const c2ExcelPath = path.join(tmpDir, 'c2-test.xlsx');
  const c2PythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["事件ID", "外网IP", "域名", "受影响资产", "最近发生时间", "处置状态"])',
    'ws.append(["incident-001", "1.1.1.1（未知）、1.1.1.2（严重）", "", "10.0.0.1", "2026-06-28 10:22:31", "处置中"])',
    'ws.append(["incident-002", "", "a.com（未知）、b.com（严重）、c.com（严重）", "10.0.0.2", "2026-06-27 08:01:02", "已遏制"])',
    'ws.append(["incident-003", "2.2.2.2（严重）", "x.com（严重）", "10.0.0.3", "2026-06-26 01:02:03", "处置完成"])',
    'ws.append(["incident-004", "3.3.3.3（严重）", "", "10.0.0.4", "2026-06-25 01:02:03", "处置完成"])',
    'ws.append(["incident-005", "4.4.4.4（严重）", "", "10.0.0.5", "2026-06-24 01:02:03", "处置完成"])',
    'ws.append(["incident-006", "5.5.5.5（严重）", "", "10.0.0.6", "2026-06-23 01:02:03", "处置完成"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', c2PythonCode, c2ExcelPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const c2Examples = await extractC2ConnectionExamples(c2ExcelPath, [
    'incident-001',
    'incident-002',
    'incident-003',
    'incident-004',
    'incident-005',
    'incident-006'
  ]);

  assert.ok(Array.isArray(c2Examples.c2Connections), 'c2Connections 应为数组');
  assert.strictEqual(c2Examples.c2Connections.length, 5, '最多只取 5 条');
  assert.strictEqual(c2Examples.c2Connections[0].ioc, '1.1.1.2', '应只取外网IP中的严重项');
  assert.strictEqual(c2Examples.c2Connections[1].ioc, 'b.com、c.com', '应取域名中的多个严重项并用顿号拼接');
  assert.strictEqual(c2Examples.c2Connections[2].ioc, '2.2.2.2、x.com', '外网IP和域名同时存在时都应取');
  assert.strictEqual(c2Examples.c2Connections[2].affectedAsset, '10.0.0.3');
  assert.strictEqual(c2Examples.c2Connections[2].lastOccurredAt, '2026-06-26 01:02:03');
  assert.strictEqual(c2Examples.c2Connections[2].disposalStatus, '处置完成');

  // === Test extractVirusTrojanExamples ===
  const virusExcelPath = path.join(tmpDir, 'virus-test.xlsx');
  const virusPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["事件ID", "文件", "受影响资产", "最近发生时间", "处置状态"])',
    'ws.append(["incident-v1", "a3f2…8c1d（未知）、b7e1…4f9a（严重）", "10.0.1.1", "2026-06-28 11:22:33", "处置中"])',
    'ws.append(["incident-v2", "c1d2…e3f4（严重）、d4e5…f6g7（严重）", "10.0.1.2", "2026-06-27 11:22:33", "已遏制"])',
    'ws.append(["incident-v3", "e5f6…g7h8（严重）", "10.0.1.3", "2026-06-26 11:22:33", "处置完成"])',
    'ws.append(["incident-v4", "f6g7…h8i9（严重）", "10.0.1.4", "2026-06-25 11:22:33", "处置完成"])',
    'ws.append(["incident-v5", "g7h8…i9j0（严重）", "10.0.1.5", "2026-06-24 11:22:33", "处置完成"])',
    'ws.append(["incident-v6", "h8i9…j0k1（严重）", "10.0.1.6", "2026-06-23 11:22:33", "处置完成"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', virusPythonCode, virusExcelPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const virusExamples = await extractVirusTrojanExamples(virusExcelPath, [
    'incident-v1',
    'incident-v2',
    'incident-v3',
    'incident-v4',
    'incident-v5',
    'incident-v6'
  ]);

  assert.ok(Array.isArray(virusExamples.viruses), 'viruses 应为数组');
  assert.strictEqual(virusExamples.viruses.length, 5, '最多只取 5 条');
  assert.strictEqual(virusExamples.viruses[0].md5, 'b7e1…4f9a', '应只取文件列中的严重项');
  assert.strictEqual(virusExamples.viruses[1].md5, 'c1d2…e3f4、d4e5…f6g7', '多个严重项应使用顿号拼接');
  assert.strictEqual(virusExamples.viruses[1].affectedAsset, '10.0.1.2');
  assert.strictEqual(virusExamples.viruses[1].lastOccurredAt, '2026-06-27 11:22:33');
  assert.strictEqual(virusExamples.viruses[1].disposalStatus, '已遏制');

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
  assert.strictEqual(managedStats.managedAvgResponseTime, 37.5, '平均响应时长应为 37.5 分钟（(30+45)/2）');

  // 最多类型事件 TOP1
  assert.strictEqual(typeof managedStats.topEventType, 'string', 'topEventType 应为字符串');
  assert.strictEqual(managedStats.topEventType, '漏洞利用', '最多事件类型应为 漏洞利用');

  // TOP3 业务系统名称（取 businessSystemEventDistribution 前三项 name，拼接为文本）
  assert.strictEqual(typeof managedStats.top3BusinessSystems, 'string', 'top3BusinessSystems 应为字符串');
  assert.strictEqual(managedStats.top3BusinessSystems, 'OA系统、ERP系统、VPN系统', 'TOP3 应为 OA系统、ERP系统、VPN系统');

  // 业务系统安全事件分布（top5 + 其他）
  assert.ok(Array.isArray(managedStats.businessSystemEventDistribution), 'businessSystemEventDistribution 应为数组');
  assert.strictEqual(managedStats.businessSystemEventDistribution.length, 4, '共有4个业务系统（不到5项，不加"其他"）');
  assert.strictEqual(managedStats.businessSystemEventDistribution[0].name, 'OA系统', 'TOP1 应为OA系统');
  assert.strictEqual(managedStats.businessSystemEventDistribution[0].value, 2, 'OA系统应有2起事件');
  assert.strictEqual(managedStats.businessSystemEventDistribution[1].name, 'ERP系统', 'TOP2 应为ERP系统');
  assert.strictEqual(managedStats.businessSystemEventDistribution[1].value, 1, 'ERP系统应有1起事件');
  assert.strictEqual(managedStats.businessSystemEventDistribution[2].name, 'VPN系统', 'TOP3 应为VPN系统');
  assert.strictEqual(managedStats.businessSystemEventDistribution[3].name, '邮件系统', 'TOP4 应为邮件系统');

  // Test with empty paths
  const emptyManagedStats = await summarizeManagedAssetIncidents(null, null);
  assert.strictEqual(emptyManagedStats.managedAssetEvents, 0);
  assert.strictEqual(emptyManagedStats.managedAssetContainedEvents, 0);
  assert.strictEqual(emptyManagedStats.managedAssetDisposedEvents, 0);
  assert.strictEqual(emptyManagedStats.managedEventCloseRate, 0);
  assert.strictEqual(emptyManagedStats.managedAssetCount, 0);
  assert.strictEqual(emptyManagedStats.managedAvgResponseTime, 0, '空数据时 managedAvgResponseTime 应为 0');
  assert.strictEqual(emptyManagedStats.topEventType, '', '空数据时 topEventType 应为空字符串');
  assert.strictEqual(emptyManagedStats.top3BusinessSystems, '', '空数据时 top3BusinessSystems 应为空字符串');
  assert.ok(Array.isArray(emptyManagedStats.businessSystemEventDistribution), '空数据时 businessSystemEventDistribution 应为数组');
  assert.strictEqual(emptyManagedStats.businessSystemEventDistribution.length, 0, '空数据时 businessSystemEventDistribution 应为空');

  console.log('incident_excel_stats.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
