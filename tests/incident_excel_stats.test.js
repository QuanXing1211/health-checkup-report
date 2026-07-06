'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const {
  summarizeIncidentStatus,
  extractExploitStats,
  extractIncidentDirectStats,
  extractC2ConnectionExamples,
  extractVirusTrojanExamples,
  extractVulnExploitExamples,
  summarizeTopRiskAssetDetails,
  summarizeManagedAssetIncidents
} = require('../src/incident_excel_stats');

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-report-'));
  const excelPath = path.join(tmpDir, 'incident.xlsx');

  const pythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["等级", "处置状态", "影响资产", "安全事件一级分类", "完成时间", "事件创建时间"])',
    'ws.append(["严重", "处置完成", "10.5.40.62(未归类组)", "漏洞利用", "2026-06-20 10:30:00", "2026-06-20 10:00:00"])',
    'ws.append(["高危", "已遏制", "10.5.40.63(未归类组)", "病毒木马", "", "2026-06-20 11:00:00"])',
    'ws.append(["高危", "处置中", "10.5.40.62(未归类组)", "漏洞利用", "", "2026-06-20 12:00:00"])',
    'ws.append(["中危", "处置完成", "192.168.1.10(未归类组)", "Web攻击", "2026-06-20 13:20:00", "2026-06-20 13:00:00"])',
    'ws.append(["低危", "处置完成", "172.16.0.8(组B)", "暴力破解", "2026-06-20 14:45:00", "2026-06-20 14:00:00"])',
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
  assert.strictEqual(stats.containedEvents, 4);
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
    'ws.append(["事件ID", "安全事件一级分类", "影响资产", "攻击状态", "等级", "事件名称", "最近发生时间", "处置状态"])',
    'ws.append(["inc-001", "漏洞利用", "10.5.40.62(未归类组)", "成功", "中危", "事件1", "2026-06-20 00:00:00", "处置完成"])',
    'ws.append(["inc-002", "漏洞利用", "10.5.40.63(未归类组)", "成功", "严重", "事件2", "2026-06-21 00:00:00", "处置中"])',
    'ws.append(["inc-003", "漏洞利用", "10.5.40.64(未归类组)", "失败", "高危", "事件3", "2026-06-22 00:00:00", "已遏制"])',
    'ws.append(["inc-004", "漏洞利用", "10.5.40.65(未归类组)", "成功", "低危", "事件4", "2026-06-23 00:00:00", "处置完成"])',
    'ws.append(["inc-005", "病毒木马", "10.5.40.66(未归类组)", "成功", "高危", "事件5", "2026-06-24 00:00:00", "处置完成"])',
    'ws.append(["inc-006", "Web攻击", "10.5.40.67(未归类组)", "失败", "低危", "事件6", "2026-06-25 00:00:00", "处置完成"])',
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

  const exploitDirectStats = await extractIncidentDirectStats(exploitExcelPath);
  assert.deepStrictEqual(exploitDirectStats.exploitIds, ['inc-001', 'inc-002', 'inc-003', 'inc-004'], '应按一级分类直接识别漏洞利用事件');

  // Test with empty excelPath
  const emptyStats = await extractExploitStats(null);
  assert.strictEqual(emptyStats.total, 0);
  assert.strictEqual(emptyStats.highRiskAsset, '');
  assert.strictEqual(emptyStats.attackSuccessCount, 0);
  assert.deepStrictEqual(emptyStats.incidentIds, []);

  const vulnExamples = await extractVulnExploitExamples(exploitExcelPath, ['inc-001', 'inc-002', 'inc-003', 'inc-004']);
  assert.ok(Array.isArray(vulnExamples.vulnExploits), 'vulnExploits 应为数组');
  assert.strictEqual(vulnExamples.vulnExploits.length, 4, '应按传入 incidentIds 提取漏洞利用事件举例');
  assert.deepStrictEqual(
    vulnExamples.vulnExploits.map((item) => item.incidentId),
    ['inc-002', 'inc-003', 'inc-001', 'inc-004'],
    '漏洞利用事件应按等级排序，等级相同保持原始顺序'
  );

  // === Test extractC2ConnectionExamples ===
  const c2ExcelPath = path.join(tmpDir, 'c2-test.xlsx');
  const c2PythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["事件ID", "外网IP", "域名", "受影响资产", "最近发生时间", "处置状态", "等级"])',
    'ws.append(["incident-001", "1.1.1.1（未知）、1.1.1.2（严重）", "", "10.0.0.1", "2026-06-28 10:22:31", "处置中", "中危"])',
    'ws.append(["incident-002", "", "a.com（未知）、b.com（严重）、c.com（严重）", "10.0.0.2", "2026-06-27 08:01:02", "已遏制", "严重"])',
    'ws.append(["incident-003", "2.2.2.2（严重）", "x.com（严重）", "10.0.0.3", "2026-06-26 01:02:03", "处置完成", "高危"])',
    'ws.append(["incident-004", "3.3.3.3（严重）", "", "10.0.0.4", "2026-06-25 01:02:03", "处置完成", "低危"])',
    'ws.append(["incident-005", "4.4.4.4（严重）", "", "10.0.0.5", "2026-06-24 01:02:03", "处置完成", "严重"])',
    'ws.append(["incident-006", "5.5.5.5（严重）", "", "10.0.0.6", "2026-06-23 01:02:03", "处置完成", "高危"])',
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
  assert.deepStrictEqual(
    c2Examples.c2Connections.map((item) => item.incidentId),
    ['incident-002', 'incident-005', 'incident-003', 'incident-006', 'incident-001'],
    'C2 外联事件应按等级排序后截取前 5 条'
  );
  assert.strictEqual(c2Examples.c2Connections[0].ioc, 'b.com、c.com', '应取域名中的多个严重项并用顿号拼接');
  assert.strictEqual(c2Examples.c2Connections[2].ioc, '2.2.2.2、x.com', '外网IP和域名同时存在时都应取');
  assert.strictEqual(c2Examples.c2Connections[2].affectedAsset, '10.0.0.3');
  assert.strictEqual(c2Examples.c2Connections[2].lastOccurredAt, '2026-06-26 01:02:03');
  assert.strictEqual(c2Examples.c2Connections[2].disposalStatus, '处置完成');

  const directStats = await extractIncidentDirectStats(c2ExcelPath);
  assert.deepStrictEqual(
    directStats.hostCompromiseIds,
    ['incident-001', 'incident-002', 'incident-003', 'incident-004', 'incident-005', 'incident-006'],
    '应按事件表中的外网IP/域名严重实体识别 C2 外联事件'
  );
  assert.deepStrictEqual(directStats.virusTrojanIds, [], '仅含外联实体时不应识别为病毒木马');
  assert.deepStrictEqual(directStats.exploitIds, [], '未出现漏洞利用分类时 exploitIds 应为空');

  // === Test extractVirusTrojanExamples ===
  const virusExcelPath = path.join(tmpDir, 'virus-test.xlsx');
  const virusPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["事件ID", "文件", "受影响资产", "最近发生时间", "处置状态", "等级"])',
    'ws.append(["incident-v1", "a3f2…8c1d（未知）、b7e1…4f9a（严重）", "10.0.1.1", "2026-06-28 11:22:33", "处置中", "中危"])',
    'ws.append(["incident-v2", "c1d2…e3f4（严重）、d4e5…f6g7（严重）", "10.0.1.2", "2026-06-27 11:22:33", "已遏制", "严重"])',
    'ws.append(["incident-v3", "e5f6…g7h8（严重）", "10.0.1.3", "2026-06-26 11:22:33", "处置完成", "高危"])',
    'ws.append(["incident-v4", "f6g7…h8i9（严重）", "10.0.1.4", "2026-06-25 11:22:33", "处置完成", "低危"])',
    'ws.append(["incident-v5", "g7h8…i9j0（严重）", "10.0.1.5", "2026-06-24 11:22:33", "处置完成", "严重"])',
    'ws.append(["incident-v6", "h8i9…j0k1（严重）", "10.0.1.6", "2026-06-23 11:22:33", "处置完成", "高危"])',
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
  assert.deepStrictEqual(
    virusExamples.viruses.map((item) => item.incidentId),
    ['incident-v2', 'incident-v5', 'incident-v3', 'incident-v6', 'incident-v1'],
    '病毒木马事件应按等级排序后截取前 5 条'
  );
  assert.strictEqual(virusExamples.viruses[0].md5, 'c1d2…e3f4、d4e5…f6g7', '多个严重项应使用顿号拼接');
  assert.strictEqual(virusExamples.viruses[2].md5, 'e5f6…g7h8', '应只取文件列中的严重项');
  assert.strictEqual(virusExamples.viruses[0].affectedAsset, '10.0.1.2');
  assert.strictEqual(virusExamples.viruses[0].lastOccurredAt, '2026-06-27 11:22:33');
  assert.strictEqual(virusExamples.viruses[0].disposalStatus, '已遏制');

  const virusDirectStats = await extractIncidentDirectStats(virusExcelPath);
  assert.deepStrictEqual(virusDirectStats.hostCompromiseIds, [], '仅含文件严重实体时不应识别为 C2 外联');
  assert.deepStrictEqual(
    virusDirectStats.virusTrojanIds,
    ['incident-v1', 'incident-v2', 'incident-v3', 'incident-v4', 'incident-v5', 'incident-v6'],
    '应按文件列中的严重实体识别病毒木马事件'
  );

  // === Test summarizeTopRiskAssetDetails ===
  const topDetailIncidentPath = path.join(tmpDir, 'top-risk-detail-incident.xlsx');
  const topDetailAssetPath = path.join(tmpDir, 'top-risk-detail-asset.xlsx');
  const topDetailWeakpwdPath = path.join(tmpDir, 'top-risk-detail-weakpwd.xlsx');
  const topDetailVulnPath = path.join(tmpDir, 'top-risk-detail-vuln.xlsx');
  const topDetailExposurePath = path.join(tmpDir, 'top-risk-detail-exposure.xlsx');
  const topDetailIncidentPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["事件ID", "影响资产", "安全事件一级分类", "处置状态"])',
    'ws.append(["c2-1", "10.0.2.1(默认组)", "主机失陷", "处置中"])',
    'ws.append(["virus-1", "10.0.2.1(默认组)", "病毒木马", "处置中"])',
    'ws.append(["exploit-1", "10.0.2.1(默认组)", "漏洞利用", "已遏制"])',
    'ws.append(["normal-1", "10.0.2.1(默认组)", "异常访问", "待处置"])',
    'ws.append(["closed-1", "10.0.2.1(默认组)", "异常访问", "处置完成"])',
    'ws.append(["normal-2", "10.0.2.2(默认组)", "异常访问", "处置中"])',
    'wb.save(sys.argv[1])'
  ].join('\n');
  const topDetailAssetPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["IP地址", "数据源"])',
    'ws.append(["10.0.2.1", "EDR,XDR"])',
    'ws.append(["10.0.2.2", "XDR"])',
    'wb.save(sys.argv[1])'
  ].join('\n');
  const topDetailWeakpwdPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.title = "弱口令"',
    'ws.append(["风险资产", "处置状态"])',
    'ws.append(["10.0.2.1", "处置中"])',
    'ws.append(["10.0.2.1", "待处置"])',
    'ws.append(["10.0.2.1", "处置完成"])',
    'ws.append(["10.0.2.2", "处置中"])',
    'wb.save(sys.argv[1])'
  ].join('\n');
  const topDetailVulnPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.title = "漏洞"',
    'ws.append(["风险资产", "风险等级"])',
    'ws.append(["10.0.2.1", "严重"])',
    'ws.append(["10.0.2.1", "高危"])',
    'ws.append(["10.0.2.1", "中危"])',
    'ws.append(["10.0.2.2", "高危"])',
    'wb.save(sys.argv[1])'
  ].join('\n');
  const topDetailExposurePythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws_port = wb.active',
    'ws_port.title = "端口表"',
    'ws_port.append(["访问路径", "Host"])',
    'ws_port.append(["https://app.example.com", "10.0.2.1"])',
    'ws_port.append(["https://admin.example.com", "10.0.2.1"])',
    'ws_port.append(["https://other.example.com", "10.0.2.2"])',
    'ws_web = wb.create_sheet("Web服务风险分布")',
    'ws_port.append(["https://api.example.com", "10.0.2.1"])',
    'ws_web.append(["访问路径", "组件名称"])',
    'ws_web.append(["https://app.example.com", "Tomcat"])',
    'ws_web.append(["https://admin.example.com", None])',
    'ws_web.merge_cells("B2:B3")',
    'ws_web.append(["https://api.example.com", "nginx"])',
    'ws_web.append(["https://other.example.com", "apache"])',
    'ws_non = wb.create_sheet("非Web服务风险分布")',
    'ws_non.append(["IP地址/子域名", "服务"])',
    'ws_non.append(["10.0.2.1", "SSH"])',
    'ws_non.append(["10.0.2.1", None])',
    'ws_non.merge_cells("B2:B3")',
    'ws_non.append(["10.0.2.1", "RDP"])',
    'ws_non.append(["10.0.2.2", "Redis"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', topDetailIncidentPythonCode, topDetailIncidentPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  execFileSync('python', ['-c', topDetailAssetPythonCode, topDetailAssetPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  execFileSync('python', ['-c', topDetailWeakpwdPythonCode, topDetailWeakpwdPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  execFileSync('python', ['-c', topDetailVulnPythonCode, topDetailVulnPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  execFileSync('python', ['-c', topDetailExposurePythonCode, topDetailExposurePath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const topDetailStats = await summarizeTopRiskAssetDetails({
    incidentExcelPath: topDetailIncidentPath,
    assetExcelPath: topDetailAssetPath,
    weakPasswordExcelPath: topDetailWeakpwdPath,
    vulnerabilityExcelPath: topDetailVulnPath,
    exposureExcelPath: topDetailExposurePath,
    topAssets: [{ ip: '10.0.2.1' }, { ip: '10.0.2.2' }],
    c2Ids: ['c2-1'],
    virusIds: ['virus-1'],
    exploitIds: ['exploit-1']
  });

  assert.strictEqual(topDetailStats.assets['10.0.2.1'].totalEvents, 4);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].malwareAndC2Events, 2);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].vulnExploitEvents, 1);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].otherEvents, 1);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].highAndAboveVulnerabilities, 2);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].weakPasswords, 2);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].totalExposures, 6);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].webExposures, 3);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].nonWebExposures, 3);
  assert.deepStrictEqual(topDetailStats.assets['10.0.2.1'].webComponentExamples, ['Tomcat', 'nginx']);
  assert.deepStrictEqual(topDetailStats.assets['10.0.2.1'].nonWebServiceExamples, ['SSH', 'RDP']);
  assert.strictEqual(topDetailStats.assets['10.0.2.1'].hasAes, true);
  assert.deepStrictEqual(topDetailStats.assets['10.0.2.1'].detailLines, [
    '总计安全事件4个，其中，病毒木马&C2外联2起，网站攻击&漏洞攻击1起，其他事件1起',
    '该资产共发现在2个高危及以上漏洞',
    '该资产共发现2个弱口令',
    '该资产共发现6个风险暴露面。含3个非Web服务（如SSH、RDP等）与3个Web服务（如Tomcat、nginx）',
    '该资产已安装aES'
  ]);
  assert.strictEqual(topDetailStats.assets['10.0.2.2'].highAndAboveVulnerabilities, 1);
  assert.strictEqual(topDetailStats.assets['10.0.2.2'].weakPasswords, 1);
  assert.strictEqual(topDetailStats.assets['10.0.2.2'].totalExposures, 2);
  assert.strictEqual(topDetailStats.assets['10.0.2.2'].webExposures, 1);
  assert.strictEqual(topDetailStats.assets['10.0.2.2'].nonWebExposures, 1);
  assert.deepStrictEqual(topDetailStats.assets['10.0.2.2'].webComponentExamples, ['apache']);
  assert.deepStrictEqual(topDetailStats.assets['10.0.2.2'].nonWebServiceExamples, ['Redis']);
  assert.strictEqual(topDetailStats.assets['10.0.2.2'].hasAes, false);
  assert.strictEqual(topDetailStats.assets['10.0.2.2'].detailLines[4], '该资产尚未安装aES');

  const emptyExampleDetailStats = await summarizeTopRiskAssetDetails({
    incidentExcelPath: topDetailIncidentPath,
    assetExcelPath: topDetailAssetPath,
    weakPasswordExcelPath: topDetailWeakpwdPath,
    vulnerabilityExcelPath: topDetailVulnPath,
    exposureExcelPath: topDetailExposurePath,
    topAssets: [{ ip: '10.0.2.3' }],
    c2Ids: [],
    virusIds: [],
    exploitIds: []
  });
  assert.deepStrictEqual(
    emptyExampleDetailStats.assets['10.0.2.3'].detailLines,
    ['该资产尚未安装aES']
  );

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
  assert.strictEqual(managedStats.managedAssetContainedEvents, 3, '遏制事件数应为 3（事件1,2,5；已遏制+处置完成）');
  assert.strictEqual(managedStats.managedAssetDisposedEvents, 2, '处置完成事件数应为 2（事件1,5）');
  assert.strictEqual(managedStats.managedAssetCount, 3, '托管资产IP数应为 3（10.5.40.62, 10.5.40.63, 172.16.0.8）');
  assert.strictEqual(managedStats.managedEventCloseRate, 50, '闭环率应为 50%');
  assert.strictEqual(managedStats.managedAvgResponseTime, 37.5, '平均响应时长应为 37.5 分钟（(30+45)/2，由完成时间-事件创建时间计算）');

  // 最多类型事件 TOP1
  assert.strictEqual(typeof managedStats.topEventType, 'string', 'topEventType 应为字符串');
  assert.strictEqual(managedStats.topEventType, '漏洞利用', '最多事件类型应为 漏洞利用');

  // TOP3 业务系统名称（取 businessSystemEventDistribution 前三项 name，拼接为文本）
  assert.strictEqual(typeof managedStats.top3BusinessSystems, 'string', 'top3BusinessSystems 应为字符串');
  assert.strictEqual(managedStats.top3BusinessSystems, 'OA系统、ERP系统、VPN系统', 'TOP3 应为 OA系统、ERP系统、VPN系统');

  // 业务系统安全事件分布（最多 5 项，不补"其他"）
  assert.ok(Array.isArray(managedStats.businessSystemEventDistribution), 'businessSystemEventDistribution 应为数组');
  assert.strictEqual(managedStats.businessSystemEventDistribution.length, 4, '共有4个业务系统（不到5项，不加"其他"）');
  assert.strictEqual(managedStats.businessSystemEventDistribution[0].name, 'OA系统', 'TOP1 应为OA系统');
  assert.strictEqual(managedStats.businessSystemEventDistribution[0].value, 2, 'OA系统应有2起事件');
  assert.strictEqual(managedStats.businessSystemEventDistribution[0].highRisk, 2, 'OA系统高危及以上事件应为2');
  assert.strictEqual(managedStats.businessSystemEventDistribution[1].name, 'ERP系统', 'TOP2 应为ERP系统');
  assert.strictEqual(managedStats.businessSystemEventDistribution[1].value, 1, 'ERP系统应有1起事件');
  assert.strictEqual(managedStats.businessSystemEventDistribution[1].highRisk, 1, 'ERP系统高危及以上事件应为1');
  assert.strictEqual(managedStats.businessSystemEventDistribution[2].name, 'VPN系统', 'TOP3 应为VPN系统');
  assert.strictEqual(managedStats.businessSystemEventDistribution[2].highRisk, 0, 'VPN系统高危及以上事件应为0');
  assert.strictEqual(managedStats.businessSystemEventDistribution[3].name, '邮件系统', 'TOP4 应为邮件系统');
  assert.strictEqual(managedStats.businessSystemEventDistribution[3].highRisk, 0, '邮件系统高危及以上事件应为0');

  // 等级优先排序验证：高等级少量事件应排在低等级大量事件前
  const severityIncidentPath = path.join(tmpDir, 'incident-severity-rank.xlsx');
  const severityIncidentPythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["等级", "处置状态", "影响资产", "安全事件一级分类", "完成时间", "事件创建时间"])',
    'ws.append(["高危", "处置中", "10.5.40.63(未归类组)", "病毒木马", "", "2026-06-20 10:00:00"])',
    'ws.append(["中危", "处置中", "172.16.0.8(组B)", "暴力破解", "", "2026-06-20 10:00:00"])',
    'ws.append(["中危", "处置中", "172.16.0.8(组B)", "暴力破解", "", "2026-06-20 10:05:00"])',
    'ws.append(["中危", "处置中", "172.16.0.8(组B)", "暴力破解", "", "2026-06-20 10:10:00"])',
    'ws.append(["中危", "处置中", "172.16.0.8(组B)", "暴力破解", "", "2026-06-20 10:15:00"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  execFileSync('python', ['-c', severityIncidentPythonCode, severityIncidentPath], {
    encoding: 'utf8',
    stdio: 'pipe'
  });

  const severityRankStats = await summarizeManagedAssetIncidents(assetExcelPath, severityIncidentPath);
  assert.strictEqual(severityRankStats.businessSystemEventDistribution.length, 2, '应仅返回命中的2个业务系统');
  assert.strictEqual(severityRankStats.businessSystemEventDistribution[0].name, 'ERP系统', '高危事件业务系统应排在前面');
  assert.strictEqual(severityRankStats.businessSystemEventDistribution[0].value, 1, 'ERP系统应有1起事件');
  assert.strictEqual(severityRankStats.businessSystemEventDistribution[0].highRisk, 1, 'ERP系统高危及以上事件应为1');
  assert.strictEqual(severityRankStats.businessSystemEventDistribution[1].name, '邮件系统', '中危事件更多的系统应排在后面');
  assert.strictEqual(severityRankStats.businessSystemEventDistribution[1].value, 4, '邮件系统应有4起事件');
  assert.strictEqual(severityRankStats.businessSystemEventDistribution[1].highRisk, 0, '邮件系统高危及以上事件应为0');

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
