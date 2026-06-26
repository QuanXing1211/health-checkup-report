'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { summarizeIncidentStatus } = require('../src/incident_excel_stats');

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-report-'));
  const excelPath = path.join(tmpDir, 'incident.xlsx');

  const pythonCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["等级", "处置状态", "影响资产"])',
    'ws.append(["严重", "处置完成", "10.5.40.62(未归类组)"])',
    'ws.append(["高危", "已遏制", "10.5.40.63(未归类组)"])',
    'ws.append(["高危", "处置中", "10.5.40.62(未归类组)"])',
    'ws.append(["中危", "处置完成", "资产：192.168.1.10(组A)，172.16.0.8(组B)"])',
    'ws.append(["低危", "处置完成", "172.16.0.8(组B)"])',
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

  console.log('incident_excel_stats.test.js passed');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
