'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

function runPython(args) {
  return execFileSync('python', args, {
    encoding: 'utf8',
    stdio: 'pipe',
    env: Object.assign({}, process.env, { PYTHONIOENCODING: 'utf-8' })
  });
}

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-list-process-'));
  const inputPath = path.join(tmpDir, 'incident.xlsx');
  const outputDir = path.join(tmpDir, 'out');

  const createWorkbookCode = [
    'from openpyxl import Workbook',
    'import sys',
    'wb = Workbook()',
    'ws = wb.active',
    'ws.append(["事件ID", "最近发生时间", "处置状态"])',
    'for i in range(1, 6):',
    '    ws.append([f"inc-{i:03d}", f"2026-07-04 10:{i:02d}:00", "处置完成"])',
    'wb.save(sys.argv[1])'
  ].join('\n');

  runPython(['-c', createWorkbookCode, inputPath]);

  runPython([
    path.join(__dirname, '..', 'scripts', 'process_risk_list_table.py'),
    'incident',
    inputPath,
    outputDir
  ]);

  const outputPath = path.join(outputDir, 'incident.xlsx');
  assert.ok(fs.existsSync(outputPath), '应输出处理后的事件表');

  const inspectWorkbookCode = [
    'from openpyxl import load_workbook',
    'import json, sys',
    'wb = load_workbook(sys.argv[1], data_only=True)',
    'ws = wb.active',
    'headers = [cell.value for cell in ws[1]]',
    'header_index = {name: idx + 1 for idx, name in enumerate(headers) if name}',
    'rows = []',
    'for row_idx in range(2, 102):',
    '    rows.append({',
    '        "ip": ws.cell(row=row_idx, column=header_index["外网IP地址"]).value,',
    '        "domain": ws.cell(row=row_idx, column=header_index["域名"]).value,',
    '        "file": ws.cell(row=row_idx, column=header_index["文件"]).value,',
    '        "time": ws.cell(row=row_idx, column=header_index["处置时间"]).value,',
    '        "push": ws.cell(row=row_idx, column=header_index["推送状态"]).value,',
    '    })',
    'payload = {"headers": headers, "rows": rows, "max_row": ws.max_row}',
    'print(json.dumps(payload, ensure_ascii=False))'
  ].join('\n');

  const inspectResult = JSON.parse(runPython(['-c', inspectWorkbookCode, outputPath]));

  ['外网IP地址', '域名', '文件', '处置时间', '推送状态'].forEach((name) => {
    assert.ok(inspectResult.headers.includes(name), `应补充列 ${name}`);
  });
  assert.ok(inspectResult.max_row >= 101, '应至少生成 100 行模拟数据');

  const pushes = inspectResult.rows.map((row) => row.push);
  assert.strictEqual(pushes.filter((value) => value === '已推送').length, 50, '应有 50 行已推送');
  assert.strictEqual(pushes.filter((value) => value === '未推送').length, 50, '应有 50 行未推送');

  inspectResult.rows.forEach((row, index) => {
    assert.ok(String(row.ip || '').includes('恶意'), `第 ${index + 1} 行 IP 应包含恶意状态`);
    assert.ok(String(row.domain || '').includes('恶意'), `第 ${index + 1} 行域名应包含恶意状态`);
    assert.ok(String(row.file || '').includes('恶意'), `第 ${index + 1} 行文件应包含恶意状态`);
    assert.ok(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(String(row.time || '')), `第 ${index + 1} 行处置时间格式应参考原表`);
  });

  console.log('process_risk_list_table test passed');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
