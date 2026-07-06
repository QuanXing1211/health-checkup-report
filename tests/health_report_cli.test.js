'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const rootDir = path.resolve(__dirname, '..');
const scriptPath = path.join(rootDir, 'health_report.js');

function run(args) {
  return spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: rootDir,
    encoding: 'utf8'
  });
}

const unsupported = run(['xdr-asset-export']);
assert.notStrictEqual(unsupported.status, 0);
assert.match((unsupported.stderr || unsupported.stdout || ''), /Unsupported command: xdr-asset-export/);

const missingXdr = run([
  '--customer', '测试客户',
  '--mssw-cookie-path', 'fake-mssw-cookie.txt'
]);
assert.notStrictEqual(missingXdr.status, 0);
assert.match((missingXdr.stderr || missingXdr.stdout || ''), /Missing required option\(s\): --xdr-cookie-path/);

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-report-cli-'));
const xdrCookiePath = path.join(tmpDir, 'xdr.txt');
const msswCookiePath = path.join(tmpDir, 'mssw.txt');
fs.writeFileSync(xdrCookiePath, 'x-csrf-token=test-token; foo=bar', 'utf8');
fs.writeFileSync(msswCookiePath, 'PHPSESSID=test-session; XSRF-TOKEN=test-xsrf', 'utf8');

const missingMssw = run([
  '--customer', '测试客户',
  '--xdr-cookie-path', xdrCookiePath
]);
assert.notStrictEqual(missingMssw.status, 0);
assert.match((missingMssw.stderr || missingMssw.stdout || ''), /Missing required option\(s\): --mssw-cookie-path/);

console.log('health_report_cli.test.js passed');
