#!/usr/bin/env node
'use strict';

const path = require('path');
const { parseArgs, requireArgs } = require('./src/args');
const { collectReportData } = require('./src/data_client');
const { renderReportToFile } = require('./src/template_renderer');

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));

  if (!command || command === 'help' || options.help) {
    printHelp();
    return;
  }

  if (command !== 'generate') {
    throw new Error(`Unsupported command: ${command}`);
  }

  requireArgs(options, ['customer', 'start', 'end']);

  const root = __dirname;
  const templatePath = options.template || path.join(root, 'security-report-preview.html');
  const outputDir = options['output-dir'] || path.join(root, 'output');

  const reportData = await collectReportData({
    customer: options.customer,
    customerId: options['customer-id'],
    start: options.start,
    end: options.end,
    cookiePath: options['cookie-path'],
    xdrCookiePath: options['xdr-cookie-path'],
    mock: options.mock !== false && options.mock !== 'false'
  });

  const result = await renderReportToFile({
    templatePath,
    outputDir,
    reportData
  });

  console.log(JSON.stringify(result, null, 2));
}

function printHelp() {
  console.log(`Usage:
  node health_report.js generate --customer "客户名" --start YYYY-MM-DD --end YYYY-MM-DD [options]

Options:
  --customer-id <id>             Optional customer id
  --cookie-path <path>           MSS cookie file path
  --xdr-cookie-path <path>       XDR cookie file path
  --template <path>              HTML template path
  --output-dir <path>            Output directory
  --mock true|false              Use mock data source for skeleton development, default true
`);
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});

