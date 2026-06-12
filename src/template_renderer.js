'use strict';

const fs = require('fs/promises');
const path = require('path');

const DATA_FIELD_MAP = {
  'assets.total': 'assets.total',
  'assets.core': 'assets.core',
  'assets.retire': 'assets.retire',
  'assets.review': 'assets.review',
  'ops.devices-v': 'ops.devices',
  'ops.sangfor-v': 'ops.sangfor',
  'ops.log_reduce-v': 'ops.logReduce',
  'ops.alert_reduce-v': 'ops.alertReduce',
  'ops.severe-v': 'ops.severe',
  'ops.high-v': 'ops.high'
};

async function renderReportToFile({ templatePath, outputDir, reportData }) {
  const template = await fs.readFile(templatePath, 'utf8');
  const html = renderTemplate(template, reportData);
  await fs.mkdir(outputDir, { recursive: true });

  const filename = buildOutputFilename(reportData);
  const outputPath = path.join(outputDir, filename);
  await fs.writeFile(outputPath, html, 'utf8');

  return {
    ok: true,
    html_path: outputPath,
    customer: reportData.report.customerName,
    start: reportData.report.startDate,
    end: reportData.report.endDate
  };
}

function renderTemplate(template, reportData) {
  let html = template;

  html = replaceHandlebarsTokens(html, reportData);
  html = patchKnownText(html, reportData);
  html = patchDataFields(html, reportData);
  html = injectReportData(html, reportData);

  return html;
}

function replaceHandlebarsTokens(html, data) {
  return html.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (match, keyPath) => {
    const value = getPath(data, keyPath);
    return value === undefined || value === null ? '' : escapeHtml(String(value));
  });
}

function patchKnownText(html, data) {
  const report = data.report || {};
  const customer = report.customerName || '';
  const start = report.startDate || '';
  const end = report.endDate || '';
  const title = report.title || '安全体检报告';
  const period = `${start} ~ ${end}`;

  return html
    .replace(/<meta name="report-data-mode" content="[^"]*">/, '<meta name="report-data-mode" content="generated">')
    .replace(/<title>.*?<\/title>/, `<title>${escapeHtml(title)} - ${escapeHtml(customer)}</title>`)
    .replace(/<h1>首次安全体检报告<\/h1>/, `<h1>${escapeHtml(title)}</h1>`)
    .replace(/示例科技有限公司 · 2026-01-01 ~ 2026-03-31/g, `${escapeHtml(customer)} · ${escapeHtml(period)}`)
    .replace(/「示例科技有限公司」/g, `「${escapeHtml(customer)}」`)
    .replace(/示例科技有限公司/g, escapeHtml(customer))
    .replace(/2026-01-01 ~ 2026-03-31/g, escapeHtml(period));
}

function patchDataFields(html, data) {
  let output = html;

  for (const [field, keyPath] of Object.entries(DATA_FIELD_MAP)) {
    const value = getPath(data, keyPath);
    if (value === undefined || value === null) {
      continue;
    }

    const pattern = new RegExp(`(<[^>]+data-field="${escapeRegExp(field)}"[^>]*>)(.*?)(</[^>]+>)`, 'g');
    output = output.replace(pattern, `$1${escapeHtml(String(value))}$3`);
  }

  return output;
}

function injectReportData(html, data) {
  const payload = JSON.stringify(data).replace(/</g, '\\u003c');
  const script = `<script>window.SECURITY_REPORT_DATA=${payload};</script>`;

  if (html.includes('window.SECURITY_REPORT_DATA=')) {
    return html.replace(/<script>window\.SECURITY_REPORT_DATA=.*?<\/script>/, script);
  }

  return html.replace('</head>', `${script}\n</head>`);
}

function buildOutputFilename(data) {
  const report = data.report || {};
  const raw = `${report.customerName || '客户'}_${report.startDate || 'start'}_${report.endDate || 'end'}_安全体检报告.html`;
  return raw.replace(/[\\/:*?"<>|]/g, '_');
}

function getPath(obj, keyPath) {
  return keyPath.split('.').reduce((current, key) => {
    if (current && Object.prototype.hasOwnProperty.call(current, key)) {
      return current[key];
    }
    return undefined;
  }, obj);
}

function escapeHtml(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = {
  renderReportToFile,
  renderTemplate,
  getPath
};

