'use strict';

const fs = require('fs/promises');
const path = require('path');

const DATA_FIELD_MAP = {
  'ops.devices-v': 'riskOverview.devices',
  'ops.sangfor-v': 'riskDetails.sangfor',
  'ops.af-v': 'riskDetails.af',
  'ops.aes-v': 'riskDetails.aes',
  'ops.sip-v': 'riskDetails.sip',
  'ops.sta-v': 'riskDetails.sta',
  'ops.other_sf-v': 'riskDetails.other_sf',
  'ops.third-v': 'riskDetails.third',
  'ops.log_reduce-v': 'ops.logReduce',
  'ops.alert_reduce-v': 'ops.alertReduce',
  'ops.severe-v': 'ops.severe',
  'ops.high-v': 'ops.high',
  'riskBiz': 'riskOverview.riskBusinessCount',
  'riskAssets': 'riskOverview.riskAssetCount',
  'impactAssets': 'riskOverview.affectedAssetCount'
};

const SECTION_RENDERERS = {
  'assetLedger.summary': renderAssetLedgerSummary,
  'riskOverview.summary': renderRiskOverviewSummary,
  'riskOverview.topRiskAssetsSummary': renderTopRiskAssetsSummary,
  'riskDetails.caseStudy': renderCaseStudySection,
  'riskDetails.potentialLoss': () => '',
  'riskDetail.severeHighEventsPhrase': renderSevereHighEventsPhrase,
  'riskDetail.sangforDeviceBreakdown': renderSangforDeviceBreakdown,
  'riskDetail.severeHighEventsTail': renderSevereHighEventsTail,
  'riskDetail.internetSummary': renderInternetRiskSummary,
  'riskDetail.intranetSummary': renderIntranetRiskSummary,
  'internet.vuln.levelDetail': renderInternetVulnLevelDetail,
  'internet.vuln.prioritySummary': renderInternetVulnPrioritySummary,
  'internet.vuln.topAssetsBlock': renderInternetVulnTopAssetsBlock,
  'intranet.vuln.levelDetail': renderIntranetVulnLevelDetail,
  'intranet.vuln.prioritySummary': renderIntranetVulnPrioritySummary,
  'intranet.vuln.topBlocksGroup': renderIntranetVulnTopBlocksGroup
};

const REPEAT_RENDERERS = {
  'riskOverview.keyRisks': renderKeyRiskRows,
  'riskOverview.topRiskAssets': renderTopRiskAssetRows,
  'riskDetails.highRiskIncidentExamples.vulnExploits': renderVulnExploitRows,
  'riskDetails.highRiskIncidentExamples.viruses': renderVirusRows,
  'riskDetails.highRiskIncidentExamples.c2Connections': renderC2Rows,
  'protection_effectiveness.policy_stats.by_device': renderPolicyByDeviceRows,
  'protection_effectiveness.policy_stats.policy_check_example': renderPolicyCheckExampleRows
};

async function renderReportToFile({ templatePath, outputDir, reportData }) {
  const template = await fs.readFile(templatePath, 'utf8');
  const gradeAssets = extractGradeAssets(template);
  const html = renderTemplate(template, reportData, gradeAssets);
  await fs.mkdir(outputDir, { recursive: true });

  const filename = buildOutputFilename(reportData);
  const outputPath = path.join(outputDir, filename);
  await fs.writeFile(outputPath, html, 'utf8');

  return {
    ok: true,
    html_path: outputPath,
    customer: getProjectBackground(reportData).customerName,
    start: getProjectBackground(reportData).startDate,
    end: getProjectBackground(reportData).endDate
  };
}

function extractGradeAssets(template) {
  const assets = {};
  const re = /'([优劣中差])':\s*'(data:image\/png;base64,[^']+)'/g;
  let m;
  while ((m = re.exec(template)) !== null) {
    assets[m[1]] = m[2];
  }
  return assets;
}

function renderTemplate(template, reportData, gradeAssets) {
  let html = template;

  html = replaceHandlebarsTokens(html, reportData);
  html = renderSections(html, reportData);
  html = renderRepeats(html, reportData);
  html = patchKnownText(html, reportData);
  html = patchDataFields(html, reportData);
  html = patchGrade(html, reportData, gradeAssets);
  html = injectReportData(html, reportData);
  html = patchOps3DeviceCells(html, reportData);
  html = syncPipelineDeviceData(html, reportData);

  return html;
}

function patchGrade(html, data, gradeAssets) {
  const grade = getPath(data, 'scoring.grade');
  if (!grade) return html;

  const gradeText = String(grade).trim();
  if (!['优', '良', '中', '差'].includes(gradeText)) return html;

  html = html.replace(
    /(<html[^>]*\sdata-report-grade=")([^"]*)(")/,
    (match, before, _old, after) => `${before}${gradeText}${after}`
  );

  html = html.replace(
    /(<span[^>]*class="[^"]*sr-grade--)(优|良|中|差)([^"]*"[^>]*data-field="sections\.riskOverview\.grade"[^>]*>)([^<]*)(<\/span>)/,
    (match, prefix, _oldGrade, mid, _oldText, close) => `${prefix}${gradeText}${mid}${gradeText}${close}`
  );

  html = html.replace(
    /(<div[^>]*id="ro5-gauge-card"[^>]*\sdata-grade=")([^"]*)(")/,
    (match, before, _old, after) => `${before}${gradeText}${after}`
  );

  if (gradeAssets && gradeAssets[gradeText]) {
    const newSrc = gradeAssets[gradeText];
    html = html.replace(
      /(<img[^>]*id="ro5-gauge-img"[^>]*\ssrc=")([^"]*)(")/,
      (match, before, _old, after) => `${before}${newSrc}${after}`
    );
  }

  return html;
}

function replaceHandlebarsTokens(html, data) {
  return html.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (match, keyPath) => {
    const value = getPath(data, keyPath);
    if (value === undefined || value === null) return '';
    if (typeof value === 'object') return JSON.stringify(value);
    return escapeHtml(String(value));
  });
}

function patchKnownText(html, data) {
  const projectBackground = getProjectBackground(data);
  const customer = projectBackground.customerName || '';
  const start = projectBackground.startDate || '';
  const end = projectBackground.endDate || '';
  const title = projectBackground.title || '安全体检报告';
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
  return html.replace(/(<[^>]+data-field="([^"]+)"[^>]*>)(.*?)(<\/[^>]+>)/g, (match, open, field, inner, close) => {
    const keyPath = DATA_FIELD_MAP[field] || field;
    const value = getPath(data, keyPath);
    return value === undefined || value === null ? match : `${open}${escapeHtml(String(value))}${close}`;
  });
}

function renderSections(html, data) {
  return html.replace(/<([a-zA-Z0-9]+)([^>]*)data-section="([^"]+)"([^>]*)><\/\1>/g, (match, tag, before, sectionName, after) => {
    const renderer = SECTION_RENDERERS[sectionName];
    if (!renderer) {
      return match;
    }

    return `<${tag}${before}data-section="${sectionName}"${after}>${renderer(data)}</${tag}>`;
  });
}

function renderRepeats(html, data) {
  return html.replace(/<tbody([^>]*)data-repeat="([^"]+)"([^>]*)><\/tbody>/g, (match, before, repeatName, after) => {
    const renderer = REPEAT_RENDERERS[repeatName];
    if (!renderer) {
      return match;
    }

    const rows = getPath(data, repeatName) || [];
    return `<tbody${before}data-repeat="${repeatName}"${after}>${renderer(rows)}</tbody>`;
  });
}

function renderAssetLedgerSummary(data) {
  const assetLedger = data.assetLedger || {};
  return [
    paragraph(`【资产统计】台账资产${displayValue(assetLedger.manage_asset)}个，核心资产${displayValue(assetLedger.core_asset)}个，7天内即将退库${displayValue(assetLedger.ready_to_outbound)}个`),
    paragraph(`【资产类型分布】${formatNameValueList(assetLedger.typeDistribution)}`),
    paragraph(`【资产防护统计】${formatNameValueList(assetLedger.protectionDistribution)}`),
    paragraph(`【互联网暴露资产】${formatNameValueList(assetLedger.internetExposureDistribution)}`)
  ].join('');
}

function renderSevereHighEventsPhrase(data) {
  const details = data.riskDetails || {};
  const severe = Number(details.severeEvents || 0);
  const high = Number(details.highEvents || 0);

  const parts = [];
  if (severe > 0) parts.push(`严重事件 <strong>${severe}</strong> 起`);
  if (high > 0) parts.push(`高危事件 <strong>${high}</strong> 起`);

  if (!parts.length) return '';
  return `（${parts.join('、')}）`;
}

function renderSangforDeviceBreakdown(data) {
  const details = data.riskDetails || {};
  const items = [
    { label: 'AF', value: Number(details.af || 0) },
    { label: 'aES', value: Number(details.aes || 0) },
    { label: 'SIP', value: Number(details.sip || 0) },
    { label: 'STA', value: Number(details.sta || 0) },
    { label: '其他', value: Number(details.other_sf || 0) }
  ];

  const parts = items.filter((it) => it.value > 0).map((it) => `${it.label} <strong>${it.value}</strong> 个`);
  if (!parts.length) return '';
  return `（${parts.join('、')}）`;
}

function renderSevereHighEventsTail(data) {
  const details = data.riskDetails || {};
  const severe = Number(details.severeEvents || 0);
  const high = Number(details.highEvents || 0);

  const parts = [];
  if (severe > 0) parts.push(`严重事件 <strong>${severe}</strong> 起`);
  if (high > 0) parts.push(`高危事件 <strong>${high}</strong> 起`);

  if (!parts.length) return '';
  return `，其中${parts.join('、')}`;
}

function renderRiskOverviewSummary(data) {
  const overview = data.riskOverview || {};
  const ranking = Array.isArray(overview.coreBusinessSystemRanking)
    ? overview.coreBusinessSystemRanking.filter(Boolean)
    : [];

  // 没有业务系统：只显示简化版概述，不带排序文案和后半句
  if (ranking.length === 0) {
    return paragraph(`本次安全体检中，您的核心业务系统存在 <strong>${num(overview.securityRiskTotal)}</strong> 个安全风险。`);
  }

  // 根据业务系统数量构建排序文案
  let rankingText;
  if (ranking.length === 1) {
    rankingText = `「<strong>${escapeHtml(ranking[0])}</strong>」`;
  } else if (ranking.length === 2) {
    rankingText = `「${ranking.map((name) => `<strong>${escapeHtml(name)}</strong>`).join('、')}」`;
  } else {
    rankingText = `「${ranking.slice(0, 3).map((name) => `<strong>${escapeHtml(name)}</strong>`).join('、')}等」`;
  }

  const topSystemText = overview.maxRiskSystem
    ? `【<strong>${escapeHtml(overview.maxRiskSystem)}</strong>】`
    : '【<strong>暂无</strong>】';

  return paragraph(`本次安全体检中，您的核心业务系统${rankingText}存在 <strong>${num(overview.securityRiskTotal)}</strong> 个安全风险，其中${topSystemText}风险较大，系统下的资产存在 <strong>${num(overview.highAndAboveRiskCount)}</strong> 个高危及以上的安全风险。`);
}

function renderKeyRiskRows(rows) {
  if (!rows.length) {
    return '<tr><td colspan="5">暂无关键风险数据</td></tr>';
  }

  return rows.map((row) => [
    '<tr>',
    `<td>${escapeHtml(row.risk || '')}</td>`,
    `<td>${escapeHtml(row.description || '')}</td>`,
    `<td>${escapeHtml(row.impact || '')}</td>`,
    `<td>${formatLines(row.strategy)}</td>`,
    `<td>${formatLines(row.status)}</td>`,
    '</tr>'
  ].join('')).join('');
}


function renderTopRiskAssetsSummary(data) {
  const rows = Array.isArray(data && data.riskOverview && data.riskOverview.topRiskAssets)
    ? data.riskOverview.topRiskAssets.filter(Boolean)
    : [];
  const topTargets = rows
    .map((row) => String(row.businessSystem || row.ip || '').trim())
    .filter(Boolean)
    .filter((value, index, list) => list.indexOf(value) === index)
    .slice(0, 2);

  const targetText = topTargets.length
    ? topTargets.map((name) => `<strong>${escapeHtml(name)}</strong>`).join('、')
    : '<strong>重点风险资产</strong>';

  return `综上，贵公司当前的安全建设水位有一定差距，随时可能面临数据泄露、系统破坏导致业务中断以及由此带来的经济损失、信誉损害、公信力下降等更为致命的风险。修复方案重点针对 ${targetText}。`;
}

function renderCaseStudySection(data) {
  const caseStudy = (data && data.riskDetails && data.riskDetails.caseStudy) || {};
  const attackTimeline = Array.isArray(caseStudy.attackTimeline) ? caseStudy.attackTimeline : [];
  const defenseTimeline = Array.isArray(caseStudy.defenseTimeline) ? caseStudy.defenseTimeline : [];

  if (!attackTimeline.length && !defenseTimeline.length) {
    return '';
  }

  const attackGroups = groupAttackTimelineByStage(attackTimeline);
  const rowCount = Math.max(attackGroups.length, defenseTimeline.length);
  const rows = [];

  for (let index = 0; index < rowCount; index += 1) {
    const attackGroup = attackGroups[index];
    const defenseItem = defenseTimeline[index];
    rows.push([
      '<div class="tm-row">',
      attackGroup ? renderAttackTimelineColumn(attackGroup, index) : '<div class="tm-left"></div>',
      `<div class="tm-dot ${resolveCaseStudyDotClass(attackGroup, defenseItem)}"></div>`,
      defenseItem ? renderDefenseTimelineColumn(defenseItem) : '<div class="tm-right"></div>',
      '</div>'
    ].join(''));
  }

  return `<div class="sr-attack-chain"><div class="tm">${rows.join('')}</div></div>`;
}

function renderTopRiskAssetRows(rows) {
  if (!Array.isArray(rows) || !rows.length) {
    return '<tr><td colspan="3">暂无风险资产 TOP5 数据</td></tr>';
  }

  return rows.slice(0, 5).map((row) => {
    const ip = String(row.ip || '').trim();
    const managedStatus = String(row.managedStatus || '').trim();
    const businessSystem = String(row.businessSystem || '').trim();
    const riskCount = Number(row.riskCount || 0);
    const managedTag = managedStatus
      ? `<span class="sr-tag sr-tag--light sr-tag--${managedStatusLevel(managedStatus)}">${escapeHtml(managedStatus)}</span>`
      : '';
    const detailLines = Array.isArray(row.detailLines) && row.detailLines.length
      ? row.detailLines.map((line) => escapeHtml(String(line)))
      : [
        businessSystem ? `所属业务：${escapeHtml(businessSystem)}` : '所属业务：暂无',
        managedStatus ? `托管状态：${escapeHtml(managedStatus)}` : '托管状态：暂无'
      ];

    return [
      '<tr>',
      `<td class="sr-top5-asset"><div class="sr-top5-asset-ip-row"><span class="sr-top5-asset-ip">${escapeHtml(ip)}</span>${managedTag}</div><div class="sr-top5-asset-biz">${escapeHtml(businessSystem || '暂无业务')}</div></td>`,
      `<td><strong>${riskCount}</strong></td>`,
      `<td>${detailLines.join('<br>')}</td>`,
      '</tr>'
    ].join('');
  }).join('');
}

function renderVulnExploitRows(rows) {
  if (!rows.length) {
    return '<tr><td colspan="4">暂无漏洞利用事件</td></tr>';
  }

  return rows.slice(0, 5).map((row) => [
    '<tr>',
    `<td><span class="sr-event-name">${escapeHtml(row.eventName || '')}</span></td>`,
    `<td>${escapeHtml(row.affectedAsset || '')}</td>`,
    `<td>${escapeHtml(row.lastOccurredAt || '')}</td>`,
    `<td>${renderStatusTag(row.disposalStatus)}</td>`,
    '</tr>'
  ].join('')).join('');
}

function renderVirusRows(rows) {
  if (!rows.length) {
    return '<tr><td colspan="4">暂无病毒木马事件</td></tr>';
  }

  return rows.slice(0, 5).map((row) => [
    '<tr>',
    `<td>${escapeHtml(row.affectedAsset || '')}</td>`,
    `<td><span class="sr-event-name">${formatMultiValueCell(row.md5 || '')}</span></td>`,
    `<td>${escapeHtml(row.lastOccurredAt || '')}</td>`,
    `<td>${renderStatusTag(row.disposalStatus)}</td>`,
    '</tr>'
  ].join('')).join('');
}

function renderC2Rows(rows) {
  if (!rows.length) {
    return '<tr><td colspan="4">暂无 C2 外联事件</td></tr>';
  }

  return rows.slice(0, 5).map((row) => [
    '<tr>',
    `<td>${escapeHtml(row.affectedAsset || '')}</td>`,
    `<td><span class="sr-event-name">${formatMultiValueCell(row.ioc || '')}</span></td>`,
    `<td>${escapeHtml(row.lastOccurredAt || '')}</td>`,
    `<td>${renderStatusTag(row.disposalStatus)}</td>`,
    '</tr>'
  ].join('')).join('');
}

function renderPolicyByDeviceRows(rows) {
  if (!Array.isArray(rows) || !rows.length) {
    return '<tr><td colspan="4">暂无策略检查数据</td></tr>';
  }

  return rows.map((row, index) => {
    const checkCount = Number(row && row.check_count) || 0;
    const abnormalCount = Number(row && row.abnormal_count) || 0;
    const riskSpan = abnormalCount > 0
      ? `<span class="sr-stat-risk">（<span class="sr-text-danger"><strong>${abnormalCount}</strong></span>）</span>`
      : '';
    return [
      '<tr>',
      `<td>${index + 1}</td>`,
      `<td>${escapeHtml(row.dev_type || '')}</td>`,
      `<td>${escapeHtml(row.dev_name || '')}</td>`,
      `<td><strong>${checkCount}</strong>${riskSpan}</td>`,
      '</tr>'
    ].join('');
  }).join('');
}

function renderPolicyCheckExampleRows(rows) {
  if (!Array.isArray(rows) || !rows.length) {
    return '<tr><td colspan="6">暂无策略检查异常项</td></tr>';
  }

  return rows.map((row, index) => {
    const devTypeTag = renderDevTypeTag(row.dev_type);
    const statusTag = renderPolicyStatusTag(row.policy_status);
    return [
      '<tr>',
      `<td>${index + 1}</td>`,
      `<td><div class="sr-component-name-row"><span class="sr-component-name">${escapeHtml(row.dev_name || '')}</span>${devTypeTag}</div></td>`,
      `<td>${escapeHtml(row.name || '')}</td>`,
      `<td>${statusTag}</td>`,
      `<td>${escapeHtml(row.description || '')}</td>`,
      `<td>${escapeHtml(row.risk_desc || '')}</td>`,
      '</tr>'
    ].join('');
  }).join('');
}

function renderDevTypeTag(devType) {
  const text = String(devType || '').trim();
  if (!text || text === '未知') return '';
  return `<span class="sr-tag sr-tag--light sr-tag--blue">${escapeHtml(text)}</span>`;
}

function renderPolicyStatusTag(status) {
  const text = String(status || '').trim();
  if (!text) return '';
  const level = policyStatusLevel(text);
  return `<span class="sr-tag sr-tag--light sr-tag--${level}">${escapeHtml(text)}</span>`;
}

function policyStatusLevel(text) {
  if (/异常|失败|过期|未开通|未启用/.test(text)) return 'high';
  if (/仅上报|不处置|未处置|待处置/.test(text)) return 'medium';
  if (/正常|生效|已处置|完成/.test(text)) return 'success';
  return 'medium';
}

function paragraph(text) {
  return `<p class="sr-p">${text}</p>`;
}

function num(value) {
  return escapeHtml(String(value === undefined || value === null ? 0 : value));
}

function displayValue(value) {
  return escapeHtml(String(value === undefined || value === null ? '暂无数据' : value));
}

function formatNameValueList(items) {
  if (!Array.isArray(items) || !items.length) {
    return '暂无数据';
  }

  return items.map((item) => `${escapeHtml(String(item.name || '未命名'))}${num(item.value)}个`).join('，');
}

function formatLines(value) {
  const lines = Array.isArray(value) ? value : [value || ''];
  return lines.map((line, index) => `${index + 1}.${escapeHtml(String(line))}`).join('<br>');
}

function formatMultiValueCell(value) {
  return String(value || '')
    .split('、')
    .map((item) => escapeHtml(item.trim()))
    .filter(Boolean)
    .join('<br>');
}

function renderStatusTag(status) {
  const text = String(status || '').trim();
  const level = eventStatusLevel(text);
  return `<span class="sr-tag sr-tag--light sr-tag--${level}">${escapeHtml(text)}</span>`;
}

function eventStatusLevel(text) {
  if (/待处置/.test(text)) return 'high';
  if (/处置中/.test(text)) return 'warning';
  if (/处置完成|已处置/.test(text)) return 'success';
  if (/挂起/.test(text)) return 'medium-low';
  if (/已忽略/.test(text)) return 'info';
  if (/已遏制/.test(text)) return 'medium';
  return 'info';
}

function managedStatusLevel(text) {
  if (/未托管|未纳管/.test(text)) return 'medium';
  if (/已托管|已纳管/.test(text)) return 'success';
  return 'info';
}

function groupAttackTimelineByStage(rows) {
  const groups = [];
  const groupMap = new Map();

  rows.forEach((row) => {
    if (!row) return;
    const stageId = String(row.stageId || '').trim();
    const stageName = String(row.stageName || '').trim();
    const key = `${stageId}::${stageName}`;
    if (!groupMap.has(key)) {
      const group = { stageId, stageName, items: [] };
      groupMap.set(key, group);
      groups.push(group);
    }
    groupMap.get(key).items.push(row);
  });

  return groups;
}

function renderAttackTimelineColumn(group, index) {
  const stageName = String(group.stageName || group.stageId || '未知阶段').trim();
  const stageLabel = `阶段${formatChineseStageIndex(index + 1)}：${escapeHtml(stageName)}`;
  const entries = group.items.map((item) => {
    const time = formatCaseStudyTimestamp(item && item.timestamp);
    const narrative = escapeHtml(String((item && item.narrative) || '').trim());
    return [
      time ? `<div class="tm-time">${time}</div>` : '',
      narrative ? `<div class="tm-desc">${narrative}</div>` : ''
    ].join('');
  }).join('');

  return [
    '<div class="tm-left">',
    '<div class="tm-card atk">',
    `<div class="tm-tag">${stageLabel}</div>`,
    entries || '<div class="tm-desc">暂无攻击侧时间线</div>',
    '<span class="tm-arrow"></span>',
    '</div>',
    '</div>'
  ].join('');
}

function renderDefenseTimelineColumn(item) {
  const label = escapeHtml(String((item && item.label) || '防守时间线').trim());
  const time = formatCaseStudyTimestamp(item && item.timestamp);

  return [
    '<div class="tm-right">',
    '<div class="tm-card def">',
    `<div class="tm-tag">${label}</div>`,
    time ? `<div class="tm-time">${time}</div>` : '',
    '<span class="tm-arrow"></span>',
    '</div>',
    '</div>'
  ].join('');
}

function resolveCaseStudyDotClass(attackGroup, defenseItem) {
  if (attackGroup) return 'rd';
  if (defenseItem) return 'bl';
  return 'gn';
}

function formatCaseStudyTimestamp(value) {
  const timestamp = Number(value);
  if (!Number.isFinite(timestamp) || timestamp <= 0) return '';
  const date = new Date(timestamp * 1000);
  if (Number.isNaN(date.getTime())) return '';

  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  return `${month}-${day} ${hours}:${minutes}`;
}

function formatChineseStageIndex(index) {
  const numerals = ['零', '一', '二', '三', '四', '五', '六', '七', '八', '九', '十'];
  if (index <= 10) {
    return numerals[index] || String(index);
  }
  if (index < 20) {
    return `十${numerals[index - 10] || ''}`;
  }
  if (index === 20) {
    return '二十';
  }
  return String(index);
}

function injectReportData(html, data) {
  const payload = JSON.stringify(data).replace(/</g, '\\u003c');
  const script = `<script>window.SECURITY_REPORT_DATA=${payload};</script>`;

  if (html.includes('window.SECURITY_REPORT_DATA=')) {
    return html.replace(/<script>window\.SECURITY_REPORT_DATA=.*?<\/script>/, script);
  }

  return html.replace('</head>', `${script}\n</head>`);
}

function patchOps3DeviceCells(html, data) {
  // 4.1.1 设备格子：值为0的服务端直接删除元素，不依赖浏览器端JS
  // 匹配设备格子: <div class="ops3-device-cell" data-hide-ops3="riskDetails.XX"><span class="nm">XX</span><span class="nv">0</span></div>
  html = html.replace(
    /<div\s+class="ops3-device-cell"\s+data-hide-ops3="riskDetails\.\w+"\s*>\s*<span\s+class="nm">[^<]*<\/span>\s*<span\s+class="nv">0<\/span>\s*<\/div>/g,
    ''
  );

  // 第三方合计格子（class 中有 ops3-layer ops3-device-third 两个类名）
  html = html.replace(
    /<div\s+class="[^"]*ops3-device-third[^"]*"\s+data-hide-ops3="riskDetails\.\w+"\s*>\s*<span\s+class="nm">[^<]*<\/span>\s*<span\s+class="nv">0<\/span>\s*<\/div>/g,
    ''
  );

  // 如果第三方设备为0，也隐藏"第三方设备"标签
  const rd = data.riskDetails || {};
  if (Number(rd.third) === 0) {
    html = html.replace(
      /<p\s+class="ops3-layer ops3-ingest-label ops3-ingest-label--3rd">[^<]*<\/p>/g,
      ''
    );
  }

  // 如果深信服设备为0，也隐藏"深信服设备"标签
  if (Number(rd.sangfor) === 0) {
    html = html.replace(
      /<p\s+class="ops3-layer ops3-ingest-label ops3-ingest-label--sf">[^<]*<\/p>/g,
      ''
    );
  }

  return html;
}

function syncPipelineDeviceData(html, data) {
  // 在 bootPipeline 函数开头注入代码，从 SECURITY_REPORT_DATA 同步设备数据到 XDR_PIPELINE_DATA
  // 确保 Canvas 管道图的 buildDeviceSources 能读到正确的设备数量
  const syncCode = `      var reportRd = (window.SECURITY_REPORT_DATA || {}).riskDetails || {};
      if (reportRd.devices !== undefined) window.XDR_PIPELINE_DATA.devices = Number(reportRd.devices) || window.XDR_PIPELINE_DATA.devices;
      if (reportRd.af !== undefined) window.XDR_PIPELINE_DATA.af = Number(reportRd.af) || 0;
      if (reportRd.aes !== undefined) window.XDR_PIPELINE_DATA.aes = Number(reportRd.aes) || 0;
      if (reportRd.sip !== undefined) window.XDR_PIPELINE_DATA.sip = Number(reportRd.sip) || 0;
      if (reportRd.sta !== undefined) window.XDR_PIPELINE_DATA.sta = Number(reportRd.sta) || 0;
      if (reportRd.other_sf !== undefined) window.XDR_PIPELINE_DATA.other_sf = Number(reportRd.other_sf) || 0;
      if (reportRd.third !== undefined) window.XDR_PIPELINE_DATA.third = Number(reportRd.third) || 0;
      if (reportRd.sangfor !== undefined) window.XDR_PIPELINE_DATA.sangfor = Number(reportRd.sangfor) || 0;
      syncKpiDom();`;

  // 注入到 bootPipeline 函数体中，在 renderPipeline(0) 之前
  html = html.replace(
    /(function bootPipeline\(\)\s*\{\s*if\s*\(\!pipelineReady\(\)\)\s*\{\s*requestAnimationFrame\(bootPipeline\);\s*return;\s*\})/,
    '$1\n' + syncCode + '\n'
  );

  return html;
}

function buildOutputFilename(data) {
  const projectBackground = getProjectBackground(data);
  const raw = `${projectBackground.customerName || '客户'}_${projectBackground.startDate || 'start'}_${projectBackground.endDate || 'end'}_安全体检报告.html`;
  return raw.replace(/[\\/:*?"<>|]/g, '_');
}

function getPath(obj, keyPath) {
  const normalizedPath = keyPath.startsWith('report.')
    ? `projectBackground.${keyPath.slice('report.'.length)}`
    : keyPath;
  return normalizedPath.split('.').reduce((current, key) => {
    if (current && Object.prototype.hasOwnProperty.call(current, key)) {
      return current[key];
    }
    return undefined;
  }, obj);
}

function getProjectBackground(data) {
  return data.projectBackground || data.report || {};
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

function renderInternetRiskSummary(data) {
  const rd = (data.risk_detail && data.risk_detail.internet) || {};
  const main = (
    `互联网业务总计发现风险 <strong>${num(rd.total)}</strong> 个` +
    `（风险暴露面 <strong>${num(rd.exposure)}</strong> 个、` +
    `漏洞 <strong>${num(rd.vuln)}</strong> 个、` +
    `弱口令 <strong>${num(rd.weak_pwd)}</strong> 个）`
  );
  const tail = rd.high_above
    ? `，其中高危及以上风险 <strong>${num(rd.high_above)}</strong> 个。`
    : `。`;
  return paragraph(main + tail);
}

function renderIntranetRiskSummary(data) {
  const rd = (data.risk_detail && data.risk_detail.intranet) || {};
  const main = (
    `内网核心业务总计发现风险 <strong>${num(rd.total)}</strong> 个` +
    `（漏洞 <strong>${num(rd.vuln)}</strong> 个、` +
    `弱口令 <strong>${num(rd.weak_pwd)}</strong> 个）`
  );
  const tail = rd.high
    ? `，其中高危及以上风险 <strong>${num(rd.high)}</strong> 个。`
    : `。`;
  return paragraph(main + tail);
}

function renderInternetVulnLevelDetail(data) {
  const v = (data.internet && data.internet.vuln) || {};
  if (!v.total) return '';
  return (
    `（严重 <strong>${num(v.critical)}</strong> 个、` +
    `高危 <strong>${num(v.high)}</strong> 个、` +
    `中危 <strong>${num(v.medium)}</strong> 个、` +
    `低危 <strong>${num(v.low)}</strong> 个）`
  );
}

function renderInternetVulnPrioritySummary(data) {
  const v = (data.internet && data.internet.vuln) || {};
  if (!v.total) return '';
  return paragraph(
    `从漏洞修复优先级视角统计，` +
    `急需修复 <strong>${num(v.priority_urgent)}</strong> 个、` +
    `尽快修复 <strong>${num(v.priority_soon)}</strong> 个、` +
    `建议修复 <strong>${num(v.priority_suggest)}</strong> 个。`
  );
}

function renderInternetVulnTopAssetsBlock(data) {
  const v = (data.internet && data.internet.vuln) || {};
  if (!v.total) return '';

  const rows = Array.isArray(v.top_rows) ? v.top_rows : [];
  const tableRows = rows.map((r, i) =>
    '<tr>' +
    `<td>${i + 1}</td>` +
    `<td>${escapeHtml(r.asset)}</td>` +
    '<td class="sr-vuln-priority-stats">' +
    `<div>急需修复：<strong>${num(r.urgent)}</strong>个</div>` +
    `<div>尽快修复：<strong>${num(r.soon)}</strong>个</div>` +
    `<div>建议修复：<strong>${num(r.suggest)}</strong>个</div>` +
    '</td></tr>'
  ).join('');

  return (
    '<p class="report-body sr-p">互联网漏洞风险资产TOP 5如下：</p>\n' +
    '<table class="report-table sr-tbl" id="tbl-internet-vuln-top">' +
    '<thead><tr><th>序号</th><th>风险资产</th><th>漏洞修复优先级</th></tr></thead>' +
    `<tbody>${tableRows}</tbody></table>`
  );
}

function renderIntranetVulnLevelDetail(data) {
  const v = (data.intranet && data.intranet.vuln) || {};
  if (!v.total) return '';
  return (
    `（严重 <strong>${num(v.critical)}</strong> 个、` +
    `高危 <strong>${num(v.high)}</strong> 个、` +
    `中危 <strong>${num(v.medium)}</strong> 个、` +
    `低危 <strong>${num(v.low)}</strong> 个）`
  );
}

function renderIntranetVulnPrioritySummary(data) {
  const v = (data.intranet && data.intranet.vuln) || {};
  if (!v.total) return '';
  return paragraph(
    `从漏洞修复优先级视角统计，` +
    `急需修复 <strong>${num(v.priority_urgent)}</strong> 个、` +
    `尽快修复 <strong>${num(v.priority_soon)}</strong> 个、` +
    `建议修复 <strong>${num(v.priority_suggest)}</strong> 个。`
  );
}

function renderIntranetVulnTopBlocksGroup(data) {
  const v = (data.intranet && data.intranet.vuln) || {};
  if (!v.total) return '';

  const bizRows = Array.isArray(v.biz_top_rows) ? v.biz_top_rows : [];
  const bizTableRows = bizRows.map((r, i) =>
    '<tr>' +
    `<td>${i + 1}</td>` +
    `<td>${escapeHtml(r.asset)}</td>` +
    '<td class="sr-vuln-priority-stats">' +
    `<div>急需修复：<strong>${num(r.urgent)}</strong>个</div>` +
    `<div>尽快修复：<strong>${num(r.soon)}</strong>个</div>` +
    `<div>建议修复：<strong>${num(r.suggest)}</strong>个</div>` +
    '</td></tr>'
  ).join('');

  const assetRows = Array.isArray(v.asset_top_rows) ? v.asset_top_rows : [];
  const assetTableRows = assetRows.map((r, i) =>
    '<tr>' +
    `<td>${i + 1}</td>` +
    `<td>${escapeHtml(r.asset)}</td>` +
    '<td class="sr-vuln-priority-stats">' +
    `<div>急需修复：<strong>${num(r.urgent)}</strong>个</div>` +
    `<div>尽快修复：<strong>${num(r.soon)}</strong>个</div>` +
    `<div>建议修复：<strong>${num(r.suggest)}</strong>个</div>` +
    '</td></tr>'
  ).join('');

  return (
    '<p class="report-body sr-p">业务系统TOP 5如下：</p>\n' +
    '<table class="report-table sr-tbl" id="tbl-biz-vuln-top">' +
    '<thead><tr><th>序号</th><th>风险资产</th><th>漏洞修复优先级</th></tr></thead>' +
    `<tbody>${bizTableRows}</tbody></table>\n` +
    '<p class="report-body sr-p">内网漏洞风险资产TOP 5如下：</p>\n' +
    '<table class="report-table sr-tbl" id="tbl-intra-vuln-top">' +
    '<thead><tr><th>序号</th><th>风险资产</th><th>漏洞修复优先级</th></tr></thead>' +
    `<tbody>${assetTableRows}</tbody></table>`
  );
}

module.exports = {
  renderReportToFile,
  renderTemplate,
  getPath
};
