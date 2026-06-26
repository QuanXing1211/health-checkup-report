'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const https = require('https');
const http = require('http');
const path = require('path');

const DEFAULT_XDR_BASE_URL = normalizeBaseUrl(process.env.SANGFOR_XDR_BASE_URL || 'xdr.sangfor.com.cn');
const XDR_ASSET_PAGE_PATH = '/xdr/asset/host-asset';
const ASSET_COUNT_ENDPOINT = '/apps/asset/view/asset/asset_view/count?_method=GET&viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const ASSET_PROTECTION_ENDPOINT = '/apps/asset/view/overview/asset_protection?_method=GET&viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const ASSET_EXPOSURE_ENDPOINT = '/apps/asset/view/overview/asset_exposure?_method=GET&viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const ASSET_TYPE_ENDPOINT = '/apps/asset/view/overview/asset_type?_method=GET&viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const EXPORT_FIELDS_ENDPOINT = '/apps/asset/view/asset/export_fields?_method=GET&viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const EXPORT_ENDPOINT = '/apps/asset/view/asset/export?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const INCIDENT_EXPORT_ADD_ENDPOINT = '/ngsoc/INCIDENT/api/v1/operation/task/add/exportIncidentExcel?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const INCIDENT_EXPORT_RESULT_ENDPOINT = '/ngsoc/INCIDENT/api/v1/operation/task/result?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const INCIDENT_COUNT_ENDPOINT = '/ngsoc/INCIDENT/api/v1/table/count/incidentTableQueryHandler?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const XDR_INCIDENT_PAGE_PATH = '/incident/sec-event';
const INCIDENT_VIEW_INSTANCE_ID = '6734768b73bfc87aeb00462c';
const INCIDENT_SERVICE_INFO = {
  appName: 'incident',
  servletContextPath: '/',
  serviceType: 'batchOperation',
  handler: 'exportIncidentExcel'
};
const INCIDENT_TABLE_SERVICE_INFO = {
  appName: 'incident',
  servletContextPath: '/',
  serviceType: 'table',
  handler: 'incidentTableQueryHandler'
};
const ALERT_QUERY_ENDPOINT = '/ngsoc/INCIDENT/api/v1/table/query/alertTableQueryHandler?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const ALERT_VIEW_INSTANCE_ID = '67aebe12c29c0b7b63b0c51e';
const ALERT_TABLE_SERVICE_INFO = {
  appName: 'incident',
  servletContextPath: '/',
  serviceType: 'table',
  handler: 'alertTableQueryHandler'
};
const GPT_YUNYING_ALERT_QUERY_ENDPOINT = '/ngsoc/GPT_API_JAVA/api/v1/table/query/gptYunyingAlertTableQueryHandler/6a38ac0320c2b912aef72ef6?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const GPT_YUNYING_ALERT_VIEW_INSTANCE_ID = '6a38ac0320c2b912aef72ef6';
const GPT_YUNYING_ALERT_SERVICE_INFO = {
  appName: 'gpt-api-java',
  servletContextPath: '/',
  serviceType: 'table',
  handler: 'gptYunyingAlertTableQueryHandler'
};
const GPT_YUNYING_ALERT_MATCHERS = {
  virusFiles: '病毒木马活动',
  c2ExternalLink: '主机失陷活动',
  exploitAttacks: '漏洞攻击',
  webAttacks: '网站攻击'
};
const DEVICE_LIST_ENDPOINT = '/api/apex/device/v1/devices/list?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const DEVICE_TYPE_INFO_ENDPOINT = '/api/apex/device/v1/branch/dev_type_info?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const THIRD_PARTY_DEVICE_STATS_ENDPOINT = '/api/apex/thirdparty/v1/app/instance/list?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const LOG_SEARCH_COUNT_ENDPOINT = '/api/apex/logsearch/v1/log/search/count?enableCache=true&viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';
const OVERVIEW_COUNT_ENDPOINT = '/ngsoc/INCIDENT/api/v1/overview/count?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false';

// devType 到分类名称的映射
const DEVICE_TYPE_CATEGORIES = {
  aes: [12, 37, 100038, 50038, 100012],  // EDR, CWPP, SaaS-EDR-探针版, EDR-探针版, SAAS EDR
  sip: [9],
  af: [3],
  sta: [25]
};

function classifyDeviceType(devType) {
  for (const [category, types] of Object.entries(DEVICE_TYPE_CATEGORIES)) {
    if (types.includes(devType)) {
      return category;
    }
  }
  return 'other';
}

const INCIDENT_EXPORT_FIELDS = [
  ['mssIncidentServiceStatus', true, 150, 'value'],
  ['severity', true, 90, 'value'],
  ['name', true, 252, 'value'],
  ['uuId', true, 280, 'value'],
  ['hostIp', true, 144, 'value'],
  ['connectStatus', true, 100, 'value'],
  ['timeLimit', true, 150, 'value'],
  ['alertNumber', true, 100, 'value'],
  ['dataSources', true, 86, 'array'],
  ['dealStatus', true, 120, 'value'],
  ['gptResult', true, 150, 'value'],
  ['serviceEventId', true, 92, 'value'],
  ['incidentThreatClass', true, 150, 'value'],
  ['incidentThreatType', true, 150, 'value'],
  ['description', true, 320, 'value', 'disable', false],
  ['threatDefine', true, 180, 'array', 'disable', false],
  ['riskTag', true, 200, 'value', 'disable', false],
  ['responsible', true, 150, 'value', 'disable', false],
  ['newestUsername', true, 150, 'value', 'disable', false],
  ['checkOutUsername', true, 150, 'value', 'disable', false],
  ['startTime', true, 160, 'value', 'disable', false],
  ['endTime', true, 160, 'value', 'desc', false],
  ['logTraceInfo', true, 150, 'value', 'disable', false],
  ['devSourceNames', true, 200, 'array', 'disable', false],
  ['incidentSourceProxy', true, 200, 'value', 'disable', false],
  ['eventEngine', true, 150, 'array', 'disable', false],
  ['whiteStatus', true, 150, 'value', 'disable', false],
  ['eventRuleId', true, 92, 'value', 'disable', false],
  ['soarMatchEventTag', true, 150, 'value', 'disable', false],
  ['remarkInfo', true, 150, 'value', 'disable', false],
  ['platformHostBranchId', true, 150, 'value', 'disable', false],
  ['disposeTime', true, 140, 'value', 'disable', false],
  ['suppressTime', true, 140, 'value', 'disable', false],
  ['platformId', true, 150, 'value', 'disable', false],
  ['platformHostGroupIds', true, 150, 'array', 'disable', false],
  ['hostAssetAnalyzeResult', true, 150, 'value', 'disable', false],
  ['hostBranchId', false, 200, 'value', 'notSortable', false],
  ['hostIpAll', false, null, 'value', 'notSortable', false],
  ['uploadTime', false, null, 'value', 'disable', false],
  ['insertTime', false, null, 'value', 'disable', false],
  ['auditTime', false, null, 'value', 'disable', false],
  ['occurTime', false, null, 'value', 'disable', false],
  ['auditLogTraceInfo', false, null, 'value', 'notSortable', false],
  ['devUId', false, null, 'array', 'notSortable', false],
  ['devUIdProxy', false, null, 'array', 'notSortable', false],
  ['xthAttackIntent', false, null, 'value', 'notSortable', false],
  ['dealAction', false, null, 'value', 'notSortable', false],
  ['id', false, null, 'value', 'notSortable', false],
  ['alertIds', false, null, 'array', 'notSortable', false],
  ['hostGroupIds', false, null, 'array', 'notSortable', false],
  ['hostAssetId', false, null, 'value', 'disable', false],
  ['hostCountryName', false, null, 'value', 'notSortable', false],
  ['hostProvinceName', false, null, 'value', 'notSortable', false],
  ['xthType', false, null, 'value', 'notSortable', false],
  ['xthTag', false, null, 'value', 'notSortable', false],
  ['fromXth', false, null, 'value', 'notSortable', false],
  ['auditType', false, null, 'value', 'notSortable', false],
  ['pendingXth', false, null, 'value', 'notSortable', false],
  ['read', false, null, 'value', 'notSortable', false],
  ['xthConfirm', false, null, 'value', 'notSortable', false],
  ['hostClassifyId', false, null, 'value', 'notSortable', false],
  ['hostClassify1Id', false, null, 'value', 'notSortable', false],
  ['dataAuthorityBranchId', false, null, 'value', 'notSortable', false],
  ['huntingIps', false, null, 'array', 'notSortable', false],
  ['huntingDomains', false, null, 'array', 'notSortable', false],
  ['huntingMD5s', false, null, 'array', 'notSortable', false],
  ['isAutoDispose', false, null, 'value', 'notSortable', false],
  ['phishing', false, null, 'value', 'notSortable', false],
  ['xthExpert', false, null, 'value', 'notSortable', false],
  ['auditFrom', false, null, 'array', 'notSortable', false],
  ['regionId', false, null, 'value', 'notSortable', false],
  ['mssTagType', false, null, 'value', 'notSortable', false],
  ['attackState', false, null, 'value', 'notSortable', false],
  ['platformRole', false, null, 'value', 'notSortable', false],
  ['platformIsDelete', false, null, 'value', 'notSortable', false],
  ['pendingDisableFlag', false, null, 'value', 'notSortable', false],
  ['disposingDisableFlag', false, null, 'value', 'notSortable', false],
  ['disposedDisableFlag', false, null, 'value', 'notSortable', false],
  ['ignoreDisableFlag', false, null, 'value', 'notSortable', false],
  ['hungupDisableFlag', false, null, 'value', 'notSortable', false],
  ['addWhiteDisableFlag', false, null, 'value', 'notSortable', false],
  ['orderDisableFlag', false, null, 'value', 'notSortable', false]
];

function normalizeBaseUrl(value) {
  const raw = String(value || '').trim().replace(/^\./, '');
  if (!raw) return '';

  const withScheme = raw.includes('://') ? raw : `https://${raw}`;
  try {
    return new URL(withScheme).hostname;
  } catch (error) {
    return raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  }
}

function cookiePairsToString(pairs) {
  return pairs
    .filter((item) => item && item.name && item.value !== undefined)
    .map((item) => `${item.name}=${item.value}`)
    .join('; ');
}

function inferXdrBaseUrlFromCookiePairs(pairs) {
  if (!Array.isArray(pairs)) return '';

  const matched = pairs
    .map((item) => normalizeBaseUrl(item && item.domain ? item.domain : ''))
    .find((domain) => /^xdr[a-z0-9-]*\.sangfor\.com\.cn$/i.test(domain));

  return matched || '';
}

function inferXdrBaseUrlsFromText(text) {
  const matches = String(text || '').match(/\.?xdr[a-z0-9-]*\.sangfor\.com\.cn/ig) || [];
  return unique(matches.map((item) => normalizeBaseUrl(item)));
}

function unique(items) {
  return [...new Set(items.filter(Boolean))];
}

function logInfo(logger, message) {
  if (typeof logger === 'function') {
    logger(message);
  }
}

function parseCookieString(cookieString) {
  const cookies = {};

  String(cookieString || '')
    .split(';')
    .forEach((cookie) => {
      const [name, ...valueParts] = cookie.trim().split('=');
      if (!name) return;
      cookies[name.trim()] = valueParts.join('=').trim();
    });

  return cookies;
}

function extractCsrfToken(cookieString) {
  const cookies = parseCookieString(cookieString);
  const tokenKeys = ['csrf_token', 'x-csrf-token', 'X-Csrftoken', 'csrftoken', '_csrf'];

  for (const key of tokenKeys) {
    if (cookies[key]) {
      return cookies[key];
    }
  }

  throw new Error('无法从 XDR Cookie 中找到 x-csrf-token');
}

function normalizeCookieContent(rawContent) {
  const content = String(rawContent || '').trim();
  if (!content) {
    throw new Error('XDR Cookie 文件内容为空');
  }

  if (content.startsWith('{') || content.startsWith('[')) {
    const parsed = JSON.parse(content);

    if (Array.isArray(parsed)) {
      return {
        cookieString: cookiePairsToString(parsed),
        csrfToken: null,
        xdrBaseUrl: inferXdrBaseUrlFromCookiePairs(parsed)
      };
    }

    const cookieString = parsed.cookie || parsed.cookieString || parsed.Cookie || parsed.cookiesText;
    const xdrBaseUrl = normalizeBaseUrl(parsed.xdrBaseUrl || parsed.baseUrl || parsed.domain);
    if (typeof cookieString === 'string' && cookieString.trim()) {
      return {
        cookieString: cookieString.trim(),
        csrfToken: parsed.csrfToken || parsed.xCsrftoken || parsed['x-csrf-token'] || null,
        xdrBaseUrl
      };
    }

    if (Array.isArray(parsed.cookies)) {
      return {
        cookieString: cookiePairsToString(parsed.cookies),
        csrfToken: parsed.csrfToken || parsed.xCsrftoken || parsed['x-csrf-token'] || null,
        xdrBaseUrl: xdrBaseUrl || inferXdrBaseUrlFromCookiePairs(parsed.cookies)
      };
    }

    throw new Error('无法识别 XDR Cookie 的 JSON 格式');
  }

  return {
    cookieString: content,
    csrfToken: null,
    xdrBaseUrl: ''
  };
}

async function readXdrCookieInfo(cookiePath) {
  if (!cookiePath) {
    throw new Error('Real mode requires --xdr-cookie-path');
  }

  const resolvedPath = await resolveCookiePath(cookiePath);
  const rawContent = await fsp.readFile(resolvedPath, 'utf8');
  const normalized = normalizeCookieContent(rawContent);
  const cookieString = normalized.cookieString;

  return {
    resolvedPath,
    rawContent,
    cookieString,
    csrfToken: normalized.csrfToken || extractCsrfToken(cookieString),
    xdrBaseUrl: normalized.xdrBaseUrl || '',
    xdrBaseUrlCandidates: unique([
      normalized.xdrBaseUrl,
      ...inferXdrBaseUrlsFromText(rawContent)
    ]),
    cookies: parseCookieString(cookieString)
  };
}

async function resolveCookiePath(cookiePath) {
  const stat = await fsp.stat(cookiePath);
  if (stat.isFile()) {
    return cookiePath;
  }

  const candidates = await fsp.readdir(cookiePath, { withFileTypes: true });
  const files = candidates
    .filter((entry) => entry.isFile() && /\.(txt|json|cookie|cookies)$/i.test(entry.name))
    .map((entry) => path.join(cookiePath, entry.name));

  if (!files.length) {
    throw new Error(`XDR Cookie 目录中没有找到 txt/json/cookie 文件: ${cookiePath}`);
  }

  files.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  return files[0];
}

function buildXdrHeaders(cookieString, csrfToken, baseUrl, overrides = {}) {
  const xdrBaseUrl = normalizeBaseUrl(baseUrl || DEFAULT_XDR_BASE_URL);

  return {
    host: xdrBaseUrl,
    accept: 'application/json, text/plain, */*',
    'accept-language': 'zh-CN,zh;q=0.9',
    connection: 'keep-alive',
    'content-type': 'application/json',
    cookie: cookieString,
    origin: `https://${xdrBaseUrl}`,
    referer: `https://${xdrBaseUrl}${XDR_ASSET_PAGE_PATH}`,
    'sec-ch-ua': '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    'x-csrf-token': csrfToken,
    'x-requested-with': 'XMLHttpRequest',
    ...overrides
  };
}

function buildXdrPageHeaders(cookieString, csrfToken, baseUrl, overrides = {}) {
  const xdrBaseUrl = normalizeBaseUrl(baseUrl || DEFAULT_XDR_BASE_URL);
  return {
    host: xdrBaseUrl,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': 'zh-CN,zh;q=0.9',
    connection: 'keep-alive',
    cookie: cookieString,
    origin: `https://${xdrBaseUrl}`,
    referer: `https://${xdrBaseUrl}${XDR_ASSET_PAGE_PATH}`,
    'sec-ch-ua': '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    'x-csrf-token': csrfToken,
    ...overrides
  };
}

async function requestJson(url, { headers, body, timeout }) {
  const parsedUrl = new URL(url);
  const transport = parsedUrl.protocol === 'http:' ? http : https;
  const timeoutMs = Number(timeout) || 30000;

  return new Promise((resolve, reject) => {
    const req = transport.request(parsedUrl, {
      method: body === undefined ? 'GET' : 'POST',
      headers
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed;
        try {
          parsed = JSON.parse(text);
        } catch (error) {
          parsed = text;
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`XDR 请求失败 ${res.statusCode}: ${typeof parsed === 'string' ? parsed : JSON.stringify(parsed).slice(0, 500)}`));
          return;
        }

        resolve(parsed);
      });
    });

    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`XDR 请求超时: ${url}`));
    });

    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

async function requestBuffer(url, { headers }) {
  const parsedUrl = new URL(url);
  const transport = parsedUrl.protocol === 'http:' ? http : https;

  return new Promise((resolve, reject) => {
    const req = transport.request(parsedUrl, {
      method: 'GET',
      headers
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const buffer = Buffer.concat(chunks);
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`XDR 下载失败 ${res.statusCode}: ${buffer.toString('utf8').slice(0, 500)}`));
          return;
        }
        resolve({
          buffer,
          headers: res.headers,
          statusCode: res.statusCode
        });
      });
    });

    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy(new Error(`XDR 下载请求超时: ${url}`));
    });
    req.end();
  });
}

function assertXdrApiSuccess(response, label) {
  if (!response || typeof response !== 'object') {
    throw new Error(`${label} 返回异常: ${JSON.stringify(response).slice(0, 500)}`);
  }

  const code = response.code;
  const message = String(response.message || response.msg || '').trim();

  if (code === 401 || message === 'session.expired') {
    throw new Error(`${label} 会话已过期，请重新登录后刷新 xdr_cookies.txt`);
  }
}

async function visitXdrAssetPage(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrPageHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL)}${XDR_ASSET_PAGE_PATH}`;
  try {
    await requestBuffer(url, { headers });
  } catch (error) {
    if (!/404|405/.test(String(error && error.message))) {
      throw error;
    }
  }
}

function buildExportFieldsRequestBody() {
  return {};
}

function buildAssetExportRequestBody(exportFields) {
  return {
    branch_id: 'all',
    search_type: 'current',
    platform_ids: [],
    is_all: false,
    ids: [],
    exclude_ids: [],
    export_fields: exportFields
  };
}

function buildIncidentTableFields() {
  return INCIDENT_EXPORT_FIELDS.map(([field, show, columnWidth, dataType, sort = 'disable', selected = show, fixed = null]) => ({
    field,
    show,
    selected,
    sort,
    columnWidth,
    fixed,
    dataType
  }));
}

function buildIncidentTableQuerySection(pageSize) {
  return {
    enable: true,
    viewName: 'IncidentView',
    aggregationStrategies: null,
    tableFields: buildIncidentTableFields(),
    pageNum: 1,
    pageSize,
    serviceInfo: INCIDENT_TABLE_SERVICE_INFO,
    subTable: null,
    rightClicked: false,
    selectAllPage: true,
    routers: [
      {
        icon: null,
        path: '/incident/sec-event/detail',
        type: 'drillDown',
        params: null,
        actionParams: {
          disposedDisableFlag: '$disposedDisableFlag',
          orderDisableFlag: '$orderDisableFlag',
          disposingDisableFlag: '$disposingDisableFlag',
          pendingDisableFlag: '$pendingDisableFlag',
          ignoreDisableFlag: '$ignoreDisableFlag',
          id: '$uuId',
          hungupDisableFlag: '$hungupDisableFlag',
          soarDisableFlag: '$soarDisableFlag'
        },
        applicableCols: ['name']
      }
    ],
    rightActions: [
      {
        name: 'addFilter',
        type: 'filter',
        params: null,
        actionParams: null,
        applicableCols: ['attackState', 'devSourceNames', 'xthExpert', 'occurTime', 'soarMatchEventTag', 'ignoreDisableFlag', 'platformIsDelete', 'platformHostBranchId', 'hostBranchId', 'remarkInfo', 'huntingDomains', 'serviceEventId', 'incidentThreatClass', 'devUIdProxy', 'suppressTime', 'id', 'dataSources', 'phishing', 'read', 'gptStartAt', 'hostIp', 'huntingIps', 'mssTagType', 'hostAssetAnalyzeResult', 'dealStatus', 'soarDisableFlag', 'insertTime', 'hostProvinceName', 'hostIpAll', 'orderDisableFlag', 'auditTime', 'auditLogTraceInfo', 'disposingDisableFlag', 'name', 'dataAuthorityBranchId', 'gptResult', 'xthAttackIntent', 'whiteStatus', 'alertNumber', 'incidentSourceProxy', 'gptEndAt', 'eventRuleId', 'description', 'isAutoDispose', 'regionIds', 'auditType', 'hungupDisableFlag', 'mssIncidentServiceStatus', 'platformRole', 'auditFrom', 'xthTag', 'pendingDisableFlag', 'eventEngine', 'startTime', 'addWhiteDisableFlag', 'hostGroupIds', 'gptAnalyzeTime', 'hostAssetId', 'severity', 'hostClassify1Id', 'connectStatus', 'disposedDisableFlag', 'hostClassifyId', 'xthConfirm', 'pendingXth', 'platformId', 'uploadTime', 'uuId', 'logTraceInfo', 'timeLimit', 'incidentThreatType', 'devUId', 'platformHostGroupIds', 'fromXth', 'riskTag', 'disposeTime', 'alertIds', 'dealAction', 'hostCountryName', 'regionId', 'huntingMD5s', 'xthType', 'endTime', 'threatDefine']
      },
      {
        name: 'copyCellText',
        type: 'copy',
        params: null,
        actionParams: null,
        applicableCols: ['name', 'uuId', 'hostIp']
      },
      {
        name: 'removeFilter',
        type: 'filter',
        params: null,
        actionParams: null,
        applicableCols: ['attackState', 'devSourceNames', 'xthExpert', 'occurTime', 'soarMatchEventTag', 'ignoreDisableFlag', 'platformIsDelete', 'platformHostBranchId', 'hostBranchId', 'remarkInfo', 'huntingDomains', 'serviceEventId', 'incidentThreatClass', 'devUIdProxy', 'suppressTime', 'id', 'dataSources', 'phishing', 'read', 'gptStartAt', 'hostIp', 'huntingIps', 'mssTagType', 'hostAssetAnalyzeResult', 'dealStatus', 'soarDisableFlag', 'insertTime', 'hostProvinceName', 'hostIpAll', 'orderDisableFlag', 'auditTime', 'auditLogTraceInfo', 'disposingDisableFlag', 'name', 'dataAuthorityBranchId', 'gptResult', 'xthAttackIntent', 'whiteStatus', 'alertNumber', 'incidentSourceProxy', 'gptEndAt', 'eventRuleId', 'description', 'isAutoDispose', 'regionIds', 'auditType', 'hungupDisableFlag', 'mssIncidentServiceStatus', 'platformRole', 'auditFrom', 'xthTag', 'pendingDisableFlag', 'eventEngine', 'startTime', 'addWhiteDisableFlag', 'hostGroupIds', 'gptAnalyzeTime', 'hostAssetId', 'severity', 'hostClassify1Id', 'connectStatus', 'disposedDisableFlag', 'hostClassifyId', 'xthConfirm', 'pendingXth', 'platformId', 'uploadTime', 'uuId', 'logTraceInfo', 'timeLimit', 'incidentThreatType', 'devUId', 'platformHostGroupIds', 'fromXth', 'riskTag', 'disposeTime', 'alertIds', 'dealAction', 'hostCountryName', 'regionId', 'huntingMD5s', 'xthType', 'endTime', 'threatDefine']
      },
      {
        name: 'incidentUnRead',
        type: 'modifyReadStatus',
        params: null,
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentRead',
        type: 'modifyReadStatus',
        params: null,
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentPending',
        type: 'modifyDealStatus',
        params: { disable: '$pendingDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentDisposing',
        type: 'modifyDealStatus',
        params: { disable: '$disposingDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentDisposed',
        type: 'modifyDealStatus',
        params: { disable: '$disposedDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentSuppress',
        type: 'modifyDealStatus',
        params: { disable: '$disposedDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentHungup',
        type: 'modifyDealStatus',
        params: { disable: '$hungupDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentIgnored',
        type: 'modifyDealStatus',
        params: { disable: '$ignoreDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'incidentAddWhite',
        type: 'addWhite',
        params: { disable: '$addWhiteDisableFlag' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'soarDisposalRecord',
        type: 'item',
        params: { disable: '$soarDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      },
      {
        name: 'flowDisposalRecord',
        type: 'item',
        params: { disable: '$orderDisableFlag', applicableLimit: '' },
        actionParams: { uuId: '$uuId' },
        applicableCols: null
      }
    ],
    extensionParams: {
      spl: 'filter xthConfirm= true'
    },
    tag: [
      {
        field: 'fromXth',
        fieldValue: true,
        tagColor: '#1C6EFF',
        tagValue: 'XTH',
        tagSuspendedValue: 'XTH：云端主动威胁狩猎'
      }
    ]
  };
}

function buildIncidentExportRequestBody({ begin, end, timeField = 'startTime' }) {
  return {
    globalCondition: {
      branchIds: [],
      time: {
        timeField,
        begin: { type: 'absolute', value: begin },
        end: { type: 'absolute', value: end }
      }
    },
    spl: {
      mappedSpl: '',
      originalSpl: '',
      extensionParams: {
        frontRender: [],
        mappedInputSpl: '',
        originalInputSpl: ''
      }
    },
    selection: {
      childSelections: [],
      parentSelections: [],
      selectAll: false,
      selected: []
    },
    tableArea: {
      ...buildIncidentTableQuerySection(50)
    },
    viewInstanceId: INCIDENT_VIEW_INSTANCE_ID,
    model: 'simple',
    batchSize: 5000,
    max: 100000,
    serviceInfo: INCIDENT_SERVICE_INFO,
    timeOutMs: 1000000,
    type: 'exportIncidentExcel',
    name: '导出报告'
  };
}

function buildIncidentCountRequestBody({ begin, end, timeField = 'startTime' }) {
  return {
    extensionParams: null,
    spl: {
      mappedSpl: '',
      originalSpl: '',
      extensionParams: {
        frontRender: [],
        mappedInputSpl: '',
        originalInputSpl: ''
      }
    },
    serviceInfo: INCIDENT_TABLE_SERVICE_INFO,
    globalCondition: {
      branchIds: [],
      time: {
        timeField,
        begin: { type: 'absolute', value: begin },
        end: { type: 'absolute', value: end }
      }
    },
    table: buildIncidentTableQuerySection(1000),
    viewName: 'IncidentView',
    model: 'simple',
    viewInstanceId: INCIDENT_VIEW_INSTANCE_ID,
    enableHistory: true
  };
}

function buildAlertTableFields() {
  // Each entry: [field, show, selected, sort, columnWidth, fixed, dataType]
  var fields = [
    ['lastTime', true, true, 'desc', 130, null, 'value'],
    ['name', true, true, 'disable', 200, null, 'value'],
    ['operationLabels', true, true, 'disable', 330, null, 'array'],
    ['severity', true, true, 'disable', 85, null, 'value'],
    ['threatDefine', true, true, 'disable', 95, null, 'array'],
    ['similarRuleId', true, true, 'disable', 100, null, 'value'],
    ['whiteListIds', true, true, 'disable', 150, null, 'array'],
    ['srcIp', true, true, 'disable', 125, null, 'array'],
    ['dstIp', true, true, 'disable', 125, null, 'array'],
    ['hostIp', true, true, 'disable', 145, null, 'value'],
    ['attackResult', true, true, 'disable', 105, null, 'value'],
    ['accessDirection', true, true, 'disable', 110, null, 'value'],
    ['trafficForwardLocation', true, true, 'disable', 200, null, 'array'],
    ['newestUsername', true, false, 'disable', 150, null, 'value'],
    ['checkOutUsername', true, false, 'disable', 150, null, 'value'],
    ['responsible', true, false, 'disable', 80, null, 'value'],
    ['uuId', true, false, 'disable', 300, null, 'value'],
    ['riskTag', true, false, 'disable', 180, null, 'value'],
    ['similarId', true, false, 'disable', 100, null, 'value'],
    ['requestHead', true, false, 'disable', 150, null, 'value'],
    ['responseHead', true, false, 'disable', 150, null, 'value'],
    ['requestBody', true, false, 'disable', 150, null, 'value'],
    ['responseBody', true, false, 'disable', 150, null, 'value'],
    ['confidence', true, false, 'disable', 110, null, 'value'],
    ['stage', true, false, 'disable', 100, null, 'value'],
    ['natTransform', true, false, 'disable', 150, null, 'value'],
    ['srcPort', true, false, 'disable', 110, null, 'array'],
    ['dstPort', true, false, 'disable', 110, null, 'array'],
    ['platformHostBranchId', true, false, 'disable', 150, null, 'value'],
    ['platformHostGroupIds', true, false, 'disable', 150, null, 'array'],
    ['whiteStatus', true, false, 'disable', 100, null, 'value'],
    ['engineName', true, false, 'disable', 140, null, 'array'],
    ['virusName', true, false, 'disable', 140, null, 'array'],
    ['xForwardedFor', true, false, 'disable', 125, null, 'array'],
    ['threatClass', true, false, 'disable', 150, null, 'value'],
    ['threatTypeProxy', true, false, 'disable', 150, null, 'value'],
    ['threatSubTypeProxy', true, false, 'disable', 150, null, 'value'],
    ['respStatus', true, false, 'disable', 110, null, 'value'],
    ['attckTechnique', true, false, 'disable', 150, null, 'array'],
    ['attckSubTechnique', true, false, 'disable', 150, null, 'array'],
    ['fileMd5', true, false, 'disable', 180, null, 'array'],
    ['url', true, false, 'disable', 200, null, 'array'],
    ['domain', true, false, 'disable', 125, null, 'array'],
    ['cveId', true, false, 'disable', 180, null, 'value'],
    ['pName', true, false, 'disable', 180, null, 'array'],
    ['firstTime', true, false, 'disable', 136, null, 'value'],
    ['logTraceInfo', true, false, 'disable', 150, null, 'value'],
    ['incidentRelated', true, false, 'disable', 150, null, 'value'],
    ['devUId', true, false, 'disable', 150, null, 'array'],
    ['devUIdProxy', true, false, 'disable', 120, null, 'array'],
    ['devSourceNames', true, false, 'disable', 180, null, 'array'],
    ['dealStatus', true, false, 'disable', 126, null, 'value'],
    ['disposeTime', true, false, 'disable', 140, null, 'value'],
    ['dealAction', true, false, 'disable', 132, null, 'value'],
    ['mssStatus', true, false, 'disable', 150, null, 'value'],
    ['platformId', true, false, 'disable', 110, null, 'value'],
    ['gptResult', true, false, 'disable', 150, null, 'value'],
    ['gptStartAt', true, false, 'disable', 150, null, 'value'],
    ['gptEndAt', true, false, 'disable', 150, null, 'value'],
    ['gptAnalyzeTime', true, false, 'disable', 150, null, 'value'],
    ['gptSubResult', true, false, 'disable', 150, null, 'value'],
    ['incidentRootIds', true, false, 'disable', 150, null, 'array'],
    ['xUserName', true, false, 'disable', 150, null, 'value'],
    ['xUserGroup', true, false, 'disable', 150, null, 'value'],
    ['hostAssetAnalyzeResult', true, false, 'disable', 150, null, 'value'],
    ['platformIdAndGroupId', true, false, 'disable', 120, null, 'value'],
    ['gptRuleUid', true, false, 'disable', 150, null, 'value'],
    ['aiRuleIds', true, false, 'disable', 150, null, 'array'],
    // show: false fields
    ['proofType', false, false, 'notSortable', null, null, 'array'],
    ['hostBranchId', false, false, 'disable', null, null, 'value'],
    ['hostGroupIds', false, false, 'notSortable', null, null, 'array'],
    ['logType', false, false, 'notSortable', null, null, 'value'],
    ['vulnName', false, false, 'notSortable', null, null, 'array'],
    ['username', false, false, 'notSortable', null, null, 'array'],
    ['read', false, false, 'notSortable', null, null, 'value'],
    ['fusionAlert', false, false, 'notSortable', null, null, 'value'],
    ['uploadTime', false, false, 'disable', null, null, 'value'],
    ['insertTime', false, false, 'disable', null, null, 'value'],
    ['ndrSecdetectBreachMid', false, false, 'notSortable', null, null, 'value'],
    ['occurTime', false, false, 'disable', null, null, 'value'],
    ['hostClassifyId', false, false, 'notSortable', null, null, 'value'],
    ['hostClassify1Id', false, false, 'notSortable', null, null, 'value'],
    ['srcIpInfos', false, false, 'notSortable', null, null, 'array'],
    ['dstIpInfos', false, false, 'notSortable', null, null, 'array'],
    ['pendingDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['disposingDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['disposedDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['ignoreDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['misReportDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['customAlertGenerateIncidentDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['gptResultStrategyDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['banIpDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['addWhiteDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['statusChangeDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['orderDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['quarantineHostDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['disposeFileDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['trustFileDisableFlag', false, false, 'notSortable', null, null, 'value'],
    ['hostAssetId', false, false, 'notSortable', null, null, 'value'],
    ['hostCountryName', false, false, 'notSortable', null, null, 'value'],
    ['hostProvinceName', false, false, 'notSortable', null, null, 'value'],
    ['ioaRuleRelated', false, false, 'notSortable', null, null, 'value'],
    ['ruleIds', false, false, 'notSortable', null, null, 'array'],
    ['alertRuleId', false, false, 'notSortable', null, null, 'value'],
    ['huntingIps', false, false, 'notSortable', null, null, 'array'],
    ['huntingDomains', false, false, 'notSortable', null, null, 'array'],
    ['huntingMD5s', false, false, 'notSortable', null, null, 'array'],
    ['suspectedMisReport', false, false, 'notSortable', null, null, 'value'],
    ['devices', false, false, 'notSortable', null, null, 'array'],
    ['combineType', false, false, 'notSortable', null, null, 'value'],
    ['regionId', false, false, 'notSortable', null, null, 'value'],
    ['disposalRecord', false, false, 'notSortable', null, null, 'value'],
    ['gptRespAction', false, false, 'disable', null, null, 'value'],
    ['gptAction', false, false, 'notSortable', null, null, 'value'],
    ['gptEngineList', false, false, 'notSortable', null, null, 'array'],
    ['platformRole', false, false, 'notSortable', null, null, 'value'],
    ['platformIsDelete', false, false, 'notSortable', null, null, 'value'],
    ['srcAssetAnalyzeResultsStatus', false, false, 'notSortable', null, null, 'value'],
    ['srcAssetAnalyzeResults', false, false, 'notSortable', null, null, 'value'],
    ['hostAddress', false, false, 'notSortable', null, null, 'value'],
    ['smtpFrom', false, false, 'notSortable', null, null, 'value'],
    ['userAgent', false, false, 'notSortable', null, null, 'value'],
    ['reqCookie', false, false, 'notSortable', null, null, 'value'],
    ['dnsQueries', false, false, 'notSortable', null, null, 'value'],
    ['dnsAnswers', false, false, 'notSortable', null, null, 'value'],
    ['redisCommandCall', false, false, 'notSortable', null, null, 'value'],
    ['redisLogin', false, false, 'notSortable', null, null, 'value'],
    ['redisPassword', false, false, 'notSortable', null, null, 'value'],
    ['webmailUser', false, false, 'notSortable', null, null, 'value'],
    ['webmailFrom', false, false, 'notSortable', null, null, 'value'],
    ['webmailTo', false, false, 'notSortable', null, null, 'value'],
    ['mysqlCommand', false, false, 'notSortable', null, null, 'value'],
    ['webmailSubject', false, false, 'notSortable', null, null, 'value'],
    ['webmailAttachmentFilename', false, false, 'notSortable', null, null, 'value'],
    ['sqlServerRequest', false, false, 'notSortable', null, null, 'value'],
    ['smtpTo', false, false, 'notSortable', null, null, 'value'],
    ['smtpSubject', false, false, 'notSortable', null, null, 'value'],
    ['ftpUser', false, false, 'notSortable', null, null, 'value'],
    ['ftpCommand', false, false, 'notSortable', null, null, 'value'],
    ['ftpCwd', false, false, 'notSortable', null, null, 'value'],
    ['description', false, false, 'notSortable', null, null, 'value'],
    ['exploitCveId', false, false, 'notSortable', null, null, 'value'],
    ['sasUsername', false, false, 'notSortable', null, null, 'value'],
    ['snmpVersion', false, false, 'notSortable', null, null, 'value'],
    ['recommendation', false, false, 'notSortable', null, null, 'value'],
    ['aiRuleId', false, false, 'notSortable', null, null, 'value'],
    ['fileState', false, false, 'notSortable', null, null, 'value'],
    ['fileStatus', false, false, 'notSortable', null, null, 'value']
  ];

  return fields.map(function(f) {
    return {
      field: f[0],
      show: f[1],
      selected: f[2],
      sort: f[3],
      columnWidth: f[4],
      fixed: f[5],
      dataType: f[6]
    };
  });
}

function buildAlertCountRequestBody({ begin, end }) {
  return {
    extensionParams: null,
    spl: {
      mappedSpl: '',
      originalSpl: '',
      extensionParams: {
        frontRender: [],
        mappedInputSpl: '',
        originalInputSpl: ''
      }
    },
    serviceInfo: ALERT_TABLE_SERVICE_INFO,
    globalCondition: {
      branchIds: [],
      time: {
        timeField: 'firstTime',
        begin: { type: 'absolute', value: begin },
        end: { type: 'absolute', value: end }
      }
    },
    table: {
      enable: true,
      viewName: 'AlertView',
      aggregationStrategies: null,
      tableFields: buildAlertTableFields(),
      pageNum: 1,
      pageSize: 100,
      serviceInfo: ALERT_TABLE_SERVICE_INFO,
      subTable: null,
      rightClicked: false,
      selectAllPage: true,
      routers: [
        {
          icon: null,
          path: '/incident/event/detail',
          type: 'drillDown',
          params: null,
          actionParams: {
            quarantineHostDisableFlag: '$quarantineHostDisableFlag',
            disposedDisableFlag: '$disposedDisableFlag',
            ignoreDisableFlag: '$ignoreDisableFlag',
            trustFileDisableFlag: '$trustFileDisableFlag',
            disposeFileDisableFlag: '$disposeFileDisableFlag',
            soarDisableFlag: '$soarDisableFlag',
            orderDisableFlag: '$orderDisableFlag',
            disposingDisableFlag: '$disposingDisableFlag',
            banIpDisableFlag: '$banIpDisableFlag',
            gptResultStrategyDisableFlag: '$gptResultStrategyDisableFlag',
            pendingDisableFlag: '$pendingDisableFlag',
            toBeTransferDisableFlag: '$toBeTransferDisableFlag',
            id: '$uuId',
            customAlertGenerateIncidentDisableFlag: '$customAlertGenerateIncidentDisableFlag',
            misReportDisableFlag: '$misReportDisableFlag'
          },
          applicableCols: ['name']
        }
      ],
      rightActions: [
        {
          name: 'addFilter',
          type: 'filter',
          params: null,
          actionParams: null,
          applicableCols: ['responseHead', 'smtpTo', 'devSourceNames', 'sendFrom', 'occurTime', 'ignoreDisableFlag', 'platformIsDelete', 'recommendation', 'threatSubType', 'ftpCwd', 'similarId', 'srcPort', 'platformHostBranchId', 'accessDirection', 'huntingDomains', 'xUserGroup', 'humanCheck', 'redisLogin', 'tenant', 'fullTextSearch', 'quarantineHostDisableFlag', 'hostIp', 'respStatus', 'devices', 'ndrSecdetectBreachMid', 'mitreid', 'dealStatus', 'threatTypeProxy', 'aiRuleId', 'aiRuleIds', 'vulnName', 'soarDisableFlag', 'ftpCommand', 'newFullTextSearch', 'redisPassword', 'incidentRelated', 'gptAction', 'redisCommandCall', 'dealTime', 'threatType', 'orderDisableFlag', 'mssStatus', 'domain', 'disposingDisableFlag', 'reqCookie', 'whiteStatus', 'engineName', 'customAlertGenerateIncidentDisableFlag', 'gptRespAction', 'natTransform', 'dataAuthorityOwner', 'ioaRuleRelated', 'responseBody', 'webmailAttachmentFilename', 'statusChangeDisableFlag', 'featureInfo', 'dstIpStr', 'incidentRootIds', 'trustFileDisableFlag', 'regionIds', 'investigationResult', 'smtpFrom', 'ftpUser', 'ruleIds', 'dstPort', 'webmailSubject', 'whiteListIds', 'pName', 'requestBody', 'srcAssetAnalyzeResultsStatus', 'pendingDisableFlag', 'addWhiteDisableFlag', 'misReportDisableFlag', 'suspectedMisReport', 'hostClassify1Id', 'disposedDisableFlag', 'combineType', 'updateTime', 'userAgent', 'fileMd5', 'dstIpInfos', 'url', 'firstTime', 'platformHostGroupIds', 'devUId', 'riskTag', 'gptJudgementEngine', 'stage', 'dealAction', 'hostCountryName', 'exploitCveId', 'gptResultStrategyDisableFlag', 'huntingMD5s', 'hostAddress', 'dstIp', 'xForwardedFor', 'dnsQueries', 'alertRuleId', 'lastTime', 'similarRuleId', 'gptRuleUid', 'mysqlCommand', 'xUserName', 'requestHead', 'sasUsername', 'checker', 'disposeFileDisableFlag', 'webmailFrom', 'hostBranchId', 'attckTechnique', 'disposalRecord', 'srcIpInfos', 'fileState', 'devUIdProxy', 'banIpDisableFlag', 'srcAssetAnalyzeResults', 'sqlServerRequest', 'smtpSubject', 'fusionAlert', 'srcIp', 'attackResult', 'read', 'gptStartAt', 'virusName', 'correctGptResult', 'snmpVersion', 'threatClass', 'huntingIps', 'proofType', 'cveId', 'webmailUser', 'isCascade', 'trafficForwardLocation', 'hostAssetAnalyzeResult', 'gptSubResult', 'insertTime', 'hostProvinceName', 'gptAnalyzeTrace', 'webmailTo', 'name', 'dataAuthorityBranchId', 'gptResult', '_id', 'gptEngineList', 'logType', 'hostIpStr', 'platformIdAndGroupId', 'gptEndAt', 'humanNote', 'description', 'platformRole', 'srcIpStr', 'fileStatus', 'humanInvestigation', 'hostGroupIds', 'gptAnalyzeTime', 'hostAssetId', 'severity', 'owner', 'hostClassifyId', 'confidence', 'attckSubTechnique', 'platformId', 'label', 'uploadTime', 'uuId', 'logTraceInfo', 'disposeTime', 'regionId', 'threatSubTypeProxy', 'operationLabels', 'dnsAnswers', 'toBeTransferDisableFlag', 'threatDefine', 'dataAuthorityCooperators', 'username']
        },
        {
          name: 'removeFilter',
          type: 'filter',
          params: null,
          actionParams: null,
          applicableCols: ['responseHead', 'smtpTo', 'devSourceNames', 'sendFrom', 'occurTime', 'ignoreDisableFlag', 'platformIsDelete', 'recommendation', 'threatSubType', 'ftpCwd', 'similarId', 'srcPort', 'platformHostBranchId', 'accessDirection', 'huntingDomains', 'xUserGroup', 'humanCheck', 'redisLogin', 'tenant', 'fullTextSearch', 'quarantineHostDisableFlag', 'hostIp', 'respStatus', 'devices', 'ndrSecdetectBreachMid', 'mitreid', 'dealStatus', 'threatTypeProxy', 'aiRuleId', 'aiRuleIds', 'vulnName', 'soarDisableFlag', 'ftpCommand', 'newFullTextSearch', 'redisPassword', 'incidentRelated', 'gptAction', 'redisCommandCall', 'dealTime', 'threatType', 'orderDisableFlag', 'mssStatus', 'domain', 'disposingDisableFlag', 'reqCookie', 'whiteStatus', 'engineName', 'customAlertGenerateIncidentDisableFlag', 'gptRespAction', 'natTransform', 'dataAuthorityOwner', 'ioaRuleRelated', 'responseBody', 'webmailAttachmentFilename', 'statusChangeDisableFlag', 'featureInfo', 'dstIpStr', 'incidentRootIds', 'trustFileDisableFlag', 'regionIds', 'investigationResult', 'smtpFrom', 'ftpUser', 'ruleIds', 'dstPort', 'webmailSubject', 'whiteListIds', 'pName', 'requestBody', 'srcAssetAnalyzeResultsStatus', 'pendingDisableFlag', 'addWhiteDisableFlag', 'misReportDisableFlag', 'suspectedMisReport', 'hostClassify1Id', 'disposedDisableFlag', 'combineType', 'updateTime', 'userAgent', 'fileMd5', 'dstIpInfos', 'url', 'firstTime', 'platformHostGroupIds', 'devUId', 'riskTag', 'gptJudgementEngine', 'stage', 'dealAction', 'hostCountryName', 'exploitCveId', 'gptResultStrategyDisableFlag', 'huntingMD5s', 'hostAddress', 'dstIp', 'xForwardedFor', 'dnsQueries', 'alertRuleId', 'lastTime', 'similarRuleId', 'gptRuleUid', 'mysqlCommand', 'xUserName', 'requestHead', 'sasUsername', 'checker', 'disposeFileDisableFlag', 'webmailFrom', 'hostBranchId', 'attckTechnique', 'disposalRecord', 'srcIpInfos', 'fileState', 'devUIdProxy', 'banIpDisableFlag', 'srcAssetAnalyzeResults', 'sqlServerRequest', 'smtpSubject', 'fusionAlert', 'srcIp', 'attackResult', 'read', 'gptStartAt', 'virusName', 'correctGptResult', 'snmpVersion', 'threatClass', 'huntingIps', 'proofType', 'cveId', 'webmailUser', 'isCascade', 'trafficForwardLocation', 'hostAssetAnalyzeResult', 'gptSubResult', 'insertTime', 'hostProvinceName', 'gptAnalyzeTrace', 'webmailTo', 'name', 'dataAuthorityBranchId', 'gptResult', '_id', 'gptEngineList', 'logType', 'hostIpStr', 'platformIdAndGroupId', 'gptEndAt', 'humanNote', 'description', 'platformRole', 'srcIpStr', 'fileStatus', 'humanInvestigation', 'hostGroupIds', 'gptAnalyzeTime', 'hostAssetId', 'severity', 'owner', 'hostClassifyId', 'confidence', 'attckSubTechnique', 'platformId', 'label', 'uploadTime', 'uuId', 'logTraceInfo', 'disposeTime', 'regionId', 'threatSubTypeProxy', 'operationLabels', 'dnsAnswers', 'toBeTransferDisableFlag', 'threatDefine', 'dataAuthorityCooperators', 'username']
        },
        {
          name: 'copyCellText',
          type: 'copy',
          params: null,
          actionParams: null,
          applicableCols: null
        },
        {
          name: 'copyRecordData',
          type: 'copy',
          params: null,
          actionParams: null,
          applicableCols: null
        },
        {
          name: 'decodeTool',
          type: 'tool',
          params: null,
          actionParams: null,
          applicableCols: null
        },
        {
          name: 'hostIpAssetDetail',
          type: 'assetJump',
          params: null,
          actionParams: { assetId: '$hostAssetId', ip: '$hostIp', uuId: '$uuId' },
          applicableCols: ['hostIp']
        },
        {
          name: 'srcIpAssetDetail',
          type: 'assetJump',
          params: null,
          actionParams: { srcIpInfos: '$srcIpInfos', ip: '$.', uuId: '$uuId' },
          applicableCols: ['srcIp']
        },
        {
          name: 'dstIpAssetDetail',
          type: 'assetJump',
          params: null,
          actionParams: { ip: '$.', uuId: '$uuId', dstIpInfos: '$dstIpInfos' },
          applicableCols: ['dstIp']
        },
        {
          name: 'incidentBanIp',
          type: 'item',
          params: { disable: '$banIpDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentQuarantineHost',
          type: 'item',
          params: { disable: '$quarantineHostDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'alertGptResultStrategy',
          type: 'addAlertGptResultStrategy',
          params: { disable: '$gptResultStrategyDisableFlag' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentAddWhite',
          type: 'addWhite',
          params: { disable: '$addWhiteDisableFlag' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'alertStatusChange',
          type: 'statusChange',
          params: { disable: '$statusChangeDisableFlag' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'customAlertGenerateIncident',
          type: 'customAlertGenerateIncident',
          params: { disable: '$customAlertGenerateIncidentDisableFlag' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentDisposeFile',
          type: 'item',
          params: { disable: '$disposeFileDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentTrustFile',
          type: 'item',
          params: { disable: '$trustFileDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'jumpAllowList',
          type: 'jump',
          params: { hidden: true, disable: '$isCascade', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: ['whiteStatus']
        },
        {
          name: 'incidentIgnore',
          type: 'modifyDealStatus',
          params: { disable: '$ignoreDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentMisReport',
          type: 'modifyDealStatus',
          params: { disable: '$misReportDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentPending',
          type: 'modifyDealStatus',
          params: { disable: '$pendingDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentDisposing',
          type: 'modifyDealStatus',
          params: { disable: '$disposingDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentDisposed',
          type: 'modifyDealStatus',
          params: { disable: '$disposedDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentSuppressed',
          type: 'modifyDealStatus',
          params: { disable: '$disposedDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentToBeTransferred',
          type: 'transferred',
          params: { hidden: true, disable: '$toBeTransferDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'flowDisposalRecord',
          type: 'item',
          params: { disable: '$orderDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'soarDisposalRecord',
          type: 'item',
          params: { disable: '$soarDisableFlag', applicableLimit: '' },
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentUnRead',
          type: 'modifyReadStatus',
          params: null,
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        },
        {
          name: 'incidentRead',
          type: 'modifyReadStatus',
          params: null,
          actionParams: { uuId: '$uuId' },
          applicableCols: null
        }
      ],
      extensionParams: {}
    },
    tag: null,
    viewName: 'AlertView',
    model: 'expert',
    autoRefresh: false,
    viewInstanceId: ALERT_VIEW_INSTANCE_ID,
    enableHistory: true
  };
}

function buildAlertThreatClassRequestBody({ begin, end, pageNum = 1, pageSize = 1000 }) {
  const spl = 'filter 是否关联事件  in { "已关联" } | filter 告警一级分类  in { "网站攻击", "漏洞攻击" }';
  return {
    extensionParams: null,
    spl: {
      mappedSpl: spl,
      originalSpl: spl,
      extensionParams: {
        frontRender: [
          {
            displayField: '是否关联事件',
            field: 'incidentRelated',
            value: [true],
            headerType: 'metaType',
            searchType: 'selector',
            valueText: '已关联',
            isValueNegate: false,
            type: 'number',
            filterSelect: 'renderValue'
          },
          {
            displayField: '告警一级分类',
            field: 'threatClass',
            value: [90, 30],
            headerType: 'analysisThreatClass',
            searchType: 'treeSelector',
            valueText: '网站攻击, 漏洞攻击',
            isValueNegate: false,
            type: 'number',
            filterSelect: 'renderValue',
            isReadonly: false
          }
        ],
        mappedInputSpl: '',
        originalInputSpl: ''
      }
    },
    serviceInfo: ALERT_TABLE_SERVICE_INFO,
    globalCondition: {
      branchIds: [],
      time: {
        timeField: 'firstTime',
        begin: { type: 'absolute', value: begin },
        end: { type: 'absolute', value: end }
      }
    },
    table: {
      enable: true,
      viewName: 'AlertView',
      aggregationStrategies: null,
      tableFields: buildAlertTableFields(),
      pageNum,
      pageSize,
      serviceInfo: ALERT_TABLE_SERVICE_INFO,
      subTable: null,
      rightClicked: false,
      selectAllPage: true,
      routers: [
        {
          icon: null,
          path: '/incident/event/detail',
          type: 'drillDown',
          params: null,
          actionParams: {
            quarantineHostDisableFlag: '$quarantineHostDisableFlag',
            disposedDisableFlag: '$disposedDisableFlag',
            ignoreDisableFlag: '$ignoreDisableFlag',
            trustFileDisableFlag: '$trustFileDisableFlag',
            disposeFileDisableFlag: '$disposeFileDisableFlag',
            soarDisableFlag: '$soarDisableFlag',
            orderDisableFlag: '$orderDisableFlag',
            disposingDisableFlag: '$disposingDisableFlag',
            banIpDisableFlag: '$banIpDisableFlag',
            gptResultStrategyDisableFlag: '$gptResultStrategyDisableFlag',
            pendingDisableFlag: '$pendingDisableFlag',
            toBeTransferDisableFlag: '$toBeTransferDisableFlag',
            id: '$uuId',
            customAlertGenerateIncidentDisableFlag: '$customAlertGenerateIncidentDisableFlag',
            misReportDisableFlag: '$misReportDisableFlag'
          },
          applicableCols: ['name']
        }
      ],
      rightActions: [
        {
          name: 'addFilter',
          type: 'filter',
          params: null,
          actionParams: null,
          applicableCols: ['responseHead', 'smtpTo', 'devSourceNames', 'sendFrom', 'occurTime', 'ignoreDisableFlag', 'platformIsDelete', 'recommendation', 'threatSubType', 'ftpCwd', 'similarId', 'srcPort', 'platformHostBranchId', 'accessDirection', 'huntingDomains', 'xUserGroup', 'humanCheck', 'redisLogin', 'tenant', 'fullTextSearch', 'quarantineHostDisableFlag', 'hostIp', 'respStatus', 'devices', 'ndrSecdetectBreachMid', 'mitreid', 'dealStatus', 'threatTypeProxy', 'aiRuleId', 'aiRuleIds', 'vulnName', 'soarDisableFlag', 'ftpCommand', 'newFullTextSearch', 'redisPassword', 'incidentRelated', 'gptAction', 'redisCommandCall', 'dealTime', 'threatType', 'orderDisableFlag', 'mssStatus', 'domain', 'disposingDisableFlag', 'reqCookie', 'whiteStatus', 'engineName', 'customAlertGenerateIncidentDisableFlag', 'gptRespAction', 'natTransform', 'dataAuthorityOwner', 'ioaRuleRelated', 'responseBody', 'webmailAttachmentFilename', 'statusChangeDisableFlag', 'featureInfo', 'dstIpStr', 'incidentRootIds', 'trustFileDisableFlag', 'regionIds', 'investigationResult', 'smtpFrom', 'ftpUser', 'ruleIds', 'dstPort', 'webmailSubject', 'whiteListIds', 'pName', 'requestBody', 'srcAssetAnalyzeResultsStatus', 'pendingDisableFlag', 'addWhiteDisableFlag', 'misReportDisableFlag', 'suspectedMisReport', 'hostClassify1Id', 'disposedDisableFlag', 'combineType', 'updateTime', 'userAgent', 'fileMd5', 'dstIpInfos', 'url', 'firstTime', 'platformHostGroupIds', 'devUId', 'riskTag', 'gptJudgementEngine', 'stage', 'dealAction', 'hostCountryName', 'exploitCveId', 'gptResultStrategyDisableFlag', 'huntingMD5s', 'hostAddress', 'dstIp', 'xForwardedFor', 'dnsQueries', 'alertRuleId', 'lastTime', 'similarRuleId', 'gptRuleUid', 'mysqlCommand', 'xUserName', 'requestHead', 'sasUsername', 'checker', 'disposeFileDisableFlag', 'webmailFrom', 'hostBranchId', 'attckTechnique', 'disposalRecord', 'srcIpInfos', 'fileState', 'devUIdProxy', 'banIpDisableFlag', 'srcAssetAnalyzeResults', 'sqlServerRequest', 'smtpSubject', 'fusionAlert', 'srcIp', 'attackResult', 'read', 'gptStartAt', 'virusName', 'correctGptResult', 'snmpVersion', 'threatClass', 'huntingIps', 'proofType', 'cveId', 'webmailUser', 'isCascade', 'trafficForwardLocation', 'hostAssetAnalyzeResult', 'gptSubResult', 'insertTime', 'hostProvinceName', 'gptAnalyzeTrace', 'webmailTo', 'name', 'dataAuthorityBranchId', 'gptResult', '_id', 'gptEngineList', 'logType', 'hostIpStr', 'platformIdAndGroupId', 'gptEndAt', 'humanNote', 'description', 'platformRole', 'srcIpStr', 'fileStatus', 'humanInvestigation', 'hostGroupIds', 'gptAnalyzeTime', 'hostAssetId', 'severity', 'owner', 'hostClassifyId', 'confidence', 'attckSubTechnique', 'platformId', 'label', 'uploadTime', 'uuId', 'logTraceInfo', 'disposeTime', 'regionId', 'threatSubTypeProxy', 'operationLabels', 'dnsAnswers', 'toBeTransferDisableFlag', 'threatDefine', 'dataAuthorityCooperators', 'username']
        },
        {
          name: 'removeFilter',
          type: 'filter',
          params: null,
          actionParams: null,
          applicableCols: ['responseHead', 'smtpTo', 'devSourceNames', 'sendFrom', 'occurTime', 'ignoreDisableFlag', 'platformIsDelete', 'recommendation', 'threatSubType', 'ftpCwd', 'similarId', 'srcPort', 'platformHostBranchId', 'accessDirection', 'huntingDomains', 'xUserGroup', 'humanCheck', 'redisLogin', 'tenant', 'fullTextSearch', 'quarantineHostDisableFlag', 'hostIp', 'respStatus', 'devices', 'ndrSecdetectBreachMid', 'mitreid', 'dealStatus', 'threatTypeProxy', 'aiRuleId', 'aiRuleIds', 'vulnName', 'soarDisableFlag', 'ftpCommand', 'newFullTextSearch', 'redisPassword', 'incidentRelated', 'gptAction', 'redisCommandCall', 'dealTime', 'threatType', 'orderDisableFlag', 'mssStatus', 'domain', 'disposingDisableFlag', 'reqCookie', 'whiteStatus', 'engineName', 'customAlertGenerateIncidentDisableFlag', 'gptRespAction', 'natTransform', 'dataAuthorityOwner', 'ioaRuleRelated', 'responseBody', 'webmailAttachmentFilename', 'statusChangeDisableFlag', 'featureInfo', 'dstIpStr', 'incidentRootIds', 'trustFileDisableFlag', 'regionIds', 'investigationResult', 'smtpFrom', 'ftpUser', 'ruleIds', 'dstPort', 'webmailSubject', 'whiteListIds', 'pName', 'requestBody', 'srcAssetAnalyzeResultsStatus', 'pendingDisableFlag', 'addWhiteDisableFlag', 'misReportDisableFlag', 'suspectedMisReport', 'hostClassify1Id', 'disposedDisableFlag', 'combineType', 'updateTime', 'userAgent', 'fileMd5', 'dstIpInfos', 'url', 'firstTime', 'platformHostGroupIds', 'devUId', 'riskTag', 'gptJudgementEngine', 'stage', 'dealAction', 'hostCountryName', 'exploitCveId', 'gptResultStrategyDisableFlag', 'huntingMD5s', 'hostAddress', 'dstIp', 'xForwardedFor', 'dnsQueries', 'alertRuleId', 'lastTime', 'similarRuleId', 'gptRuleUid', 'mysqlCommand', 'xUserName', 'requestHead', 'sasUsername', 'checker', 'disposeFileDisableFlag', 'webmailFrom', 'hostBranchId', 'attckTechnique', 'disposalRecord', 'srcIpInfos', 'fileState', 'devUIdProxy', 'banIpDisableFlag', 'srcAssetAnalyzeResults', 'sqlServerRequest', 'smtpSubject', 'fusionAlert', 'srcIp', 'attackResult', 'read', 'gptStartAt', 'virusName', 'correctGptResult', 'snmpVersion', 'threatClass', 'huntingIps', 'proofType', 'cveId', 'webmailUser', 'isCascade', 'trafficForwardLocation', 'hostAssetAnalyzeResult', 'gptSubResult', 'insertTime', 'hostProvinceName', 'gptAnalyzeTrace', 'webmailTo', 'name', 'dataAuthorityBranchId', 'gptResult', '_id', 'gptEngineList', 'logType', 'hostIpStr', 'platformIdAndGroupId', 'gptEndAt', 'humanNote', 'description', 'platformRole', 'srcIpStr', 'fileStatus', 'humanInvestigation', 'hostGroupIds', 'gptAnalyzeTime', 'hostAssetId', 'severity', 'owner', 'hostClassifyId', 'confidence', 'attckSubTechnique', 'platformId', 'label', 'uploadTime', 'uuId', 'logTraceInfo', 'disposeTime', 'regionId', 'threatSubTypeProxy', 'operationLabels', 'dnsAnswers', 'toBeTransferDisableFlag', 'threatDefine', 'dataAuthorityCooperators', 'username']
        }
      ],
      extensionParams: {}
    },
    tag: null,
    viewName: 'AlertView',
    model: 'expert',
    autoRefresh: false,
    viewInstanceId: ALERT_VIEW_INSTANCE_ID,
    enableHistory: true
  };
}

function buildGptYunyingAlertTableFields() {
  return [
    ['lastTime', true, true, 'desc', 130, null, 'value'],
    ['newestUsername', true, false, 'disable', 150, null, 'value'],
    ['checkOutUsername', true, false, 'disable', 150, null, 'value'],
    ['responsible', true, false, 'disable', 80, null, 'value'],
    ['uuId', true, false, 'disable', 200, null, 'value'],
    ['name', true, true, 'disable', 200, null, 'value'],
    ['severity', true, true, 'disable', 85, null, 'value'],
    ['threatDefine', true, true, 'disable', 95, null, 'array'],
    ['srcIp', true, true, 'disable', 125, null, 'array'],
    ['dstIp', true, true, 'disable', 125, null, 'array'],
    ['hostIp', true, true, 'disable', 145, null, 'value'],
    ['gptResult', true, true, 'disable', 150, null, 'value'],
    ['attackResult', true, true, 'disable', 105, null, 'value'],
    ['accessDirection', true, true, 'disable', 110, null, 'value'],
    ['devUIdProxy', true, true, 'disable', 120, null, 'array'],
    ['gptJudgementEngine', true, true, 'disable', 120, null, 'value'],
    ['gptAnalyzeTrace', true, true, 'disable', 150, null, 'value'],
    ['correctGptResult', true, true, 'disable', 150, null, 'value'],
    ['updateTime', true, true, 'disable', 150, null, 'value'],
    ['investigationResult', true, true, 'disable', 150, null, 'array'],
    ['humanInvestigation', true, true, 'disable', 130, null, 'value'],
    ['featureInfo', true, true, 'disable', 250, null, 'value'],
    ['humanNote', true, true, 'disable', 130, null, 'value'],
    ['gptYunyingPayloadStatus', true, true, 'disable', 150, null, 'value'],
    ['gptYunyingChecker', true, true, 'disable', 150, null, 'value'],
    ['modelLabel', true, true, 'disable', 150, null, 'value'],
    ['correctGptResultHistory', true, true, 'disable', 150, null, 'value'],
    ['correctGptResultConflict', true, true, 'disable', 150, null, 'value'],
    ['correctGptResultHumanCount', true, true, 'disable', 150, null, 'value']
  ].map(([field, show, selected, sort, columnWidth, fixed, dataType]) => ({
    field,
    show,
    selected,
    sort,
    columnWidth,
    fixed,
    dataType
  }));
}

function buildGptYunyingAlertSubTableFields() {
  return [
    ['id', false, false, 'notSortable', null, null, 'value'],
    ['alertId', false, false, 'notSortable', null, null, 'value'],
    ['eventId', false, false, 'notSortable', null, null, 'value'],
    ['foundTime', true, true, 'disable', null, null, 'value'],
    ['alertLevel', true, true, 'desc', null, null, 'value'],
    ['alertName', true, true, 'notSortable', null, null, 'value'],
    ['alertDescription', true, true, 'notSortable', null, null, 'value'],
    ['matchPros', true, true, 'notSortable', null, null, 'array'],
    ['riskTag', true, true, 'notSortable', null, null, 'value'],
    ['attcks', true, true, 'notSortable', null, null, 'array'],
    ['alertTypeProxy', true, true, 'notSortable', null, null, 'array']
  ].map(([field, show, selected, sort, columnWidth, fixed, dataType]) => ({
    viewName: 'ProcessTreeAlertView',
    field,
    displayField: field,
    type: 'string',
    show,
    selected,
    sort,
    aggregate: false,
    searchType: 'disable',
    headerType: '',
    columnWidth,
    render: null,
    filterSelect: 'renderValue',
    dataType,
    groupSupport: false,
    selectKey: false,
    commonField: null,
    countType: null,
    tipsInfo: '',
    fixed,
    fullTextSearchSupport: null,
    metadataShardName: 'incident',
    headerName: field,
    headerNameI18n: `metadata.metaApi.ProcessTreeAlertApi.properties.${field}.headerName`
  }));
}

function buildGptYunyingAlertTableQuerySection(pageNum, pageSize) {
  return {
    enable: true,
    viewName: 'GptYunyingAlertView',
    aggregationStrategies: null,
    tableFields: buildGptYunyingAlertTableFields(),
    pageNum,
    pageSize,
    serviceInfo: GPT_YUNYING_ALERT_SERVICE_INFO,
    subTable: {
      enable: true,
      viewName: 'ProcessTreeAlertView',
      aggregationStrategies: null,
      tableFields: buildGptYunyingAlertSubTableFields(),
      pageNum: null,
      pageSize: null,
      serviceInfo: {
        appName: 'gpt-api-java',
        servletContextPath: '/',
        serviceType: 'subTable',
        handler: 'processTreeAlertGroupSubTableQueryHandler'
      },
      subTable: null,
      rightClicked: null,
      selectAllPage: false,
      routers: [],
      rightActions: [],
      extensionParams: null,
      tag: null,
      type: 'group',
      tableMappings: [
        {
          parentField: 'uuId',
          childField: 'eventId'
        }
      ],
      tableMapping: null
    },
    rightClicked: false,
    selectAllPage: true,
    routers: [
      {
        icon: null,
        path: '/incident/event/detail',
        type: 'drillDown',
        params: null,
        actionParams: {
          quarantineHostDisableFlag: '$quarantineHostDisableFlag',
          disposedDisableFlag: '$disposedDisableFlag',
          orderDisableFlag: '$orderDisableFlag',
          disposingDisableFlag: '$disposingDisableFlag',
          pendingDisableFlag: '$pendingDisableFlag',
          ignoreDisableFlag: '$ignoreDisableFlag',
          trustFileDisableFlag: '$trustFileDisableFlag',
          toBeTransferDisableFlag: '$toBeTransferDisableFlag',
          id: '$uuId',
          disposeFileDisableFlag: '$disposeFileDisableFlag',
          soarDisableFlag: '$soarDisableFlag',
          misReportDisableFlag: '$misReportDisableFlag'
        },
        applicableCols: ['name']
      }
    ],
    rightActions: [],
    extensionParams: {},
    tag: null
  };
}

function buildGptYunyingAlertTableQueryRequestBody({ begin, end, pageNum = 1, pageSize = 1000 }) {
  return {
    extensionParams: null,
    spl: {
      mappedSpl: '',
      originalSpl: '',
      extensionParams: {
        frontRender: [],
        mappedInputSpl: '',
        originalInputSpl: ''
      }
    },
    serviceInfo: GPT_YUNYING_ALERT_SERVICE_INFO,
    globalCondition: {
      branchIds: [],
      time: {
        timeField: 'firstTime',
        begin: { type: 'absolute', value: begin },
        end: { type: 'absolute', value: end }
      }
    },
    table: buildGptYunyingAlertTableQuerySection(pageNum, pageSize),
    rightClicked: false,
    selectAllPage: true,
    routers: [],
    rightActions: [],
    extensionParams: {},
    tag: null,
    type: 'group',
    viewName: 'GptYunyingAlertView',
    model: 'simple',
    autoRefresh: false,
    viewInstanceId: GPT_YUNYING_ALERT_VIEW_INSTANCE_ID,
    enableHistory: false
  };
}

function getWrappedField(fieldValue) {
  const value = fieldValue && typeof fieldValue === 'object' ? fieldValue : {};
  return {
    originalValue: value.originalValue,
    renderValue: value.renderValue
  };
}

function normalizeYunyingMatchValue(value) {
  return String(value || '').trim();
}

function resolveGptYunyingAlertTimeRange(options = {}) {
  const start = options.start || (options.projectBackground && options.projectBackground.startDate) || options.begin;
  const end = options.end || (options.projectBackground && options.projectBackground.endDate);
  return resolveIncidentTimeRange({ start, end });
}

function summarizeGptYunyingAlertRows(rows, logger) {
  const summary = {
    virusFiles: {
      total: 0,
      hostIps: [],
      records: []
    },
    c2ExternalLink: {
      total: 0,
      hostIps: [],
      records: []
    },
    exploitAttacks: {
      total: 0,
      hostIps: [],
      records: []
    },
    webAttacks: {
      total: 0,
      hostIps: [],
      records: []
    }
  };
  const hostIpSets = {
    virusFiles: new Set(),
    c2ExternalLink: new Set(),
    exploitAttacks: new Set(),
    webAttacks: new Set()
  };
  const log = typeof logger === 'function' ? logger : null;
  const rowsList = Array.isArray(rows) ? rows : [];

  if (log) {
    logInfo(log, `GPT 运营告警明细行数: ${rowsList.length}`);
  }

  for (let index = 0; index < rowsList.length; index += 1) {
    const row = rowsList[index];
    const gptResult = getWrappedField(row && row.gptResult);
    const gptResultValue = normalizeYunyingMatchValue(gptResult.renderValue);
    const threatClass = getWrappedField(row && row.threatClass);
    const threatClassValue = normalizeYunyingMatchValue(threatClass.renderValue);
    const hostIp = getWrappedField(row && row.hostIp);
    const hostIpOriginalValue = normalizeYunyingMatchValue(hostIp.originalValue);
    const record = {
      hostIp,
      gptResult,
      threatClass
    };

    if (log) {
      logInfo(
        log,
        `GPT 运营告警行#${index + 1}: hostIp=${hostIpOriginalValue || '空'}, threatClass=${threatClassValue || '空'}, gptResult=${gptResultValue || '空'}`
      );
    }

    if (gptResultValue === GPT_YUNYING_ALERT_MATCHERS.virusFiles) {
      summary.virusFiles.total += 1;
      summary.virusFiles.records.push(record);
      if (hostIpOriginalValue && !hostIpSets.virusFiles.has(hostIpOriginalValue)) {
        hostIpSets.virusFiles.add(hostIpOriginalValue);
        summary.virusFiles.hostIps.push(hostIpOriginalValue);
      }
      continue;
    }

    if (gptResultValue === GPT_YUNYING_ALERT_MATCHERS.c2ExternalLink) {
      summary.c2ExternalLink.total += 1;
      summary.c2ExternalLink.records.push(record);
      if (hostIpOriginalValue && !hostIpSets.c2ExternalLink.has(hostIpOriginalValue)) {
        hostIpSets.c2ExternalLink.add(hostIpOriginalValue);
        summary.c2ExternalLink.hostIps.push(hostIpOriginalValue);
      }
      continue;
    }

    if (threatClassValue === GPT_YUNYING_ALERT_MATCHERS.exploitAttacks) {
      summary.exploitAttacks.total += 1;
      summary.exploitAttacks.records.push(record);
      if (hostIpOriginalValue && !hostIpSets.exploitAttacks.has(hostIpOriginalValue)) {
        hostIpSets.exploitAttacks.add(hostIpOriginalValue);
        summary.exploitAttacks.hostIps.push(hostIpOriginalValue);
      }
      continue;
    }

    if (threatClassValue === GPT_YUNYING_ALERT_MATCHERS.webAttacks) {
      summary.webAttacks.total += 1;
      summary.webAttacks.records.push(record);
      if (hostIpOriginalValue && !hostIpSets.webAttacks.has(hostIpOriginalValue)) {
        hostIpSets.webAttacks.add(hostIpOriginalValue);
        summary.webAttacks.hostIps.push(hostIpOriginalValue);
      }
      continue;
    }

    if (log) {
      logInfo(
        log,
        `GPT 运营告警未命中: gptResult=${gptResultValue || '空'}, threatClass=${threatClassValue || '空'}`
      );
    }
  }

  if (log) {
    logInfo(
      log,
      `GPT 运营告警汇总: 病毒木马=${summary.virusFiles.total}, C2外联=${summary.c2ExternalLink.total}, 漏洞利用=${summary.exploitAttacks.total}, Web攻击=${summary.webAttacks.total}`
    );
  }

  return summary;
}

function summarizeAlertThreatClassRows(rows, logger) {
  const summary = {
    exploitAttacks: {
      total: 0,
      hostIps: [],
      records: []
    },
    webAttacks: {
      total: 0,
      hostIps: [],
      records: []
    }
  };
  const hostIpSets = {
    exploitAttacks: new Set(),
    webAttacks: new Set()
  };
  const log = typeof logger === 'function' ? logger : null;
  const rowsList = Array.isArray(rows) ? rows : [];

  if (log) {
    logInfo(log, `告警总览明细行数: ${rowsList.length}`);
  }

  for (let index = 0; index < rowsList.length; index += 1) {
    const row = rowsList[index];
    const threatClass = getWrappedField(row && row.threatClass);
    const threatClassValue = normalizeYunyingMatchValue(threatClass.renderValue);
    const hostIp = getWrappedField(row && row.hostIp);
    const hostIpOriginalValue = normalizeYunyingMatchValue(hostIp.originalValue);
    const record = {
      hostIp,
      threatClass
    };

    if (log) {
      logInfo(
        log,
        `告警总览行#${index + 1}: hostIp=${hostIpOriginalValue || '空'}, threatClass=${threatClassValue || '空'}`
      );
    }

    if (threatClassValue === GPT_YUNYING_ALERT_MATCHERS.exploitAttacks) {
      summary.exploitAttacks.total += 1;
      summary.exploitAttacks.records.push(record);
      if (hostIpOriginalValue && !hostIpSets.exploitAttacks.has(hostIpOriginalValue)) {
        hostIpSets.exploitAttacks.add(hostIpOriginalValue);
        summary.exploitAttacks.hostIps.push(hostIpOriginalValue);
      }
      continue;
    }

    if (threatClassValue === GPT_YUNYING_ALERT_MATCHERS.webAttacks) {
      summary.webAttacks.total += 1;
      summary.webAttacks.records.push(record);
      if (hostIpOriginalValue && !hostIpSets.webAttacks.has(hostIpOriginalValue)) {
        hostIpSets.webAttacks.add(hostIpOriginalValue);
        summary.webAttacks.hostIps.push(hostIpOriginalValue);
      }
      continue;
    }

    if (log) {
      logInfo(log, `告警总览未命中: threatClass=${threatClassValue || '空'}`);
    }
  }

  if (log) {
    logInfo(log, `告警总览汇总: 漏洞利用=${summary.exploitAttacks.total}, Web攻击=${summary.webAttacks.total}`);
  }

  return summary;
}

async function fetchGptYunyingAlertTablePage(cookieInfo, xdrBaseUrl, options, pageNum, pageSize) {
  const headers = buildXdrPageHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl, {
    accept: 'application/json, text/plain, */*',
    'content-type': 'application/json',
    origin: `https://${normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL)}`,
    referer: `https://${normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL)}/`,
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'x-requested-with': 'XMLHttpRequest'
  });
  const url = `https://${normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL)}${GPT_YUNYING_ALERT_QUERY_ENDPOINT}`;
  const timeRange = resolveGptYunyingAlertTimeRange(options);
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildGptYunyingAlertTableQueryRequestBody({
      begin: timeRange.begin,
      end: timeRange.end,
      pageNum,
      pageSize
    }))
  });
  assertXdrApiSuccess(response, 'XDR GPT 运营告警查询接口');
  return response;
}

async function fetchGptYunyingAlertOverview(cookieInfo, xdrBaseUrl, options = {}) {
  const logger = options.logger;
  logInfo(logger, '拉取 GPT 运营告警风险总览');
  const pageSize = Number(options.pageSize || 1000);
  const firstPage = await fetchGptYunyingAlertTablePage(cookieInfo, xdrBaseUrl, options, 1, pageSize);
  const firstData = firstPage && firstPage.data && typeof firstPage.data === 'object' ? firstPage.data : {};
  const total = Number(firstData.total || 0);
  const rows = Array.isArray(firstData.data) ? [...firstData.data] : [];
  const totalPages = total > 0 ? Math.ceil(total / pageSize) : 1;

  for (let pageNum = 2; pageNum <= totalPages; pageNum += 1) {
    const pageResponse = await fetchGptYunyingAlertTablePage(cookieInfo, xdrBaseUrl, options, pageNum, pageSize);
    const pageData = pageResponse && pageResponse.data && typeof pageResponse.data === 'object' ? pageResponse.data : {};
    const pageRows = Array.isArray(pageData.data) ? pageData.data : [];
    rows.push(...pageRows);
    if (pageRows.length < pageSize) {
      break;
    }
  }

  const alertStats = summarizeGptYunyingAlertRows(rows, logger);
  return {
    total,
    ...alertStats
  };
}

async function fetchAlertThreatClassTablePage(cookieInfo, xdrBaseUrl, options, pageNum, pageSize) {
  const headers = buildXdrPageHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl, {
    accept: 'application/json, text/plain, */*',
    'content-type': 'application/json',
    origin: `https://${normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL)}`,
    referer: `https://${normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL)}/`,
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'x-requested-with': 'XMLHttpRequest'
  });
  const url = `https://${normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL)}${ALERT_QUERY_ENDPOINT}`;
  const timeRange = resolveGptYunyingAlertTimeRange(options);
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildAlertThreatClassRequestBody({
      begin: timeRange.begin,
      end: timeRange.end,
      pageNum,
      pageSize
    }))
  });
  assertXdrApiSuccess(response, 'XDR 告警总览查询接口');
  return response;
}

async function fetchAlertThreatClassOverview(cookieInfo, xdrBaseUrl, options = {}) {
  const logger = options.logger;
  logInfo(logger, '拉取 告警总览风险项');
  const pageSize = Number(options.pageSize || 1000);
  const firstPage = await fetchAlertThreatClassTablePage(cookieInfo, xdrBaseUrl, options, 1, pageSize);
  const firstData = firstPage && firstPage.data && typeof firstPage.data === 'object' ? firstPage.data : {};
  const total = Number(firstData.total || 0);
  const rows = Array.isArray(firstData.data) ? [...firstData.data] : [];
  const totalPages = total > 0 ? Math.ceil(total / pageSize) : 1;

  for (let pageNum = 2; pageNum <= totalPages; pageNum += 1) {
    const pageResponse = await fetchAlertThreatClassTablePage(cookieInfo, xdrBaseUrl, options, pageNum, pageSize);
    const pageData = pageResponse && pageResponse.data && typeof pageResponse.data === 'object' ? pageResponse.data : {};
    const pageRows = Array.isArray(pageData.data) ? pageData.data : [];
    rows.push(...pageRows);
    if (pageRows.length < pageSize) {
      break;
    }
  }

  const alertStats = summarizeAlertThreatClassRows(rows, logger);
  return {
    total,
    ...alertStats
  };
}

async function fetchAlertTableCount(cookieInfo, xdrBaseUrl, options) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl, {
    referer: 'https://' + normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL) + '/'
  });
  const url = 'https://' + normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL) + ALERT_QUERY_ENDPOINT;
  const timeRange = resolveIncidentTimeRange(options);
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildAlertCountRequestBody(timeRange))
  });
  assertXdrApiSuccess(response, 'XDR 告警数量接口');

  const total = Number(response && response.data ? response.data.total : 0);
  if (!Number.isFinite(total)) {
    throw new Error('XDR 告警数量接口返回缺少 total: ' + JSON.stringify(response).slice(0, 500));
  }
  return {
    total,
    response
  };
}

function mapProtectionTypeLabels(typeData) {
  const type = typeData && typeof typeData === 'object' ? typeData : {};
  const items = [
    ['online', '在线'],
    ['offline', '离线'],
    ['disabled', '已禁用'],
    ['demoted', '已降级'],
    ['unprotected', '未安装']
  ];

  return items
    .map(([key, label]) => ({
      name: label,
      value: Number(type[key] || 0)
    }))
    .filter((item) => Number.isFinite(item.value));
}

function mapExposureTypeLabels(typeData) {
  const type = typeData && typeof typeData === 'object' ? typeData : {};
  const items = [
    ['server', '服务器'],
    ['terminal', '终端'],
    ['other', '其他']
  ];

  return items
    .map(([key, label]) => ({
      name: label,
      value: Number(type[key] || 0)
    }))
    .filter((item) => Number.isFinite(item.value));
}

function mapAssetTypeLabels(typeData) {
  const type = typeData && typeof typeData === 'object' ? typeData : {};
  const items = [
    ['server', '服务器'],
    ['terminal', '终端'],
    ['other', '其他']
  ];

  return items
    .map(([key, label]) => ({
      name: label,
      value: Number(type[key] || 0)
    }))
    .filter((item) => Number.isFinite(item.value));
}

function normalizeCountTotal(response) {
  const total = response && response.total !== undefined
    ? response.total
    : response && response.data && response.data.total !== undefined
      ? response.data.total
      : 0;
  const value = Number(total || 0);
  return Number.isFinite(value) ? value : 0;
}

function normalizeAssetStatisticsResponse(response) {
  return {
    manage_asset: normalizeCountTotal(response)
  };
}

function normalizeAssetCoreResponse(response) {
  return {
    core_asset: normalizeCountTotal(response)
  };
}

function normalizeAssetReadyToOutboundResponse(response) {
  return {
    ready_to_outbound: normalizeCountTotal(response)
  };
}

function normalizeAssetProtectionResponse(response) {
  const data = response && response.data && typeof response.data === 'object' ? response.data : {};
  const type = data.type && typeof data.type === 'object' ? data.type : {};
  return {
    protectionDistribution: mapProtectionTypeLabels(type)
  };
}

function normalizeAssetExposureResponse(response) {
  const data = response && response.data && typeof response.data === 'object' ? response.data : {};
  const type = data.type && typeof data.type === 'object' ? data.type : {};
  return {
    internetExposureDistribution: mapExposureTypeLabels(type)
  };
}

function normalizeAssetTypeResponse(response) {
  const data = response && response.data && typeof response.data === 'object' ? response.data : {};
  const type = data.type && typeof data.type === 'object' ? data.type : {};
  return {
    typeDistribution: mapAssetTypeLabels(type)
  };
}

function parseLocalDate(value, endOfDay = false) {
  if (value === undefined || value === null || value === '') {
    return null;
  }

  if (typeof value === 'number' || /^\d+$/.test(String(value))) {
    return Number(value);
  }

  const match = String(value).trim().match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) {
    throw new Error(`日期格式无效: ${value}，请使用 YYYY-MM-DD`);
  }

  const [, year, month, day] = match.map(Number);
  const date = endOfDay
    ? new Date(year, month - 1, day, 23, 59, 59, 999)
    : new Date(year, month - 1, day, 0, 0, 0, 0);
  return Math.floor(date.getTime() / 1000);
}

function resolveIncidentTimeRange(options = {}) {
  const begin = parseLocalDate(options.begin || options.start, false);
  const end = parseLocalDate(options.end, true);

  if (!begin || !end) {
    throw new Error('XDR 事件导出需要 --start YYYY-MM-DD 和 --end YYYY-MM-DD');
  }

  if (begin > end) {
    throw new Error('XDR 事件导出时间范围无效: --start 不能晚于 --end');
  }

  return { begin, end };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseContentDispositionFilename(value) {
  const header = String(value || '');
  const encodedMatch = header.match(/filename\*=UTF-8''([^;]+)/i);
  if (encodedMatch) {
    return decodeURIComponent(encodedMatch[1].trim().replace(/^"|"$/g, ''));
  }

  const plainMatch = header.match(/filename="?([^";]+)"?/i);
  return plainMatch ? plainMatch[1].trim() : '';
}

async function fetchExportFields(cookieInfo, xdrBaseUrl) {
  await visitXdrAssetPage(cookieInfo, xdrBaseUrl);
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${EXPORT_FIELDS_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildExportFieldsRequestBody())
  });
  assertXdrApiSuccess(response, 'XDR 资产字段接口');
  return response;
}

async function fetchAssetStatistics(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${ASSET_COUNT_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildAssetCountRequestBody())
  });
  assertXdrApiSuccess(response, 'XDR 资产台账数量接口');
  return response;
}

async function fetchAssetCore(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${ASSET_COUNT_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildAssetCountRequestBody({
      magnitude: {
        op: '=',
        val: 'core'
      }
    }))
  });
  assertXdrApiSuccess(response, 'XDR 核心资产数量接口');
  return response;
}

async function fetchAssetReadyToOutbound(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${ASSET_COUNT_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildAssetCountRequestBody({
      ready_to_outbound: {
        op: '=',
        val: 'last7d'
      }
    }))
  });
  assertXdrApiSuccess(response, 'XDR 7天内即将退库资产数量接口');
  return response;
}

async function fetchAssetProtection(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${ASSET_PROTECTION_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify({})
  });
  assertXdrApiSuccess(response, 'XDR 资产防护接口');
  return response;
}

async function fetchAssetExposure(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${ASSET_EXPOSURE_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify({ is_exposure: 2 })
  });
  assertXdrApiSuccess(response, 'XDR 互联网暴露资产接口');
  return response;
}

async function fetchAssetType(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${ASSET_TYPE_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify({ is_core: 0 })
  });
  assertXdrApiSuccess(response, 'XDR 资产类型接口');
  return response;
}

function buildAssetCountRequestBody(filters = {}) {
  return {
    branch_id: 'all',
    search_type: 'current',
    platform_ids: [],
    start: 0,
    limit: 20,
    ...filters
  };
}

async function resolveWorkingXdrBaseUrl(cookieInfo, explicitBaseUrl, logger) {
  const candidates = unique([
    explicitBaseUrl,
    ...(cookieInfo.xdrBaseUrlCandidates || []),
    cookieInfo.xdrBaseUrl,
    DEFAULT_XDR_BASE_URL,
    'xdrsz.sangfor.com.cn'
  ].map((item) => normalizeBaseUrl(item)));

  const errors = [];
  for (const candidate of candidates) {
    try {
      const exportFieldsResponse = await fetchExportFields(cookieInfo, candidate);
      logInfo(logger, `使用 XDR 域名: ${candidate}`);
      return {
        xdrBaseUrl: candidate,
        exportFieldsResponse
      };
    } catch (error) {
      errors.push(`${candidate}: ${error.message}`);
    }
  }

  throw new Error(`无法确定可用的 XDR 域名，已尝试: ${errors.join(' | ')}`);
}

async function triggerAssetExport(cookieInfo, xdrBaseUrl, exportFields) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${xdrBaseUrl}${EXPORT_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildAssetExportRequestBody(exportFields))
  });
  assertXdrApiSuccess(response, 'XDR 资产导出接口');
  return response;
}

async function triggerIncidentExport(cookieInfo, xdrBaseUrl, options) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl, {
    referer: `https://${xdrBaseUrl}${XDR_INCIDENT_PAGE_PATH}`
  });
  const url = `https://${xdrBaseUrl}${INCIDENT_EXPORT_ADD_ENDPOINT}`;
  const timeRange = resolveIncidentTimeRange(options);
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildIncidentExportRequestBody(timeRange))
  });
  assertXdrApiSuccess(response, 'XDR 事件导出创建任务接口');
  return response;
}

async function fetchIncidentTableCount(cookieInfo, xdrBaseUrl, options) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl, {
    referer: `https://${xdrBaseUrl}/`
  });
  const url = `https://${xdrBaseUrl}${INCIDENT_COUNT_ENDPOINT}`;
  const timeRange = resolveIncidentTimeRange(options);
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildIncidentCountRequestBody(timeRange))
  });
  assertXdrApiSuccess(response, 'XDR 事件数量接口');

  const total = Number(response && response.data ? response.data.total : 0);
  if (!Number.isFinite(total)) {
    throw new Error(`XDR 事件数量接口返回缺少 total: ${JSON.stringify(response).slice(0, 500)}`);
  }
  return {
    total,
    response
  };
}

async function pollIncidentExportResult(cookieInfo, xdrBaseUrl, taskId, options = {}) {
  const timeoutMs = Number(options.timeoutMs || 1000000);
  const intervalMs = Number(options.pollIntervalMs || 2000);
  const startedAt = Date.now();
  const logger = options.logger;
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl, {
    referer: `https://${xdrBaseUrl}${XDR_INCIDENT_PAGE_PATH}`
  });
  const url = `https://${xdrBaseUrl}${INCIDENT_EXPORT_RESULT_ENDPOINT}`;
  let lastProgressKey = '';

  while (Date.now() - startedAt <= timeoutMs) {
    const response = await requestJson(url, {
      headers,
      body: JSON.stringify({
        taskId,
        viewInstanceId: INCIDENT_VIEW_INSTANCE_ID,
        serviceInfo: INCIDENT_SERVICE_INFO
      })
    });
    assertXdrApiSuccess(response, 'XDR 事件导出结果接口');

    const data = response && response.data && typeof response.data === 'object' ? response.data : {};
    const task = data.task && typeof data.task === 'object' ? data.task : {};
    const status = String(task.status || '').toLowerCase();
    const handled = task.handled !== undefined ? task.handled : '-';
    const total = task.total !== undefined ? task.total : '-';
    const progressKey = `${status}:${handled}/${total}`;
    if (progressKey !== lastProgressKey) {
      logInfo(logger, `事件表导出中: ${handled}/${total}`);
      lastProgressKey = progressKey;
    }
    if (status === 'success' && data.result) {
      return response;
    }
    if (status === 'failed' || status === 'error') {
      throw new Error(`XDR 事件导出失败: ${task.errorMessage || task.businessErrorMessage || JSON.stringify(response).slice(0, 500)}`);
    }

    await sleep(intervalMs);
  }

  throw new Error(`XDR 事件导出轮询超时: ${timeoutMs}ms`);
}

async function downloadAssetFile(cookieInfo, xdrBaseUrl, filename, downloadDir) {
  const xdrHost = normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL);
  const downloadUrl = `https://${xdrHost}/apps/asset/view/asset/download_file?file=${encodeURIComponent(filename)}`;
  const headers = buildXdrPageHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrHost, {
    accept: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel,application/octet-stream,*/*',
    referer: `https://${xdrHost}${XDR_ASSET_PAGE_PATH}`,
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors'
  });
  delete headers['content-type'];

  const downloaded = await requestBuffer(downloadUrl, { headers });
  const targetPath = path.join(downloadDir, filename);
  await fsp.mkdir(downloadDir, { recursive: true });
  await fsp.writeFile(targetPath, downloaded.buffer);
  return {
    ...downloaded,
    filePath: targetPath
  };
}

async function downloadIncidentFile(cookieInfo, xdrBaseUrl, resultPath, downloadDir, fallbackFilename) {
  const xdrHost = normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL);
  const resultUrl = new URL(resultPath, `https://${xdrHost}`);
  const headers = buildXdrPageHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrHost, {
    accept: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel,application/octet-stream,*/*',
    referer: `https://${xdrHost}${XDR_INCIDENT_PAGE_PATH}`,
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors'
  });
  delete headers['content-type'];

  const downloaded = await requestBuffer(resultUrl.toString(), { headers });
  const filename = parseContentDispositionFilename(downloaded.headers['content-disposition'])
    || fallbackFilename
    || `incident-export-${Date.now()}.xlsx`;
  const targetPath = path.join(downloadDir, filename);
  await fsp.mkdir(downloadDir, { recursive: true });
  await fsp.writeFile(targetPath, downloaded.buffer);
  return {
    ...downloaded,
    filePath: targetPath,
    filename,
    downloadUrl: resultUrl.toString()
  };
}

async function exportXdrAssetList(options) {
  const logger = options.logger;
  logInfo(logger, '导出 XDR 资产表');
  const cookieInfo = await readXdrCookieInfo(options.xdrCookiePath);
  const resolved = await resolveWorkingXdrBaseUrl(cookieInfo, options.xdrBaseUrl, logger);
  const xdrBaseUrl = resolved.xdrBaseUrl;
  const exportFieldsResponse = resolved.exportFieldsResponse;

  if (!exportFieldsResponse || exportFieldsResponse.success !== true || !exportFieldsResponse.data) {
    throw new Error(`XDR 资产字段接口返回异常: ${JSON.stringify(exportFieldsResponse).slice(0, 500)}`);
  }

  const exportResponse = await triggerAssetExport(cookieInfo, xdrBaseUrl, exportFieldsResponse.data);
  const filename = String(exportResponse && exportResponse.data ? exportResponse.data : exportResponse && exportResponse.filename ? exportResponse.filename : '');
  if (!filename) {
    throw new Error(`XDR 资产导出接口返回缺少文件名: ${JSON.stringify(exportResponse).slice(0, 500)}`);
  }

  const downloadDir = options.downloadDir || path.dirname(cookieInfo.resolvedPath);
  const downloaded = await downloadAssetFile(cookieInfo, xdrBaseUrl, filename, downloadDir);
  logInfo(logger, `XDR 资产表: ${downloaded.filePath}`);

  return {
    xdrBaseUrl,
    downloadDir,
    filePath: downloaded.filePath,
    filename,
    exportFields: exportFieldsResponse.data,
    exportResponse,
    downloadResponse: {
      statusCode: downloaded.statusCode,
      headers: downloaded.headers
    }
  };
}

async function exportXdrIncidentList(options) {
  const logger = options.logger;
  logInfo(logger, `导出 XDR 事件表: ${options.start} ~ ${options.end}`);
  const cookieInfo = await readXdrCookieInfo(options.xdrCookiePath);
  const resolved = await resolveWorkingXdrBaseUrl(cookieInfo, options.xdrBaseUrl, logger);
  const xdrBaseUrl = resolved.xdrBaseUrl;
  const incidentCount = await fetchIncidentTableCount(cookieInfo, xdrBaseUrl, options);
  logInfo(logger, `XDR 事件数量: ${incidentCount.total}`);
  const exportResponse = await triggerIncidentExport(cookieInfo, xdrBaseUrl, options);
  const task = exportResponse && exportResponse.data && typeof exportResponse.data === 'object' ? exportResponse.data : {};
  const taskId = task.id;
  if (!taskId) {
    throw new Error(`XDR 事件导出创建任务接口返回缺少 taskId: ${JSON.stringify(exportResponse).slice(0, 500)}`);
  }

  logInfo(logger, `事件导出任务: ${taskId}`);
  const resultResponse = await pollIncidentExportResult(cookieInfo, xdrBaseUrl, taskId, options);
  const resultPath = resultResponse && resultResponse.data ? resultResponse.data.result : '';
  if (!resultPath) {
    throw new Error(`XDR 事件导出结果接口返回缺少下载路径: ${JSON.stringify(resultResponse).slice(0, 500)}`);
  }

  const downloadDir = options.downloadDir || path.dirname(cookieInfo.resolvedPath);
  const fallbackFilename = `incident-export-${taskId}.xlsx`;
  const downloaded = await downloadIncidentFile(cookieInfo, xdrBaseUrl, resultPath, downloadDir, fallbackFilename);
  logInfo(logger, `XDR 事件表: ${downloaded.filePath}`);

  return {
    xdrBaseUrl,
    downloadDir,
    filePath: downloaded.filePath,
    filename: downloaded.filename,
    taskId,
    totalEvents: incidentCount.total,
    resultPath,
    downloadUrl: downloaded.downloadUrl,
    exportResponse,
    resultResponse,
    countResponse: incidentCount.response,
    downloadResponse: {
      statusCode: downloaded.statusCode,
      headers: downloaded.headers
    }
  };
}

async function exportXdrDeviceList(options) {
  const logger = options.logger;
  logInfo(logger, '导出 XDR 设备表');
  const cookieInfo = await readXdrCookieInfo(options.xdrCookiePath);
  const resolved = await resolveWorkingXdrBaseUrl(cookieInfo, options.xdrBaseUrl, logger);
  const xdrBaseUrl = resolved.xdrBaseUrl;
  const pageSize = 20;
  const firstResponse = await fetchDeviceList(cookieInfo, xdrBaseUrl, pageSize, 1);
  const firstData = firstResponse && firstResponse.data && typeof firstResponse.data === 'object' ? firstResponse.data : {};
  const total = Number(firstData.total || 0);
  const firstPageDevices = Array.isArray(firstData.list) ? firstData.list : [];
  const devices = [...firstPageDevices];
  const totalPages = total > 0 ? Math.ceil(total / pageSize) : 1;

  for (let pageNum = 2; pageNum <= totalPages; pageNum += 1) {
    const pageResponse = await fetchDeviceList(cookieInfo, xdrBaseUrl, pageSize, pageNum);
    const pageData = pageResponse && pageResponse.data && typeof pageResponse.data === 'object' ? pageResponse.data : {};
    const pageDevices = Array.isArray(pageData.list) ? pageData.list : [];
    devices.push(...pageDevices);
  }

  const response = {
    ...firstResponse,
    data: {
      ...firstData,
      list: devices
    }
  };
  const outputPath = path.join(path.resolve(__dirname, '..'), 'tmp', 'device.json');
  await fsp.mkdir(path.dirname(outputPath), { recursive: true });
  await fsp.writeFile(outputPath, JSON.stringify(response, null, 2), 'utf8');
  logInfo(logger, `XDR 设备表: ${outputPath} (共 ${devices.length} 条)`);

  return {
    xdrBaseUrl,
    filePath: outputPath,
    response
  };
}

async function fetchXdrAssetOverview(cookiePathOrInfo, options = {}) {
  const logger = options.logger;
  logInfo(logger, '拉取 XDR 资产台账统计');
  const cookieInfo = cookiePathOrInfo && cookiePathOrInfo.cookieString
    ? cookiePathOrInfo
    : await readXdrCookieInfo(cookiePathOrInfo);
  const resolved = await resolveWorkingXdrBaseUrl(cookieInfo, options.xdrBaseUrl, logger);
  const xdrBaseUrl = resolved.xdrBaseUrl;
  const start = options.start || (options.projectBackground && options.projectBackground.startDate) || options.begin;
  const end = options.end || (options.projectBackground && options.projectBackground.endDate);
  const timeOptions = {
    ...options,
    start,
    end
  };
  const [assetCoreResponse, assetReadyToOutboundResponse] = await Promise.all([
    fetchAssetCore(cookieInfo, xdrBaseUrl),
    fetchAssetReadyToOutbound(cookieInfo, xdrBaseUrl)
  ]);

  const assetLedger = {
    ...normalizeAssetCoreResponse(assetCoreResponse),
    ...normalizeAssetReadyToOutboundResponse(assetReadyToOutboundResponse),
    manage_asset: 0,
    typeDistribution: [],
    protectionDistribution: [],
    internetExposureDistribution: []
  };

  let gptYunyingAlertStats = {
    total: 0,
    virusFiles: {
      total: 0,
      hostIps: [],
      records: []
    },
    c2ExternalLink: {
      total: 0,
      hostIps: [],
      records: []
    },
    exploitAttacks: {
      total: 0,
      hostIps: [],
      records: []
    },
    webAttacks: {
      total: 0,
      hostIps: [],
      records: []
    }
  };
  let alertThreatClassStats = {
    total: 0,
    exploitAttacks: {
      total: 0,
      hostIps: [],
      records: []
    },
    webAttacks: {
      total: 0,
      hostIps: [],
      records: []
    }
  };

  try {
    gptYunyingAlertStats = await fetchGptYunyingAlertOverview(cookieInfo, xdrBaseUrl, timeOptions);
  } catch (error) {
    logInfo(logger, `获取 GPT 运营告警风险总览失败: ${error.message}，将使用空结果`);
  }

  try {
    alertThreatClassStats = await fetchAlertThreatClassOverview(cookieInfo, xdrBaseUrl, timeOptions);
  } catch (error) {
    logInfo(logger, `获取 告警总览风险项失败: ${error.message}，将使用空结果`);
  }

  let securityLogTotal = 0;
  let alertTotal = 0;
  let alertReductionRate = 0;
  try {
    [securityLogTotal, { alertTotal, reductionRate: alertReductionRate }] = await Promise.all([
      fetchSecurityLogCount(cookieInfo, xdrBaseUrl, timeOptions),
      fetchAlertReductionRate(cookieInfo, xdrBaseUrl, timeOptions)
    ]);
  } catch (error) {
    logInfo(logger, `获取安全日志量或有效告警统计失败: ${error.message}，将使用空结果`);
  }

  const yunyingAlertStats = {
    c2VirusTotal: gptYunyingAlertStats.virusFiles.total + gptYunyingAlertStats.c2ExternalLink.total,
    webVulnTotal: alertThreatClassStats.exploitAttacks.total + alertThreatClassStats.webAttacks.total,
    virusFiles: gptYunyingAlertStats.virusFiles,
    c2ExternalLink: gptYunyingAlertStats.c2ExternalLink,
    exploitAttacks: alertThreatClassStats.exploitAttacks,
    webAttacks: alertThreatClassStats.webAttacks
  };

  return {
    projectBackground: options.projectBackground || {},
    assetLedger,
    riskOverview: {
      yunyingAlertStats,
      securityLogTotal,
      alertTotal,
      alertReductionRate,
      closeRate: alertReductionRate
    },
    riskDetails: {
      securityLogTotal,
      alertTotal,
      alertReductionRate,
      closeRate: alertReductionRate
    },
    appendix: {}
  };
}

async function fetchDeviceTypeInfo(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${normalizeBaseUrl(xdrBaseUrl)}${DEVICE_TYPE_INFO_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify({})
  });
  assertXdrApiSuccess(response, 'XDR 设备类型枚举接口');
  return response;
}

async function fetchDeviceList(cookieInfo, xdrBaseUrl, pageSize, pageNum = 1) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${normalizeBaseUrl(xdrBaseUrl)}${DEVICE_LIST_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify({
      keyword: '',
      type: 0,
      pageSize: pageSize || 1000,
      pageNum,
      devStatus: [1, 2, 3, 4]
    })
  });
  assertXdrApiSuccess(response, 'XDR 设备列表接口');
  return response;
}

async function fetchThirdPartyDeviceStats(cookieInfo, xdrBaseUrl) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = `https://${normalizeBaseUrl(xdrBaseUrl)}${THIRD_PARTY_DEVICE_STATS_ENDPOINT}`;
  const response = await requestJson(url, {
    headers,
    method: 'POST',
    body: JSON.stringify({
      name: '',
      appIds: [],
      hostIp: '',
      statusList: [],
      abilityTypeList: [],
      enableList: [],
      appInstanceId: '',
      pageIndex: 1,
      pageSize: 20
    })
  });
  assertXdrApiSuccess(response, 'XDR 第三方设备统计接口');
  return response;
}

async function collectDeviceCategoryCounts(cookieInfo, xdrBaseUrl, logger) {
  const log = typeof logger === 'function' ? logger : function() {};
  // 查询深信服设备列表
  let firstPageResponse;
  try {
    firstPageResponse = await fetchDeviceList(cookieInfo, xdrBaseUrl, 1000, 1);
  } catch (error) {
    throw new Error(`获取深信服设备列表失败: ${error.message}`);
  }

  // 解析深信服设备
  const firstPageData = firstPageResponse && firstPageResponse.data && typeof firstPageResponse.data === 'object' ? firstPageResponse.data : {};
  const totalSangfor = Number(firstPageData.total || 0);
  const firstPageDevices = Array.isArray(firstPageData.list) ? firstPageData.list : [];

  // 按 devType 分类统计
  const categoryCounts = { af: 0, aes: 0, sip: 0, sta: 0, other: 0 };
  const pageSize = 1000;
  const totalPages = totalSangfor > 0 ? Math.ceil(totalSangfor / pageSize) : 1;
  const devices = [...firstPageDevices];

  for (let pageNum = 2; pageNum <= totalPages; pageNum += 1) {
    const pageResponse = await fetchDeviceList(cookieInfo, xdrBaseUrl, pageSize, pageNum);
    const pageData = pageResponse && pageResponse.data && typeof pageResponse.data === 'object' ? pageResponse.data : {};
    const pageDevices = Array.isArray(pageData.list) ? pageData.list : [];
    devices.push(...pageDevices);
  }

  for (const device of devices) {
    const category = classifyDeviceType(Number(device.devType));
    if (categoryCounts[category] !== undefined) {
      categoryCounts[category] += 1;
    }
  }

  // 单独查询第三方设备（容错，查不到就记为 0）
  let totalThird = 0;
  try {
    const thirdPartyResponse = await fetchThirdPartyDeviceStats(cookieInfo, xdrBaseUrl);
    const thirdPartyData = thirdPartyResponse && thirdPartyResponse.data && typeof thirdPartyResponse.data === 'object' ? thirdPartyResponse.data : {};
    totalThird = Number(thirdPartyData.count || 0);
    log(`第三方设备数量: ${totalThird}`);
  } catch (error) {
    log(`获取第三方设备数量失败: ${error.message}，将跳过第三方设备统计`);
  }

  return {
    devices: totalSangfor + totalThird,
    sangfor: totalSangfor,
    af: categoryCounts.af,
    aes: categoryCounts.aes,
    sip: categoryCounts.sip,
    sta: categoryCounts.sta,
    other_sf: categoryCounts.other,
    third: totalThird
  };
}

function buildLogSearchCountRequestBody({ begin, end }) {
  return {
    time: {
      start: begin,
      end
    },
    tables: ['NetworkSecurityLog', 'EndpointSecurityLog']
  };
}

async function fetchSecurityLogCount(cookieInfo, xdrBaseUrl, options) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = 'https://' + normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL) + LOG_SEARCH_COUNT_ENDPOINT;
  const { begin, end } = resolveIncidentTimeRange(options);
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildLogSearchCountRequestBody({ begin, end })),
    timeout: 90000
  });

  const code = response && response.code;
  if (code !== 'Success') {
    throw new Error(`安全日志量查询接口返回异常: ${JSON.stringify(response).slice(0, 500)}`);
  }

  const count = Number(response && response.data != null ? response.data : 0);
  if (!Number.isFinite(count)) {
    throw new Error(`安全日志量查询接口返回 data 无效: ${JSON.stringify(response).slice(0, 500)}`);
  }
  return count;
}

function buildOverviewCountRequestBody({ begin, end }) {
  return {
    timeField: 'startTime',
    begin: { type: 'absolute', value: begin },
    end: { type: 'absolute', value: end }
  };
}

async function fetchAlertReductionRate(cookieInfo, xdrBaseUrl, options) {
  const headers = buildXdrHeaders(cookieInfo.cookieString, cookieInfo.csrfToken, xdrBaseUrl);
  const url = 'https://' + normalizeBaseUrl(xdrBaseUrl || DEFAULT_XDR_BASE_URL) + OVERVIEW_COUNT_ENDPOINT;
  const { begin, end } = resolveIncidentTimeRange(options);
  const response = await requestJson(url, {
    headers,
    body: JSON.stringify(buildOverviewCountRequestBody({ begin, end }))
  });

  const code = response && response.code;
  if (code !== 0 && code !== '0') {
    throw new Error(`告警消减率接口返回异常: ${JSON.stringify(response).slice(0, 500)}`);
  }

  const data = response && response.data && typeof response.data === 'object' ? response.data : {};
  const alertTotal = Number(data.alertTotalCount && data.alertTotalCount.value != null ? data.alertTotalCount.value : 0);
  const incidentTotal = Number(data.incidentCount && data.incidentCount.value != null ? data.incidentCount.value : 0);

  if (!Number.isFinite(alertTotal) || !Number.isFinite(incidentTotal)) {
    throw new Error(`告警消减率接口返回数据无效: ${JSON.stringify(response).slice(0, 500)}`);
  }

  const rate = alertTotal > 0 ? (alertTotal - incidentTotal) / alertTotal : 0;
  return {
    alertTotal,
    incidentTotal,
    reductionRate: Math.round(rate * 10) / 10
  };
}

module.exports = {
  DEFAULT_XDR_BASE_URL,
  ASSET_COUNT_ENDPOINT,
  ASSET_STATISTICS_ENDPOINT: ASSET_COUNT_ENDPOINT,
  ASSET_PROTECTION_ENDPOINT,
  ASSET_EXPOSURE_ENDPOINT,
  ASSET_TYPE_ENDPOINT,
  EXPORT_FIELDS_ENDPOINT,
  EXPORT_ENDPOINT,
  normalizeBaseUrl,
  normalizeCookieContent,
  readXdrCookieInfo,
  buildExportFieldsRequestBody,
  buildAssetExportRequestBody,
  buildAssetCountRequestBody,
  buildIncidentTableFields,
  buildIncidentExportRequestBody,
  buildIncidentCountRequestBody,
  buildAlertCountRequestBody,
  buildAlertThreatClassRequestBody,
  mapProtectionTypeLabels,
  mapExposureTypeLabels,
  mapAssetTypeLabels,
  parseLocalDate,
  resolveIncidentTimeRange,
  normalizeAssetStatisticsResponse,
  normalizeAssetCoreResponse,
  normalizeAssetReadyToOutboundResponse,
  normalizeAssetProtectionResponse,
  normalizeAssetExposureResponse,
  normalizeAssetTypeResponse,
  fetchAssetStatistics,
  fetchAssetCore,
  fetchAssetReadyToOutbound,
  fetchAssetProtection,
  fetchAssetExposure,
  fetchAssetType,
  resolveWorkingXdrBaseUrl,
  fetchXdrAssetOverview,
  exportXdrAssetList,
  triggerIncidentExport,
  pollIncidentExportResult,
  downloadIncidentFile,
  exportXdrIncidentList,
  exportXdrDeviceList,
  fetchAlertTableCount,
  buildGptYunyingAlertTableFields,
  buildGptYunyingAlertSubTableFields,
  buildGptYunyingAlertTableQuerySection,
  buildGptYunyingAlertTableQueryRequestBody,
  summarizeGptYunyingAlertRows,
  summarizeAlertThreatClassRows,
  fetchGptYunyingAlertTablePage,
  fetchGptYunyingAlertOverview,
  fetchAlertThreatClassTablePage,
  fetchAlertThreatClassOverview,
  fetchDeviceTypeInfo,
  fetchDeviceList,
  fetchThirdPartyDeviceStats,
  collectDeviceCategoryCounts,
  DEVICE_TYPE_CATEGORIES,
  classifyDeviceType,
  buildLogSearchCountRequestBody,
  fetchSecurityLogCount,
  buildOverviewCountRequestBody,
  fetchAlertReductionRate
};
