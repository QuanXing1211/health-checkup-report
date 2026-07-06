'use strict';

const path = require('path');
const https = require('https');
const { readMsswCookieInfo, buildMsswExportHeaders, DEFAULT_MSSW_BASE_URL } = require(path.join(__dirname, '..', 'src', 'mssw_client'));

async function main() {
  const cookiePath = process.env['USERPROFILE'] + '\\Downloads\\mssw_cookies.txt';
  console.log('Cookie path:', cookiePath);

  const cookieInfo = await readMsswCookieInfo(cookiePath);
  const csrfToken = cookieInfo.cookies && cookieInfo.cookies['csrf_token'];
  console.log('CSRF Token:', csrfToken);
  console.log('Cookie length:', cookieInfo.cookieString.length);

  const companyId = '67262236';
  const msswBaseUrl = 'pre.soar.sangfor.com';
  const headers = buildMsswExportHeaders(cookieInfo, msswBaseUrl, companyId);
  console.log('Headers:', JSON.stringify(headers, null, 2));

  // Try incident table
  const incidentBody = JSON.stringify({
    limit: 20,
    offset: 0,
    filters: {
      end_time: [1778803200000, 1781193599000],
      customer_type: 'single_customer',
      company_ids: [companyId]
    },
    sorts: [{ field: 'sla_deadline', order: 'asc' }]
  });

  console.log('\n=== Test 1: Event Table ===');
  await sendRequest(msswBaseUrl, '/gateway/mss-mdr/web/api/mssw/mss-mdr/v1/incident_table', headers, incidentBody);

  // Try alert table (direct /ngsoc/INCIDENT)
  const alertBody = JSON.stringify({
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
    serviceInfo: { appName: 'incident', servletContextPath: '/', serviceType: 'table', handler: 'alertTableQueryHandler' },
    globalCondition: { branchIds: [], time: { timeField: 'firstTime', begin: { type: 'absolute', value: 1778803200 }, end: { type: 'absolute', value: 1781193599 } } },
    table: { enable: true, viewName: 'AlertView', aggregationStrategies: null, tableFields: [], pageNum: 1, pageSize: 100, serviceInfo: { appName: 'incident', servletContextPath: '/', serviceType: 'table', handler: 'alertTableQueryHandler' }, subTable: null, rightClicked: false, selectAllPage: true, routers: [], rightActions: [], extensionParams: {} },
    tag: null, viewName: 'AlertView', model: 'expert', autoRefresh: false, viewInstanceId: '67aebe12c29c0b7b63b0c51e', enableHistory: true
  });

  console.log('\n=== Test 2: Alert Table (direct /ngsoc/INCIDENT) ===');
  await sendRequest(msswBaseUrl, '/ngsoc/INCIDENT/api/v1/table/query/alertTableQueryHandler?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false', headers, alertBody);
}

function sendRequest(host, path, headers, body) {
  return new Promise((resolve) => {
    const opts = {
      hostname: host,
      port: 443,
      path: path,
      method: 'POST',
      headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
      rejectUnauthorized: false
    };

    console.log('URL: https://' + host + path);
    console.log('Method: POST');

    const req = https.request(opts, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        console.log('Status:', res.statusCode, res.statusMessage);
        try {
          const parsed = JSON.parse(text);
          console.log('Response:', JSON.stringify(parsed, null, 2));
        } catch (e) {
          console.log('Raw response:', text.substring(0, 500));
        }
        resolve();
      });
    });

    req.on('error', (err) => {
      console.log('Error:', err.message);
      resolve();
    });

    req.write(body);
    req.end();
  });
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
