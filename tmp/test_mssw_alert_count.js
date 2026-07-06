'use strict';

const path = require('path');
const { readMsswCookieInfo, fetchMsswAlertTableCount, DEFAULT_MSSW_BASE_URL } = require(path.join(__dirname, '..', 'src', 'mssw_client'));

async function main() {
  const cookiePath = process.env['USERPROFILE'] + '\\Downloads\\mssw_cookies.txt';
  const cookieInfo = await readMsswCookieInfo(cookiePath);

  const result = await fetchMsswAlertTableCount(
    cookieInfo,
    DEFAULT_MSSW_BASE_URL,
    '67262236',
    { start: '2026-05-31', end: '2026-06-29' }
  );

  console.log('MSSW 告警总数:', result.total);
  console.log('响应:', JSON.stringify(result.response, null, 2).substring(0, 300));
}

main().catch((err) => {
  console.error('失败:', err.message);
  process.exit(1);
});
