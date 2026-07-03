'use strict';

const path = require('path');
const { readMsswCookieInfo, fetchMsswSecurityLogCount, DEFAULT_MSSW_BASE_URL } = require(path.join(__dirname, '..', 'src', 'xdr_asset_client'));

async function main() {
  const cookiePath = process.env['USERPROFILE'] + '\\Downloads\\mssw_cookies.txt';
  const cookieInfo = await readMsswCookieInfo(cookiePath);

  const result = await fetchMsswSecurityLogCount(
    cookieInfo,
    DEFAULT_MSSW_BASE_URL,
    '67262236',
    { start: '2026-05-31', end: '2026-06-29' }
  );

  console.log('MSSW 安全日志总量（tableId=62 网络安全 + tableId=26 终端安全）:', result);
}

main().catch((err) => {
  console.error('失败:', err.message);
  process.exit(1);
});
