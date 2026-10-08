'use strict';

// 默认时间范围推导回归测试。
// 关键口径：先剔除已终止项目/服务，再取 min(service_start) ~ min(今天, max(expect_end_time))。
const assert = require('assert');
const { resolveDefaultProjectTimeRangeFromResponse } = require('../src/mssw_client');

// 用本地时间构造时间戳，避免测试结果随运行环境时区漂移
function localTimestamp(year, month, day, hour = 0, minute = 0, second = 0) {
  return new Date(year, month - 1, day, hour, minute, second, 0).getTime();
}

function project(curNode, services) {
  return { cur_node: curNode, service_info: services };
}

function service(startMs, endMs, status) {
  return { service_start: startMs, service_end: null, expect_end_time: endMs, service_status: status };
}

// ---- 1) 真实响应：已终止的 EASM 体验版必须被剔除 -------------------------------
// 修复前，2024 那个项目把 start/end 一起拖到 2024-11-25，整个窗口塌成 1 天。
const realResponse = {
  code: 0,
  data: [
    {
      project_id: '6ab352759f8e347403b29f9a',
      project_name: '【MSS测试】江西省妇女儿童医学中心-全资产',
      cur_node: 'in_progress',
      service_info: [
        {
          service_start: 1790524800000,
          service_end: null,
          expect_end_time: 1791820799000,
          service_status: 'running',
          service_type: 'test'
        },
        {
          service_start: 1790524800000,
          service_end: null,
          expect_end_time: 1791820799000,
          service_status: 'running',
          service_type: 'attached'
        }
      ]
    },
    {
      project_id: '67441553445626993a17509e',
      project_name: '江西省儿童医院客户EASM体验版',
      cur_node: 'terminated',
      service_info: [
        {
          service_start: 1732515185096,
          service_end: 1781220732799,
          expect_end_time: 1732550399000,
          service_status: 'finish',
          service_type: 'main'
        }
      ]
    }
  ]
};

const realRange = resolveDefaultProjectTimeRangeFromResponse(realResponse, new Date(2026, 9, 8, 12, 0, 0));
assert.strictEqual(realRange.start, '2026-09-28');
assert.strictEqual(realRange.end, '2026-10-08');
assert.strictEqual(realRange.meta.activeServiceCount, 2);
assert.strictEqual(realRange.meta.skippedServiceCount, 1);
assert.strictEqual(realRange.meta.serviceEndMaxMs, 1791820799000);

// ---- 2) end 取 max 而非 min：已到期的服务不能把窗口拽回过去 ---------------------
// 主服务 09-28~09-30 已到期，附加服务仍在服务到 2027 → 客户此刻仍被服务，窗口应顶到今天。
const partlyExpired = {
  data: [
    project('in_progress', [
      service(localTimestamp(2026, 9, 28), localTimestamp(2026, 9, 30), 'finish'),
      service(localTimestamp(2026, 9, 28), localTimestamp(2027, 9, 28), 'running')
    ])
  ]
};
const partlyExpiredRange = resolveDefaultProjectTimeRangeFromResponse(
  partlyExpired,
  new Date(2026, 9, 8, 12, 0, 0)
);
assert.strictEqual(partlyExpiredRange.start, '2026-09-28');
assert.strictEqual(partlyExpiredRange.end, '2026-10-08'); // 修复前为 2026-09-30

// ---- 3) 服务级过滤：in_progress 项目里已 finish 的附加模块不参与推导 ------------
const mixedStatusRange = resolveDefaultProjectTimeRangeFromResponse(
  {
    data: [
      project('in_progress', [
        service(localTimestamp(2026, 5, 1), localTimestamp(2026, 5, 10), 'finish'),
        service(localTimestamp(2026, 6, 1), localTimestamp(2026, 9, 1), 'running')
      ])
    ]
  },
  new Date(2026, 6, 15, 12, 0, 0)
);
assert.strictEqual(mixedStatusRange.start, '2026-06-01'); // 不能取到已 finish 那条的 05-01
assert.strictEqual(mixedStatusRange.end, '2026-07-15');
assert.strictEqual(mixedStatusRange.meta.skippedServiceCount, 1);

// ---- 4) 旧的 min 反例用例：现在是 max，断言随之改变 ----------------------------
// 原 tests/xdr_asset_client.test.js 断言 end === '2026-06-24'（min），此处改为 max 后的期望。
const legacyResponse = {
  data: [
    project(undefined, [
      service(localTimestamp(2026, 6, 23, 10, 8, 9), null, undefined),
      service(localTimestamp(2026, 5, 20, 8, 42, 30), localTimestamp(2026, 6, 28), undefined),
      service(localTimestamp(2026, 6, 25, 7, 39, 10), localTimestamp(2026, 6, 24), undefined)
    ])
  ]
};
const legacyRange = resolveDefaultProjectTimeRangeFromResponse(legacyResponse, new Date(2026, 5, 26, 20, 34, 56));
assert.strictEqual(legacyRange.start, '2026-05-20');
assert.strictEqual(legacyRange.end, '2026-06-26'); // min(生成时刻 06-26, max(06-28, 06-24))
assert.strictEqual(legacyRange.meta.serviceEndMaxMs, localTimestamp(2026, 6, 28));

// 缺 status 字段的历史响应按「在服」处理，不能被误杀
assert.strictEqual(legacyRange.meta.activeServiceCount, 3);
assert.strictEqual(legacyRange.meta.skippedServiceCount, 0);

// ---- 5) expect_end_time 全空 → 退回报告生成时刻 --------------------------------
const noEndRange = resolveDefaultProjectTimeRangeFromResponse(
  { data: [project('in_progress', [service(localTimestamp(2026, 6, 25), null, 'running')])] },
  new Date(2026, 5, 27, 1, 2, 3)
);
assert.strictEqual(noEndRange.start, '2026-06-25');
assert.strictEqual(noEndRange.end, '2026-06-27');
assert.strictEqual(noEndRange.meta.serviceEndMaxMs, null);

// ---- 6) 状态值大小写与空白容错 ------------------------------------------------
const messyRange = resolveDefaultProjectTimeRangeFromResponse(
  {
    data: [
      project(' TERMINATED ', [service(localTimestamp(2026, 1, 1), localTimestamp(2026, 1, 5), 'finish')]),
      project('In_Progress', [service(localTimestamp(2026, 6, 1), localTimestamp(2026, 12, 1), 'Running')])
    ]
  },
  new Date(2026, 6, 15, 12, 0, 0)
);
assert.strictEqual(messyRange.start, '2026-06-01');
assert.strictEqual(messyRange.end, '2026-07-15');
assert.strictEqual(messyRange.meta.skippedServiceCount, 1);

// ---- 7) 全部已终止 → 明确报错，不同于「接口没返回 service_info」 ----------------
assert.throws(
  () => resolveDefaultProjectTimeRangeFromResponse(
    { data: [project('terminated', [service(localTimestamp(2026, 1, 1), localTimestamp(2026, 1, 5), 'finish')])] },
    new Date(2026, 6, 15)
  ),
  /无在服务中的 MSSW 项目/
);

assert.throws(
  () => resolveDefaultProjectTimeRangeFromResponse({ data: [{ service_info: [] }] }, new Date(2026, 6, 15)),
  /service_info/
);

// ---- 8) 日志回调拿到观测到的状态值 ---------------------------------------------
const seenLogs = [];
resolveDefaultProjectTimeRangeFromResponse(realResponse, new Date(2026, 9, 8, 12, 0, 0), (line) => seenLogs.push(line));
assert.ok(seenLogs.some((line) => line.includes('cur_node=[in_progress, terminated]')), `未记录观测到的 cur_node: ${seenLogs.join(' | ')}`);
assert.ok(seenLogs.some((line) => line.includes('service_status=[finish, running]')), `未记录观测到的 service_status: ${seenLogs.join(' | ')}`);
assert.ok(seenLogs.some((line) => line.includes('已跳过 1 个已终止服务')), `未记录跳过数量: ${seenLogs.join(' | ')}`);

console.log('project_time_range.test.js passed');
