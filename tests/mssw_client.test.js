'use strict';

const assert = require('assert');
const { classifyDeviceType, DEVICE_TYPE_CATEGORIES, resolveDefaultProjectTimeRangeFromResponse } = require('../src/xdr_asset_client');

function localTimestamp(year, month, day, hour = 0, minute = 0, second = 0) {
  return new Date(year, month - 1, day, hour, minute, second, 0).getTime();
}

assert.deepStrictEqual(Object.keys(DEVICE_TYPE_CATEGORIES).sort(), ['aes', 'af', 'sip', 'sta'].sort());
assert.strictEqual(classifyDeviceType(3), 'af');
assert.strictEqual(classifyDeviceType(12), 'aes');
assert.strictEqual(classifyDeviceType(9), 'sip');
assert.strictEqual(classifyDeviceType(25), 'sta');
assert.strictEqual(classifyDeviceType(999), 'other');

const responseWithNullEnd = {
  data: [
    {
      service_info: [
        { service_start: localTimestamp(2026, 6, 23, 10, 8, 9), service_end: null },
        { service_start: localTimestamp(2026, 5, 20, 8, 42, 30), service_end: localTimestamp(2026, 6, 28, 0, 0, 0) },
        { service_start: localTimestamp(2026, 6, 25, 7, 39, 10), service_end: localTimestamp(2026, 6, 24, 0, 0, 0) }
      ]
    }
  ]
};
const generatedAt = new Date(2026, 5, 26, 20, 34, 56, 0);
const inferredRange = resolveDefaultProjectTimeRangeFromResponse(responseWithNullEnd, generatedAt);
assert.strictEqual(inferredRange.start, '2026-05-20');
assert.strictEqual(inferredRange.end, '2026-06-24');

const responseWithoutServiceEnd = {
  data: [
    {
      service_info: [
        { service_start: localTimestamp(2026, 6, 25, 0, 0, 0), service_end: null }
      ]
    }
  ]
};
const inferredFallbackRange = resolveDefaultProjectTimeRangeFromResponse(
  responseWithoutServiceEnd,
  new Date(2026, 5, 27, 1, 2, 3, 0)
);
assert.strictEqual(inferredFallbackRange.start, '2026-06-25');
assert.strictEqual(inferredFallbackRange.end, '2026-06-27');

assert.throws(
  () => resolveDefaultProjectTimeRangeFromResponse({ data: [{ service_info: [] }] }, generatedAt),
  /service_info/
);

console.log('xdr_asset_client.test.js passed');
