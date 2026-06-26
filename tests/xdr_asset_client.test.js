'use strict';

const assert = require('assert');
const { classifyDeviceType, DEVICE_TYPE_CATEGORIES } = require('../src/xdr_asset_client');

assert.deepStrictEqual(Object.keys(DEVICE_TYPE_CATEGORIES).sort(), ['aes', 'af', 'sip', 'sta'].sort());
assert.strictEqual(classifyDeviceType(3), 'af');
assert.strictEqual(classifyDeviceType(12), 'aes');
assert.strictEqual(classifyDeviceType(9), 'sip');
assert.strictEqual(classifyDeviceType(25), 'sta');
assert.strictEqual(classifyDeviceType(999), 'other');

console.log('xdr_asset_client.test.js passed');
