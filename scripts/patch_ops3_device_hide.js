#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const filePath = path.resolve(__dirname, '..', 'security-report-preview.html');
let html = fs.readFileSync(filePath, 'utf8');
let count = 0;

// 1. Add buildDeviceSources function before renderPipelineHorizontal
const funcMarker = '    function renderPipelineHorizontal(progress) {';
if (!html.includes('function buildDeviceSources(D)')) {
  const buildSourcesFn = [
    '',
    '    // 动态构建设备数据源列表，值为0的设备不展示',
    '    function buildDeviceSources(D) {',
    '      var all = [',
    "        { label: 'AF', count: D.af, color: '#FF4D4F' },",
    "        { label: 'aES', count: D.aes, color: '#FA8C16' },",
    "        { label: 'SIP', count: D.sip, color: '#1890FF' },",
    "        { label: 'STA', count: D.sta, color: '#722ED1' },",
    "        { label: '其它', count: D.other_sf, color: '#EB2F96' },",
    "        { label: '第三方', count: D.third, color: '#13C2C2' }",
    '      ];',
    "      var filtered = all.filter(function(s) { return s.count > 0; });",
    "      if (!filtered.length) {",
    "        return [{ label: '无设备', count: '0台', color: '#BFBFBF' }];",
    '      }',
    "      return filtered.map(function(s) { return { label: s.label, count: s.count + '台', color: s.color }; });",
    '    }',
    ''
  ].join('\n');
  html = html.replace(funcMarker, buildSourcesFn + '\n' + funcMarker);
  count++;
  console.log('[1/4] Added buildDeviceSources function');
}

// 2. Fix horizontal pipeline — replace hardcoded sources with buildDeviceSources
const horPattern = /(if \(idx === 0\) \{\s+var sources = \[[\s\S]*?\];)\s+(var iconY = cy - H \* 0\.06, span = segW \* 0\.72;\s+sources\.forEach\(function\(s, si\) \{\s+drawSourceIcon\(ctx, fx \+ segW \/ 2 - span \/ 2 \+ si \* )\(span \/ 3\)/;
const horReplacement = [
  'if (idx === 0) {',
  '          var sourcesH = buildDeviceSources(D);',
  '',
  '          var iconY = cy - H * 0.06, span = segW * 0.72;',
  '          var stepH = sourcesH.length > 1 ? span / (sourcesH.length - 1) : 0;',
  '          sourcesH.forEach(function(s, si) {',
  '            drawSourceIcon(ctx, fx + segW / 2 - span / 2 + si * '
].join('\n');
if (horPattern.test(html)) {
  html = html.replace(horPattern, horReplacement + 'stepH');
  count++;
  console.log('[2/4] Fixed horizontal pipeline device sources');
}

// 3. Fix vertical pipeline — replace hardcoded sources with buildDeviceSources
const verPattern = /(if \(idx === 0\) \{\s+var sources = \[[\s\S]*?\];)\s+(var iconSpan = seg\.topW \* appear \* 0\.72;\s+var iconY = fy \+ segH \* 0\.38;\s+sources\.forEach\(function\(s, si\) \{\s+drawSourceIcon\(ctx, cx - iconSpan \/ 2 \+ si \* )\(iconSpan \/ 3\)/;
const verReplacement = [
  'if (idx === 0) {',
  '          var sourcesV = buildDeviceSources(D);',
  '',
  '          var iconSpan = seg.topW * appear * 0.72;',
  '          var iconY = fy + segH * 0.38;',
  '          var stepV = sourcesV.length > 1 ? iconSpan / (sourcesV.length - 1) : 0;',
  '          sourcesV.forEach(function(s, si) {',
  '            drawSourceIcon(ctx, cx - iconSpan / 2 + si * '
].join('\n');
if (verPattern.test(html)) {
  html = html.replace(verPattern, verReplacement + 'stepV');
  count++;
  console.log('[3/4] Fixed vertical pipeline device sources');
}

// 4. Fix HTML ops3 device cells — add data-hide for zero-count devices
// Find the ops3-device-row div and replace with data-field driven rendering
const ops3DevicePattern = /(<div class="ops3-layer ops3-device-row">\s*<div class="ops3-device-cell"><span class="nm">AF<\/span><span class="nv">\{\{ riskDetails\.af \}\}<\/span><\/div>\s*<div class="ops3-device-cell"><span class="nm">aES<\/span><span class="nv">\{\{ riskDetails\.aes \}\}<\/span><\/div>\s*<div class="ops3-device-cell"><span class="nm">SIP<\/span><span class="nv">\{\{ riskDetails\.sip \}\}<\/span><\/div>\s*<div class="ops3-device-cell"><span class="nm">STA<\/span><span class="nv">\{\{ riskDetails\.sta \}\}<\/span><\/div>\s*<div class="ops3-device-cell"><span class="nm">其它<\/span><span class="nv">\{\{ riskDetails\.other_sf \}\}<\/span><\/div>\s*<\/div>)/;
const ops3Replacement = [
  '<div class="ops3-layer ops3-device-row">',
  '          <div class="ops3-device-cell" data-hide-ops3="riskDetails.af"><span class="nm">AF</span><span class="nv">{{ riskDetails.af }}</span></div>',
  '          <div class="ops3-device-cell" data-hide-ops3="riskDetails.aes"><span class="nm">aES</span><span class="nv">{{ riskDetails.aes }}</span></div>',
  '          <div class="ops3-device-cell" data-hide-ops3="riskDetails.sip"><span class="nm">SIP</span><span class="nv">{{ riskDetails.sip }}</span></div>',
  '          <div class="ops3-device-cell" data-hide-ops3="riskDetails.sta"><span class="nm">STA</span><span class="nv">{{ riskDetails.sta }}</span></div>',
  '          <div class="ops3-device-cell" data-hide-ops3="riskDetails.other_sf"><span class="nm">其它</span><span class="nv">{{ riskDetails.other_sf }}</span></div>',
  '        </div>'
].join('\n');
if (ops3DevicePattern.test(html)) {
  html = html.replace(ops3DevicePattern, ops3Replacement);
  count++;
  console.log('[4/5] Added data-hide-ops3 attributes to device cells');
}

// 5. Also hide the third-party sum if it's 0
const ops3ThirdPattern = /(<div class="ops3-layer ops3-device-third">\s*<span class="nm">合计<\/span><span class="nv">\{\{ riskDetails\.third \}\}<\/span>\s*<\/div>)/;
const ops3ThirdReplacement = '<div class="ops3-layer ops3-device-third" data-hide-ops3="riskDetails.third">\n          <span class="nm">合计</span><span class="nv">{{ riskDetails.third }}</span>\n        </div>';
if (ops3ThirdPattern.test(html)) {
  html = html.replace(ops3ThirdPattern, ops3ThirdReplacement);
  count++;
  console.log('[5/5] Added data-hide-ops3 to third-party sum');
}

// 6. Add CSS rule for data-hide-ops3
if (!html.includes('[data-hide-ops3]')) {
  const cssRule = '\n/* data-hide-ops3: 值为0时隐藏设备格子 */\n[data-hide-ops3-zero="true"] {\n  display: none !important;\n}\n';
  // Insert after the existing data-hide CSS rules
  const cssInsert = '[data-hide="true"] {';
  if (html.includes(cssInsert)) {
    html = html.replace(cssInsert, cssRule + cssInsert);
    count++;
    console.log('[6/6] Added data-hide-ops3 CSS rule');
  }
}

// 7. Add JS to handle data-hide-ops3 after template rendering
const ops3Js = [
  '',
  '  // ===== Ops3 device cells: hide if value is 0 =====',
  '  (function initOps3HideZeroDevices() {',
  "    var data = window.SECURITY_REPORT_DATA || {};",
  "    function getPath(obj, keyPath) {",
  "      return keyPath.split('.').reduce(function(current, key) {",
  "        if (current && Object.prototype.hasOwnProperty.call(current, key)) {",
  "          return current[key];",
  "        }",
  "        return undefined;",
  "      }, obj);",
  '    }',
  "    function applyOps3Hide() {",
  "      var cells = document.querySelectorAll('[data-hide-ops3]');",
  "      cells.forEach(function(el) {",
  "        var keyPath = el.getAttribute('data-hide-ops3');",
  "        var value = getPath(data, keyPath);",
  "        var isZero = (value === 0 || value === '0' || value === undefined || value === null || value === '');",
  "        if (isZero) {",
  "          el.setAttribute('data-hide-ops3-zero', 'true');",
  '        }',
  '      });',
  '    }',
  "    if (document.readyState === 'complete') applyOps3Hide();",
  "    else window.addEventListener('load', applyOps3Hide);",
  '  })();',
  ''
].join('\n');

// Insert before the M2 event distribution section
const m2Marker = "  // ===== M2: 安全事件等级 / 类型分布（preset） =====";
if (html.includes(m2Marker) && !html.includes('initOps3HideZeroDevices')) {
  html = html.replace(m2Marker, ops3Js + '\n' + m2Marker);
  count++;
  console.log('[7/7] Added ops3 hide-zero JS logic');
}

fs.writeFileSync(filePath, html, 'utf8');
console.log('\nDone. Total changes: ' + count);
