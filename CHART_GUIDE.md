# 已有柱状图替换为新 JSON 数据

## 示例对象

模板里现有图表：

- 标题：`总体暴露面分布`
- 容器：`m3-exposure-overview-bar`
- 模板位置：[security-report-preview.html:8063](C:/Users/xupai/.openclaw/workspace/skills/health-checkup-report/security-report-preview.html:8063)
- 图表脚本位置：[security-report-preview.html:9442](C:/Users/xupai/.openclaw/workspace/skills/health-checkup-report/security-report-preview.html:9442)

## 假设新增的 JSON

假设你已经把新数据放进：

```js
reportData.riskOverview.exposureOverviewDistribution = [
  { name: '端口资产', value: 172, priority: '重点系统' },
  { name: 'WEB资产', value: 157, priority: '重点系统' },
  { name: '网络&安全设备', value: 28, priority: '重点系统' },
  { name: '子域名资产', value: 25, priority: '尽快处置' },
  { name: '非WEB资产', value: 15, priority: '尽快处置' },
  { name: 'SSL证书', value: 7, priority: '尽快处置' }
];
```

要求数据结构保持为：

```js
[
  { name: '名称', value: 数值, priority: '优先级' }
]
```

## 要改什么文件

只改：

- [security-report-preview.html](C:/Users/xupai/.openclaw/workspace/skills/health-checkup-report/security-report-preview.html)

不要改：

- `output/*.html`

## 第 1 步：找到原来的 mock 数据

打开 [security-report-preview.html:9442](C:/Users/xupai/.openclaw/workspace/skills/health-checkup-report/security-report-preview.html:9442)

你会看到原来写死的：

```js
var exposureDist = [
  { name: '端口资产', value: 172, priority: '重点系统' },
  { name: 'WEB资产', value: 157, priority: '重点系统' },
  { name: '网络&安全设备', value: 28, priority: '重点系统' },
  { name: '子域名资产', value: 25, priority: '尽快处置' },
  { name: '非WEB资产', value: 15, priority: '尽快处置' },
  { name: 'SSL证书', value: 7, priority: '尽快处置' },
  { name: 'IP资产', value: 5, priority: '尽快处置' },
  { name: '云类资产', value: 3, priority: '持续监控' },
  { name: '根域名资产', value: 0, priority: '持续监控' },
  { name: 'APP', value: 0, priority: '持续监控' },
  { name: '公众号', value: 0, priority: '持续监控' },
  { name: '小程序', value: 0, priority: '持续监控' }
];
```

## 第 2 步：把 mock 数据改成读取 JSON

把上面整段替换成：

```js
var rootData = window.SECURITY_REPORT_DATA || {};
var riskOverview = rootData.riskOverview || {};
var exposureDist = Array.isArray(riskOverview.exposureOverviewDistribution)
  ? riskOverview.exposureOverviewDistribution
  : [];
```

## 第 3 步：保留后面的图表代码不动

下面这句保留：

```js
var yNames = exposureDist.map(function (d) { return d.name; });
```

后面的 `tooltip`、`xAxis`、`yAxis`、`series` 都不用改。

这张图本来就是按下面的方式消费数据：

```js
data: exposureDist.map(function (d) { return d.value; })
```

tooltip 里也会继续读：

```js
exposureDist[p.dataIndex].priority
```

所以你的 JSON 里必须有：

- `name`
- `value`
- `priority`

## 第 4 步：改完后的完整关键片段

改完后，这一段应当类似：

```js
(function () {
  var el = document.getElementById('m3-exposure-overview-bar');
  if (!el) return;
  var chart = null;

  var rootData = window.SECURITY_REPORT_DATA || {};
  var riskOverview = rootData.riskOverview || {};
  var exposureDist = Array.isArray(riskOverview.exposureOverviewDistribution)
    ? riskOverview.exposureOverviewDistribution
    : [];

  var yNames = exposureDist.map(function (d) { return d.name; });

  function renderExposureOverviewBar() {
    if (!chart) chart = SRChartTheme.init(el);
    var w = el.clientWidth || el.offsetWidth || 610;
    var compact = T.barRankCompact(w);
    chart.setOption({
      tooltip: {
        trigger: 'item',
        formatter: function (p) {
          var d = exposureDist[p.dataIndex];
          return T.tooltip.item(p.name, [
            '数量: <b>' + p.value + '</b>',
            '处置优先级: <span style="color:' + priorityColor[d.priority] + '">' + d.priority + '</span>'
          ]);
        }
      },
      grid: T.grid.rank({
        containerWidth: w,
        left: compact ? 108 : 132,
        hasAxisName: !compact,
        verticalCenter: true,
        edgeShrink: 0.08
      }),
      xAxis: Object.assign({
        type: 'value',
        min: 0,
        max: 200,
        interval: 50
      }, compact ? T.axis.value() : T.axis.valueName('数量', 28)),
      yAxis: Object.assign({
        type: 'category',
        data: yNames,
        inverse: true
      }, T.axis.category({ axisLabel: { fontSize: T.fontSize.legendSm, width: compact ? 96 : 120, overflow: 'truncate' } })),
      series: [{
        type: 'bar',
        barWidth: T.rankBarWidth(w),
        data: exposureDist.map(function (d) { return d.value; }),
        itemStyle: {
          color: function (p) { return priorityColor[exposureDist[p.dataIndex].priority]; },
          barBorderRadius: T.barRadius()
        },
        label: T.rankBarLabel('{c}')
      }]
    }, true);
    chart.resize();
  }
})();
```

## 第 5 步：重新生成 HTML

改完模板后，重新执行生成脚本。

## 如果你的 JSON 字段名不叫这个

如果你实际新增的路径不是：

```js
reportData.riskOverview.exposureOverviewDistribution
```

就只改这句：

```js
var exposureDist = Array.isArray(riskOverview.exposureOverviewDistribution)
  ? riskOverview.exposureOverviewDistribution
  : [];
```

改成你的真实路径。

## 最后检查

1. `window.SECURITY_REPORT_DATA.riskOverview.exposureOverviewDistribution` 是否存在
2. 是否是数组
3. 每项是否都有 `name`、`value`、`priority`
4. 是否重新生成了 HTML
