# Health Checkup Report

生成指定客户、指定时间段的安全体检 HTML 报告。

当前是骨架版本：CLI、数据契约、mock 数据源和 HTML 渲染器已经可运行；真实 MSS/XDR 接口调用后续接入 `src/data_client.js`。

## Run

```powershell
node health_report.js generate `
  --customer "示例客户" `
  --start "2026-05-01" `
  --end "2026-05-31"
```

输出文件默认写入 `output/`。

## Template Strategy

推荐模板里显式放占位符：

```html
{{ report.customerName }}
{{ report.startDate }}
{{ assets.total }}
```

对于已有模板中的 KPI，可继续使用：

```html
<div data-field="assets.total">520</div>
```

渲染器会按数据路径回填 `data-field` 的文本内容，并把完整 `window.SECURITY_REPORT_DATA` 注入页面，方便后续图表脚本读取结构化数据。

复杂表格、列表、图表建议不要靠纯文本替换，后续应扩展成命名 section renderer，例如 `renderKeyRisksTable(reportData.risks.keyRisks)`。

