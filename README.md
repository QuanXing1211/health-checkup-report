# Health Checkup Report

生成指定客户、指定时间段的安全体检 HTML 报告。

当前版本可以生成 HTML 报告；提供 XDR Cookie 时，会在同一次运行中导出配置的 XDR 表格并拉取资产台账统计。

## Run

```powershell
node health_report.js `
  --customer "示例客户" `
  --start "2026-06-01" `
  --end "2026-06-16" `
  --xdr-cookie-path "M:\Users\$env:USERNAME\Downloads\xdr_cookies.txt"
```

`--end` 可省略，默认取脚本执行当天，格式为 `YYYY-MM-DD`。

输出文件默认写入 `output/`。接口拿到并用于填充 HTML 的结构化数据会落盘到 `output/report-data.json`，可用 `--output-json` 指定路径。

默认只输出简洁摘要；如需完整 JSON 结果，加 `--json`。

默认会导出 `asset,incident`。如需指定表格：

```powershell
node health_report.js `
  --customer "示例客户" `
  --start "2026-06-01" `
  --end "2026-06-16" `
  --xdr-cookie-path "M:\Users\$env:USERNAME\Downloads\xdr_cookies.txt" `
  --xdr-tables "asset,incident"
```

## Data Contract

当前 `output/report-data.json` 的字段约定如下。后续新增取值逻辑必须继续补这张表。

业务系统排名脚本当前只按资产表的 `资产组名` 字段归因到业务系统；如果资产表缺少该列，则回退到脚本内置的 IP 兜底映射。

| 字段 | 语义 | 来源 | 取值逻辑 |
| --- | --- | --- | --- |
| `projectBackground.title` | 报告标题 | CLI / 默认值 | 固定为 `首次安全体检报告` |
| `projectBackground.customerName` | 客户名称 | `--customer` | 直接取命令行参数 |
| `projectBackground.customerId` | 客户 ID | `--customer-id` | 直接取命令行参数，未传则 `null` |
| `projectBackground.startDate` | 报告开始日期 | `--start` | 直接取命令行参数 |
| `projectBackground.endDate` | 报告结束日期 | `--end` | 未传则取脚本执行当天 |
| `projectBackground.generatedAt` | 数据生成时间 | 运行时 | 取脚本执行时的 ISO 时间字符串 |
| `assetLedger.core_asset` | 核心资产数 | XDR 资产台账 count 接口 | 取 `{"magnitude":{"op":"=","val":"core"}}` 的 `total` |
| `assetLedger.manage_asset` | 台账资产数 | 导出的资产表 Excel | 统计第三行开始的有效行数 |
| `assetLedger.ready_to_outbound` | 7天内即将退库资产数 | XDR 资产台账 count 接口 | 取 `{"ready_to_outbound":{"op":"=","val":"last7d"}}` 的 `total` |
| `assetLedger.typeDistribution` | 资产类型分布 | 导出的资产表 Excel | 按资产类型列统计 `服务器 / 终端`，其他 = 台账资产 - 服务器 - 终端 |
| `assetLedger.protectionDistribution` | 资产防护统计 | 导出的资产表 Excel | 按 agent 状态列统计 `在线 / 离线 / 已禁用 / 已降级`，`未防护资产 = 台账资产 - 在线 - 离线 - 已禁用 - 已降级` |
| `assetLedger.internetExposureDistribution` | 互联网暴露资产分布 | 导出的资产表 Excel | 按互联网暴露列筛出暴露资产，再按资产类型列统计 `服务器 / 终端`，其他 = 暴露资产 - 服务器 - 终端 |
| `assetLedger.internetExposureTotal` | 互联网暴露资产总数 | 导出的资产表 Excel | 统计互联网暴露列中命中的资产数 |
| `riskOverview.securityLogTotal` | XDR接收安全日志数 | XDR 安全日志量接口 | 取 `log/search/count` 接口返回的总数 |
| `riskOverview.alertTotal` | 有效告警数 | XDR 告警消减率接口 | 取 `overview/count` 接口返回的 `alertTotalCount.value` |
| `riskOverview.totalEvents` | 有效安全事件数 | 导出的事件表 Excel | 直接复用 `riskDetails.totalEvents`，即事件表非空数据行数 |
| `riskOverview.closedEvents` | 处置闭环数 | 导出的事件表 Excel | 直接复用 `riskDetails.closedEvents`，即 `处置状态 = 处置完成` 的事件行数 |
| `riskOverview.containedEvents` | 总计遏制数 | 导出的事件表 Excel | 直接复用 `riskDetails.containedEvents`，即 `处置状态 = 已遏制` 的事件行数 |
| `riskOverview.alertReductionRate` | 告警消减率 | XDR 告警消减率接口 | `1 - 有效告警数 / XDR接收安全日志数`，按接口返回值保留小数 |
| `riskOverview.closeRate` | 事件闭环率 | 导出的事件表 Excel | 直接复用 `riskDetails.closeRate`，保证与风险详情完全一致 |
| `riskOverview.yunyingAlertStats.c2VirusTotal` | C2外联&病毒文件总数 | 两个接口汇总 | `病毒木马活动` + `主机失陷活动` 命中数之和 |
| `riskOverview.yunyingAlertStats.webVulnTotal` | Web攻击&Web漏洞总数 | 两个接口汇总 | `网站攻击` + `漏洞攻击` 命中数之和 |
| `riskOverview.yunyingAlertStats.virusFiles.total` | 病毒文件总数 | GPT 运营告警查询接口 | 过滤 `gptResult.renderValue === 病毒木马活动`，统计命中行数 |
| `riskOverview.yunyingAlertStats.virusFiles.hostIps` | 病毒文件主机列表 | GPT 运营告警查询接口 | 收集命中行里的 `hostIp.originalValue`，去重后保留原始主机 IP |
| `riskOverview.yunyingAlertStats.virusFiles.records` | 病毒文件命中明细 | GPT 运营告警查询接口 | 保留每条命中的 `hostIp` / `gptResult` 原始包装值 |
| `riskOverview.yunyingAlertStats.c2ExternalLink.total` | C2外联总数 | GPT 运营告警查询接口 | 过滤 `gptResult.renderValue === 主机失陷活动`，统计命中行数 |
| `riskOverview.yunyingAlertStats.c2ExternalLink.hostIps` | C2外联主机列表 | GPT 运营告警查询接口 | 收集命中行里的 `hostIp.originalValue`，去重后保留原始主机 IP |
| `riskOverview.yunyingAlertStats.c2ExternalLink.records` | C2外联命中明细 | GPT 运营告警查询接口 | 保留每条命中的 `hostIp` / `gptResult` 原始包装值 |
| `riskOverview.yunyingAlertStats.exploitAttacks.total` | 漏洞利用总数 | GPT 运营告警查询接口 | 过滤 `threatClass.renderValue === 漏洞攻击`，统计命中行数 |
| `riskOverview.yunyingAlertStats.exploitAttacks.hostIps` | 漏洞利用主机列表 | GPT 运营告警查询接口 | 收集命中行里的 `hostIp.originalValue`，去重后保留原始主机 IP |
| `riskOverview.yunyingAlertStats.exploitAttacks.records` | 漏洞利用命中明细 | GPT 运营告警查询接口 | 保留每条命中的 `hostIp` / `gptResult` 原始包装值 |
| `riskOverview.yunyingAlertStats.webAttacks.total` | Web攻击总数 | GPT 运营告警查询接口 | 过滤 `threatClass.renderValue === 网站攻击`，统计命中行数 |
| `riskOverview.yunyingAlertStats.webAttacks.hostIps` | Web攻击主机列表 | GPT 运营告警查询接口 | 收集命中行里的 `hostIp.originalValue`，去重后保留原始主机 IP |
| `riskOverview.yunyingAlertStats.webAttacks.records` | Web攻击命中明细 | GPT 运营告警查询接口 | 保留每条命中的 `hostIp` / `gptResult` 原始包装值 |
| `riskDetails.totalAlerts` | 告警总数 | XDR 告警查询接口 | 取告警查询接口 `data.total` |
| `riskDetails.totalEvents` | 事件总数 | XDR 事件数量接口 + 导出的事件表 Excel | 优先取数量接口 `data.total`，并用导出表统计结果校正闭环率 |
| `riskDetails.severeEvents` | 严重事件数 | 导出的事件表 Excel | 统计 C 列值等于 `严重` 的事件行数 |
| `riskDetails.highEvents` | 高危事件数 | 导出的事件表 Excel | 统计 C 列值等于 `高危` 的事件行数 |
| `riskDetails.closedEvents` | 已闭环事件数 | 导出的事件表 Excel | 统计 `处置状态` 列值等于 `处置完成` 的事件行数；指标名仍保留“已闭环” |
| `riskDetails.containedEvents` | 已遏制事件数 | 导出的事件表 Excel | 统计 S 列值等于 `已遏制` 的事件行数 |
| `riskDetails.processingEvents` | 处置中事件数 | 导出的事件表 Excel | 统计 S 列值等于 `处置中` 的事件行数 |
| `riskDetails.closeRate` | 闭环率 | 导出的事件表 Excel | `已闭环事件数 / 总事件数 * 100`，四舍五入为整数 |
| `riskDetails.alertReductionRate` | 告警消减率 | XDR 告警消减率接口 | 直接复用 XDR `overview/count` 的消减率计算结果 |
| `riskDetails.uniqueAssetCount` | 涉及到的资产数 | 导出的事件表 Excel | 遍历事件表所有事件，提取“影响资产”列中的 IPv4 地址（如 `10.5.40.62(未归类组)` 取 `10.5.40.62`）后去重计数 |
| `riskOverview.devices` | 接入组件数 | 深信服设备列表接口 + 第三方设备列表接口 | 深信服设备总数优先取 `/api/apex/device/v1/devices/list` 返回的 `data.total`，第三方设备数取 `/api/apex/thirdparty/v1/app/instance/list` 的 `data.count`，两者相加 |
| `riskDetails.devices` | 接入安全设备数 | 深信服设备列表接口 + 第三方设备列表接口 | 保留兼容字段，值与 `riskDetails.sangfor + riskDetails.third` 一致 |
| `riskDetails.sangfor` | 深信服设备数 | 深信服设备列表接口 | 取 `/api/apex/device/v1/devices/list` 返回的 `data.total` |
| `riskDetails.third` | 第三方设备数 | 第三方设备列表接口 | 取 `/api/apex/thirdparty/v1/app/instance/list` 返回的 `data.count` |
| `riskDetails.af` | AF 设备数 | 深信服设备列表接口 | 遍历设备列表中 `devType` 等于 `3` 的记录计数 |
| `riskDetails.aes` | aES 设备数 | 深信服设备列表接口 | 遍历设备列表中 `devType` 属于 `12 / 37 / 100038 / 50038 / 100012` 的记录计数 |
| `riskDetails.sip` | SIP 设备数 | 深信服设备列表接口 | 遍历设备列表中 `devType` 等于 `9` 的记录计数 |
| `riskDetails.sta` | STA 设备数 | 深信服设备列表接口 | 遍历设备列表中 `devType` 等于 `25` 的记录计数 |
| `riskDetails.other_sf` | 其它深信服设备数 | 深信服设备列表接口 | 遍历设备列表中未命中上述映射的记录计数 |

说明：

- 真实模式下，结构化 JSON 以 `projectBackground`、`assetLedger`、`riskDetails`、`riskOverview`、`appendix` 为主。
- `riskOverview` 当前主要给模板里的风险总览章节预留，后续新增真实取值时必须继续补上来源和逻辑。

## Template Strategy

模板改造标准见 [TEMPLATE_STANDARD.md](./TEMPLATE_STANDARD.md)。

推荐模板里显式放占位符：

```html
{{ projectBackground.customerName }}
{{ projectBackground.startDate }}
{{ assetLedger.manage_asset }}
```

对于已有模板中的 KPI，可继续使用：

```html
<div data-field="assetLedger.manage_asset">520</div>
```

渲染器会按数据路径回填 `data-field` 的文本内容，并把完整 `window.SECURITY_REPORT_DATA` 注入页面，方便后续图表脚本读取结构化数据。

复杂表格、列表、图表建议不要靠纯文本替换，后续应扩展成命名 section renderer，例如 `renderKeyRisksTable(reportData.risks.keyRisks)`。
