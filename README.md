# Health Checkup Report

生成指定客户、指定时间段的安全体检 HTML 报告。

当前版本可以生成 HTML 报告；提供 XDR Cookie 时，会在同一次运行中导出配置的 XDR 表格并拉取资产台账统计。

## Run

```powershell
node health_report.js `
  --customer "示例客户" `
  --xdr-cookie-path "M:\Users\$env:USERNAME\Downloads\xdr_cookies.txt"
```

也可以显式传时间：

```powershell
node health_report.js `
  --customer "示例客户" `
  --start "2026-06-01" `
  --end "2026-06-16" `
  --xdr-cookie-path "M:\Users\$env:USERNAME\Downloads\xdr_cookies.txt"
```

时间规则：

- `--start` 和 `--end` 要么同时传，要么都不传
- 都不传时，脚本会通过 MSSW 项目列表接口自动推导
- 默认开始时间取所有 `service_info[*].service_start` 的最早值
- 默认结束时间取 `min(报告生成时刻, 所有非空 service_end 的最小值)`

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
| `projectBackground.startDate` | 报告开始日期 | `--start` / MSSW 项目列表接口 | 用户传时间时直接取命令行参数；未传时取最早 `service_start` |
| `projectBackground.endDate` | 报告结束日期 | `--end` / MSSW 项目列表接口 + 运行时 | 用户传时间时直接取命令行参数；未传时取 `min(报告生成时刻, 最早非空 service_end)` |
| `projectBackground.generatedAt` | 数据生成时间 | 运行时 | 取脚本执行时的 ISO 时间字符串 |
| `assetLedger.core_asset` | 核心资产数 | XDR 资产台账 count 接口 | 取 `{"magnitude":{"op":"=","val":"core"}}` 的 `total` |
| `assetLedger.manage_asset` | 台账资产数 | 导出的资产表 Excel | 统计第三行开始的有效行数 |
| `assetLedger.ready_to_outbound` | 7天内即将退库资产数 | XDR 资产台账 count 接口 | 取 `{"ready_to_outbound":{"op":"=","val":"last7d"}}` 的 `total` |
| `assetLedger.typeDistribution` | 资产类型分布 | 导出的资产表 Excel | 读取第二行表头里的 `资产类型(一级)` 列；值包含 `服务器` 计入服务器，包含 `终端` 计入终端，其余计入其他 |
| `assetLedger.protectionDistribution` | 资产防护统计 | 导出的资产表 Excel | 读取第二行表头里的 `agent状态` 列；只统计值恰好等于 `在线 / 离线 / 已禁用 / 已降级 / 未安装` 的资产，并按这 5 个固定枚举输出 |
| `assetLedger.internetExposureDistribution` | 互联网暴露资产分布 | 导出的资产表 Excel | 读取第二行表头里的 `互联网暴露` 列；列值非空且不等于 `未暴露` 时视为暴露，再按 `资产类型(一级)` 列统计 `服务器 / 终端 / 其他` |
| `assetLedger.internetExposureTotal` | 互联网暴露资产总数 | 导出的资产表 Excel | 读取第二行表头里的 `互联网暴露` 列；列值非空且不等于 `未暴露` 时计为 1 |
| `riskOverview.securityLogTotal` | XDR接收安全日志数 | XDR 安全日志量接口 | 取 `log/search/count` 接口返回的总数 |
| `riskOverview.alertTotal` | 有效告警数 | XDR 告警消减率接口 | 取 `overview/count` 接口返回的 `alertTotalCount.value` |
| `riskOverview.totalEvents` | 有效安全事件数 | XDR 事件数量接口 + 导出的事件表 Excel | 直接复用 `riskDetails.totalEvents`；优先取事件数量接口 `data.total`，缺失时回退到事件表非空数据行数 |
| `riskOverview.closedEvents` | 处置闭环数 | 导出的事件表 Excel | 直接复用 `riskDetails.closedEvents`，即 `处置状态 = 处置完成` 的事件行数 |
| `riskOverview.containedEvents` | 总计遏制数 | 导出的事件表 Excel | 直接复用 `riskDetails.containedEvents`，即 `处置状态 = 已遏制` 的事件行数 |
| `riskOverview.alertReductionRate` | 告警消减率 | XDR 告警消减率接口 | 直接复用 `riskDetails.alertReductionRate`；计算口径为 `(alertTotalCount.value - incidentCount.value) / alertTotalCount.value`，结果按 0.1 为粒度四舍五入 |
| `riskOverview.closeRate` | 事件闭环率 | 导出的事件表 Excel | 直接复用 `riskDetails.closeRate`，保证与风险详情完全一致 |
| `riskOverview.affectedAssetCount` | 影响资产数 | 导出的事件表 Excel | 直接复用 `riskDetails.uniqueAssetCount`；遍历事件表所有事件，提取"影响资产"列中的 IPv4 地址后去重计数 |
| `riskOverview.incidentGptStats.total` | 已确认的威胁运营事件总数 | MSSW 事件表 Excel / MSSW 事件表接口 + 处置标签接口 | `incidentGptStats.hostCompromise.total + incidentGptStats.virusTrojan.total` |
| `riskOverview.incidentGptStats.hostCompromise.total` | 已确认 C2 外联事件数 | MSSW 事件表 Excel / MSSW 事件表接口 + 处置标签接口 | 先筛出 `GPT研判结论 = 主机失陷活动` 的事件，再通过 `disposalTabs(IP)` 和 `disposalTabs(DNS)` 确认存在恶意实体后计数 |
| `riskOverview.incidentGptStats.hostCompromise.confirmedIncidentIds` | 已确认 C2 外联事件 ID 列表 | 同上 | 保留通过确认的主机失陷事件 ID，按遍历顺序输出 |
| `riskOverview.incidentGptStats.virusTrojan.total` | 已确认病毒木马事件数 | MSSW 事件表 Excel / MSSW 事件表接口 + 处置标签接口 | 先筛出 `GPT研判结论 = 病毒木马活动` 的事件，再通过 `disposalTabs(FILE)` 确认存在恶意实体后计数 |
| `riskOverview.incidentGptStats.virusTrojan.confirmedIncidentIds` | 已确认病毒木马事件 ID 列表 | 同上 | 保留通过确认的病毒木马事件 ID，按遍历顺序输出 |
| `riskOverview.incidentGptStats.threatActorStats` | 威胁家族 Top2 | MSSW 事件表 Excel / MSSW 事件查询接口 | 遍历全部已确认事件的 `GPT定性结论`，按内置威胁家族关键字匹配并计数，按命中次数倒序取前 2 |
| `riskOverview.incidentGptStats.threatTypeRanking` | 威胁类型 Top2 | 同上 | 在已命中的威胁家族集合上，按内置固定优先级顺序取前 2 |
| `riskOverview.incidentGptStats.virusAttackAsset` | 首个病毒攻击资产 IP | 事件表 Excel + 资产表 Excel | 在已确认事件里，取第一个已确认病毒木马事件的 `影响资产` 中提取到的首个 IPv4 |
| `riskOverview.incidentGptStats.nonAesCoveredAssets` | 未被 AES 覆盖资产 IP 列表 | 事件表 Excel + 资产表 Excel | 对已确认事件涉及资产按事件表顺序去重；在资产表中若 `数据源` 缺失或不包含 `EDR`，则视为未被覆盖，最多返回 2 个 |
| `riskOverview.incidentGptStats.unlabeledAssets` | 未标注责任人资产 IP 列表 | 事件表 Excel + 资产表 Excel | 对已确认事件涉及资产按事件表顺序去重；在资产表中若 `责任人` 为空或资产缺失，则计入，最多返回 2 个 |
| `riskOverview.exploitStats.total` | 漏洞利用事件总数 | 导出的事件表 Excel | 读取 `安全事件一级分类` 列，值等于 `漏洞利用` 的事件行数 |
| `riskOverview.exploitStats.highRiskAsset` | 漏洞利用高风险资产 | 导出的事件表 Excel | 取第一条 `安全事件一级分类 = 漏洞利用` 事件的 `影响资产` 原始值 |
| `riskOverview.exploitStats.attackSuccessCount` | 漏洞利用成功次数 | 导出的事件表 Excel | 在 `安全事件一级分类 = 漏洞利用` 的事件中，统计 `攻击状态 = 成功` 的事件行数 |
| `riskDetails.totalAlerts` | 告警总数 | XDR 告警查询接口 | 取告警查询接口 `data.total` |
| `riskDetails.totalEvents` | 事件总数 | XDR 事件数量接口 + 导出的事件表 Excel | 优先取数量接口 `data.total`，并用导出表统计结果校正闭环率 |
| `riskDetails.severeEvents` | 严重事件数 | 导出的事件表 Excel | 读取表头为 `等级` 的列，统计值等于 `严重` 的事件行数 |
| `riskDetails.highEvents` | 高危事件数 | 导出的事件表 Excel | 读取表头为 `等级` 的列，统计值等于 `高危` 的事件行数 |
| `riskDetails.closedEvents` | 已闭环事件数 | 导出的事件表 Excel | 统计 `处置状态` 列值等于 `处置完成` 的事件行数；指标名仍保留“已闭环” |
| `riskDetails.containedEvents` | 已遏制事件数 | 导出的事件表 Excel | 读取表头为 `处置状态` 的列，统计值等于 `已遏制` 的事件行数 |
| `riskDetails.processingEvents` | 处置中事件数 | 导出的事件表 Excel | 读取表头为 `处置状态` 的列，统计值等于 `处置中` 的事件行数 |
| `riskDetails.closeRate` | 闭环率 | XDR 事件数量接口 + 导出的事件表 Excel | 用 `closedEvents / totalEvents * 100` 计算，四舍五入为整数；若存在事件数量接口返回值，则分母使用接口 `data.total` |
| `riskDetails.alertReductionRate` | 告警消减率 | XDR 告警消减率接口 | 取 `overview/count` 中 `alertTotalCount.value` 和 `incidentCount.value`，按 `(alertTotalCount.value - incidentCount.value) / alertTotalCount.value` 计算，结果按 0.1 为粒度四舍五入 |
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
