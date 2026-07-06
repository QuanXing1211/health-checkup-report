# 字段接线排查清单

本文档记录当前 `health-checkup-report` 中“有取值/有入 `reportData`，但未接到当前模板主流程”的字段，供后续逐项整改。

## 排查范围

- 主入口：`health_report.js`
- 数据组装：`src/data_client.js`、`src/xdr_asset_client.js`
- 分支合并：`src/branch1_adapter.js`
- 模板渲染：`src/template_renderer.js`
- 模板：`security-report-preview.html`

## 结论分类

### A. 已入 `reportData`，但当前模板完全未消费

#### 1. `appendix.businessSystemRanking.*`

状态：已计算，未展示，未被其他渲染链消费。

写入位置：
- `health_report.js:355`
- `health_report.js:364`

字段：
- `appendix.businessSystemRanking.coreBusinessSystemRanking`
- `appendix.businessSystemRanking.maxRiskSystem`
- `appendix.businessSystemRanking.securityRiskTotal`
- `appendix.businessSystemRanking.highAndAboveRiskCount`

说明：
- 当前模板和渲染器中没有任何 `appendix.businessSystemRanking` 的引用。
- 这整块属于“真断线”。

建议：
- 要么补模板展示位。
- 要么从主流程中移除这段计算和合并。

#### 2. `scoring.*` 中除 `scoring.grade` 外的大部分字段

状态：已合并，只有 `grade` 被消费，其余字段未展示。

写入位置：
- `src/branch1_adapter.js:92`

消费位置：
- `src/template_renderer.js:79`

当前已消费：
- `scoring.grade`

当前未消费：
- `scoring.total_score`
- `scoring.grade_color`
- `scoring.L1.*`
- `scoring.L2.*`
- `scoring.L3.*`
- `scoring.data_summary.*`
- `scoring.weights_used.*`

说明：
- 当前评分体系只驱动报告评级样式和文本。
- 其余分数字段都已进入 JSON，但没有模板引用，也没有二次计算消费。

建议：
- 如果后续要做评分拆解页，可以补展示。
- 如果近期不用，至少先确认是否继续保留在产物 JSON 中。

#### 3. `riskOverview.incidentGptStats.threatTypeRanking`

状态：已计算，未展示，未被其他链路使用。

生成位置：
- `src/xdr_asset_client.js:1448`
- `src/xdr_asset_client.js:1470`

说明：
- 当前模板使用的是 `threatActorStats.0/1`，不是 `threatTypeRanking`。
- 全仓库没有模板消费点。

建议：
- 如果要在文案里固定输出“威胁类型 Top2”，补模板。
- 否则可考虑移除该字段计算。

#### 4. `riskDetails.managedAssetCount`

状态：已写入，未展示。

写入位置：
- `health_report.js:228`
- `health_report.js:240`

说明：
- 当前模板展示了托管资产事件数、遏制数、处置数、闭环率、平均响应时间。
- 没有任何位置展示“涉及托管资产数”。

建议：
- 如果业务需要，可补一处统计文案。
- 否则可以保留但标记为未使用字段。

#### 5. `projectBackground.customerId`

状态：已入 JSON，未展示。

写入位置：
- `src/data_client.js:17`

说明：
- 当前页面只用 `customerName`、`startDate`、`endDate`。
- `customerId` 不参与标题、正文、图表或导出命名。

建议：
- 若仅用于调试/追踪，可保留。
- 若想减少输出噪音，可考虑不落最终 JSON。

### B. 有重复存储，页面只消费其中一份

#### 6. `riskOverview.incidentGptStats.c2ConnectionExamples`

状态：已生成，但页面实际使用的是镜像到 `riskDetails` 的版本。

生成位置：
- `src/xdr_asset_client.js:2903`
- `src/xdr_asset_client.js:2905`

实际页面消费：
- `riskDetails.highRiskIncidentExamples.c2Connections`

消费位置：
- `src/xdr_asset_client.js:2964`
- `src/template_renderer.js:30`

说明：
- 这不是完全断线。
- 但 `incidentGptStats.c2ConnectionExamples` 这一份本体没有被模板直接消费，属于重复存储。

建议：
- 确认是否需要保留双份结构。
- 如果不需要，可只保留 `riskDetails.highRiskIncidentExamples.c2Connections`。

#### 7. `riskOverview.incidentGptStats.virusTrojanExamples`

状态：已生成，但页面实际使用的是镜像到 `riskDetails` 的版本。

生成位置：
- `src/xdr_asset_client.js:2914`
- `src/xdr_asset_client.js:2916`

实际页面消费：
- `riskDetails.highRiskIncidentExamples.viruses`

消费位置：
- `src/xdr_asset_client.js:2961`
- `src/template_renderer.js:29`

说明：
- 与 `c2ConnectionExamples` 情况相同。

建议：
- 确认是否保留双份结构。

### C. 不应误判为断线的中间字段

以下字段虽然不直接展示，但它们已经接入主流程，属于中间态依赖，不建议直接删除。

#### 8. `riskOverview.exploitStats.incidentIds`

用途：用于回查漏洞利用举例。

使用位置：
- `health_report.js:171`

说明：
- 先统计事件 ID。
- 再根据这些 ID 生成 `riskDetails.highRiskIncidentExamples.vulnExploits`。

结论：
- 不是断线字段。

#### 9. `riskOverview.incidentGptStats.hostCompromise.confirmedIncidentIds`

用途：用于回查 C2 事件举例和资产信息。

使用位置：
- `src/xdr_asset_client.js:2880`
- `src/xdr_asset_client.js:2903`

结论：
- 不是断线字段。

#### 10. `riskOverview.incidentGptStats.virusTrojan.confirmedIncidentIds`

用途：用于回查病毒木马举例和资产信息。

使用位置：
- `src/xdr_asset_client.js:2881`
- `src/xdr_asset_client.js:2914`

结论：
- 不是断线字段。

## 额外发现

### D. 渲染器有能力，但模板没有占位

以下渲染器已经存在，但当前 HTML 没有对应挂载点，所以实际不会触发。

定义位置：
- `src/template_renderer.js:22`
- `src/template_renderer.js:27`

未挂载的渲染入口：
- `assetLedger.summary`
- `riskOverview.summary`
- `riskOverview.keyRisks`

说明：
- 这类问题不是“字段没取到”，而是“渲染器写了，但模板没接”。

建议：
- 如果这些 section/repeat 是计划中的正式内容，应补 `data-section` / `data-repeat` 占位。
- 如果不再需要，应删除对应 renderer，避免维护假链路。

## 建议处理顺序

建议优先按下面顺序逐项整改：

1. `appendix.businessSystemRanking.*`
2. `scoring.*` 除 `grade` 外的字段
3. `riskOverview.incidentGptStats.threatTypeRanking`
4. `riskDetails.managedAssetCount`
5. `riskOverview.incidentGptStats.c2ConnectionExamples`
6. `riskOverview.incidentGptStats.virusTrojanExamples`
7. `assetLedger.summary` / `riskOverview.summary` / `riskOverview.keyRisks` 三个未挂载渲染入口

## 后续协作方式

你后面可以直接按下面格式点名：

- “先改 `appendix.businessSystemRanking`”
- “把 `managedAssetCount` 接到正文里”
- “删掉 `threatTypeRanking`”
- “把 `assetLedger.summary` 真正接到模板”

我会按你指定的项逐个改，不会一起混改。
