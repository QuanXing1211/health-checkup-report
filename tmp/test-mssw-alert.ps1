# MSSW 告警表查询测试脚本 - 使用 curl.exe
# 在 PowerShell 中执行: .\tmp\test-mssw-alert.ps1

$companyId = "67262236"
$downloads = "$env:USERPROFILE\Downloads"
$cookieFile = Join-Path $downloads "mssw_cookies.txt"
$cookieString = (Get-Content -Path $cookieFile -Raw -Encoding UTF8).Trim()

# 提取 csrf_token
$csrfToken = ""
if ($cookieString -match 'csrf_token=([^;]+)') {
    $csrfToken = $matches[1]
}

Write-Host "csrf_token: $csrfToken"
Write-Host "company_id: $companyId"

# 时间戳
$beginTime = [Math]::Floor((Get-Date "2026-05-31" -UFormat %s))
$endTime   = [Math]::Floor((Get-Date "2026-06-29 23:59:59" -UFormat %s))

# 构建请求体（注意：spl 字段不能为空，否则后端 NPE）
$body = @"
{
  "extensionParams": null,
  "spl": {
    "mappedSpl": "",
    "originalSpl": "",
    "extensionParams": {
      "frontRender": [],
      "mappedInputSpl": "",
      "originalInputSpl": ""
    }
  },
  "serviceInfo": {
    "appName": "incident",
    "servletContextPath": "/",
    "serviceType": "table",
    "handler": "alertTableQueryHandler"
  },
  "globalCondition": {
    "branchIds": [],
    "time": {
      "timeField": "firstTime",
      "begin": { "type": "absolute", "value": $beginTime },
      "end": { "type": "absolute", "value": $endTime }
    }
  },
  "table": {
    "enable": true,
    "viewName": "AlertView",
    "aggregationStrategies": null,
    "tableFields": [],
    "pageNum": 1,
    "pageSize": 100,
    "serviceInfo": {
      "appName": "incident",
      "servletContextPath": "/",
      "serviceType": "table",
      "handler": "alertTableQueryHandler"
    },
    "subTable": null,
    "rightClicked": false,
    "selectAllPage": true,
    "routers": [],
    "rightActions": [],
    "extensionParams": {}
  },
  "tag": null,
  "viewName": "AlertView",
  "model": "expert",
  "autoRefresh": false,
  "viewInstanceId": "67aebe12c29c0b7b63b0c51e",
  "enableHistory": true
}
"@

# 写入临时 body 文件（避免命令行太长）
$bodyFile = "C:\Users\User\AppData\Local\Temp\mssw_alert_body.json"
Set-Content -Path $bodyFile -Value $body -Encoding UTF8

Write-Host "Temp body: $bodyFile"

$url = "https://pre.soar.sangfor.com/ngsoc/INCIDENT/api/v1/table/query/alertTableQueryHandler?viewRegionId=ffffffffffffffffffffffff&onlySelfPlatform=false"

Write-Host "`n正在发送请求..." -ForegroundColor Cyan

# 用 curl.exe 发送（带 -k 忽略 SSL 证书错误）
& curl.exe -k -s -S -X POST -H "Host: pre.soar.sangfor.com" -H "Accept: application/json, text/plain, */*" -H "Content-Type: application/json" -H "Cookie: $cookieString" -H "Origin: https://pre.soar.sangfor.com" -H "Referer: https://pre.soar.sangfor.com/index.html" -H "x-csrf-token: $csrfToken" -H "x-mssw-company-id: $companyId" -H "x-requested-with: XMLHttpRequest" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" -d "@$bodyFile" $url 2>&1

Write-Host "`n`n退出码: $LASTEXITCODE" -ForegroundColor Cyan
