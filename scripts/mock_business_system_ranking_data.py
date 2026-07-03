# -*- coding: utf-8 -*-
"""
生成用于核心业务系统风险排序的 mock Excel 数据。
"""

import os

from openpyxl import Workbook


OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'output', 'mock-business-system-ranking')


ASSET_HEADERS = [
    'IP地址', '资产组名', '所属业务', '组织架构', 'MAC地址', '公网IP', 'EIP', '操作系统', '主机名',
    '资产类型(一级)', '资产类型(二级)', 'agent状态', '互联网暴露', '重要级别', '资产名称',
    '资产位置', '资产标签', '数据源', '责任人', '责任人电话', '托管状态'
]

EVENT_HEADERS = [
    '客户名称', '事件ID', '事件名称', '影响资产', '设备类型', '闭环角色', 'GPT研判结论',
    'GPT定性标签', '等级', '处置状态', '安全事件一级分类', '安全事件二级分类',
    '攻击状态', '最近发生时间', '事件创建时间', '源IP', '目的IP', 'IOC', '设备来源名'
]

VULN_HEADERS = [
    '漏洞名称', '修复优先级', '风险等级', '漏洞类型', '修复建议', '风险描述', '威胁标签', '数据源',
    '检测方式', 'CVE 编号', '最近发现时间', '首次发现时间', '风险资产', '资产类型',
    '所属资产组', '所属业务', '资产责任人', '资产重要性', '资产管理状态', '端口'
]

WEAK_HEADERS = [
    '弱密码名称', '账号', '密码', 'url', '数据源', '最近发现时间', '首次发现时间', '风险资产',
    '资产类型', '所属资产组', '所属业务', '资产责任人', '资产重要性', '资产管理状态',
    '托管状态', '端口', 'refer', '互联网暴露', '举证信息', '加白状态'
]

EXPOSURE_WEB_HEADERS = ['序号', '组件名称', '访问路径', '责任单位/部门']
EXPOSURE_NON_WEB_HEADERS = ['序号', '服务', 'IP地址/子域名', '端口', 'banner', '责任单位/部门']
PORT_HEADERS = [
    '序号', 'Host', '解析IP', '端口', '服务', '端口连通性', 'WEB组件', '访问路径',
    'WEB状态码', 'WEB标题', '归属地', '资产标签', '关联SSL证书', '网站监测授权',
    '业务系统', '业务状态', '目标单位', '责任单位/部门', '首次发现时间', '最近发现时间'
]


def write_workbook(path, sheet_specs):
    wb = Workbook()
    wb.remove(wb.active)
    for title, headers, rows, blank_first_row in sheet_specs:
        ws = wb.create_sheet(title)
        if blank_first_row:
            ws.append([])
        ws.append(headers)
        for row in rows:
            ws.append(row)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    wb.save(path)


def build_asset_rows():
    return [
        ['10.10.1.10', '核心资产池', '支付网关', '信息技术部', '', '', '', 'Linux', 'pay-api-01', '服务器', '应用服务器', '在线', '未暴露', '核心', '支付接口节点1', '', '', 'EDR', '张三', '13800000001', '已托管'],
        ['10.10.1.11', '核心资产池', '支付网关', '信息技术部', '', '', '', 'Linux', 'pay-db-01', '服务器', '数据库服务器', '在线', '未暴露', '核心', '支付数据库节点1', '', '', 'EDR', '张三', '13800000001', '已托管'],
        ['10.10.2.20', '核心资产池', '电商平台', '电商中心', '', '', '', 'Linux', 'mall-app-01', '服务器', '应用服务器', '在线', '未暴露', '核心', '商城应用节点1', '', '', 'EDR', '李四', '13800000002', '已托管'],
        ['10.10.2.21', '核心资产池', '电商平台', '电商中心', '', '', '', 'Linux', 'mall-cache-01', '服务器', '缓存服务器', '在线', '未暴露', '核心', '商城缓存节点1', '', '', 'EDR', '李四', '13800000002', '未托管'],
        ['10.10.3.30', '办公资产池', 'OA系统', '行政中心', '', '', '', 'Windows', 'oa-web-01', '服务器', '应用服务器', '在线', '未暴露', '普通', 'OA门户节点1', '', '', 'EDR', '王五', '13800000003', '已托管'],
        ['10.10.3.31', '办公资产池', 'OA系统', '行政中心', '', '', '', 'Windows', 'oa-db-01', '服务器', '数据库服务器', '在线', '未暴露', '核心', 'OA数据库节点1', '', '', 'EDR', '王五', '13800000003', '未托管'],
    ]


def build_event_rows():
    return [
        ['测试客户', 'INC-001', '支付接口存在异常登录行为', '10.10.1.10', 'STA', '-', '-', '-', '严重', '待处置', '账号攻击', '异常登录', '成功', '2026-06-30 09:01:00', '2026-06-30 09:00:00', '', '', '', 'STA'],
        ['测试客户', 'INC-002', '商城应用出现高危扫描行为', '10.10.2.20', 'EDR', '-', '-', '-', '高危', '待处置', '扫描探测', '漏洞扫描', '成功', '2026-06-29 18:21:00', '2026-06-29 18:00:00', '', '', '', 'EDR'],
        ['测试客户', 'INC-003', 'OA数据库发现可疑访问', '10.10.3.31', 'EDR', '-', '-', '-', '低危', '处置中', '异常访问', '数据库访问', '失败', '2026-06-28 14:12:00', '2026-06-28 14:00:00', '', '', '', 'EDR'],
    ]


def build_vuln_rows():
    return [
        ['支付数据库未授权访问漏洞', '尽快修复', '严重', 'Unauthorized Access', '限制访问', '数据库暴露风险', 'Exposure', '云镜', '配置检查', 'CVE-2026-0002', '2026-06-30 02:10:00', '2026-06-29 02:10:00', '10.10.1.11', '服务器', '核心资产池', '支付网关', '张三', '核心', '已纳管', '3306'],
        ['商城应用SQL注入漏洞', '尽快修复', '高危', 'SQL Injection', '参数化查询', '可读取业务数据', 'Injection', '云镜', 'POC检测', 'CVE-2026-0011', '2026-06-30 03:00:00', '2026-06-29 03:00:00', '10.10.2.20', '服务器', '核心资产池', '电商平台', '李四', '核心', '已纳管', '443'],
        ['商城缓存越权访问漏洞', '尽快修复', '高危', 'Broken Access Control', '收敛权限', '存在越权访问风险', 'Auth', '云镜', '配置检查', 'CVE-2026-0012', '2026-06-30 03:10:00', '2026-06-29 03:10:00', '10.10.2.21', '服务器', '核心资产池', '电商平台', '李四', '核心', '已纳管', '6379'],
        ['OA数据库弱鉴权漏洞', '修复', '中危', 'Weak Auth', '加强鉴权', '访问控制不足', 'Auth', '云镜', '配置检查', 'CVE-2026-0021', '2026-06-30 04:00:00', '2026-06-29 04:00:00', '10.10.3.31', '服务器', '办公资产池', 'OA系统', '王五', '核心', '已纳管', '1521'],
    ]


def build_weak_rows():
    return [
        ['Redis 弱密码', 'default', '123456', '', '云镜', '2026-06-30 08:10:00', '2026-06-29 08:10:00', '10.10.2.21', '服务器', '核心资产池', '电商平台', '李四', '核心', '已纳管', '已托管', '6379', '', '未暴露', '', '未加白'],
    ]


def build_exposure_sheet_rows():
    web_rows = [
        [1, 'Nginx 低版本', 'https://pay.example.com', '信息技术部'],
    ]
    non_web_rows = [
        [1, 'mysql', '10.10.8.8', '3306', 'mysql', '信息技术部'],
        [2, 'redis', '10.10.2.20', '6379', 'redis', '电商中心'],
    ]
    port_rows = [
        [1, '10.10.1.11', '10.10.1.11', '443', 'https', '可达', 'Nginx', 'https://pay.example.com', '200', 'Pay', '', '', '', '', '支付网关', '运行中', '', '信息技术部', '', ''],
        [2, '10.10.2.21', '10.10.2.21', '443', 'https', '可达', 'Nginx', 'https://shop.example.com', '200', 'Shop', '', '', '', '', '电商平台', '运行中', '', '电商中心', '', ''],
    ]
    return web_rows, non_web_rows, port_rows


def main():
    asset_path = os.path.join(OUTPUT_DIR, 'Asset_Export__mock.xlsx')
    event_path = os.path.join(OUTPUT_DIR, '测试客户_事件跟踪表_mock.xlsx')
    vuln_path = os.path.join(OUTPUT_DIR, '漏洞清单_mock.xlsx')
    weak_path = os.path.join(OUTPUT_DIR, '弱口令清单_mock.xlsx')
    exposure_path = os.path.join(OUTPUT_DIR, '暴露面清单_mock.xlsx')

    write_workbook(asset_path, [('Sheet1', ASSET_HEADERS, build_asset_rows(), True)])
    write_workbook(event_path, [('事件表', EVENT_HEADERS, build_event_rows(), False)])
    write_workbook(vuln_path, [('漏洞', VULN_HEADERS, build_vuln_rows(), False)])
    write_workbook(weak_path, [('弱口令', WEAK_HEADERS, build_weak_rows(), False)])

    web_rows, non_web_rows, port_rows = build_exposure_sheet_rows()
    write_workbook(exposure_path, [
        ('Web服务风险分布', EXPOSURE_WEB_HEADERS, web_rows, False),
        ('非Web服务风险分布', EXPOSURE_NON_WEB_HEADERS, non_web_rows, False),
        ('端口表', PORT_HEADERS, port_rows, False),
    ])

    print(asset_path)
    print(event_path)
    print(vuln_path)
    print(weak_path)
    print(exposure_path)


if __name__ == '__main__':
    main()
