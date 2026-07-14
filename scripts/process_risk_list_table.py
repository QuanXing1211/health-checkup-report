#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资产表和事件表后处理脚本。

功能：
- asset: 删除 zdy、责任人电话、责任人(设备上报)、实时认证用户名 四列；保留原文件名复制到输出目录
- incident: 缺少指定列时自动补列，并为前 100 行补充模拟值

用法：
    python process_risk_list_table.py asset <input.xlsx> <output_dir>
    python process_risk_list_table.py incident <input.xlsx> <output_dir>

输出：
    JSON: {"filePath": "<output_dir>/<原文件名>.xlsx" }
"""
import json
import os
import shutil
import sys

from openpyxl import load_workbook

from _path_helper import decode_argv
decode_argv()


ASSET_COLUMNS_TO_REMOVE = [
    'zdy',
    '责任人电话',
    '责任人(设备上报)',
    '实时认证用户名',
]

INCIDENT_COLUMNS_TO_MOCK = [
    '外网IP地址',
    '域名',
    '文件',
    '推送状态',
]

def normalize(value):
    return '' if value is None else str(value).strip()


def build_col_header(ws):
    """查找第一行非空行作为表头，返回 (col_name->index 字典, header_row_number)。"""
    for idx, row in enumerate(ws.iter_rows(min_row=1, max_row=10, values_only=True), start=1):
        values = [normalize(cell) for cell in row]
        if any(values):
            return {name: i for i, name in enumerate(values) if name}, idx
    return {}, 1


def process_asset_table(input_path, output_dir):
    """处理资产表：删除指定列，保留原文件名输出到 output_dir。"""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, os.path.basename(input_path))

    wb = load_workbook(input_path)
    ws = wb.active

    col_map, header_row = build_col_header(ws)
    to_remove_cols = []
    for col_name in ASSET_COLUMNS_TO_REMOVE:
        if col_name in col_map:
            to_remove_cols.append(col_map[col_name])

    if to_remove_cols:
        # 按列索引从大到小排序，从右往左删除（避免删除后索引偏移）
        to_remove_cols.sort(reverse=True)
        # 读取所有行数据
        all_rows = list(ws.iter_rows(min_row=1, values_only=True))
        # 清空原 sheet
        ws.delete_rows(1, ws.max_row)
        # 逐行删除指定列
        for row_idx, row in enumerate(all_rows, start=1):
            row_list = list(row)
            for col_idx in to_remove_cols:
                if col_idx < len(row_list):
                    del row_list[col_idx]
            ws.append(row_list)

    wb.save(output_path)
    wb.close()
    return output_path


def build_mock_ip_value(index):
    first = f'{(index % 200) + 1}.{((index + 30) % 200) + 1}.{((index + 60) % 200) + 1}.{((index + 90) % 200) + 1}'
    if index % 3 == 0:
        return f'{first}（恶意）'
    second = f'{((index + 5) % 200) + 1}.{((index + 35) % 200) + 1}.{((index + 65) % 200) + 1}.{((index + 95) % 200) + 1}'
    return f'{first}（恶意）、{second}（未知）'


def build_mock_domain_value(index):
    if index % 4 == 0:
        return f'evil{index + 1}.com（恶意）'
    return f'evil{index + 1}.com（恶意）、check{index + 1}.net（未知）'


def build_mock_file_value(index):
    first = f'{0x1200 + index:04x}{0x3400 + index:04x}'
    if index % 5 == 0:
        return f'{first}（恶意）'
    second = f'{0x5600 + index:04x}{0x7800 + index:04x}'
    return f'{first}（恶意）、{second}（未知）'


def build_mock_push_status(index):
    return '已推送' if index % 2 == 0 else '未推送'


def ensure_minimum_data_rows(ws, header_row, min_rows):
    current_rows = max(ws.max_row - header_row, 0)
    for _ in range(current_rows, min_rows):
        ws.append([''] * ws.max_column)


def process_incident_table(input_path, output_dir):
    """处理事件表：缺列时补列，并为前 100 行填充模拟值。"""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, os.path.basename(input_path))

    wb = load_workbook(input_path)
    ws = wb.active
    col_map, header_row = build_col_header(ws)

    missing_columns = [name for name in INCIDENT_COLUMNS_TO_MOCK if name not in col_map]
    if not missing_columns:
        wb.close()
        shutil.copy2(input_path, output_path)
        return output_path

    for column_name in missing_columns:
        new_col = ws.max_column + 1
        ws.cell(row=header_row, column=new_col).value = column_name
        col_map[column_name] = new_col - 1

    ensure_minimum_data_rows(ws, header_row, 100)

    for index in range(100):
        row_idx = header_row + 1 + index
        if '外网IP地址' in missing_columns:
            ws.cell(row=row_idx, column=col_map['外网IP地址'] + 1).value = build_mock_ip_value(index)
        if '域名' in missing_columns:
            ws.cell(row=row_idx, column=col_map['域名'] + 1).value = build_mock_domain_value(index)
        if '文件' in missing_columns:
            ws.cell(row=row_idx, column=col_map['文件'] + 1).value = build_mock_file_value(index)
        if '推送状态' in missing_columns:
            ws.cell(row=row_idx, column=col_map['推送状态'] + 1).value = build_mock_push_status(index)

    wb.save(output_path)
    wb.close()
    return output_path


def main():
    if len(sys.argv) < 4:
        raise SystemExit(
            'Usage: process_risk_list_table.py <asset|incident> <input.xlsx> <output_dir>'
        )

    table_type = sys.argv[1].lower()
    input_path = sys.argv[2]
    output_dir = sys.argv[3]

    if not os.path.isfile(input_path):
        raise SystemExit(f'输入文件不存在: {input_path}')

    if table_type == 'asset':
        output_path = process_asset_table(input_path, output_dir)
    elif table_type == 'incident':
        output_path = process_incident_table(input_path, output_dir)
    else:
        raise SystemExit(f'不支持的表类型: {table_type}（仅支持 asset / incident）')

    print(json.dumps({'filePath': output_path}, ensure_ascii=False))


if __name__ == '__main__':
    main()
