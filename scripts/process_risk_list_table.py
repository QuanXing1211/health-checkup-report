#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资产表和事件表后处理脚本。

功能：
- asset: 删除 zdy、责任人电话、责任人(设备上报)、实时认证用户名 四列；保留原文件名复制到输出目录
- incident: 原样复制到输出目录，不修改列或数据

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

BUSINESS_COLUMN_ALIASES = ['所属业务']


def normalize(value):
    return '' if value is None else str(value).strip()


def clean_business_column(value):
    """处理所属业务列：按逗号分隔，每个分段去掉 '/' 及其前面的部分，保留后面的内容。"""
    text = normalize(value)
    if not text:
        return text
    parts = text.split(',')
    cleaned = []
    for part in parts:
        part = part.strip()
        if '/' in part:
            part = part.rsplit('/', 1)[-1].strip()
        if part:
            cleaned.append(part)
    return ', '.join(cleaned) if cleaned else ''


def build_col_header(ws):
    """查找第一行非空行作为表头，返回 (col_name->index 字典, header_row_number)。"""
    for idx, row in enumerate(ws.iter_rows(min_row=1, max_row=10, values_only=True), start=1):
        values = [normalize(cell) for cell in row]
        if any(values):
            return {name: i for i, name in enumerate(values) if name}, idx
    return {}, 1


def process_asset_table(input_path, output_dir):
    """处理资产表：删除指定列，清理所属业务列，保留原文件名输出到 output_dir。"""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, os.path.basename(input_path))

    wb = load_workbook(input_path)
    ws = wb.active

    col_map, header_row = build_col_header(ws)

    # 1) 删除指定列
    to_remove_cols = []
    for col_name in ASSET_COLUMNS_TO_REMOVE:
        if col_name in col_map:
            to_remove_cols.append(col_map[col_name])

    if to_remove_cols:
        to_remove_cols.sort(reverse=True)
        for col_idx in to_remove_cols:
            ws.delete_cols(col_idx + 1, 1)

    # 删除列后重新读取表头（列索引已变）
    col_map, _ = build_col_header(ws)

    # 2) 清理所属业务列
    business_col_idx = None
    for alias in BUSINESS_COLUMN_ALIASES:
        if alias in col_map:
            business_col_idx = col_map[alias]
            break

    if business_col_idx is not None:
        for row in ws.iter_rows(min_row=header_row + 1):
            cell = row[business_col_idx]
            if cell.value is not None:
                raw = normalize(cell.value)
                cleaned = clean_business_column(raw)
                if cleaned != raw:
                    cell.value = cleaned

    wb.save(output_path)
    wb.close()
    return output_path


def process_incident_table(input_path, output_dir):
    """原样复制事件表，不补列、不填充模拟数据。"""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, os.path.basename(input_path))
    shutil.copy2(input_path, output_path)
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
