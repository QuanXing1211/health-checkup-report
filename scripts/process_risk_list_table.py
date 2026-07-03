#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资产表和事件表后处理脚本。

功能：
- asset: 删除 zdy、责任人电话、责任人(设备上报)、实时认证用户名 四列；sheet 重命名为"资产清单"；输出为"资产清单.xlsx"
- incident: 复制为"安全事件表.xlsx"（sheet 不变）

用法：
    python process_risk_list_table.py asset <input.xlsx> <output_dir>
    python process_risk_list_table.py incident <input.xlsx> <output_dir>

输出：
    JSON: {"filePath": "<output_dir>/资产清单.xlsx" }
"""
import json
import os
import shutil
import sys

from openpyxl import load_workbook
from openpyxl.utils import get_column_letter

from _path_helper import decode_argv
decode_argv()


ASSET_COLUMNS_TO_REMOVE = [
    'zdy',
    '责任人电话',
    '责任人(设备上报)',
    '实时认证用户名',
]

ASSET_OUTPUT_NAME = '资产清单.xlsx'
INCIDENT_OUTPUT_NAME = '安全事件表.xlsx'
ASSET_SHEET_NAME = '资产清单'


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
    """处理资产表：删除指定列，重命名 sheet，输出到 output_dir/资产清单.xlsx"""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, ASSET_OUTPUT_NAME)

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

    # 重命名 sheet 为"资产清单"
    if ws.title != ASSET_SHEET_NAME:
        ws.title = ASSET_SHEET_NAME
    # 把文件名的 sheet 也统一命名
    for s in wb.sheetnames:
        sheet = wb[s]
        if sheet.title != ASSET_SHEET_NAME:
            sheet.title = ASSET_SHEET_NAME

    wb.save(output_path)
    wb.close()
    return output_path


def process_incident_table(input_path, output_dir):
    """处理事件表：原样复制到 output_dir/安全事件表.xlsx"""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, INCIDENT_OUTPUT_NAME)
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
