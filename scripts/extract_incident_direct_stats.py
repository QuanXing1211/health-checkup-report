#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从事件表 Excel 中直接提取三类事件统计：

1. C2 外联：GPT研判结论 = "主机失陷活动" 且 外网IP / 域名列中存在标记为"恶意"的实体
2. 病毒木马：GPT研判结论 = "病毒木马活动" 且 文件列中存在标记为"恶意"的实体
3. 漏洞利用：安全事件一级分类列值为"漏洞利用"

用法:
  extract_incident_direct_stats.py <incident.xlsx>

输出 JSON:
{
  "hostCompromiseIds": ["incident-001"],
  "virusTrojanIds": ["incident-002"],
  "exploitIds": ["incident-003"]
}
"""

import json
import re
import sys

from openpyxl import load_workbook

from _path_helper import decode_argv, reset_read_only_dimensions
decode_argv()


SEVERE_LABEL = "恶意"
GPT_HOST_COMPROMISE = "主机失陷活动"
GPT_VIRUS_TROJAN = "病毒木马活动"


def normalize(value):
    return "" if value is None else str(value).strip()


def build_col_map(ws):
    header = [normalize(cell) for cell in next(ws.iter_rows(values_only=True))]
    return {name: i for i, name in enumerate(header) if name}


def find_column(col_map, aliases):
    for alias in aliases:
        if alias in col_map:
            return col_map[alias]
    return None


def extract_severe_entities(raw):
    text = normalize(raw)
    if not text:
        return []

    matches = re.findall(r'([^，,、()（）]+?)\s*[（(]\s*([^()（）]+?)\s*[）)]', text)
    entities = []
    for entity, severity in matches:
        if normalize(severity) == SEVERE_LABEL:
            entities.append(normalize(entity))
    return entities


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: extract_incident_direct_stats.py <incident.xlsx>")

    workbook = load_workbook(sys.argv[1], read_only=True, data_only=True)
    sheet = reset_read_only_dimensions(workbook.active)
    col_map = build_col_map(sheet)

    id_col = find_column(col_map, ["事件ID", "事件Id", "incident_id", "incidentId", "id", "ID"])
    gpt_col = find_column(col_map, ["GPT研判结论"])
    file_col = find_column(col_map, ["文件", "文件MD5", "md5", "file"])
    ext_ip_col = find_column(col_map, ["外网IP地址"])
    domain_col = find_column(col_map, ["域名", "外联域名"])
    class_col = find_column(col_map, [
        "安全事件一级分类", "事件分类", "incident_threat_class",
        "incidentThreatClass", "威胁分类", "threatClass"
    ])

    if id_col is None:
        raise SystemExit(f"事件表缺少事件ID列，可用列: {list(col_map.keys())}")

    host_compromise_ids = []
    virus_trojan_ids = []
    exploit_ids = []

    for row in sheet.iter_rows(min_row=2, values_only=True):
        incident_id = normalize(row[id_col]) if len(row) > id_col else ""
        if not incident_id:
            continue

        gpt_value = normalize(row[gpt_col]) if gpt_col is not None and len(row) > gpt_col else ""

        if gpt_value == GPT_HOST_COMPROMISE:
            severe_iocs = []
            if ext_ip_col is not None and len(row) > ext_ip_col:
                severe_iocs = extract_severe_entities(row[ext_ip_col])
            if not severe_iocs and domain_col is not None and len(row) > domain_col:
                severe_iocs = extract_severe_entities(row[domain_col])
            if severe_iocs:
                host_compromise_ids.append(incident_id)

        if gpt_value == GPT_VIRUS_TROJAN:
            severe_files = extract_severe_entities(row[file_col]) if file_col is not None and len(row) > file_col else []
            if severe_files:
                virus_trojan_ids.append(incident_id)

        class_value = normalize(row[class_col]) if class_col is not None and len(row) > class_col else ""
        if class_value == "漏洞利用":
            exploit_ids.append(incident_id)

    workbook.close()
    print(json.dumps({
        "hostCompromiseIds": host_compromise_ids,
        "virusTrojanIds": virus_trojan_ids,
        "exploitIds": exploit_ids
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
