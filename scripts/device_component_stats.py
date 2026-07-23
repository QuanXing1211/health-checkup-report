#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全组件分布统计脚本。

读取 tmp/device.json，按 devType 聚合设备数，并映射为组件类型名称。

输出 JSON：
{
  "total": 总设备数,
  "componentDistribution": [{"name": "EDR", "value": 19}, ...]
}
"""
import json
import os
import sys
from collections import Counter

from _path_helper import decode_argv
decode_argv()


# devType → 组件类型名称映射（与 分支1/report/policy_check_export.py 的 DEV_TYPE_DICT 保持一致）
DEV_TYPE_DICT = {
    3: "AF",
    9: "SIP",
    12: "EDR",
    25: "STA",
    72: "云镜-服务版",
    50038: "EDR-探针版",
    19: "aTrust",
    2: "AC",
    15: "云镜",
    100012: "SAAS EDR",
    69: "SaaS NGES",
    37: "CWPP",
    100038: "SaaS-EDR-探针版",
}


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: device_component_stats.py <device.json>")

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("data", {}).get("list", []) or []
    component_counter = Counter()
    unknown_count = 0
    total = 0

    for item in items:
        total += 1
        dev_type = item.get("devType")
        name = DEV_TYPE_DICT.get(dev_type)
        if name:
            component_counter[name] += 1
        else:
            unknown_count += 1

    # 按数量降序排列
    distribution = [
        {"name": name, "value": count}
        for name, count in component_counter.most_common()
    ]
    if unknown_count > 0:
        distribution.append({"name": "未知", "value": unknown_count})

    print(json.dumps({
        "total": total,
        "componentDistribution": distribution
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
