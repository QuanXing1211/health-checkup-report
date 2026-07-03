import json
import re
import sys
from collections import Counter

from openpyxl import load_workbook

from _path_helper import decode_argv
decode_argv()

# 确保 stdout 使用 UTF-8 编码（Windows 兼容）
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

IP_PATTERN = re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')


def normalize(value):
    return "" if value is None else str(value).strip()


def normalize_header(value):
    return normalize(value).lower().replace(" ", "").replace("_", "")


def find_column(headers, aliases):
    for index, header in enumerate(headers):
        normalized = normalize_header(header)
        if not normalized:
            continue
        for alias in aliases:
            if alias in normalized:
                return index
    return None


def extract_ips(text):
    return IP_PATTERN.findall(normalize(text))


def top1_name(counter):
    """取 Counter 第1项的名称, 无可返回空字符串"""
    items = counter.most_common(1)
    return items[0][0] if items else ""


def top_n(counter, n):
    """取 Counter 前n项, 返回 [{name, value}] 格式"""
    return [{"name": k, "value": v} for k, v in counter.most_common(n)]


def parse_response_time(value):
    """解析响应时间（分钟），支持 "23"、"23分钟"、"23 min" 等格式"""
    text = normalize(value)
    if not text:
        return None

    # 尝试直接解析数字
    try:
        return float(text)
    except ValueError:
        pass

    # 尝试提取数字（支持 "23分钟"、"23min" 等格式）
    m = re.search(r'(\d+(?:\.\d+)?)\s*[分钟分min]*', text)
    if m:
        return float(m.group(1))

    return None


def top_n_with_other(counter, n):
    """取 Counter 前 n 项, 超过 n 项时末尾补充"其他"（取值 = 总数 - 前 n 项之和）"""
    items = counter.most_common(n)
    total = sum(counter.values())
    top_sum = sum(v for _, v in items)

    result = [{"name": k, "value": v} for k, v in items]
    if len(counter) > n:
        result.append({"name": "其他", "value": total - top_sum})
    return result


def main():
    if len(sys.argv) < 3:
        raise SystemExit("Usage: managed_asset_incident_stats.py <asset.xlsx> <incident.xlsx>")

    asset_path = sys.argv[1]
    incident_path = sys.argv[2]

    # ====== 读取资产表 ======
    managed_asset_ips = set()
    ip_to_business = {}  # IP -> 所属业务

    try:
        asset_wb = load_workbook(asset_path, read_only=True, data_only=True)
        asset_ws = asset_wb.active
        header_row = next(asset_ws.iter_rows(min_row=2, max_row=2, values_only=True), ())
        headers = [normalize(h) for h in header_row]

        managed_col = find_column(headers, ["托管状态"])
        ip_col = find_column(headers, ["ip地址"])
        biz_col = find_column(headers, ["所属业务"])

        for row in asset_ws.iter_rows(min_row=3, values_only=True):
            if not any(normalize(cell) for cell in row):
                continue

            # 提取 IP
            ips = extract_ips(row[ip_col]) if (ip_col is not None and ip_col < len(row)) else []

            if not ips:
                continue

            ip = ips[0]

            # 收集业务系统映射
            if biz_col is not None and biz_col < len(row):
                biz = normalize(row[biz_col])
                if biz:
                    ip_to_business[ip] = biz

            # 收集托管资产 IP
            is_managed = False
            if managed_col is not None and managed_col < len(row):
                val = normalize(row[managed_col])
                if "已托管" in val or "托管" == val:
                    is_managed = True

            if is_managed:
                managed_asset_ips.add(ip)

        asset_wb.close()
    except Exception as e:
        print(json.dumps({
            "managedAssetEvents": 0,
            "managedAssetContainedEvents": 0,
            "managedAssetDisposedEvents": 0,
            "managedEventCloseRate": 0,
            "managedAssetCount": 0,
            "managedAvgResponseTime": 0,
            "topEventType": "",
            "top3BusinessSystems": "",
            "businessSystemEventDistribution": [],
            "error": f"读取资产表失败: {str(e)}"
        }, ensure_ascii=False))
        return

    # ====== 读取事件表 ======
    total_managed = 0
    contained_managed = 0
    disposed_managed = 0
    disposed_response_times = []
    event_type_counter = Counter()
    business_counter = Counter()

    try:
        incident_wb = load_workbook(incident_path, data_only=True)
        incident_ws = incident_wb.active

        header_row = next(incident_ws.iter_rows(values_only=True))
        incident_headers = [normalize(h) for h in header_row]

        status_col = find_column(incident_headers, ["处置状态"])
        asset_col = find_column(incident_headers, ["影响资产"])
        event_type_col = find_column(incident_headers, ["安全事件一级分类"])
        response_time_col = find_column(incident_headers, ["响应时间"])

        for row in incident_ws.iter_rows(min_row=2, values_only=True):
            if not any(normalize(cell) for cell in row):
                continue

            # 安全事件类型分布（所有事件）
            if event_type_col is not None and event_type_col < len(row):
                et = normalize(row[event_type_col])
                if et:
                    event_type_counter[et] += 1

            # 提取影响资产 IP
            incident_ip = None
            if asset_col is not None and asset_col < len(row):
                ips = extract_ips(row[asset_col])
                if ips:
                    incident_ip = ips[0]

            # 业务系统安全事件分布
            if incident_ip and incident_ip in ip_to_business:
                biz = ip_to_business[incident_ip]
                business_counter[biz] += 1

            # 托管资产事件统计（只统计影响资产为托管 IP 的事件）
            if not incident_ip or incident_ip not in managed_asset_ips:
                continue

            total_managed += 1

            if status_col is not None and status_col < len(row):
                status = normalize(row[status_col])
                if status == "已遏制":
                    contained_managed += 1
                elif status == "处置完成":
                    disposed_managed += 1
                    # 收集处置完成事件的响应时间
                    if response_time_col is not None and response_time_col < len(row):
                        rt = parse_response_time(row[response_time_col])
                        if rt is not None:
                            disposed_response_times.append(rt)

        incident_wb.close()
    except Exception as e:
        print(json.dumps({
            "managedAssetEvents": 0,
            "managedAssetContainedEvents": 0,
            "managedAssetDisposedEvents": 0,
            "managedEventCloseRate": 0,
            "managedAssetCount": len(managed_asset_ips),
            "managedAvgResponseTime": 0,
            "topEventType": "",
            "top3BusinessSystems": "",
            "businessSystemEventDistribution": [],
            "error": f"读取事件表失败: {str(e)}"
        }, ensure_ascii=False))
        return

    close_rate = round((disposed_managed / total_managed) * 100) if total_managed else 0
    avg_response_time = round(sum(disposed_response_times) / len(disposed_response_times), 1) if disposed_response_times else 0

    result = {
        "managedAssetEvents": total_managed,
        "managedAssetContainedEvents": contained_managed,
        "managedAssetDisposedEvents": disposed_managed,
        "managedEventCloseRate": close_rate,
        "managedAssetCount": len(managed_asset_ips),
        "managedAvgResponseTime": avg_response_time,
        "topEventType": top1_name(event_type_counter),
        "top3BusinessSystems": "、".join(item["name"] for item in top_n_with_other(business_counter, 5)[:3]),
        "businessSystemEventDistribution": top_n_with_other(business_counter, 5)
    }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
