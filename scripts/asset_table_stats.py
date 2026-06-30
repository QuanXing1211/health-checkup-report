import json
import sys

from openpyxl import load_workbook


def normalize(value):
    return "" if value is None else str(value).strip()


def normalize_header(value):
    return normalize(value).lower().replace(" ", "").replace("_", "")


def find_column(headers, aliases):
    normalized_aliases = [normalize_header(alias) for alias in aliases]
    for index, header in enumerate(headers):
        normalized = normalize_header(header)
        if not normalized:
            continue
        for alias in normalized_aliases:
            if alias in normalized:
                return index
    return None


def classify_asset_type(value):
    text = normalize(value)
    if "服务器" in text:
        return "server"
    if "终端" in text:
        return "terminal"
    return "other"


CN_PROTECTION_STATUSES = {"在线", "离线", "已禁用", "已降级"}
CN_UNPROTECTED_STATUSES = {"已卸载", "已移除", "未接入", "未授权"}


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: asset_table_stats.py <asset.xlsx>")

    workbook = load_workbook(sys.argv[1], read_only=True, data_only=True)
    sheet = workbook.active
    header_row = next(sheet.iter_rows(min_row=2, max_row=2, values_only=True), ())
    headers = list(header_row)

    # 列匹配（仅指定的列名）
    type_column = find_column(headers, ("资产类型(一级)",))
    protection_column = find_column(headers, ("agent状态",))
    exposure_column = find_column(headers, ("互联网暴露",))
    importance_column = find_column(headers, ("重要级别",))
    managed_column = find_column(headers, ("托管状态",))

    asset_total = 0
    core_asset = 0
    core_managed_asset = 0
    type_counts = {"server": 0, "terminal": 0}
    protection_counts = {}  # 直接记录中文值
    exposure_total = 0
    exposure_type_counts = {"server": 0, "terminal": 0}

    for row in sheet.iter_rows(min_row=3, values_only=True):
        if not any(normalize(cell) for cell in row):
            continue

        asset_total += 1

        # ---- 资产类型（一级） ----
        if type_column is not None and type_column < len(row):
            asset_type = classify_asset_type(row[type_column])
            if asset_type in type_counts:
                type_counts[asset_type] += 1

        # ---- agent 状态：直接记录中文值 ----
        if protection_column is not None and protection_column < len(row):
            raw = normalize(row[protection_column])
            if raw in CN_PROTECTION_STATUSES:
                protection_counts[raw] = protection_counts.get(raw, 0) + 1
            elif raw in CN_UNPROTECTED_STATUSES:
                protection_counts["未防护"] = protection_counts.get("未防护", 0) + 1

        # ---- 互联网暴露：仅"未暴露"算不暴露，其余都算暴露 ----
        exposed = False
        if exposure_column is not None and exposure_column < len(row):
            raw = normalize(row[exposure_column])
            if raw and raw != "未暴露":
                exposed = True

        if exposed:
            exposure_total += 1
            if type_column is not None and type_column < len(row):
                asset_type = classify_asset_type(row[type_column])
                if asset_type in exposure_type_counts:
                    exposure_type_counts[asset_type] += 1

        # ---- 核心资产：根据"重要级别"列统计 ----
        is_core = False
        if importance_column is not None and importance_column < len(row):
            raw = normalize(row[importance_column])
            if raw and "核心" in raw:
                is_core = True
                core_asset += 1

        # ---- 核心已托管：核心资产中"托管状态"为"已托管" ----
        if is_core and managed_column is not None and managed_column < len(row):
            raw = normalize(row[managed_column])
            if "已托管" in raw:
                core_managed_asset += 1

    print(json.dumps({
        "assetTotal": asset_total,
        "core_asset": core_asset,
        "core_managed_asset": core_managed_asset,
        "typeDistribution": {
            "server": type_counts["server"],
            "terminal": type_counts["terminal"],
            "other": max(asset_total - type_counts["server"] - type_counts["terminal"], 0)
        },
        "protectionDistribution": protection_counts,
        "internetExposureTotal": exposure_total,
        "internetExposureDistribution": {
            "server": exposure_type_counts["server"],
            "terminal": exposure_type_counts["terminal"],
            "other": max(exposure_total - exposure_type_counts["server"] - exposure_type_counts["terminal"], 0)
        }
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
