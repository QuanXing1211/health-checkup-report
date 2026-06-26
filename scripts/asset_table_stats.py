import json
import sys

from openpyxl import load_workbook


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


def classify_asset_type(value):
    text = normalize(value)
    if "服务器" in text:
        return "server"
    if "终端" in text:
        return "terminal"
    return "other"


def classify_protection_status(value):
    text = normalize(value)
    mapping = {
        "0": "offline",
        "1": "online",
        "2": "disabled",
        "3": "demoted",
        "在线": "online",
        "离线": "offline",
        "已禁用": "disabled",
        "已降级": "demoted"
    }
    if text in mapping:
        return mapping[text]
    try:
        return mapping[str(int(float(text)))]
    except Exception:
        return None


def is_exposed(value):
    text = normalize(value).lower()
    return text in {"1", "yes", "true", "是", "暴露", "y"}


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: asset_table_stats.py <asset.xlsx>")

    workbook = load_workbook(sys.argv[1], read_only=True, data_only=True)
    sheet = workbook.active
    header_row = next(sheet.iter_rows(min_row=2, max_row=2, values_only=True), ())
    headers = list(header_row)

    type_column = find_column(headers, ("资产类型",))
    protection_column = find_column(headers, ("agent状态", "连接状态"))
    exposure_column = find_column(headers, ("互联网暴露", "是否暴露"))

    asset_total = 0
    type_counts = {"server": 0, "terminal": 0}
    protection_counts = {"online": 0, "offline": 0, "disabled": 0, "demoted": 0}
    exposure_total = 0
    exposure_type_counts = {"server": 0, "terminal": 0}
    for row in sheet.iter_rows(min_row=3, values_only=True):
        if not any(normalize(cell) for cell in row):
            continue

        asset_total += 1

        if type_column is not None and type_column < len(row):
            asset_type = classify_asset_type(row[type_column])
            if asset_type in type_counts:
                type_counts[asset_type] += 1

        if protection_column is not None and protection_column < len(row):
            status = classify_protection_status(row[protection_column])
            if status in protection_counts:
                protection_counts[status] += 1

        exposed = False
        if exposure_column is not None and exposure_column < len(row):
            exposed = is_exposed(row[exposure_column])

        if exposed:
            exposure_total += 1
            if type_column is not None and type_column < len(row):
                asset_type = classify_asset_type(row[type_column])
                if asset_type in exposure_type_counts:
                    exposure_type_counts[asset_type] += 1

    print(json.dumps({
        "assetTotal": asset_total,
        "typeDistribution": {
            "server": type_counts["server"],
            "terminal": type_counts["terminal"],
            "other": max(asset_total - type_counts["server"] - type_counts["terminal"], 0)
        },
        "protectionDistribution": {
            "online": protection_counts["online"],
            "offline": protection_counts["offline"],
            "disabled": protection_counts["disabled"],
            "demoted": protection_counts["demoted"],
            "unprotected": max(asset_total - protection_counts["online"] - protection_counts["offline"] - protection_counts["disabled"] - protection_counts["demoted"], 0)
        },
        "internetExposureTotal": exposure_total,
        "internetExposureDistribution": {
            "server": exposure_type_counts["server"],
            "terminal": exposure_type_counts["terminal"],
            "other": max(exposure_total - exposure_type_counts["server"] - exposure_type_counts["terminal"], 0)
        }
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
