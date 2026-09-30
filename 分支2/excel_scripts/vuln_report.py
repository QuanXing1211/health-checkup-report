#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞清单生成工具
从 EASM 平台（外网）和 MSSW 平台（内网）分别获取漏洞数据，
合并生成统一的「漏洞清单.xlsx」。

用法: python vuln_report.py <客户ID或客户名称关键词>
示例: python vuln_report.py 深圳市口袋网络
      python vuln_report.py 35690473
"""

import os
import sys
import time
import threading
import argparse
import requests
from copy import copy
from openpyxl.styles import Font, PatternFill, Border, Alignment
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import openpyxl
from openpyxl import load_workbook


# ==================== 配置（按需修改） ====================

# --- 通用 ---
TEMP_DIR     = r"C:\Users\User\Downloads\temp_report"
OUTPUT_FILE  = r"C:\Users\User\Downloads\漏洞清单.xlsx"

POLL_INTERVAL   = 5     # 轮询间隔（秒）
# SCRIPT_TIMEOUT  = 3600  # 全局超时：1小时
MAX_RETRIES     = 3     # 最大重试次数
RETRY_DELAY     = 3     # 重试等待时间（秒）
PAGE_LIMIT      = 100   # 列表接口每次查询数量

# ===== 配置区（迁移到集成化新版时，此块替换为 api_config_loader 调用）=====
MSSW_BASE_URL     = "https://pre.soar.sangfor.com"                  # 新版→ _get_origin("mssw")
MSSW_COOKIES_FILE = r"C:\Users\User\Downloads\mssw_cookies.txt"     # 新版→ os.getcwd()/mssw_cookies.txt

# 接口路径（新版对应 config/api_config.json 的 endpoints）
EP_CUSTOMER_STATISTIC = "/gateway/customer-mgr-service/order/v1/user/customer_statistic?_method=GET"
EP_VULN_EXPORT        = "/gateway/easm-exposure/order/v1/vulnmgr/exposed_surface/report"
EP_POLL               = "/gateway/easm-exposure/order/v1/vulnmgr/exposed_surface/report_async_task"
EP_DOWNLOAD           = "/gateway/workflow/order/v1/attachments"

# 漏洞导出参数（固定）
VULN_DATA_TYPE      = 51                            # 51=漏洞
VULN_FIXED_STATUSES = [0, 1]         # 处置状态过滤

# 交付命名常量（后期改一行即可）
NAME_INTRANET = "漏洞清单（内网）.xlsx"              # 交付用（内网，平台原样30列）
NAME_INTERNET = "漏洞清单（互联网）.xlsx"            # 交付用（外网，平台原样21列）
# =====================================================================


# ---------- 日志 ----------

def log(msg: str, level: str = "INFO") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}][{level}] {msg}")


# ---------- 工具函数 ----------

def _get_system_timezone() -> str:
    offset = datetime.now().astimezone().utcoffset()
    if offset is None:
        return "+00:00"
    total_seconds = int(offset.total_seconds())
    sign = "+" if total_seconds >= 0 else "-"
    total_seconds = abs(total_seconds)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    return f"{sign}{hours:02d}:{minutes:02d}"


def extract_cookie_value(cookie_str: str, name: str) -> Optional[str]:
    for part in cookie_str.split(';'):
        part = part.strip()
        if '=' in part:
            k, _, v = part.partition('=')
            if k.strip() == name:
                return v.strip()
    return None


def _fmt_minute(val) -> str:
    """
    将时间值统一格式化到分钟精度（YYYY-MM-DD HH:MM）。
    支持 datetime 对象和字符串，空值返回空字符串。
    """
    if val is None or val == "":
        return ""
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M")
    s = str(val).strip()
    return s[:16] if len(s) >= 16 else s


# ---------- Cookie 读取 ----------

def read_cookies_as_string(filepath: str) -> str:
    """
    读取 cookies.txt，返回 Cookie 请求头字符串（name=value; name2=value2 格式）。
    支持两种输入格式：
      1. 浏览器原始 Cookie 字符串
      2. Netscape 格式（EditThisCookie 等工具导出，tab 分隔）
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read().strip()

    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    is_netscape = any('\t' in ln for ln in lines if not ln.startswith('#'))

    if is_netscape:
        pairs = []
        for ln in lines:
            if ln.startswith('#'):
                continue
            parts = ln.split('\t')
            if len(parts) >= 7:
                pairs.append(f"{parts[5]}={parts[6]}")
        return '; '.join(pairs)
    else:
        return '; '.join(lines)


# ---------- 请求封装 ----------

def _build_default_headers(base_url: str) -> Dict[str, str]:
    return {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{base_url}/index.html",
        "timezone": _get_system_timezone(),
    }


def request_with_retry(method: str, url: str, base_url: str,
                       cookie_str: str = "",
                       timeout: int = 60,
                       extra_headers: Optional[Dict] = None,
                       **kwargs) -> Optional[requests.Response]:
    headers = _build_default_headers(base_url)
    if extra_headers:
        headers.update(extra_headers)
    if cookie_str:
        headers["Cookie"] = cookie_str
        csrf_token = extract_cookie_value(cookie_str, "csrf_token")
        if csrf_token:
            headers["X-Csrftoken"] = csrf_token
        # MSSW 平台的 CSRF token（cookie名和header名都是 x-csrf-token）
        mssw_csrf = extract_cookie_value(cookie_str, "x-csrf-token")
        if mssw_csrf:
            headers["x-csrf-token"] = mssw_csrf

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10, pool_maxsize=10, max_retries=0
    )
    session.mount('https://', adapter)
    session.mount('http://', adapter)

    for attempt in range(MAX_RETRIES):
        try:
            if method.upper() == "POST":
                resp = session.post(url, headers=headers, timeout=timeout,
                                    verify=False, **kwargs)
            else:
                resp = session.get(url, headers=headers, timeout=timeout,
                                   verify=False, **kwargs)
            return resp
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
                requests.exceptions.SSLError, requests.exceptions.RequestException) as e:
            attempt_num = attempt + 1
            log(f"请求失败 (尝试 {attempt_num}/{MAX_RETRIES}) - {e}", "WARNING")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                log(f"重试 {MAX_RETRIES} 次后仍然失败，返回 None", "ERROR")
                return None
    return None


def _parse_json(resp: requests.Response, api_name: str) -> dict:
    if resp is None:
        raise RuntimeError(f"{api_name}：请求失败（已重试 {MAX_RETRIES} 次）")
    try:
        return resp.json()
    except Exception:
        raise RuntimeError(
            f"{api_name}：响应不是JSON（状态码={resp.status_code}，可能Cookie已过期）"
        )


# ---------- 风险等级归一化 ----------

RISK_NORMALIZE = {
    "超危": "严重",
    "高危": "高",
    "中危": "中",
    "低危": "低",
}


def normalize_risk(level: str) -> str:
    """将各平台的风险等级统一为映射表使用的格式"""
    return RISK_NORMALIZE.get(level, level)


# ---------- 修复优先级计算 ----------

def calc_priority(risk_norm: str, is_internal: bool, is_exploitable: bool) -> str:
    """
    根据映射表计算修复优先级。
    risk_norm: 归一化后的风险等级（严重/高/中/低）
    is_internal: True=内网, False=外网
    is_exploitable: True=可利用, False=不可利用
    """
    inout = "内网" if is_internal else "外网"
    exp   = "可利用" if is_exploitable else "不可利用"

    TABLE: Dict[Tuple[str, str, str], str] = {
        ("严重", "内网", "可利用"):    "急需修复",
        ("严重", "内网", "不可利用"):  "尽快修复",
        ("严重", "外网", "可利用"):    "急需修复",
        ("严重", "外网", "不可利用"):  "急需修复",
        ("高",   "内网", "可利用"):    "急需修复",
        ("高",   "内网", "不可利用"):  "尽快修复",
        ("高",   "外网", "可利用"):    "急需修复",
        ("高",   "外网", "不可利用"):  "急需修复",
        ("中",   "内网", "可利用"):    "急需修复",
        ("中",   "内网", "不可利用"):  "尽快修复",
        ("中",   "外网", "可利用"):    "急需修复",
        ("中",   "外网", "不可利用"):  "尽快修复",
        ("低",   "内网", "可利用"):    "建议修复",
        ("低",   "内网", "不可利用"):  "建议修复",
        ("低",   "外网", "可利用"):    "建议修复",
        ("低",   "外网", "不可利用"):  "建议修复",
    }
    return TABLE.get((risk_norm, inout, exp), "建议修复")


# ---------- 通用：搜索客户结果匹配 ----------

def _pick_exact_match(customers: list, keyword: str):
    """从多个模糊搜索结果中优先选精确匹配。返回匹配项或 None"""
    if len(customers) == 1:
        return customers[0]
    exact = [c for c in customers
             if (c.get('company_name', '') or '').strip() == keyword.strip()
             or str(c.get('company_id', '')).strip() == keyword.strip()]
    return exact[0] if exact else None


def parse_date_to_ms(date_str: str, is_end: bool = False) -> int:
    """
    将日期字符串转为13位 UTC+8 毫秒时间戳。
    支持格式: '2016-01-01' 或 '2016年1月1日'
    is_end=False → 当天 00:00:00.000
    is_end=True  → 当天 23:59:59.999
    """
    date_str = date_str.replace('年', '-').replace('月', '-').replace('日', '').strip()
    dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
    dt = dt.replace(tzinfo=timezone(timedelta(hours=8)))
    if is_end:
        return int(dt.timestamp() * 1000) + 86399999
    return int(dt.timestamp() * 1000)


# ---------- 通用：接口0 搜索客户（MSSW customer_statistic） ----------

def search_customer_mssw(cookie_str: str, keyword: str) -> list:
    """文档接口1：MSSW 客户搜索，keyword 模糊匹配名称或ID"""
    url = f"{MSSW_BASE_URL}{EP_CUSTOMER_STATISTIC}"
    payload = {
        "order": "desc", "keyword": keyword, "customer_category": 1,
        "company_id": "", "offset": 0, "limit": 100,
    }
    resp = request_with_retry("POST", url, MSSW_BASE_URL, cookie_str, json=payload, timeout=660)
    data = _parse_json(resp, "MSSW客户搜索")
    if data.get('code') != 0:
        raise RuntimeError(f"MSSW客户搜索失败: {data.get('msg')}")
    return data['data']['list']


# ====================================================================
#  MSSW 平台接口调用（内外网合并导出）
# ====================================================================

def export_vuln_combined(cookie_str: str, company_id: str, time_range: list) -> str:
    """接口3：一次性导出内外网漏洞（返回 zip），返回 task_id"""
    url = f"{MSSW_BASE_URL}{EP_VULN_EXPORT}"
    payload = {
        "data_type": VULN_DATA_TYPE,
        "need_split": False,
        "params": {
            "company_id": company_id,
            "export_scope": "combined",
            "fixed_status": VULN_FIXED_STATUSES,
            "export_mode": "single_table",
            "scan_type": [1],
            "split": {"enabled": False},
            "list_filters": {"latest_time_range": time_range},
        },
    }
    resp = request_with_retry("POST", url, MSSW_BASE_URL, cookie_str, json=payload, timeout=660)
    data = _parse_json(resp, "MSSW漏洞导出")
    if data.get('code') != 0:
        raise RuntimeError(f"MSSW漏洞导出失败: {data.get('msg')}")
    task_id = data['data']['task_id']
    log(f"MSSW 漏洞导出任务 task_id={task_id}")
    return task_id


def poll_vuln_status(cookie_str: str, task_id: str) -> str:
    """接口2-2：轮询导出状态，返回下载相对 url"""
    url = f"{MSSW_BASE_URL}{EP_POLL}"
    payload = {"task_id_list": [task_id]}
    attempt = 0
    while True:
        attempt += 1
        resp = request_with_retry("POST", url, MSSW_BASE_URL, cookie_str, json=payload, timeout=660)
        data = _parse_json(resp, "MSSW漏洞轮询")
        if data.get('code') != 0:
            raise RuntimeError(f"MSSW漏洞轮询失败: {data.get('msg')}")

        rotation_status = data.get('data', {}).get('rotation_status')
        attachment_list = data.get('data', {}).get('attachment_list', [])
        log(f"  第{attempt}次轮询: rotation_status={rotation_status}")

        if rotation_status == 2:
            if attachment_list and attachment_list[0].get('status') == 'success':
                download_path = attachment_list[0].get('url', '')
                log(f"  导出完成，下载路径: {download_path}")
                return download_path
            raise RuntimeError(f"漏洞导出任务结束但附件异常: {attachment_list}")
        time.sleep(POLL_INTERVAL)


def download_vuln_zip(cookie_str: str, download_path: str, save_dir: str) -> str:
    """下载 MSSW 导出的漏洞 zip（内外网合并），返回本地文件路径"""
    url = f"{MSSW_BASE_URL}{download_path}"
    resp = request_with_retry("GET", url, MSSW_BASE_URL, cookie_str, stream=True)
    if resp is None:
        raise RuntimeError("MSSW 漏洞文件下载失败")

    filename = f"漏洞报告_{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
    filepath = os.path.join(save_dir, filename)
    total = 0
    with open(filepath, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                total += len(chunk)

    # 校验 zip 魔数 PK\x03\x04
    with open(filepath, 'rb') as f:
        magic = f.read(4)
    if magic != b'PK\x03\x04':
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read(500)
        raise RuntimeError(f"MSSW 下载不是有效zip（{total}字节），服务器响应: {content}")

    log(f"MSSW 漏洞文件已保存: {os.path.basename(filepath)} ({total / 1024:.1f} KB)")
    return filepath


# ====================================================================
#  zip 解压（复用 exposuer_report 的 GBK 修复逻辑）
# ====================================================================

def _extract_zip_fix_encoding(zip_path: str, extract_dir: str) -> None:
    """解压 zip，自动修复 Windows 下 GBK 编码的文件名乱码。"""
    import zipfile
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            if info.flag_bits & 0x800:
                fname = info.filename
            else:
                try:
                    fname = info.filename.encode('cp437').decode('gbk')
                except (UnicodeDecodeError, UnicodeEncodeError):
                    fname = info.filename
            target = os.path.join(extract_dir, fname)
            if fname.endswith('/') or fname.endswith('\\'):
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, 'wb') as dst:
                    dst.write(src.read())


def _copy_file(src: str, dst: str) -> None:
    """复制文件（覆盖已存在目标）。"""
    import shutil
    if os.path.abspath(src) == os.path.abspath(dst):
        return
    if os.path.exists(dst):
        os.remove(dst)
    shutil.copy2(src, dst)


# ====================================================================
#  Excel 处理
# ====================================================================


# ---------- MSSW 文件B 处理 ----------

# 说明：外网表（21列）缺少 资产类型/所属资产组/所属业务/资产责任人/资产重要性/资产管理状态
# 及 托管状态 —— col_map 找不到 → 自动填空；多余列（处置标签/来源平台/GPT检测 等）忽略。
C_FROM_MSSW: List[Tuple[str, str]] = [
    ("漏洞名称",      "漏洞名称"),
    # 修复优先级：直接用平台导出值（内网/外网表头均有该列）。
    # 原 calc_priority() 计算逻辑保留但不再调用 —— 待后期确认是否启用。
    ("修复优先级",    "修复优先级"),
    ("风险等级",      "风险等级"),
    ("漏洞类型",      "漏洞类型"),
    ("修复建议",      "修复建议"),
    ("风险描述",      "风险描述"),
    ("威胁标签",      "威胁标签"),
    ("数据源",        "数据源"),
    ("检测方式",      "检测方式"),
    ("CVE 编号",      "CVE 编号"),
    ("最近发现时间",  "最近发现时间"),
    ("首次发现时间",  "首次发现时间"),
    ("风险资产",      "风险资产"),
    ("资产类型",      "资产类型"),
    ("所属资产组",    "所属资产组"),
    ("所属业务",      "所属业务"),
    ("资产责任人",    "资产责任人"),
    ("资产重要性",    "资产重要性"),
    ("资产管理状态",  "资产管理状态"),
    ("托管状态",      "托管状态"),
    ("端口",          "端口"),
    ("url",           "url"),
    ("互联网暴露",    "互联网暴露"),
    ("举证信息",      "举证信息"),
    ("处置状态",      "处置状态"),
    ("数据来源",      "__SOURCE__"),  # 由 source 参数注入（内网/外网）
]


def process_mssw_file(file_b_path: str, source: str = "内网") -> List[dict]:
    """
    处理 MSSW 导出的漏洞文件（内网或外网）：
    - 映射为文件C 的统一格式（复用 C_FROM_MSSW；外网缺列自动填空）
    - 「数据来源」列由 source 参数注入（内网/外网，须与 generate_data.py 分组值一致）
    返回 list[dict]
    """
    wb = load_workbook(file_b_path, data_only=True)
    ws = wb.active
    # 数据在「4-全部漏洞清单」sheet（sheet1/2/3 为总览/闭环指引/急需修复）
    if "4-全部漏洞清单" in wb.sheetnames:
        ws = wb["4-全部漏洞清单"]
        log(f"  取数据 sheet: 「4-全部漏洞清单」")
    else:
        log(f"  未找到「4-全部漏洞清单」，回退用活动 sheet「{ws.title}」", "WARNING")

    col_map: Dict[str, int] = {}
    for col_idx, cell in enumerate(ws[1], start=1):
        if cell.value is not None:
            col_map[str(cell.value).strip()] = col_idx

    log(f"MSSW 文件B 列数: {len(col_map)}, 数据行数: {ws.max_row - 1}")

    # 确认必要列存在
    needed = ["漏洞名称", "风险等级", "威胁标签"]
    for key in needed:
        if key not in col_map:
            log(f"  MSSW 文件缺少必要列: {key}，实际列: {list(col_map.keys())}", "WARNING")
            raise RuntimeError(f"MSSW 文件B 缺少必要列「{key}」")

    rows_out: List[dict] = []

    for row_idx in range(2, ws.max_row + 1):
        row_data = {}

        for c_col, source_col in C_FROM_MSSW:
            if source_col == "__SOURCE__":
                # 数据来源：由参数注入（内网/外网）
                row_data[c_col] = source

            elif source_col == "__FIXED_" or (source_col or "").startswith("__FIXED_"):
                # 固定值（保留兼容：__FIXED_内网 → "内网"）
                row_data[c_col] = source_col.replace("__FIXED_", "")

            else:
                src_col = col_map.get(source_col)
                if src_col is not None:
                    val = ws.cell(row=row_idx, column=src_col).value
                    val = val if val is not None else ""
                    if c_col in ("最近发现时间", "首次发现时间"):
                        val = _fmt_minute(val)
                    row_data[c_col] = val
                else:
                    # 列不存在（如外网缺 资产类型/资产重要性 等 6 列）→ 填空
                    log(f"  第{row_idx}行: 列「{source_col}」不存在，赋空值", "WARNING")
                    row_data[c_col] = ""

        rows_out.append(row_data)

    wb.close()
    log(f"MSSW 处理后共 {len(rows_out)} 行")
    return rows_out


def extract_mssw_header_styles(file_b_path: str) -> Tuple[Dict[str, object], object]:
    """
    从 MSSW 导出文件第 1 行表头提取样式信息。
    返回:
      header_styles: {列名 → {'font','fill','border','alignment','number_format'}}
      ref_style:    参考样式（取第 1 个有样式的表头单元格），用于额外字段列回退
    异常或空表头时返回 ({}, None)，不抛错。

    注意：不保存 cell._style（那是工作簿内部索引，不可跨簿复制），
    而是保存 Font/Fill/Border/Alignment 等可移植的样式属性对象。
    """
    try:
        wb = load_workbook(file_b_path, data_only=True)
    except Exception as e:
        log(f"  提取MSSW表头样式失败（文件读取失败）: {e}", "WARNING")
        return {}, None

    try:
        ws = wb.active
        header_styles: Dict[str, object] = {}
        ref_style: object = None

        for cell in ws[1]:
            if cell.value is None:
                continue
            if not cell.has_style:          # 跳过无显式样式的列，避免默认样式污染 ref_style
                continue
            col_name = str(cell.value).strip()
            # 保存样式属性对象（可跨工作簿使用），而非 _style（工作簿内部索引）
            style_props = {
                "font":          copy(cell.font),
                "fill":          copy(cell.fill),
                "border":        copy(cell.border),
                "alignment":     copy(cell.alignment),
                "number_format": cell.number_format,  # 字符串不可变，无需 copy
            }
            header_styles[col_name] = style_props
            if ref_style is None:
                ref_style = dict(style_props)       # 浅拷贝 dict，避免与第一列共享同一对象

        if not header_styles:
            log("  MSSW 表头为空或无样式，最终 Excel 表头将使用默认样式", "WARNING")

        return header_styles, ref_style
    except Exception as e:
        log(f"  提取MSSW表头样式失败（遍历异常）: {e}", "WARNING")
        return {}, None
    finally:
        wb.close()


# ====================================================================
#  主流程
# ====================================================================

# def _on_script_timeout():
#     log(f"错误：脚本执行超时（超过 {SCRIPT_TIMEOUT // 60} 分钟），强制退出", "ERROR")
#     os._exit(1)


def main():
    global TEMP_DIR, OUTPUT_FILE
    # _timer = threading.Timer(SCRIPT_TIMEOUT, _on_script_timeout)
    # _timer.daemon = True
    # _timer.start()

    parser = argparse.ArgumentParser(
        description='漏洞清单生成工具（MSSW 内外网合并导出）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            '示例:\n'
            '  python vuln_report.py 深圳市口袋网络\n'
            '  python vuln_report.py 35690473\n'
            '  python vuln_report.py 客户名 --start-time 2025-01-01 --end-time 2025-03-31\n'
            '  python vuln_report.py --zip 漏洞报告.zip  （离线：跳过接口，直接处理本地zip）'
        )
    )
    parser.add_argument('keyword', nargs='?', default=None,
                        help='客户ID或客户名称（支持模糊匹配）')
    parser.add_argument('--zip', default=None,
                        help='（可选，离线调试）跳过接口调用，直接处理本地已导出的 zip')
    parser.add_argument('--output-file', default=None,
                        help='（可选）临时表输出路径，默认脚本顶部 OUTPUT_FILE')
    parser.add_argument('--temp-dir', default=None,
                        help='（可选）临时目录，默认脚本顶部 TEMP_DIR')
    parser.add_argument('--start-time', default=None,
                        help='（可选）过滤开始日期，如 2025-01-01')
    parser.add_argument('--end-time', default=None,
                        help='（可选）过滤结束日期，如 2025-03-31')
    args = parser.parse_args()

    if args.temp_dir:
        TEMP_DIR = args.temp_dir
    if args.output_file:
        OUTPUT_FILE = args.output_file

    if not args.keyword and not args.zip:
        sys.exit("错误：请提供客户ID或客户名称关键词\n示例: python vuln_report.py 35690473")

    os.makedirs(TEMP_DIR, exist_ok=True)

    # 时间过滤：传入则过滤，不传则 []（全部数据）
    if args.start_time and args.end_time:
        start_ms = parse_date_to_ms(args.start_time, is_end=False)
        end_ms   = parse_date_to_ms(args.end_time,   is_end=True)
        time_range = [start_ms, end_ms]
        log(f"时间过滤: {args.start_time} → {start_ms}  /  {args.end_time} → {end_ms}")
    else:
        time_range = []

    # ==================== 1~4. 取数（联网）或离线 zip ====================
    if args.zip:
        # 离线：跳过所有接口，直接用本地 zip
        log("=" * 50)
        log(f"离线模式：直接处理本地 zip → {args.zip}")
        zip_path = args.zip
        if not os.path.exists(zip_path):
            sys.exit(f"错误：zip 文件不存在 → {zip_path}")
    else:
        # 步骤1：加载 Cookie
        log("=" * 50)
        log("步骤1：加载 Cookie")
        if not os.path.exists(MSSW_COOKIES_FILE):
            sys.exit(f"错误：MSSW cookies文件不存在 → {MSSW_COOKIES_FILE}")
        mssw_cookie = read_cookies_as_string(MSSW_COOKIES_FILE)
        if not mssw_cookie:
            sys.exit(f"错误：MSSW cookies解析结果为空 → {MSSW_COOKIES_FILE}")
        log(f"  MSSW Cookie: {MSSW_COOKIES_FILE}")

        # 步骤2：搜索客户（customer_statistic）
        log("=" * 50)
        log("步骤2：搜索客户")
        log(f"  MSSW 搜索客户「{args.keyword}」...")
        customers = search_customer_mssw(mssw_cookie, args.keyword)
        if not customers:
            sys.exit(f"错误：MSSW 未找到匹配客户，请检查关键词「{args.keyword}」")
        if len(customers) > 1:
            exact = _pick_exact_match(customers, args.keyword)
            if exact:
                customers = [exact]
            else:
                log(f"错误：MSSW 找到 {len(customers)} 个匹配客户，请使用更精确的关键词：", "ERROR")
                for c in customers:
                    name = c.get('company_name') or c.get('pms_customer_name', '未知')
                    print(f"  ID={c['company_id']}  名称={name}")
                sys.exit(1)
        company_id = customers[0]['company_id']
        company_name = customers[0].get('company_name') or customers[0].get('pms_customer_name', '未知')
        log(f"  确认客户: {company_name}（ID={company_id}）")

        # 步骤3：触发导出（接口3）
        log("=" * 50)
        log("步骤3：触发漏洞导出（内外网合并，接口3）")
        task_id = export_vuln_combined(mssw_cookie, company_id, time_range)

        # 步骤4：轮询 + 下载 zip
        log("=" * 50)
        log("步骤4：轮询状态并下载 zip")
        download_path = poll_vuln_status(mssw_cookie, task_id)
        zip_path = download_vuln_zip(mssw_cookie, download_path, TEMP_DIR)

    # ==================== 5. 解压 zip ====================
    log("=" * 50)
    log("步骤5：解压 zip（修复 GBK 文件名乱码）")
    extract_dir = os.path.join(TEMP_DIR, "vuln_extract")
    if os.path.exists(extract_dir):
        import shutil
        shutil.rmtree(extract_dir)
    os.makedirs(extract_dir, exist_ok=True)
    _extract_zip_fix_encoding(zip_path, extract_dir)

    # 收集解压出的 xlsx，按文件名判内外网
    xlsx_files = []
    for root, _dirs, files in os.walk(extract_dir):
        for fn in files:
            if fn.lower().endswith(".xlsx") and not fn.startswith("~$"):
                xlsx_files.append(os.path.join(root, fn))
    if not xlsx_files:
        sys.exit(f"错误：zip 内未找到 xlsx 文件 → {extract_dir}")
    log(f"  解压出 {len(xlsx_files)} 个 xlsx: {[os.path.basename(p) for p in xlsx_files]}")

    inner_path = None   # 内网
    outer_path = None   # 外网（互联网）
    for p in xlsx_files:
        base = os.path.basename(p)
        if "内网" in base:
            inner_path = p
        elif "互联网" in base or "外网" in base:
            outer_path = p
    if not inner_path:
        log("  警告：未识别出「内网」漏洞文件", "WARNING")
    if not outer_path:
        log("  警告：未识别出「互联网/外网」漏洞文件", "WARNING")

    # ==================== 6. 支线①：交付物（平台原样，仅改名） ====================
    log("=" * 50)
    log("步骤6：生成交付物（两个平台原样 excel，平铺在 temp-dir）")
    if inner_path:
        dst_inner = os.path.join(TEMP_DIR, NAME_INTRANET)
        _copy_file(inner_path, dst_inner)
        log(f"  交付(内网): {NAME_INTRANET}")
    if outer_path:
        dst_outer = os.path.join(TEMP_DIR, NAME_INTERNET)
        _copy_file(outer_path, dst_outer)
        log(f"  交付(互联网): {NAME_INTERNET}")

    # ==================== 7. 支线②：整合临时表（供计算） ====================
    log("=" * 50)
    log("步骤7：整合临时表（单 sheet「漏洞」+ 数据来源列）")
    inner_data = process_mssw_file(inner_path, source="内网") if inner_path else []
    outer_data = process_mssw_file(outer_path, source="外网") if outer_path else []
    log(f"  内网 {len(inner_data)} 行 / 外网 {len(outer_data)} 行")

    # 临时表列头（写完后删「托管状态」）
    C_HEADERS = [
        "漏洞名称", "修复优先级", "风险等级", "漏洞类型", "修复建议",
        "风险描述", "威胁标签", "数据源", "检测方式", "CVE 编号",
        "最近发现时间", "首次发现时间", "风险资产", "资产类型",
        "所属资产组", "所属业务", "资产责任人", "资产重要性",
        "资产管理状态", "托管状态", "端口", "url", "互联网暴露", "举证信息",
        "处置状态", "数据来源",
    ]

    wb_out = openpyxl.Workbook()
    ws_out = wb_out.active
    ws_out.title = "漏洞"

    # 表头样式（优先用内网文件的表头样式）
    header_styles: Dict[str, object] = {}
    ref_style: object = None
    style_src = inner_path or outer_path
    if style_src and os.path.exists(style_src):
        log("  提取表头样式...")
        header_styles, ref_style = extract_mssw_header_styles(style_src)
        log(f"  已提取 {len(header_styles)} 个列样式，参考样式={'有' if ref_style else '无'}")

    for ci, header in enumerate(C_HEADERS, start=1):
        cell = ws_out.cell(row=1, column=ci, value=header)
        style_props = header_styles.get(header) or ref_style
        if style_props is not None:
            try:
                cell.font          = copy(style_props["font"])
                cell.fill          = copy(style_props["fill"])
                cell.border        = copy(style_props["border"])
                cell.alignment     = copy(style_props["alignment"])
                cell.number_format = style_props["number_format"]
            except Exception as e:
                log(f"  应用表头样式失败 列={header}: {e}", "WARNING")

    # 内网在前，外网在后
    row_num = 2
    for record in inner_data + outer_data:
        for ci, header in enumerate(C_HEADERS, start=1):
            ws_out.cell(row=row_num, column=ci, value=record.get(header, ""))
        row_num += 1

    # 删除「托管状态」列（最终 25 列）
    DROP_COLUMNS = {"托管状态"}
    drop_indices = sorted(
        [ci for ci, header in enumerate(C_HEADERS, start=1) if header in DROP_COLUMNS],
        reverse=True
    )
    if drop_indices:
        for idx in drop_indices:
            ws_out.delete_cols(idx, 1)
        log(f"  已删除列: {DROP_COLUMNS}（临时表 {len(C_HEADERS) - len(drop_indices)} 列）")

    wb_out.save(OUTPUT_FILE)
    wb_out.close()

    total_rows = len(inner_data) + len(outer_data)
    log("完成！")
    log(f"  内网数据: {len(inner_data)} 行")
    log(f"  外网数据: {len(outer_data)} 行")
    log(f"  合计: {total_rows} 行")
    log(f"  临时表(计算用，不进交付): {OUTPUT_FILE}")
    log(f"  交付(内网): {os.path.join(TEMP_DIR, NAME_INTRANET)}")
    log(f"  交付(互联网): {os.path.join(TEMP_DIR, NAME_INTERNET)}")


if __name__ == '__main__':
    main()

# ============================================================
#  使用说明
# ============================================================
#
#  python vuln_report.py <客户ID或关键词> [选项]
#
#  必填参数:
#     keyword                 客户ID或客户名称（支持模糊匹配）
#
#  可选参数:
#     --zip <path>             离线调试：跳过接口，直接处理本地已导出的 zip
#     --output-file <path>     临时表输出路径（默认顶部 OUTPUT_FILE）
#     --temp-dir <path>        临时目录（默认顶部 TEMP_DIR）
#     --start-time <日期>      过滤开始日期，如 2025-01-01
#     --end-time   <日期>      过滤结束日期，如 2025-03-31
#
#  前置条件:
#     1. MSSW Cookie 保存在 mssw_cookies.txt
#     2. 文件路径在脚本顶部【配置】段修改 TEMP_DIR / OUTPUT_FILE
#
#  示例:
#     python vuln_report.py 35690473
#     python vuln_report.py 客户名 --start-time 2025-01-01 --end-time 2025-03-31
#     python vuln_report.py --zip 漏洞报告.zip
#
#  产物（3 个文件）:
#     1) 临时表「漏洞清单.xlsx」  → 单 sheet「漏洞」+ 数据来源列，供计算，**不进交付**
#     2) 交付「漏洞清单（内网）.xlsx」    → 平台原样 30 列（放 temp-dir，供 JS 归档）
#     3) 交付「漏洞清单（互联网）.xlsx」  → 平台原样 21 列（放 temp-dir，供 JS 归档）
#
#  过滤逻辑:
#     MSSW 接口3: fixed_status=[0,1,2,3,4,5,6]，scan_type=[1,2]
#                 list_filters.latest_time_range 可选时间过滤
# ============================================================
