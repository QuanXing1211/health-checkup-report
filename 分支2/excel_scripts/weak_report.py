#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
弱口令清单生成工具
内外网弱口令数据均从 MSSW 平台获取：
  - 内网：vul_manage 导出接口（接口2/3）
  - 外网：internet_vul_manage 导出接口（接口4/5，对应接口文档 §2.13/§2.14）

产出（3 条）：
  1) 临时表 OUTPUT_FILE（内网+外网合并，含「数据来源」列）—— 仅供报告计算，不进交付
  2) 交付 TEMP_DIR/弱口令清单（内网）.xlsx     —— 内网平台原样
  3) 交付 TEMP_DIR/弱口令清单（互联网）.xlsx   —— 外网平台原样

用法: python weak_report.py <客户ID或客户名称关键词>
示例: python weak_report.py 深圳市口袋网络
      python weak_report.py 35690473
"""

import os
import sys
import time
import argparse
import requests
from copy import copy
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import openpyxl
from openpyxl import load_workbook


# ==================== 配置（按需修改） ====================

# --- 通用 ---
TEMP_DIR     = r"C:\Users\User\Downloads\temp_report"
OUTPUT_FILE  = r"C:\Users\User\Downloads\弱口令清单.xlsx"

MAX_RETRIES     = 3     # 最大重试次数
RETRY_DELAY     = 3     # 重试等待时间（秒）

# --- 交付文件名（平铺在 TEMP_DIR） ---
NAME_INTRANET = "弱口令清单（内网）.xlsx"       # 交付用（内网，平台原样）
NAME_INTERNET = "弱口令清单（互联网）.xlsx"     # 交付用（外网，平台原样）

# --- MSSW 平台（内外网均走此平台） ---
MSSW_BASE_URL      = "https://mssw.sangfor.com.cn"
MSSW_COOKIES_FILE   = r"C:\Users\User\Downloads\mssw_cookies.txt"

# 过滤处置状态：[待处置=0, 处置中=1]（内外网一致）
MSSW_FIXED_STATUSES = [0, 1]

# ==========================================================


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


# ---------- 通用：搜索客户结果匹配 ----------

def _pick_exact_match(customers: list, keyword: str):
    """从多个模糊搜索结果中优先选精确匹配。返回匹配项或 None"""
    if len(customers) == 1:
        return customers[0]
    exact = [c for c in customers
             if (c.get('company_name', '') or '').strip() == keyword.strip()
             or (c.get('pms_customer_name', '') or '').strip() == keyword.strip()
             or str(c.get('company_id', '')).strip() == keyword.strip()]
    return exact[0] if exact else None


# ====================================================================
#  MSSW 平台接口调用
# ====================================================================

# ---------- 接口1：搜索客户 ----------

def search_customer(cookie_str: str, keyword: str) -> list:
    """接口1：MSSW 平台客户搜索，根据关键词（名称或ID）模糊搜索"""
    url = f"{MSSW_BASE_URL}/gateway/customer-mgr-service/order/v1/user?_method=GET"
    key_field = "company_id_keyword" if keyword.isdigit() else "company_name_keyword"
    payload = {
        "my_customer": 0,
        key_field: keyword,
        "offset": 0, "limit": 100,
    }
    resp = request_with_retry("POST", url, MSSW_BASE_URL, cookie_str, json=payload, timeout=120)
    data = _parse_json(resp, "接口1（搜索客户）")
    if data.get('code') != 0:
        raise RuntimeError(f"接口1（搜索客户）失败: {data.get('msg')}")
    return data['data']['list']


# ---------- 接口2：内网弱口令导出 ----------

def export_weak_pwd_intranet(cookie_str: str, company_id: str, latest_time_range: list) -> str:
    """接口2：内网弱口令导出（MSSW vul_manage），返回 file_name"""
    url = f"{MSSW_BASE_URL}/order/v1/vul_manage/vul_risk_export"
    payload = {
        "asset_ip": {"op": "=", "val": ""},
        "asset_manager": {"op": "=", "val": ""},
        "asset_status": [],
        "asset_tags": [],
        "asset_type": "all",
        "attack_state": [],
        "branch_ids": [],
        "disposal_tag": [],
        "exposure": [],
        "fix_priority": [],
        "fixed_status": MSSW_FIXED_STATUSES,
        "group_ids": [],
        "keyword": "",
        "keyword_all": "",
        "magnitude": [],
        "name": {"op": "=", "val": ""},
        "order_status": [],
        "platform_ids": [],
        "platform_filter": [],
        "retest_status": [],
        "source_device": [],
        "data_type": ["weak_pwd"],
        "whitelisted_status": [],
        "latest_time_range": latest_time_range,
        "is_show": 1, # 明文导出
        "custom_headers": {
            "asset_info": [
                {"disabled": True,  "key": "asset",                "label": "风险资产",      "selected": True},
                {"disabled": False, "key": "asset_type",           "label": "资产类型",      "selected": True},
                {"disabled": False, "key": "business_name",        "label": "所属资产组",    "selected": True},
                {"disabled": False, "key": "group_name",           "label": "所属业务",      "selected": True},
                {"disabled": False, "key": "manager",              "label": "资产责任人",    "selected": True},
                {"disabled": False, "key": "magnitude",            "label": "资产重要性",    "selected": True},
                {"disabled": True,  "key": "port",                 "label": "端口",          "selected": True},
                {"disabled": False, "key": "exposure",             "label": "互联网暴露",    "selected": True},
                {"disabled": False, "key": "evidence_information", "label": "举证信息",      "selected": True},
                {"disabled": False, "key": "asset_status",         "label": "资产管理状态",  "selected": True},
                {"disabled": False, "key": "platform_name",        "label": "来源平台",      "selected": True},
                {"disabled": False, "key": "managed_level",        "label": "托管状态",      "selected": True},
            ],
            "base_info": [
                {"disabled": True,  "key": "name",              "label": "弱密码名称",    "selected": True},
                {"disabled": True,  "key": "fix_priority_level","label": "修复优先级",    "selected": True},
                {"disabled": True,  "key": "risk_Level",        "label": "风险等级",      "selected": True},
                {"disabled": True,  "key": "user",              "label": "账号",          "selected": True},
                {"disabled": True,  "key": "pwd",               "label": "密码",          "selected": True},
                {"disabled": True,  "key": "url",               "label": "url",           "selected": True},
                {"disabled": False, "key": "refer",             "label": "refer",         "selected": True},
                {"disabled": False, "key": "process_path",      "label": "进程路径",      "selected": True},
                {"disabled": False, "key": "src_type",          "label": "数据源",        "selected": True},
                {"disabled": False, "key": "last_time",         "label": "最近发现时间",  "selected": True},
                {"disabled": False, "key": "found_time",        "label": "首次发现时间",  "selected": True},
                {"disabled": False, "key": "is_gpt",            "label": "GPT检测",       "selected": True},
            ],
            "disposal_info": [
                {"disabled": False, "key": "whitelisted_status","label": "加白状态",      "selected": True},
                {"disabled": False, "key": "fixed_status",      "label": "处置状态",      "selected": True},
                {"disabled": False, "key": "fixed_tag",         "label": "处置标签",      "selected": True},
                {"disabled": False, "key": "order_progress",    "label": "最新工单进展",  "selected": True},
                {"disabled": False, "key": "retest_status",     "label": "验证状态",      "selected": True},
            ],
        },
        "header_id": "week_pass_1",
        "is_all": False,
        "multiple_choice": [],
        "exclude_multiple_choice": [],
    }
    extra_hdrs = {"X-MSSW-Company-Id": company_id} if company_id else None
    resp = request_with_retry("POST", url, MSSW_BASE_URL, cookie_str,
                               json=payload, timeout=660, extra_headers=extra_hdrs)
    data = _parse_json(resp, "接口2（内网弱口令导出）")
    if data.get('code') != 0:
        raise RuntimeError(f"接口2失败: {data.get('message') or data.get('msg')}")
    file_name = data['data']['file_name']
    log(f"内网弱口令导出文件名: {file_name}")
    return file_name


# ---------- 接口3：内网文件下载 ----------

def download_weak_pwd_intranet(cookie_str: str, company_id: str, file_name: str, save_dir: str) -> str:
    """接口3：下载内网弱口令导出文件，返回本地文件路径"""
    url = f"{MSSW_BASE_URL}/order/v1/vul_manage/download_file?file={file_name}"
    extra_hdrs = {"X-MSSW-Company-Id": company_id} if company_id else None
    resp = request_with_retry("GET", url, MSSW_BASE_URL, cookie_str, stream=True, timeout=120, extra_headers=extra_hdrs)
    if resp is None:
        raise RuntimeError("内网弱口令文件下载失败")

    filepath = os.path.join(save_dir, file_name)
    total = 0
    try:
        with open(filepath, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    total += len(chunk)
    finally:
        resp.close()

    # 检查是否为有效xlsx
    with open(filepath, 'rb') as f:
        magic = f.read(4)
    if magic != b'PK\x03\x04':
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read(500)
        raise RuntimeError(f"内网下载文件不是有效xlsx（{total}字节），服务器响应: {content}")

    log(f"内网弱口令文件已保存: {os.path.basename(filepath)} ({total / 1024:.1f} KB)")
    return filepath


# ---------- 接口4：外网弱口令导出（对应接口文档 §2.13） ----------

# 外网弱口令模板 13 列的 custom_headers（文档扁平 object[] 格式，field 名取自文档 §2.16「表头 → 字段映射」）
INTERNET_WEAK_HEADER_FIELDS: List[Dict] = [
    {"field": "name",           "title": "弱密码名称", "required": True},
    {"field": "fix_priority",   "title": "修复优先级", "required": True},
    {"field": "weak_user",      "title": "账号",       "required": True},
    {"field": "weak_password",  "title": "密码",       "required": True},
    # 注意：「管理员账号」在文档 §2.16 映射表中无对应字段，admin_user 为占位，待联调校正
    {"field": "admin_user",     "title": "管理员账号", "required": True},
    {"field": "url",            "title": "url",        "required": True},
    {"field": "port",           "title": "端口",       "required": True},
    {"field": "last_time",      "title": "最近发现时间", "required": True},
    {"field": "first_time",     "title": "首次发现时间", "required": True},
    {"field": "source_device",  "title": "数据源",     "required": True},
    {"field": "ips",            "title": "风险资产",   "required": True},
    {"field": "fixed_status",   "title": "处置状态",   "required": True},
    {"field": "disposal_tag",   "title": "处置标签",   "required": True},
]


def export_weak_pwd_internet(cookie_str: str, company_id: str, latest_time_range: list) -> str:
    """接口4：外网弱口令导出（MSSW internet_vul_manage，对应文档 §2.13），返回 file_name"""
    url = f"{MSSW_BASE_URL}/order/v1/internet_vul_manage/asset_weak_export"
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    payload = {
        "data_type": ["weak_pwd"],
        "fixed_status": MSSW_FIXED_STATUSES,
        "latest_time_range": latest_time_range,
        "custom_headers": INTERNET_WEAK_HEADER_FIELDS,
        "file_name": f"weak_pwd_export_{ts}.xlsx",
    }
    extra_hdrs = {"X-MSSW-Company-Id": company_id} if company_id else None
    resp = request_with_retry("POST", url, MSSW_BASE_URL, cookie_str,
                               json=payload, timeout=660, extra_headers=extra_hdrs)
    data = _parse_json(resp, "接口4（外网弱口令导出）")
    if data.get('code') != 0:
        raise RuntimeError(f"接口4失败: {data.get('message') or data.get('msg')}")
    resp_data = data.get('data', {}) or {}
    if resp_data.get('over_status'):
        log(f"  警告：外网弱口令导出超上限被截断"
            f"（total={resp_data.get('total')}, max_num={resp_data.get('max_num')}），结果可能不完整", "WARNING")
    file_name = resp_data.get('file_name', '')
    if not file_name:
        raise RuntimeError("接口4未返回 file_name")
    log(f"外网弱口令导出文件名: {file_name}")
    return file_name


# ---------- 接口5：外网文件下载（对应接口文档 §2.14） ----------

def download_weak_pwd_internet(cookie_str: str, company_id: str, file_name: str, save_dir: str) -> str:
    """接口5：下载外网弱口令导出文件（MSSW internet_vul_manage，对应文档 §2.14），返回本地文件路径"""
    url = f"{MSSW_BASE_URL}/order/v1/internet_vul_manage/download_file?file_name={file_name}"
    extra_hdrs = {"X-MSSW-Company-Id": company_id} if company_id else None
    resp = request_with_retry("GET", url, MSSW_BASE_URL, cookie_str, stream=True, timeout=120, extra_headers=extra_hdrs)
    if resp is None:
        raise RuntimeError("外网弱口令文件下载失败")

    filepath = os.path.join(save_dir, file_name)
    total = 0
    try:
        with open(filepath, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    total += len(chunk)
    finally:
        resp.close()

    # 检查是否为有效xlsx
    with open(filepath, 'rb') as f:
        magic = f.read(4)
    if magic != b'PK\x03\x04':
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read(500)
        raise RuntimeError(f"外网下载文件不是有效xlsx（{total}字节），服务器响应: {content}")

    log(f"外网弱口令文件已保存: {os.path.basename(filepath)} ({total / 1024:.1f} KB)")
    return filepath


# ====================================================================
#  Excel 处理
# ====================================================================

def _copy_file(src: str, dst: str) -> None:
    """复制文件（覆盖已存在目标）。"""
    import shutil
    if os.path.abspath(src) == os.path.abspath(dst):
        return
    if os.path.exists(dst):
        os.remove(dst)
    shutil.copy2(src, dst)


# 临时表固定列头（从左到右）；写完后删「托管状态」
C_HEADERS = [
    "弱密码名称", "账号", "密码", "url",
    "数据源", "最近发现时间", "首次发现时间", "风险资产",
    "资产类型", "所属资产组", "所属业务", "资产责任人",
    "资产重要性", "资产管理状态", "托管状态", "端口", "refer",
    "互联网暴露", "举证信息", "加白状态", "处置状态", "数据来源",
]


def process_mssw_file(file_b_path: str, source: str = "内网") -> List[dict]:
    """
    处理 MSSW 导出的弱口令文件（内网或外网）：
    按临时表列头 C_HEADERS 从导出文件中提取同名字段，缺失列填空。
    - 「数据来源」列由 source 参数注入（内网/外网，须与 generate_data.py 分组值一致）
    返回 list[dict]
    """
    wb = load_workbook(file_b_path, data_only=True)
    try:
        ws = wb.active

        col_map: Dict[str, int] = {}
        for col_idx, cell in enumerate(ws[1], start=1):
            if cell.value is not None:
                col_map[str(cell.value).strip()] = col_idx

        log(f"MSSW 文件列数: {len(col_map)}, 数据行数: {ws.max_row - 1}")
        log(f"  列名: {list(col_map.keys())}")

        rows_out: List[dict] = []

        for row_idx in range(2, ws.max_row + 1):
            row_data = {}
            for header in C_HEADERS:
                src_col = col_map.get(header)
                if src_col is not None:
                    val = ws.cell(row=row_idx, column=src_col).value
                    row_data[header] = val if val is not None else ""
                else:
                    # 外网模板缺 资产类型/所属资产组/... 等列 → 填空
                    row_data[header] = ""
            row_data["数据来源"] = source
            # 时间字段统一到分钟精度
            for time_col in ("最近发现时间", "首次发现时间"):
                row_data[time_col] = _fmt_minute(row_data.get(time_col))
            rows_out.append(row_data)
    finally:
        wb.close()

    log(f"MSSW 处理后共 {len(rows_out)} 行（数据来源={source}）")
    return rows_out


def extract_mssw_header_styles(file_b_path: str) -> Tuple[Dict[str, object], object]:
    """
    从 MSSW 导出文件第 1 行表头提取样式信息。
    返回:
      header_styles: {列名 → {'font','fill','border','alignment','number_format'}}
      ref_style:    参考样式（取第 1 个有显式样式的表头单元格），用于额外字段列回退
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

def main():
    global TEMP_DIR, OUTPUT_FILE

    parser = argparse.ArgumentParser(
        description='弱口令清单生成工具（MSSW 内外网分别导出）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            '示例:\n'
            '  python weak_report.py 深圳市口袋网络\n'
            '  python weak_report.py 35690473\n'
            '  python weak_report.py 客户名 --start-time 2025-01-01 --end-time 2025-03-31'
        )
    )
    parser.add_argument('keyword', nargs='?', default=None,
                        help='客户ID或客户名称（支持模糊匹配）')
    parser.add_argument('--output-file', default=None,
                        help='（可选）临时表输出路径，默认脚本顶部 OUTPUT_FILE')
    parser.add_argument('--temp-dir', default=None,
                        help='（可选）临时目录，默认脚本顶部 TEMP_DIR')
    parser.add_argument('--start-time', default=None,
                        help='（可选）过滤开始日期，如 2025-01-01 或 2025年1月1日')
    parser.add_argument('--end-time', default=None,
                        help='（可选）过滤结束日期，如 2025-03-31 或 2025年3月31日')
    args = parser.parse_args()

    if args.temp_dir:
        TEMP_DIR = args.temp_dir
    if args.output_file:
        OUTPUT_FILE = args.output_file

    if not args.keyword:
        sys.exit("错误：请提供客户ID或客户名称关键词\n示例: python weak_report.py 35690473")

    os.makedirs(TEMP_DIR, exist_ok=True)

    # 时间过滤：传入则过滤，不传则 []（全部数据）
    if args.start_time and args.end_time:
        start_ms = parse_date_to_ms(args.start_time, is_end=False)
        end_ms   = parse_date_to_ms(args.end_time,   is_end=True)
        time_range = [start_ms, end_ms]
        log(f"时间过滤: {args.start_time} → {start_ms}  /  {args.end_time} → {end_ms}")
    else:
        time_range = []

    # ==================== 1. 加载 Cookie ====================
    log("=" * 50)
    log("步骤1：加载 Cookie")
    if not os.path.exists(MSSW_COOKIES_FILE):
        sys.exit(f"错误：MSSW cookies文件不存在 → {MSSW_COOKIES_FILE}")
    mssw_cookie = read_cookies_as_string(MSSW_COOKIES_FILE)
    if not mssw_cookie:
        sys.exit(f"错误：MSSW cookies解析结果为空 → {MSSW_COOKIES_FILE}")
    log(f"  MSSW Cookie: {MSSW_COOKIES_FILE}")

    # ==================== 2. 搜索客户（接口1） ====================
    log("=" * 50)
    log("步骤2：搜索客户（接口1）")
    log(f"  MSSW 搜索客户「{args.keyword}」...")
    customers = search_customer(mssw_cookie, args.keyword)
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

    # ==================== 3. 内网数据（接口2 → 接口3） ====================
    log("=" * 50)
    log("步骤3：内网弱口令数据（接口2 导出 → 接口3 下载）")
    file_intranet_name = export_weak_pwd_intranet(mssw_cookie, company_id, time_range)
    file_intranet = download_weak_pwd_intranet(mssw_cookie, company_id, file_intranet_name, TEMP_DIR)
    log(f"  内网文件: {os.path.basename(file_intranet)}")

    # ==================== 4. 外网数据（接口4 → 接口5） ====================
    log("=" * 50)
    log("步骤4：外网弱口令数据（接口4 导出 → 接口5 下载）")
    file_internet_name = export_weak_pwd_internet(mssw_cookie, company_id, time_range)
    file_internet = download_weak_pwd_internet(mssw_cookie, company_id, file_internet_name, TEMP_DIR)
    log(f"  外网文件: {os.path.basename(file_internet)}")

    # ==================== 5. 支线①：交付物（平台原样，仅改名） ====================
    log("=" * 50)
    log("步骤5：生成交付物（两个平台原样 excel，平铺在 temp-dir）")
    dst_intranet = os.path.join(TEMP_DIR, NAME_INTRANET)
    _copy_file(file_intranet, dst_intranet)
    log(f"  交付(内网): {NAME_INTRANET}")

    dst_internet = os.path.join(TEMP_DIR, NAME_INTERNET)
    _copy_file(file_internet, dst_internet)
    log(f"  交付(互联网): {NAME_INTERNET}")

    # ==================== 6. 支线②：整合临时表（供计算） ====================
    log("=" * 50)
    log("步骤6：整合临时表（单 sheet「弱口令」+ 数据来源列）")
    intranet_data = process_mssw_file(file_intranet, source="内网")
    internet_data = process_mssw_file(file_internet, source="外网")
    log(f"  内网 {len(intranet_data)} 行 / 外网 {len(internet_data)} 行")

    wb_out = openpyxl.Workbook()
    ws_out = wb_out.active
    ws_out.title = "弱口令"

    # 表头样式（优先用内网文件的表头样式）
    header_styles: Dict[str, object] = {}
    ref_style: object = None
    style_src = file_intranet or file_internet
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
    for record in intranet_data + internet_data:
        for ci, header in enumerate(C_HEADERS, start=1):
            ws_out.cell(row=row_num, column=ci, value=record.get(header, ""))
        row_num += 1

    # 删除「托管状态」列（临时表不含此字段）
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

    total_rows = len(intranet_data) + len(internet_data)
    log("完成！")
    log(f"  内网数据: {len(intranet_data)} 行")
    log(f"  外网数据: {len(internet_data)} 行")
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
#  python weak_report.py <客户ID或关键词> [选项]
#
#  可选参数:
#     --output-file <path>     临时表输出路径（默认顶部 OUTPUT_FILE）
#     --temp-dir <path>        临时目录（默认顶部 TEMP_DIR）
#     --start-time <日期>      过滤开始日期，如 2025-01-01
#     --end-time   <日期>      过滤结束日期，如 2025-03-31
#
#  示例:
#     python weak_report.py 35690473
#     python weak_report.py 客户名 --start-time 2025-01-01 --end-time 2025-03-31
#
#  输出:
#     临时表（仅计算）: 弱口令清单.xlsx，sheet名"弱口令"（含「数据来源」列）
#     交付物（平铺）:   弱口令清单（内网）.xlsx / 弱口令清单（互联网）.xlsx
#
#  接口:
#     接口1 search_customer            搜索客户（MSSW）
#     接口2 export_weak_pwd_intranet   内网弱口令导出（MSSW vul_manage）
#     接口3 download_weak_pwd_intranet 内网文件下载
#     接口4 export_weak_pwd_internet   外网弱口令导出（MSSW internet_vul_manage，文档 §2.13）
#     接口5 download_weak_pwd_internet 外网文件下载（文档 §2.14）
#
#  过滤逻辑:
#     fixed_status=[0(待处置), 1(处置中)]（内外网一致）
#     latest_time_range 接口层时间过滤
#
# ============================================================
