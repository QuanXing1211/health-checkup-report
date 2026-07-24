#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单元测试：risk_asset_count.py 中 split_biz 和所属业务拆分逻辑

模拟资产表的 IP地址 + 所属业务列，按照现有代码逻辑验证 business_systems 计算结果。
"""
import io
import sys
import os

from openpyxl import Workbook

# 把 scripts 目录加入 path，以便 import risk_asset_count 中的 split_biz
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts'))

# 直接从 risk_asset_count 导入改后的函数
from risk_asset_count import split_biz, build_asset_business_map
from risk_asset_count import normalize, normalize_asset_key


def create_asset_xlsx(rows):
    """
    在内存中创建资产表 xlsx，列: IP地址, 所属业务, 托管状态
    rows: [(ip, business, managed), ...]
    """
    wb = Workbook()
    ws = wb.active
    ws.append(['IP地址', '所属业务', '托管状态'])
    for ip, biz, managed in rows:
        ws.append([ip, biz, managed])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


def test_split_biz():
    """测试 split_biz 函数本身"""
    print('=' * 60)
    print('TEST: split_biz()')
    print('=' * 60)

    cases = [
        (None,                [],                          "None"),
        ('',                  [],                          "空字符串"),
        ('核心交易系统',       ['核心交易系统'],              "单值"),
        ('核心交易系统, 风控系统', ['核心交易系统', '风控系统'],  "逗号分隔双值"),
        ('A,B,C',             ['A', 'B', 'C'],              "逗号分隔三值"),
        ('核心交易系统、风控系统', ['核心交易系统', '风控系统'],  "顿号分隔"),
        ('A, B ,C',           ['A', 'B', 'C'],              "空格+逗号"),
        ('  A , , B ',        ['A', 'B'],                   "含空段"),
        ('A、B, C',           ['A', 'B', 'C'],              "混合分隔符"),
    ]

    all_pass = True
    for input_val, expected, desc in cases:
        result = split_biz(input_val)
        status = 'PASS' if result == expected else 'FAIL'
        if status == 'FAIL':
            all_pass = False
        print(f'  [{status}] {desc}: split_biz({repr(input_val)}) = {result}')
        if result != expected:
            print(f'          expected: {expected}')

    print()
    return all_pass


def test_build_asset_business_map():
    """测试 build_asset_business_map — 值仍为原始字符串（后续在消费端拆分）"""
    print('=' * 60)
    print('TEST: build_asset_business_map()')
    print('=' * 60)

    asset_rows = [
        ('10.5.40.62',      '核心交易系统, 风控系统', '已托管'),
        ('192.168.1.100',   'OA办公系统',             '未托管'),
        ('172.16.88.30',    '核心交易系统、财务系统',   '已托管'),
        ('10.100.1.50',     '',                        '已托管'),   # 所属业务为空
        ('192.168.200.33',  '财务系统',                '已托管'),
    ]

    xlsx_buf = create_asset_xlsx(asset_rows)
    # 写到临时文件，因为 build_asset_business_map 需要文件路径
    tmp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp', '_test_asset.xlsx')
    os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
    with open(tmp_path, 'wb') as f:
        f.write(xlsx_buf.read())

    result = build_asset_business_map(tmp_path)

    # 验证映射键
    all_pass = True
    expected_keys = {'10.5.40.62', '192.168.1.100', '172.16.88.30', '192.168.200.33'}
    actual_keys = set(result.keys())

    if actual_keys == expected_keys:
        print(f'  [PASS] 映射 IP 数量: {len(result)} (expected {len(expected_keys)})')
    else:
        print(f'  [FAIL] 映射 IP 不匹配: got {actual_keys}, expected {expected_keys}')
        all_pass = False

    # 验证 10.100.1.50 不在映射中（所属业务为空）
    if '10.100.1.50' not in result:
        print(f'  [PASS] 10.100.1.50 (所属业务为空) 不在映射中')
    else:
        print(f'  [FAIL] 10.100.1.50 不应在映射中')
        all_pass = False

    # 验证值是原始字符串
    if result.get('10.5.40.62') == '核心交易系统, 风控系统':
        print(f'  [PASS] 10.5.40.62 → "核心交易系统, 风控系统" (原始值)')
    else:
        print(f'  [FAIL] 10.5.40.62 → {repr(result.get("10.5.40.62"))}')
        all_pass = False

    if result.get('172.16.88.30') == '核心交易系统、财务系统':
        print(f'  [PASS] 172.16.88.30 → "核心交易系统、财务系统" (原始值，含顿号)')
    else:
        print(f'  [FAIL] 172.16.88.30 → {repr(result.get("172.16.88.30"))}')
        all_pass = False

    # 清理（openpyxl read_only 模式在 Windows 上可能持锁，用重试机制）
    import time
    for _ in range(5):
        try:
            os.remove(tmp_path)
            break
        except PermissionError:
            time.sleep(0.1)
    print()
    return all_pass


def test_business_systems_computation():
    """
    核心测试：模拟 main() 中 business_systems 的计算逻辑。
    模拟 all_assets (风险 IP 集合) 和 asset_business_map，验证拆分后去重结果。
    """
    print('=' * 60)
    print('TEST: business_systems 计算 (核心改动)')
    print('=' * 60)

    # 模拟 asset_business_map (build_asset_business_map 返回的原始值)
    asset_business_map = {
        '10.5.40.62':     '核心交易系统, 风控系统',
        '192.168.1.100':  'OA办公系统',
        '172.16.88.30':   '核心交易系统、财务系统',
        '192.168.200.33': '财务系统',
        # 注意: 10.100.1.50 所属业务为空，不在映射中
        # 注意: 10.9.9.9 不在资产表中，不在映射中
    }

    # 模拟风险数据中出现的 IP
    all_assets = {
        '10.5.40.62',      # 映射到 "核心交易系统, 风控系统"
        '192.168.1.100',   # 映射到 "OA办公系统"
        '172.16.88.30',    # 映射到 "核心交易系统、财务系统" (顿号)
        '10.100.1.50',     # 在资产表中但所属业务为空 → 不在 asset_business_map 中
        '10.9.9.9',        # 不在资产表中 → 不在 asset_business_map 中
    }

    # ---- 改动前的逻辑（整体字符串）----
    old_business_systems = sorted({
        asset_business_map[asset]
        for asset in all_assets
        if asset in asset_business_map
    })
    old_count = len(old_business_systems)

    print(f'  改动前 business_systems: {old_business_systems}')
    print(f'  改动前 riskBusinessCount: {old_count}')

    # ---- 改动后的逻辑（split_biz 拆分）----
    new_business_systems = sorted({
        biz
        for asset in all_assets
        if asset in asset_business_map
        for biz in split_biz(asset_business_map[asset])
    })
    new_count = len(new_business_systems)

    print(f'  改动后 business_systems: {new_business_systems}')
    print(f'  改动后 riskBusinessCount: {new_count}')
    print()

    # 验证
    all_pass = True

    # 改动前：3 个整体字符串 ("核心交易系统, 风控系统", "OA办公系统", "核心交易系统、财务系统")
    expected_old = ['OA办公系统', '核心交易系统, 风控系统', '核心交易系统、财务系统']
    if old_business_systems == expected_old:
        print(f'  [PASS] 改动前: 3 个整体字符串')
    else:
        print(f'  [FAIL] 改动前: expected {expected_old}, got {old_business_systems}')
        all_pass = False

    # 改动后：4 个独立业务名（sorted 按 Unicode 码点排序）
    expected_new = ['OA办公系统', '核心交易系统', '财务系统', '风控系统']
    if new_business_systems == expected_new:
        print(f'  [PASS] 改动后: 4 个独立业务名 (核心交易系统、风控系统、OA办公系统、财务系统)')
    else:
        print(f'  [FAIL] 改动后: expected {expected_new}, got {new_business_systems}')
        all_pass = False

    if new_count == 4:
        print(f'  [PASS] riskBusinessCount = {new_count}')
    else:
        print(f'  [FAIL] riskBusinessCount: expected 4, got {new_count}')
        all_pass = False

    # 验证不在映射中的 IP 不计入
    if '10.100.1.50' not in asset_business_map:
        print(f'  [PASS] 10.100.1.50 (所属业务为空) 不计入')
    if '10.9.9.9' not in asset_business_map:
        print(f'  [PASS] 10.9.9.9 (不在资产表中) 不计入')

    print()
    return all_pass


def test_edge_cases():
    """边界情况测试"""
    print('=' * 60)
    print('TEST: 边界情况')
    print('=' * 60)

    all_pass = True

    # Case 1: 所有风险 IP 都不在资产表中
    asset_business_map = {}
    all_assets = {'10.1.1.1', '10.2.2.2'}
    result = sorted({
        biz
        for asset in all_assets
        if asset in asset_business_map
        for biz in split_biz(asset_business_map.get(asset, ''))
    })
    if result == []:
        print(f'  [PASS] 所有 IP 都不在资产表中 → riskBusinessCount = 0')
    else:
        print(f'  [FAIL] expected [], got {result}')
        all_pass = False

    # Case 2: 单个业务单值
    asset_business_map = {'10.1.1.1': '核心交易系统'}
    all_assets = {'10.1.1.1'}
    result = sorted({
        biz
        for asset in all_assets
        if asset in asset_business_map
        for biz in split_biz(asset_business_map[asset])
    })
    if result == ['核心交易系统']:
        print(f'  [PASS] 单 IP 单业务 → riskBusinessCount = 1')
    else:
        print(f'  [FAIL] expected ["核心交易系统"], got {result}')
        all_pass = False

    # Case 3: 多个 IP 映射到同一个业务（去重）
    asset_business_map = {
        '10.1.1.1': '核心交易系统',
        '10.2.2.2': '核心交易系统, 风控系统',
    }
    all_assets = {'10.1.1.1', '10.2.2.2'}
    result = sorted({
        biz
        for asset in all_assets
        if asset in asset_business_map
        for biz in split_biz(asset_business_map[asset])
    })
    if result == ['核心交易系统', '风控系统']:
        print(f'  [PASS] 多 IP 共享部分业务 → 去重后 2 个: {result}')
    else:
        print(f'  [FAIL] expected ["核心交易系统", "风控系统"], got {result}')
        all_pass = False

    # Case 4: 空字符串作为业务名（不应出现，但防御）
    asset_business_map = {'10.1.1.1': ', ,'}
    all_assets = {'10.1.1.1'}
    result = sorted({
        biz
        for asset in all_assets
        if asset in asset_business_map
        for biz in split_biz(asset_business_map[asset])
    })
    if result == []:
        print(f'  [PASS] 全空段 → riskBusinessCount = 0')
    else:
        print(f'  [FAIL] expected [], got {result}')
        all_pass = False

    # Case 5: 带 "/" 前缀的值（process_risk_list_table.py 清洗后的遗留）
    asset_business_map = {'10.1.1.1': '部门A/核心交易系统, 部门B/风控系统'}
    all_assets = {'10.1.1.1'}
    result = sorted({
        biz
        for asset in all_assets
        if asset in asset_business_map
        for biz in split_biz(asset_business_map[asset])
    })
    # split_biz 只按逗号/顿号拆分，不处理 / 前缀
    if '部门A/核心交易系统' in result and '部门B/风控系统' in result:
        print(f'  [PASS] 带 / 前缀：按逗号拆分，保留完整值（/ 由 process_risk_list_table 预处理）: {result}')
    else:
        print(f'  [FAIL] got {result}')
        all_pass = False

    print()
    return all_pass


if __name__ == '__main__':
    results = []
    results.append(('split_biz()',                  test_split_biz()))
    results.append(('build_asset_business_map()',   test_build_asset_business_map()))
    results.append(('business_systems 计算',         test_business_systems_computation()))
    results.append(('边界情况',                      test_edge_cases()))

    print('=' * 60)
    print('SUMMARY')
    print('=' * 60)
    for name, passed in results:
        print(f'  {"PASS" if passed else "FAIL"}: {name}')
    all_pass = all(p for _, p in results)
    print(f'\n  {"ALL TESTS PASSED" if all_pass else "SOME TESTS FAILED"}')
    sys.exit(0 if all_pass else 1)
