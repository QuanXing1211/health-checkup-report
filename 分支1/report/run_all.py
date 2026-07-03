"""
合并执行 scoring 与 protection_effectiveness，将返回结果合并写入 data.json。

结构：
    {
        "scoring": <scoring.ScoringEngine.calc_total_score() 返回的 dict>,
        "protection_effectiveness": {
            "without_aes_asset_stats": <stat_core_assets_without_aes 返回>,
            "policy_stats": <stat_policy_check 返回>
        }
    }

用法:
    python run_all.py
    python run_all.py --config config.yaml
    python run_all.py --output data.json
"""

import argparse
import json
import os
import sys

# 确保能导入同目录下的模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scoring import ScoringEngine, load_config  # noqa: E402
from data_reader import load_data_sources, read_excel, read_json  # noqa: E402
from protection_effectiveness import (  # noqa: E402
    stat_core_assets_without_aes,
    stat_policy_check,
)


def run_scoring(config_path: str) -> dict:
    """执行评分计算，返回评分结果字典。"""
    engine = ScoringEngine(config_path)
    engine.load_data()
    return engine.calc_total_score()


def run_data_stats(config_path: str) -> dict:
    """执行数据统计，返回统计结果字典。"""
    config = load_config(config_path)
    ds_cfg = config["data_source"]
    base_path = ds_cfg["base_path"]
    files = ds_cfg["files"]

    # 资产清单
    asset_cfg = files["asset"]
    asset_path = asset_cfg["filename"]
    if not os.path.isabs(asset_path):
        asset_path = os.path.join(base_path, asset_path)
    if os.path.exists(asset_path):
        asset_data = read_excel(
            asset_path,
            header_row=asset_cfg.get("header_row", 2),
            data_start_row=asset_cfg.get("data_start_row", 3),
        )
    else:
        asset_data = []

    # 策略检查 JSON
    policy_json_cfg = files.get("policy_json", {})
    policy_path = policy_json_cfg.get("filename", "tmp/policy_check.json")
    if not os.path.isabs(policy_path):
        policy_path = os.path.join(base_path, policy_path)
    if os.path.exists(policy_path):
        policy_data = read_json(policy_path, data_path=None)
    else:
        policy_data = []

    return {
        "without_aes_asset_stats": stat_core_assets_without_aes(asset_data),
        "policy_stats": stat_policy_check(policy_data),
    }


def main():
    parser = argparse.ArgumentParser(description="合并执行 scoring 与 protection_effectiveness")
    parser.add_argument("--config", default=None, help="配置文件路径")
    parser.add_argument("--output", default=None, help="输出文件路径(JSON)")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = args.config or os.path.join(script_dir, "config.yaml")
    output_path = args.output or os.path.join(script_dir, "data.json")

    print("=" * 60)
    print("合并执行 scoring 与 protection_effectiveness")
    print("=" * 60)
    print(f"配置文件: {config_path}")
    print(f"输出文件: {output_path}\n")

    print("--- 执行 scoring ---")
    scoring_result = run_scoring(config_path)
    print(f"评分总分: {scoring_result.get('total_score')} "
          f"等级: {scoring_result.get('grade')}")

    print("\n--- 执行 protection_effectiveness ---")
    data_stats_result = run_data_stats(config_path)
    without_aes = data_stats_result["without_aes_asset_stats"]
    policy = data_stats_result["policy_stats"]
    print(f"核心资产(无 aES 数据源) IP 数: {without_aes['total']}")
    print(f"策略检查总数: {policy['total']}, 异常项: {policy['abnormal_count']}")

    merged = {
        "scoring": scoring_result,
        "protection_effectiveness": data_stats_result,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2, default=str)

    print(f"\n合并结果已保存: {output_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
