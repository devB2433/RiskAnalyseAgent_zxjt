"""
安全分析系统V2示例 - 集成真实威胁情报
"""
import sys
import os
import asyncio
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from security_analysis.architecture_v2 import (
    SecurityAnalysisSystem,
    SecurityLog,
    AnalysisType
)


async def example_1_mock_mode():
    """示例1：使用模拟模式进行开发和测试"""
    print("=" * 60)
    print("示例1：模拟模式 - 无需API密钥")
    print("=" * 60)

    # 初始化系统（模拟模式）
    system = SecurityAnalysisSystem(use_mock=True)

    # 创建测试日志
    logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.5",
            dest_port=443,
            protocol="TCP",
            action="ALLOW"
        ),
        SecurityLog(
            log_type="ids",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="8.8.8.8",
            dest_port=53,
            protocol="UDP",
            action="ALERT"
        ),
    ]

    # 执行失陷主机检测
    print("\n执行失陷主机检测...")
    result = await system.analyze(
        AnalysisType.COMPROMISED_HOST.value,
        logs
    )

    print(f"分析类型: {result.analysis_type}")
    print(f"置信度: {result.confidence}")
    print(f"证据数量: {len(result.evidence)}")
    print(f"追踪记录数: {len(result.trace)}")

    # 查看威胁情报查询记录
    print("\n威胁情报查询记录:")
    for trace_item in result.trace:
        if trace_item.get("type") == "tool_call":
            print(f"  - {trace_item.get('tool')}: {trace_item.get('params')}")
            print(f"    结果: {trace_item.get('result_summary')}")

    # 获取缓存统计
    cache_stats = system.get_cache_stats()
    print(f"\n缓存统计: {cache_stats}")


async def example_2_real_api_mode():
    """示例2：使用真实API（需要API密钥）"""
    print("\n" + "=" * 60)
    print("示例2：真实API模式")
    print("=" * 60)

    # 从环境变量读取API密钥
    api_keys = {
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", "")
    }

    # 检查是否有API密钥
    if not any(api_keys.values()):
        print("警告: 未找到API密钥，将使用模拟模式")
        print("设置环境变量 VIRUSTOTAL_API_KEY 和 ABUSEIPDB_API_KEY 以使用真实API")
        return

    # 初始化系统（真实API模式）
    system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)

    # 创建测试日志（使用真实的恶意IP）
    logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="1.2.3.4",  # 替换为已知恶意IP进行测试
            dest_port=443,
            protocol="TCP",
            action="ALLOW"
        ),
    ]

    print("\n执行失陷主机检测（使用真实威胁情报）...")
    result = await system.analyze(
        AnalysisType.COMPROMISED_HOST.value,
        logs
    )

    print(f"分析完成，置信度: {result.confidence}")

    # 查看真实威胁情报结果
    print("\n真实威胁情报查询结果:")
    for trace_item in result.trace:
        if trace_item.get("type") == "tool_call":
            print(f"  - {trace_item.get('tool')}")
            print(f"    参数: {trace_item.get('params')}")
            print(f"    结果: {trace_item.get('result_summary')}")


async def example_3_malware_detection():
    """示例3：恶意软件检测"""
    print("\n" + "=" * 60)
    print("示例3：恶意软件检测")
    print("=" * 60)

    system = SecurityAnalysisSystem(use_mock=True)

    # 创建EDR日志
    logs = [
        SecurityLog(
            log_type="edr",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="0.0.0.0",
            action="process_create",
            raw_data={
                "process_name": "suspicious.exe",
                "file_hash": "abc123def456789",  # 模拟恶意文件哈希
                "parent_process": "explorer.exe"
            }
        ),
    ]

    print("\n执行恶意软件检测...")
    result = await system.analyze(
        AnalysisType.MALWARE_DETECTION.value,
        logs
    )

    print(f"分析类型: {result.analysis_type}")
    print(f"追踪记录数: {len(result.trace)}")

    # 查看文件哈希验证结果
    print("\n文件哈希验证结果:")
    for trace_item in result.trace:
        if trace_item.get("type") == "tool_call" and "file_hash" in trace_item.get("tool", ""):
            print(f"  - 哈希: {trace_item.get('params', {}).get('file_hash')}")
            print(f"    恶意: {trace_item.get('result_summary', {}).get('is_malicious')}")
            print(f"    类型: {trace_item.get('result_summary', {}).get('malware_type')}")


async def example_4_phishing_detection():
    """示例4：钓鱼攻击检测"""
    print("\n" + "=" * 60)
    print("示例4：钓鱼攻击检测")
    print("=" * 60)

    system = SecurityAnalysisSystem(use_mock=True)

    # 创建Web访问日志
    logs = [
        SecurityLog(
            log_type="web_proxy",
            timestamp=datetime.now(),
            source_ip="192.168.1.75",
            dest_ip="1.2.3.4",
            dest_port=443,
            protocol="HTTPS",
            action="ALLOW",
            raw_data={
                "username": "user@company.com",
                "url": "https://suspicious-domain.com/login",
                "user_agent": "Mozilla/5.0"
            }
        ),
    ]

    print("\n执行钓鱼攻击检测...")
    result = await system.analyze(
        AnalysisType.PHISHING_DETECTION.value,
        logs
    )

    print(f"分析类型: {result.analysis_type}")

    # 查看域名和URL验证结果
    print("\n域名/URL验证结果:")
    for trace_item in result.trace:
        if trace_item.get("type") == "tool_call":
            tool = trace_item.get("tool", "")
            if "domain" in tool or "url" in tool:
                print(f"  - 工具: {tool}")
                print(f"    参数: {trace_item.get('params')}")
                print(f"    威胁评分: {trace_item.get('result_summary', {}).get('threat_score')}")


async def example_5_batch_analysis():
    """示例5：批量分析"""
    print("\n" + "=" * 60)
    print("示例5：批量分析多种威胁类型")
    print("=" * 60)

    system = SecurityAnalysisSystem(use_mock=True)

    # 创建综合日志
    logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.5",
            dest_port=443,
            protocol="TCP",
            action="ALLOW"
        ),
        SecurityLog(
            log_type="edr",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="0.0.0.0",
            action="process_create",
            raw_data={
                "process_name": "malware.exe",
                "file_hash": "abc123"
            }
        ),
    ]

    # 批量分析
    print("\n执行批量分析...")
    analysis_types = [
        AnalysisType.COMPROMISED_HOST.value,
        AnalysisType.MALWARE_DETECTION.value,
    ]

    results = await system.batch_analyze(analysis_types, logs)

    print(f"\n完成 {len(results)} 种分析:")
    for analysis_type, result in results.items():
        print(f"  - {analysis_type}: 置信度 {result.confidence}")

    # 缓存统计
    cache_stats = system.get_cache_stats()
    print(f"\n缓存统计: {cache_stats}")


async def example_6_cache_management():
    """示例6：缓存管理"""
    print("\n" + "=" * 60)
    print("示例6：缓存管理")
    print("=" * 60)

    system = SecurityAnalysisSystem(use_mock=True)

    logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.5",
            dest_port=443,
            protocol="TCP",
            action="ALLOW"
        ),
    ]

    # 第一次查询
    print("\n第一次分析（无缓存）...")
    await system.analyze(AnalysisType.COMPROMISED_HOST.value, logs)
    stats1 = system.get_cache_stats()
    print(f"缓存统计: {stats1}")

    # 第二次查询（使用缓存）
    print("\n第二次分析（使用缓存）...")
    await system.analyze(AnalysisType.COMPROMISED_HOST.value, logs)
    stats2 = system.get_cache_stats()
    print(f"缓存统计: {stats2}")

    # 清除缓存
    print("\n清除缓存...")
    await system.clear_cache()
    stats3 = system.get_cache_stats()
    print(f"缓存统计: {stats3}")


async def main():
    """运行所有示例"""
    print("安全分析系统V2 - 威胁情报集成示例")
    print("=" * 60)

    # 运行示例
    await example_1_mock_mode()
    await example_2_real_api_mode()
    await example_3_malware_detection()
    await example_4_phishing_detection()
    await example_5_batch_analysis()
    await example_6_cache_management()

    print("\n" + "=" * 60)
    print("所有示例完成！")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
