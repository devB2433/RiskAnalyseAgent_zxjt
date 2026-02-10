"""
威胁情报集成使用示例
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.threat_intel import ThreatIntelManager, IOCType


async def example_mock_mode():
    """示例1：Mock模式（无需API密钥）"""
    print("\n" + "="*60)
    print("示例1：Mock模式")
    print("="*60)

    # 创建管理器（Mock模式）
    manager = ThreatIntelManager(use_mock=True)

    # 查询IP
    print("\n1.1 查询IP")
    results = await manager.query_ip("192.168.1.100")

    for result in results:
        print(f"  提供商: {result.provider}")
        print(f"  是否恶意: {result.is_malicious}")
        print(f"  威胁分数: {result.threat_score}")
        print(f"  威胁级别: {result.threat_level.value}")
        print(f"  来源: {result.sources}")
        print()

    # 查询域名
    print("\n1.2 查询域名")
    results = await manager.query_domain("malicious-domain.com")

    for result in results:
        if not result.error:
            print(f"  提供商: {result.provider}")
            print(f"  是否恶意: {result.is_malicious}")
            print()

    # 查询文件哈希
    print("\n1.3 查询文件哈希")
    results = await manager.query_file_hash("abc123def456")

    for result in results:
        if not result.error:
            print(f"  提供商: {result.provider}")
            print(f"  是否恶意: {result.is_malicious}")
            print(f"  威胁类型: {result.threat_types}")
            print()


async def example_real_api():
    """示例2：真实API模式（需要API密钥）"""
    print("\n" + "="*60)
    print("示例2：真实API模式")
    print("="*60)

    # 检查API密钥
    has_vt_key = bool(os.getenv("VIRUSTOTAL_API_KEY"))
    has_abuse_key = bool(os.getenv("ABUSEIPDB_API_KEY"))

    print(f"\nVirusTotal API密钥: {'已配置' if has_vt_key else '未配置'}")
    print(f"AbuseIPDB API密钥: {'已配置' if has_abuse_key else '未配置'}")

    if not (has_vt_key or has_abuse_key):
        print("\n提示：请在.env文件中配置API密钥以使用真实API")
        print("  VIRUSTOTAL_API_KEY=your_key")
        print("  ABUSEIPDB_API_KEY=your_key")
        return

    # 创建管理器（真实API模式）
    manager = ThreatIntelManager(use_mock=False)

    # 查询已知恶意IP（示例）
    print("\n2.1 查询IP: 1.2.3.4")
    try:
        results = await manager.query_ip("1.2.3.4")

        for result in results:
            if not result.error:
                print(f"  提供商: {result.provider}")
                print(f"  是否恶意: {result.is_malicious}")
                print(f"  威胁分数: {result.threat_score}")
                print(f"  详情: {result.details}")
                print()
            else:
                print(f"  提供商: {result.provider} - 错误: {result.error}")
    except Exception as e:
        print(f"  查询失败: {e}")


async def example_aggregate():
    """示例3：聚合多个提供商结果"""
    print("\n" + "="*60)
    print("示例3：聚合多个提供商结果")
    print("="*60)

    manager = ThreatIntelManager(use_mock=True)

    # 查询IP并聚合结果
    print("\n3.1 查询并聚合IP结果")
    results = await manager.query_ip("192.168.1.100")

    print(f"  查询到 {len(results)} 个提供商的结果")

    # 聚合结果
    aggregated = manager.aggregate_results(results)

    print(f"\n聚合结果:")
    print(f"  是否恶意: {aggregated.is_malicious}")
    print(f"  威胁级别: {aggregated.threat_level.value}")
    print(f"  平均威胁分数: {aggregated.threat_score:.2f}")
    print(f"  威胁类型: {aggregated.threat_types}")
    print(f"  恶意判定: {aggregated.details['malicious_count']}/{aggregated.details['total_count']}")


async def example_cache():
    """示例4：缓存机制"""
    print("\n" + "="*60)
    print("示例4：缓存机制")
    print("="*60)

    manager = ThreatIntelManager(use_mock=True, enable_cache=True)

    # 第一次查询
    print("\n4.1 第一次查询（无缓存）")
    import time
    start = time.time()
    results = await manager.query_ip("192.168.1.100")
    elapsed = time.time() - start
    print(f"  查询时间: {elapsed:.3f}秒")
    print(f"  缓存状态: {results[0].cached}")

    # 第二次查询（使用缓存）
    print("\n4.2 第二次查询（使用缓存）")
    start = time.time()
    results = await manager.query_ip("192.168.1.100")
    elapsed = time.time() - start
    print(f"  查询时间: {elapsed:.3f}秒")
    print(f"  缓存状态: {results[0].cached}")


async def example_provider_status():
    """示例5：查看提供商状态"""
    print("\n" + "="*60)
    print("示例5：提供商状态")
    print("="*60)

    manager = ThreatIntelManager(use_mock=True)

    status = manager.get_provider_status()

    print("\n提供商状态:")
    for name, info in status.items():
        print(f"\n  {name}:")
        print(f"    名称: {info['provider_name']}")
        print(f"    Mock模式: {info['use_mock']}")
        print(f"    API密钥: {'已配置' if info['has_api_key'] else '未配置'}")
        print(f"    缓存: {'启用' if info['enable_cache'] else '禁用'}")


async def main():
    """主函数"""
    print("="*60)
    print("威胁情报集成使用示例")
    print("="*60)

    await example_mock_mode()
    await example_real_api()
    await example_aggregate()
    await example_cache()
    await example_provider_status()

    print("\n" + "="*60)
    print("所有示例执行完成")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())