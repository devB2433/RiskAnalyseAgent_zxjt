"""
数据接入层与安全分析系统集成示例
演示如何从真实数据源接入数据并进行安全分析
"""
import sys
import os
import asyncio
import json
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.data_ingestion import DataIngestionManager, DataFormat
from security_analysis.architecture import (
    SecurityAnalysisSystem,
    AnalysisType
)


async def example_integrated_analysis():
    """集成示例：从文件接入数据并进行安全分析"""
    print("="*60)
    print("集成示例：数据接入 + 安全分析")
    print("="*60)

    # 1. 创建示例日志文件
    print("\n步骤1：创建示例日志文件")
    sample_logs = [
        {
            "log_type": "firewall",
            "timestamp": "2024-01-15 10:30:00",
            "source_ip": "192.168.1.50",
            "dest_ip": "192.168.1.100",  # 可疑C2服务器
            "dest_port": 443,
            "protocol": "TCP",
            "action": "allow",
            "bytes": 1024
        },
        {
            "log_type": "ids",
            "timestamp": "2024-01-15 10:31:00",
            "source_ip": "192.168.1.50",
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "protocol": "UDP",
            "action": "alert",
            "dns_query": "malicious-domain.com"
        },
        {
            "log_type": "edr",
            "timestamp": "2024-01-15 10:32:00",
            "source_ip": "192.168.1.50",
            "dest_ip": "",
            "protocol": "",
            "action": "process_start",
            "process": "suspicious.exe",
            "hash": "abc123..."
        },
        {
            "log_type": "auth",
            "timestamp": "2024-01-15 02:30:00",  # 凌晨登录
            "source_ip": "10.0.0.100",  # 异常IP
            "dest_ip": "192.168.1.10",
            "dest_port": 22,
            "protocol": "SSH",
            "action": "success",
            "username": "admin",
            "location": "Unknown",
            "device": "New Device"
        }
    ]

    log_file = "security_logs.json"
    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(sample_logs, f, indent=2)
    print(f"✓ 创建日志文件: {log_file}")

    # 2. 使用数据接入层接入数据
    print("\n步骤2：使用数据接入层接入日志数据")
    ingestion_manager = DataIngestionManager()

    logs = await ingestion_manager.ingest_from_file(
        file_path=log_file,
        format=DataFormat.JSON,
        transformer_name='security_log'
    )
    print(f"✓ 成功接入 {len(logs)} 条日志")

    # 3. 使用安全分析系统分析数据
    print("\n步骤3：执行安全分析")
    analysis_system = SecurityAnalysisSystem()

    # 3.1 失陷主机检测
    print("\n3.1 失陷主机检测")
    result1 = await analysis_system.analyze(
        AnalysisType.COMPROMISED_HOST.value,
        logs
    )
    print(f"  分析类型: {result1.analysis_type}")
    print(f"  置信度: {result1.confidence}")
    print(f"  证据数量: {len(result1.evidence)}")

    # 3.2 异常登录检测
    print("\n3.2 异常登录检测")
    result2 = await analysis_system.analyze(
        AnalysisType.ANOMALOUS_LOGIN.value,
        logs
    )
    print(f"  分析类型: {result2.analysis_type}")
    print(f"  置信度: {result2.confidence}")

    # 4. 批量分析
    print("\n步骤4：批量分析多种威胁")
    results = await analysis_system.batch_analyze(
        [
            AnalysisType.COMPROMISED_HOST.value,
            AnalysisType.ANOMALOUS_LOGIN.value
        ],
        logs
    )

    print("\n批量分析结果:")
    for analysis_type, result in results.items():
        print(f"  - {analysis_type}: 置信度 {result.confidence}")

    # 清理
    os.remove(log_file)
    print("\n✓ 分析完成")


async def example_multi_source_analysis():
    """多数据源集成分析"""
    print("\n" + "="*60)
    print("多数据源集成分析")
    print("="*60)

    # 创建多个数据源
    print("\n步骤1：创建多个数据源")

    # 数据源1：防火墙日志
    firewall_logs = [
        {
            "log_type": "firewall",
            "timestamp": "2024-01-15 10:00:00",
            "source_ip": "192.168.1.50",
            "dest_ip": "192.168.1.100",
            "dest_port": 443,
            "protocol": "TCP",
            "action": "allow"
        }
    ]
    with open("firewall.json", 'w') as f:
        json.dump(firewall_logs, f)

    # 数据源2：IDS日志（CSV格式）
    ids_csv = """log_type,timestamp,source_ip,dest_ip,dest_port,protocol,action
ids,2024-01-15 10:01:00,192.168.1.50,8.8.8.8,53,UDP,alert"""
    with open("ids.csv", 'w') as f:
        f.write(ids_csv)

    print("✓ 创建了2个数据源文件")

    # 步骤2：批量接入数据
    print("\n步骤2：批量接入多个数据源")
    ingestion_manager = DataIngestionManager()

    sources = [
        {
            'type': 'file',
            'name': 'firewall',
            'file_path': 'firewall.json',
            'format': 'JSON',
            'transformer': 'security_log'
        },
        {
            'type': 'file',
            'name': 'ids',
            'file_path': 'ids.csv',
            'format': 'CSV',
            'parser_options': {'has_header': True},
            'transformer': 'security_log'
        }
    ]

    results = await ingestion_manager.batch_ingest(sources)

    # 合并所有数据
    all_logs = []
    for source_name, logs in results.items():
        print(f"  - {source_name}: {len(logs)} 条日志")
        all_logs.extend(logs)

    print(f"✓ 总共接入 {len(all_logs)} 条日志")

    # 步骤3：执行安全分析
    print("\n步骤3：对合并后的数据执行安全分析")
    analysis_system = SecurityAnalysisSystem()

    result = await analysis_system.analyze(
        AnalysisType.COMPROMISED_HOST.value,
        all_logs
    )

    print(f"  分析完成，置信度: {result.confidence}")

    # 清理
    os.remove("firewall.json")
    os.remove("ids.csv")
    print("\n✓ 多源分析完成")


async def example_realtime_analysis():
    """实时数据流分析示例（模拟）"""
    print("\n" + "="*60)
    print("实时数据流分析示例")
    print("="*60)

    print("\n说明：这是一个模拟的实时分析示例")
    print("在实际应用中，可以连接到：")
    print("  - Kafka消息队列")
    print("  - WebSocket数据流")
    print("  - 数据库变更流")

    # 模拟实时数据流
    async def simulate_log_stream():
        """模拟日志流"""
        for i in range(5):
            yield {
                "log_type": "firewall",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": f"192.168.1.{100+i}",
                "dest_ip": "8.8.8.8",
                "dest_port": 443,
                "protocol": "TCP",
                "action": "allow"
            }
            await asyncio.sleep(1)

    print("\n开始接收实时日志流...")
    analysis_system = SecurityAnalysisSystem()
    ingestion_manager = DataIngestionManager()

    batch_logs = []
    async for log_data in simulate_log_stream():
        print(f"  接收日志: {log_data['source_ip']} -> {log_data['dest_ip']}")

        # 转换为SecurityLog
        from security_analysis.architecture import SecurityLog
        log = SecurityLog(
            log_type=log_data['log_type'],
            timestamp=datetime.strptime(log_data['timestamp'], "%Y-%m-%d %H:%M:%S"),
            source_ip=log_data['source_ip'],
            dest_ip=log_data['dest_ip'],
            dest_port=log_data['dest_port'],
            protocol=log_data['protocol'],
            action=log_data['action']
        )
        batch_logs.append(log)

        # 每收集3条日志进行一次分析
        if len(batch_logs) >= 3:
            print(f"\n  → 分析 {len(batch_logs)} 条日志...")
            result = await analysis_system.analyze(
                AnalysisType.COMPROMISED_HOST.value,
                batch_logs
            )
            print(f"  → 分析完成，置信度: {result.confidence}")
            batch_logs = []

    print("\n✓ 实时分析完成")


async def main():
    """主函数"""
    print("="*60)
    print("数据接入层与安全分析系统集成示例")
    print("="*60)

    await example_integrated_analysis()
    await example_multi_source_analysis()
    await example_realtime_analysis()

    print("\n" + "="*60)
    print("所有集成示例执行完成")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())