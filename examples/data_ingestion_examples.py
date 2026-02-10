"""
数据接入层使用示例
演示如何使用各种连接器接入数据
"""
import sys
import os
import asyncio
from datetime import datetime
import json

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.data_ingestion import (
    DataIngestionManager,
    DataFormat,
    ConnectorConfig,
    DataSourceType
)


async def example_file_ingestion():
    """示例1：从文件接入数据"""
    print("\n" + "="*60)
    print("示例1：从文件接入数据")
    print("="*60)

    manager = DataIngestionManager()

    # 1. 从JSON文件接入
    print("\n1.1 从JSON文件接入数据")
    try:
        # 首先创建一个示例JSON文件
        sample_data = [
            {
                "log_type": "firewall",
                "timestamp": "2024-01-15 10:30:00",
                "source_ip": "192.168.1.100",
                "dest_ip": "8.8.8.8",
                "dest_port": 443,
                "protocol": "TCP",
                "action": "allow"
            },
            {
                "log_type": "ids",
                "timestamp": "2024-01-15 10:31:00",
                "source_ip": "192.168.1.101",
                "dest_ip": "10.0.0.1",
                "dest_port": 22,
                "protocol": "SSH",
                "action": "alert"
            }
        ]

        # 创建示例文件
        sample_file = "sample_logs.json"
        with open(sample_file, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f, indent=2)

        # 接入数据
        data = await manager.ingest_from_file(
            file_path=sample_file,
            format=DataFormat.JSON,
            transformer_name='security_log'
        )

        print(f"成功接入 {len(data)} 条数据")
        for item in data:
            print(f"  - {item.log_type}: {item.source_ip} -> {item.dest_ip}")

        # 清理示例文件
        os.remove(sample_file)

    except Exception as e:
        print(f"错误: {e}")

    # 2. 从CSV文件接入
    print("\n1.2 从CSV文件接入数据")
    try:
        # 创建示例CSV文件
        csv_content = """log_type,timestamp,source_ip,dest_ip,dest_port,protocol,action
firewall,2024-01-15 10:30:00,192.168.1.100,8.8.8.8,443,TCP,allow
ids,2024-01-15 10:31:00,192.168.1.101,10.0.0.1,22,SSH,alert"""

        csv_file = "sample_logs.csv"
        with open(csv_file, 'w', encoding='utf-8') as f:
            f.write(csv_content)

        # 接入数据
        data = await manager.ingest_from_file(
            file_path=csv_file,
            format=DataFormat.CSV,
            parser_options={'has_header': True},
            transformer_name='security_log'
        )

        print(f"成功接入 {len(data)} 条数据")
        for item in data:
            print(f"  - {item.log_type}: {item.source_ip} -> {item.dest_ip}")

        # 清理示例文件
        os.remove(csv_file)

    except Exception as e:
        print(f"错误: {e}")


async def example_api_ingestion():
    """示例2：从API接入数据"""
    print("\n" + "="*60)
    print("示例2：从API接入数据")
    print("="*60)

    manager = DataIngestionManager()

    # 使用公开的测试API
    print("\n2.1 从REST API接入数据")
    try:
        data = await manager.ingest_from_api(
            base_url="https://jsonplaceholder.typicode.com",
            endpoint="/posts",
            method="GET",
            params={"_limit": 5},
            transformer_name='generic'
        )

        print(f"成功接入 {len(data)} 条数据")
        for item in data[:3]:
            print(f"  - Post {item.get('id')}: {item.get('title', '')[:50]}...")

    except Exception as e:
        print(f"错误: {e}")


async def example_database_ingestion():
    """示例3：从数据库接入数据（需要配置数据库）"""
    print("\n" + "="*60)
    print("示例3：从数据库接入数据")
    print("="*60)

    manager = DataIngestionManager()

    print("\n3.1 数据库连接示例（需要实际数据库）")
    print("提示：需要安装对应的数据库驱动")
    print("  - PostgreSQL: pip install asyncpg")
    print("  - MySQL: pip install aiomysql")
    print("  - MongoDB: pip install motor")

    # 示例代码（需要实际数据库才能运行）
    """
    try:
        data = await manager.ingest_from_database(
            connection_string="postgresql://user:password@localhost/dbname",
            query={
                "sql": "SELECT * FROM security_logs LIMIT 10"
            },
            db_type="postgresql",
            transformer_name='security_log'
        )

        print(f"成功接入 {len(data)} 条数据")
    except Exception as e:
        print(f"错误: {e}")
    """


async def example_batch_ingestion():
    """示例4：批量接入多个数据源"""
    print("\n" + "="*60)
    print("示例4：批量接入多个数据源")
    print("="*60)

    manager = DataIngestionManager()

    # 创建示例文件
    json_file = "logs1.json"
    csv_file = "logs2.csv"

    with open(json_file, 'w') as f:
        json.dump([
            {"log_type": "firewall", "timestamp": "2024-01-15 10:00:00",
             "source_ip": "192.168.1.1", "dest_ip": "8.8.8.8"}
        ], f)

    with open(csv_file, 'w') as f:
        f.write("log_type,timestamp,source_ip,dest_ip\n")
        f.write("ids,2024-01-15 10:01:00,192.168.1.2,10.0.0.1\n")

    try:
        # 批量接入
        sources = [
            {
                'type': 'file',
                'name': 'json_source',
                'file_path': json_file,
                'format': 'JSON',
                'transformer': 'security_log'
            },
            {
                'type': 'file',
                'name': 'csv_source',
                'file_path': csv_file,
                'format': 'CSV',
                'parser_options': {'has_header': True},
                'transformer': 'security_log'
            },
            {
                'type': 'api',
                'name': 'api_source',
                'base_url': 'https://jsonplaceholder.typicode.com',
                'endpoint': '/posts',
                'method': 'GET',
                'params': {'_limit': 3},
                'transformer': 'generic'
            }
        ]

        results = await manager.batch_ingest(sources)

        print("\n批量接入结果：")
        for source_name, data in results.items():
            print(f"  - {source_name}: {len(data)} 条数据")

    except Exception as e:
        print(f"错误: {e}")
    finally:
        # 清理文件
        if os.path.exists(json_file):
            os.remove(json_file)
        if os.path.exists(csv_file):
            os.remove(csv_file)


async def example_custom_transformer():
    """示例5：使用自定义转换器"""
    print("\n" + "="*60)
    print("示例5：使用自定义转换器")
    print("="*60)

    manager = DataIngestionManager()

    # 定义转换模式
    schema = {
        'event_type': 'log_type',
        'time': {
            'source': 'timestamp',
            'transform': lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S')
        },
        'src': 'source_ip',
        'dst': 'dest_ip'
    }

    # 创建示例文件
    sample_file = "custom_logs.json"
    with open(sample_file, 'w') as f:
        json.dump([
            {
                "log_type": "firewall",
                "timestamp": "2024-01-15 10:00:00",
                "source_ip": "192.168.1.1",
                "dest_ip": "8.8.8.8"
            }
        ], f)

    try:
        data = await manager.ingest_from_file(
            file_path=sample_file,
            format=DataFormat.JSON,
            transformer_name='generic',
            transform_schema=schema
        )

        print(f"成功接入并转换 {len(data)} 条数据")
        for item in data:
            print(f"  - {item}")

    except Exception as e:
        print(f"错误: {e}")
    finally:
        if os.path.exists(sample_file):
            os.remove(sample_file)


async def main():
    """主函数"""
    print("="*60)
    print("数据接入层使用示例")
    print("="*60)

    await example_file_ingestion()
    await example_api_ingestion()
    await example_database_ingestion()
    await example_batch_ingestion()
    await example_custom_transformer()

    print("\n" + "="*60)
    print("所有示例执行完成")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())