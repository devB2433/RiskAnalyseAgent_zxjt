# 数据接入层 (Data Ingestion Layer)

## 概述

数据接入层为Agent框架提供统一的数据接入接口，支持多种数据源和格式。

## 架构

```
DataIngestionManager (统一管理器)
    ↓
BaseConnector (抽象连接器)
    ├── FileConnector (文件)
    ├── DatabaseConnector (数据库)
    ├── APIConnector (API)
    └── StreamConnector (流数据)
    ↓
BaseParser (抽象解析器)
    ├── JSONParser
    ├── CSVParser
    ├── XMLParser
    ├── ExcelParser
    └── LogParser
    ↓
BaseTransformer (抽象转换器)
    ├── GenericTransformer
    └── SecurityLogTransformer
```

## 支持的数据源

### 1. 文件数据源
- **格式**: JSON, CSV, XML, Excel, 日志文件
- **特性**: 支持批量读取和流式读取

### 2. 数据库数据源
- **支持**: PostgreSQL, MySQL, SQLite, MongoDB
- **特性**: SQL查询、流式游标、连接池

### 3. API数据源
- **支持**: REST API
- **特性**: 认证（Bearer, Basic）、分页、自定义请求头

### 4. 流数据源
- **支持**: WebSocket, Kafka, RabbitMQ
- **特性**: 实时数据流、批量处理

## 快速开始

### 安装依赖

```bash
# 基础依赖
pip install aiofiles

# 文件解析
pip install openpyxl  # Excel支持

# 数据库
pip install asyncpg    # PostgreSQL
pip install aiomysql   # MySQL
pip install motor      # MongoDB

# API和流
pip install aiohttp    # HTTP客户端
pip install websockets # WebSocket
pip install aiokafka   # Kafka
```

### 基本使用

```python
from src.data_ingestion import DataIngestionManager, DataFormat

# 创建管理器
manager = DataIngestionManager()

# 从JSON文件接入
data = await manager.ingest_from_file(
    file_path="logs.json",
    format=DataFormat.JSON,
    transformer_name='security_log'
)

# 从API接入
data = await manager.ingest_from_api(
    base_url="https://api.example.com",
    endpoint="/logs",
    auth={"type": "bearer", "token": "your_token"}
)

# 从数据库接入
data = await manager.ingest_from_database(
    connection_string="postgresql://user:pass@localhost/db",
    query={"sql": "SELECT * FROM logs LIMIT 100"}
)
```

## 详细示例

### 1. 文件接入

#### JSON文件
```python
data = await manager.ingest_from_file(
    file_path="data.json",
    format=DataFormat.JSON,
    transformer_name='generic'
)
```

#### CSV文件
```python
data = await manager.ingest_from_file(
    file_path="data.csv",
    format=DataFormat.CSV,
    parser_options={'has_header': True, 'delimiter': ','},
    transformer_name='generic'
)
```

#### Excel文件
```python
data = await manager.ingest_from_file(
    file_path="data.xlsx",
    format=DataFormat.EXCEL,
    parser_options={'sheet_name': 'Sheet1', 'has_header': True}
)
```

### 2. API接入

#### 基本GET请求
```python
data = await manager.ingest_from_api(
    base_url="https://api.example.com",
    endpoint="/data",
    method="GET",
    params={"limit": 100}
)
```

#### 带认证的POST请求
```python
data = await manager.ingest_from_api(
    base_url="https://api.example.com",
    endpoint="/data",
    method="POST",
    body={"query": "value"},
    auth={
        "type": "bearer",
        "token": "your_access_token"
    },
    headers={
        "Content-Type": "application/json"
    }
)
```

### 3. 数据库接入

#### PostgreSQL
```python
data = await manager.ingest_from_database(
    connection_string="postgresql://user:password@localhost:5432/dbname",
    query={
        "sql": "SELECT * FROM logs WHERE timestamp > NOW() - INTERVAL '1 day'"
    },
    db_type="postgresql"
)
```

#### MongoDB
```python
data = await manager.ingest_from_database(
    connection_string="mongodb://localhost:27017",
    query={
        "database": "mydb",
        "collection": "logs",
        "filter": {"status": "active"}
    },
    db_type="mongodb"
)
```

### 4. 流式接入

```python
# 创建流连接器
connector = manager.create_stream_connector(
    name="websocket_stream",
    stream_url="ws://example.com/stream",
    stream_type="websocket"
)

# 流式接收数据
async for batch in manager.ingest_stream(
    connector_name="websocket_stream",
    transformer_name='security_log',
    max_batches=10
):
    print(f"接收到 {len(batch)} 条数据")
    # 处理数据...
```

### 5. 批量接入

```python
sources = [
    {
        'type': 'file',
        'name': 'json_logs',
        'file_path': 'logs.json',
        'format': 'JSON',
        'transformer': 'security_log'
    },
    {
        'type': 'api',
        'name': 'api_logs',
        'base_url': 'https://api.example.com',
        'endpoint': '/logs',
        'transformer': 'security_log'
    }
]

results = await manager.batch_ingest(sources)
for name, data in results.items():
    print(f"{name}: {len(data)} 条数据")
```

## 自定义扩展

### 自定义连接器

```python
from src.data_ingestion.base import BaseConnector, DataBatch

class CustomConnector(BaseConnector):
    async def connect(self) -> bool:
        # 实现连接逻辑
        pass

    async def disconnect(self) -> bool:
        # 实现断开逻辑
        pass

    async def fetch_data(self, query=None, limit=None) -> DataBatch:
        # 实现数据获取逻辑
        pass

    async def fetch_stream(self, query=None):
        # 实现流式获取逻辑
        pass
```

### 自定义解析器

```python
from src.data_ingestion.base import BaseParser

class CustomParser(BaseParser):
    async def parse(self, raw_data, options=None):
        # 实现解析逻辑
        return parsed_data

    def validate_format(self, raw_data) -> bool:
        # 实现格式验证
        return True
```

### 自定义转换器

```python
from src.data_ingestion.base import BaseTransformer

class CustomTransformer(BaseTransformer):
    async def transform(self, data, schema=None):
        # 实现转换逻辑
        return transformed_data

    def validate_schema(self, data) -> bool:
        # 实现模式验证
        return True

    def transform_single(self, item):
        # 转换单条数据
        return transformed_item
```

## 配置选项

### ConnectorConfig

```python
from src.data_ingestion import ConnectorConfig, DataSourceType

config = ConnectorConfig(
    source_type=DataSourceType.FILE,
    connection_params={},
    retry_count=3,          # 重试次数
    timeout=30,             # 超时时间（秒）
    batch_size=1000,        # 批量大小
    enable_cache=True,      # 启用缓存
    metadata={}             # 元数据
)
```

## 最佳实践

1. **使用异步上下文管理器**
   ```python
   async with connector:
       data = await connector.fetch_data()
   ```

2. **流式处理大数据**
   ```python
   async for batch in connector.fetch_stream():
       process_batch(batch)
   ```

3. **批量接入多个数据源**
   ```python
   results = await manager.batch_ingest(sources)
   ```

4. **错误处理**
   ```python
   try:
       data = await manager.ingest_from_file(file_path)
   except FileNotFoundError:
       # 处理文件不存在
   except ConnectionError:
       # 处理连接错误
   ```

## 性能优化

1. **调整批量大小**: 根据数据量调整`batch_size`
2. **启用缓存**: 对于重复查询启用`enable_cache`
3. **并发接入**: 使用`batch_ingest`并发处理多个数据源
4. **流式处理**: 对于大数据使用`fetch_stream`而不是`fetch_data`

## 故障排除

### 常见问题

1. **导入错误**: 确保安装了所需的依赖库
2. **连接超时**: 增加`timeout`配置
3. **内存不足**: 使用流式接入或减小`batch_size`
4. **解析失败**: 检查数据格式和解析器选项

## 示例代码

完整示例请参考: `examples/data_ingestion_examples.py`

```bash
python examples/data_ingestion_examples.py
```