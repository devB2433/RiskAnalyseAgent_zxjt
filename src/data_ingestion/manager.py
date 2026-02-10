"""
数据接入管理器
统一管理所有数据源的接入
"""
from typing import Any, Dict, List, Optional, AsyncIterator
import asyncio

from .base import (
    BaseConnector,
    BaseParser,
    BaseTransformer,
    DataSource,
    DataBatch,
    ConnectorConfig,
    DataSourceType,
    DataFormat
)
from .connectors import (
    FileConnector,
    DatabaseConnector,
    APIConnector,
    StreamConnector
)
from .parsers import (
    CSVParser,
    JSONParser,
    XMLParser,
    ExcelParser,
    LogParser
)
from .transformers import (
    GenericTransformer,
    SecurityLogTransformer
)


class DataIngestionManager:
    """数据接入管理器"""

    def __init__(self):
        self.connectors: Dict[str, BaseConnector] = {}
        self.parsers: Dict[DataFormat, BaseParser] = {
            DataFormat.CSV: CSVParser(),
            DataFormat.JSON: JSONParser(),
            DataFormat.XML: XMLParser(),
            DataFormat.EXCEL: ExcelParser(),
            DataFormat.LOG: LogParser(),
        }
        self.transformers: Dict[str, BaseTransformer] = {
            'generic': GenericTransformer(),
            'security_log': SecurityLogTransformer(),
        }

    def register_connector(self, name: str, connector: BaseConnector):
        """注册连接器"""
        self.connectors[name] = connector

    def register_parser(self, format: DataFormat, parser: BaseParser):
        """注册解析器"""
        self.parsers[format] = parser

    def register_transformer(self, name: str, transformer: BaseTransformer):
        """注册转换器"""
        self.transformers[name] = transformer

    def create_file_connector(
        self,
        name: str,
        file_path: str,
        format: DataFormat = DataFormat.JSON,
        config: Optional[ConnectorConfig] = None
    ) -> FileConnector:
        """创建文件连接器"""
        if config is None:
            config = ConnectorConfig(source_type=DataSourceType.FILE)

        connector = FileConnector(config, file_path, format)
        self.register_connector(name, connector)
        return connector

    def create_database_connector(
        self,
        name: str,
        connection_string: str,
        db_type: str = "postgresql",
        config: Optional[ConnectorConfig] = None
    ) -> DatabaseConnector:
        """创建数据库连接器"""
        if config is None:
            config = ConnectorConfig(source_type=DataSourceType.DATABASE)

        connector = DatabaseConnector(config, connection_string, db_type)
        self.register_connector(name, connector)
        return connector

    def create_api_connector(
        self,
        name: str,
        base_url: str,
        auth: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        config: Optional[ConnectorConfig] = None
    ) -> APIConnector:
        """创建API连接器"""
        if config is None:
            config = ConnectorConfig(source_type=DataSourceType.API)

        connector = APIConnector(config, base_url, auth, headers)
        self.register_connector(name, connector)
        return connector

    def create_stream_connector(
        self,
        name: str,
        stream_url: str,
        stream_type: str = "websocket",
        config: Optional[ConnectorConfig] = None
    ) -> StreamConnector:
        """创建流连接器"""
        if config is None:
            config = ConnectorConfig(source_type=DataSourceType.STREAM)

        connector = StreamConnector(config, stream_url, stream_type)
        self.register_connector(name, connector)
        return connector

    async def ingest_from_file(
        self,
        file_path: str,
        format: DataFormat = DataFormat.JSON,
        parser_options: Optional[Dict[str, Any]] = None,
        transformer_name: str = 'generic',
        transform_schema: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """从文件接入数据"""
        # 创建连接器
        config = ConnectorConfig(source_type=DataSourceType.FILE)
        connector = FileConnector(config, file_path, format)

        # 获取数据
        async with connector:
            batch = await connector.fetch_data()

        # 解析数据
        parser = self.parsers.get(format)
        if parser and batch.data:
            parsed_data = []
            for item in batch.data:
                if 'raw' in item:
                    parsed = await parser.parse(item['raw'], parser_options)
                    parsed_data.extend(parsed)
                else:
                    parsed_data.append(item)
        else:
            parsed_data = batch.data

        # 转换数据
        transformer = self.transformers.get(transformer_name)
        if transformer:
            return await transformer.transform(parsed_data, transform_schema)
        else:
            return parsed_data

    async def ingest_from_database(
        self,
        connection_string: str,
        query: Dict[str, Any],
        db_type: str = "postgresql",
        transformer_name: str = 'generic',
        transform_schema: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """从数据库接入数据"""
        config = ConnectorConfig(source_type=DataSourceType.DATABASE)
        connector = DatabaseConnector(config, connection_string, db_type)

        async with connector:
            batch = await connector.fetch_data(query)

        # 转换数据
        transformer = self.transformers.get(transformer_name)
        if transformer:
            return await transformer.transform(batch.data, transform_schema)
        else:
            return batch.data

    async def ingest_from_api(
        self,
        base_url: str,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        auth: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        transformer_name: str = 'generic',
        transform_schema: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """从API接入数据"""
        config = ConnectorConfig(source_type=DataSourceType.API)
        connector = APIConnector(config, base_url, auth, headers)

        query = {
            "endpoint": endpoint,
            "method": method,
            "params": params or {},
            "body": body or {}
        }

        async with connector:
            batch = await connector.fetch_data(query)

        # 转换数据
        transformer = self.transformers.get(transformer_name)
        if transformer:
            return await transformer.transform(batch.data, transform_schema)
        else:
            return batch.data

    async def ingest_stream(
        self,
        connector_name: str,
        query: Optional[Dict[str, Any]] = None,
        transformer_name: str = 'generic',
        transform_schema: Optional[Dict[str, Any]] = None,
        max_batches: Optional[int] = None
    ) -> AsyncIterator[List[Any]]:
        """流式接入数据"""
        connector = self.connectors.get(connector_name)
        if not connector:
            raise ValueError(f"连接器不存在: {connector_name}")

        transformer = self.transformers.get(transformer_name)
        batch_count = 0

        async with connector:
            async for batch in connector.fetch_stream(query):
                if transformer:
                    transformed = await transformer.transform(batch.data, transform_schema)
                    yield transformed
                else:
                    yield batch.data

                batch_count += 1
                if max_batches and batch_count >= max_batches:
                    break

    async def batch_ingest(
        self,
        sources: List[Dict[str, Any]]
    ) -> Dict[str, List[Any]]:
        """批量接入多个数据源"""
        tasks = []
        source_names = []

        for source in sources:
            source_type = source.get('type')
            name = source.get('name', f'source_{len(tasks)}')
            source_names.append(name)

            if source_type == 'file':
                task = self.ingest_from_file(
                    file_path=source['file_path'],
                    format=DataFormat[source.get('format', 'JSON').upper()],
                    parser_options=source.get('parser_options'),
                    transformer_name=source.get('transformer', 'generic'),
                    transform_schema=source.get('schema')
                )
            elif source_type == 'database':
                task = self.ingest_from_database(
                    connection_string=source['connection_string'],
                    query=source['query'],
                    db_type=source.get('db_type', 'postgresql'),
                    transformer_name=source.get('transformer', 'generic'),
                    transform_schema=source.get('schema')
                )
            elif source_type == 'api':
                task = self.ingest_from_api(
                    base_url=source['base_url'],
                    endpoint=source['endpoint'],
                    method=source.get('method', 'GET'),
                    params=source.get('params'),
                    body=source.get('body'),
                    auth=source.get('auth'),
                    headers=source.get('headers'),
                    transformer_name=source.get('transformer', 'generic'),
                    transform_schema=source.get('schema')
                )
            else:
                continue

            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            name: result if not isinstance(result, Exception) else []
            for name, result in zip(source_names, results)
        }


__all__ = ['DataIngestionManager']