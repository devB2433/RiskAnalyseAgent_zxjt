"""
连接器实现
"""
import asyncio
import aiofiles
import json
from typing import Any, Dict, List, Optional, AsyncIterator
from pathlib import Path
import uuid

from ..base import (
    BaseConnector,
    ConnectorConfig,
    DataBatch,
    DataSource,
    DataSourceType,
    DataFormat
)


class FileConnector(BaseConnector):
    """文件连接器"""

    def __init__(
        self,
        config: ConnectorConfig,
        file_path: str,
        format: DataFormat = DataFormat.JSON
    ):
        super().__init__(config)
        self.file_path = Path(file_path)
        self.format = format
        self.data_source = DataSource(
            name=self.file_path.name,
            source_type=DataSourceType.FILE,
            format=format,
            location=str(file_path),
            config=config
        )

    async def connect(self) -> bool:
        """检查文件是否存在"""
        if not self.file_path.exists():
            raise FileNotFoundError(f"文件不存在: {self.file_path}")
        self.is_connected = True
        return True

    async def disconnect(self) -> bool:
        """文件连接器无需断开"""
        self.is_connected = False
        return True

    async def fetch_data(
        self,
        query: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
    ) -> DataBatch:
        """读取文件数据"""
        if not self.is_connected:
            await self.connect()

        async with aiofiles.open(self.file_path, 'r', encoding='utf-8') as f:
            content = await f.read()

        # 根据格式解析数据
        if self.format == DataFormat.JSON:
            data = json.loads(content)
            if isinstance(data, dict):
                data = [data]
        elif self.format == DataFormat.CSV:
            # CSV解析将在Parser中处理
            data = [{"raw": content}]
        else:
            data = [{"raw": content}]

        if limit:
            data = data[:limit]

        return DataBatch(
            source=self.data_source,
            data=data,
            batch_id=str(uuid.uuid4()),
            metadata={"file_path": str(self.file_path)}
        )

    async def fetch_stream(
        self,
        query: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[DataBatch]:
        """流式读取文件（按行）"""
        if not self.is_connected:
            await self.connect()

        batch_size = self.config.batch_size
        batch_data = []

        async with aiofiles.open(self.file_path, 'r', encoding='utf-8') as f:
            async for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    if self.format == DataFormat.JSON:
                        item = json.loads(line)
                    else:
                        item = {"raw": line}

                    batch_data.append(item)

                    if len(batch_data) >= batch_size:
                        yield DataBatch(
                            source=self.data_source,
                            data=batch_data,
                            batch_id=str(uuid.uuid4())
                        )
                        batch_data = []
                except Exception as e:
                    # 跳过解析失败的行
                    continue

        # 返回剩余数据
        if batch_data:
            yield DataBatch(
                source=self.data_source,
                data=batch_data,
                batch_id=str(uuid.uuid4())
            )


class DatabaseConnector(BaseConnector):
    """数据库连接器（支持多种数据库）"""

    def __init__(
        self,
        config: ConnectorConfig,
        connection_string: str,
        db_type: str = "postgresql"  # postgresql, mysql, sqlite, mongodb
    ):
        super().__init__(config)
        self.connection_string = connection_string
        self.db_type = db_type
        self.data_source = DataSource(
            name=f"{db_type}_database",
            source_type=DataSourceType.DATABASE,
            format=DataFormat.RAW,
            location=connection_string,
            config=config
        )

    async def connect(self) -> bool:
        """建立数据库连接"""
        try:
            if self.db_type in ["postgresql", "mysql", "sqlite"]:
                # 使用 asyncpg, aiomysql, aiosqlite
                # 这里提供接口，具体实现需要安装对应库
                self._connection = await self._create_sql_connection()
            elif self.db_type == "mongodb":
                # 使用 motor (MongoDB异步驱动)
                self._connection = await self._create_mongo_connection()
            else:
                raise ValueError(f"不支持的数据库类型: {self.db_type}")

            self.is_connected = True
            return True
        except Exception as e:
            raise ConnectionError(f"数据库连接失败: {e}")

    async def disconnect(self) -> bool:
        """断开数据库连接"""
        if self._connection:
            if self.db_type in ["postgresql", "mysql", "sqlite"]:
                await self._connection.close()
            elif self.db_type == "mongodb":
                self._connection.close()
            self._connection = None
        self.is_connected = False
        return True

    async def fetch_data(
        self,
        query: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
    ) -> DataBatch:
        """执行查询并获取数据"""
        if not self.is_connected:
            await self.connect()

        if self.db_type in ["postgresql", "mysql", "sqlite"]:
            data = await self._fetch_sql_data(query, limit)
        elif self.db_type == "mongodb":
            data = await self._fetch_mongo_data(query, limit)
        else:
            data = []

        return DataBatch(
            source=self.data_source,
            data=data,
            batch_id=str(uuid.uuid4()),
            metadata={"query": query, "db_type": self.db_type}
        )

    async def fetch_stream(
        self,
        query: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[DataBatch]:
        """流式获取数据库数据"""
        if not self.is_connected:
            await self.connect()

        batch_size = self.config.batch_size
        batch_data = []

        # 这里需要根据具体数据库实现游标流式读取
        # 示例实现
        async for row in self._stream_query(query):
            batch_data.append(row)

            if len(batch_data) >= batch_size:
                yield DataBatch(
                    source=self.data_source,
                    data=batch_data,
                    batch_id=str(uuid.uuid4())
                )
                batch_data = []

        if batch_data:
            yield DataBatch(
                source=self.data_source,
                data=batch_data,
                batch_id=str(uuid.uuid4())
            )

    async def _create_sql_connection(self):
        """创建SQL连接（需要安装对应库）"""
        # 示例：使用 asyncpg for PostgreSQL
        # import asyncpg
        # return await asyncpg.connect(self.connection_string)
        raise NotImplementedError(
            f"请安装 {self.db_type} 的异步驱动库。"
            f"PostgreSQL: asyncpg, MySQL: aiomysql, SQLite: aiosqlite"
        )

    async def _create_mongo_connection(self):
        """创建MongoDB连接（需要安装motor）"""
        # from motor.motor_asyncio import AsyncIOMotorClient
        # return AsyncIOMotorClient(self.connection_string)
        raise NotImplementedError("请安装 motor 库以支持 MongoDB")

    async def _fetch_sql_data(
        self,
        query: Optional[Dict[str, Any]],
        limit: Optional[int]
    ) -> List[Dict[str, Any]]:
        """获取SQL数据"""
        sql = query.get("sql", "SELECT * FROM table") if query else "SELECT * FROM table"
        if limit:
            sql += f" LIMIT {limit}"

        # 执行查询并返回结果
        # rows = await self._connection.fetch(sql)
        # return [dict(row) for row in rows]
        return []

    async def _fetch_mongo_data(
        self,
        query: Optional[Dict[str, Any]],
        limit: Optional[int]
    ) -> List[Dict[str, Any]]:
        """获取MongoDB数据"""
        collection_name = query.get("collection") if query else "default"
        filter_query = query.get("filter", {}) if query else {}

        # db = self._connection[query.get("database", "default")]
        # collection = db[collection_name]
        # cursor = collection.find(filter_query)
        # if limit:
        #     cursor = cursor.limit(limit)
        # return await cursor.to_list(length=limit)
        return []

    async def _stream_query(self, query: Optional[Dict[str, Any]]):
        """流式查询（示例）"""
        # 实际实现需要使用数据库游标
        for i in range(10):
            yield {"id": i, "data": f"row_{i}"}
            await asyncio.sleep(0.1)


class APIConnector(BaseConnector):
    """API连接器（支持REST API）"""

    def __init__(
        self,
        config: ConnectorConfig,
        base_url: str,
        auth: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        super().__init__(config)
        self.base_url = base_url.rstrip('/')
        self.auth = auth or {}
        self.headers = headers or {}
        self.session = None
        self.data_source = DataSource(
            name="api_endpoint",
            source_type=DataSourceType.API,
            format=DataFormat.JSON,
            location=base_url,
            config=config
        )

    async def connect(self) -> bool:
        """创建HTTP会话"""
        try:
            import aiohttp
            self.session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
            self.is_connected = True
            return True
        except ImportError:
            raise ImportError("请安装 aiohttp 库: pip install aiohttp")

    async def disconnect(self) -> bool:
        """关闭HTTP会话"""
        if self.session:
            await self.session.close()
            self.session = None
        self.is_connected = False
        return True

    async def fetch_data(
        self,
        query: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
    ) -> DataBatch:
        """从API获取数据"""
        if not self.is_connected:
            await self.connect()

        endpoint = query.get("endpoint", "") if query else ""
        method = query.get("method", "GET").upper() if query else "GET"
        params = query.get("params", {}) if query else {}
        body = query.get("body", {}) if query else {}

        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        # 添加认证
        if self.auth.get("type") == "bearer":
            self.headers["Authorization"] = f"Bearer {self.auth.get('token')}"
        elif self.auth.get("type") == "basic":
            import base64
            credentials = f"{self.auth.get('username')}:{self.auth.get('password')}"
            encoded = base64.b64encode(credentials.encode()).decode()
            self.headers["Authorization"] = f"Basic {encoded}"

        # 发送请求
        async with self.session.request(
            method,
            url,
            params=params,
            json=body if method in ["POST", "PUT", "PATCH"] else None
        ) as response:
            response.raise_for_status()
            data = await response.json()

            # 处理不同的响应格式
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                # 尝试从常见的数据字段中提取
                items = data.get("data", data.get("items", data.get("results", [data])))
            else:
                items = [{"raw": data}]

            if limit:
                items = items[:limit]

            return DataBatch(
                source=self.data_source,
                data=items,
                batch_id=str(uuid.uuid4()),
                metadata={
                    "url": url,
                    "method": method,
                    "status": response.status
                }
            )

    async def fetch_stream(
        self,
        query: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[DataBatch]:
        """流式获取API数据（分页）"""
        if not self.is_connected:
            await self.connect()

        endpoint = query.get("endpoint", "") if query else ""
        params = query.get("params", {}) if query else {}
        pagination = query.get("pagination", {}) if query else {}

        page = pagination.get("start_page", 1)
        page_size = pagination.get("page_size", self.config.batch_size)
        page_param = pagination.get("page_param", "page")
        size_param = pagination.get("size_param", "size")
        max_pages = pagination.get("max_pages", 100)

        for _ in range(max_pages):
            params[page_param] = page
            params[size_param] = page_size

            batch = await self.fetch_data({
                "endpoint": endpoint,
                "params": params,
                "method": "GET"
            })

            if not batch.data:
                break

            yield batch
            page += 1

            # 如果返回的数据少于page_size，说明已经到最后一页
            if len(batch.data) < page_size:
                break


class StreamConnector(BaseConnector):
    """流数据连接器（Kafka, WebSocket等）"""

    def __init__(
        self,
        config: ConnectorConfig,
        stream_url: str,
        stream_type: str = "websocket"  # websocket, kafka, rabbitmq
    ):
        super().__init__(config)
        self.stream_url = stream_url
        self.stream_type = stream_type
        self.data_source = DataSource(
            name=f"{stream_type}_stream",
            source_type=DataSourceType.STREAM,
            format=DataFormat.JSON,
            location=stream_url,
            config=config
        )

    async def connect(self) -> bool:
        """建立流连接"""
        if self.stream_type == "websocket":
            return await self._connect_websocket()
        elif self.stream_type == "kafka":
            return await self._connect_kafka()
        else:
            raise ValueError(f"不支持的流类型: {self.stream_type}")

    async def disconnect(self) -> bool:
        """断开流连接"""
        if self._connection:
            if self.stream_type == "websocket":
                await self._connection.close()
            elif self.stream_type == "kafka":
                await self._connection.stop()
            self._connection = None
        self.is_connected = False
        return True

    async def fetch_data(
        self,
        query: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
    ) -> DataBatch:
        """从流中获取一批数据"""
        data = []
        async for batch in self.fetch_stream(query):
            data.extend(batch.data)
            if limit and len(data) >= limit:
                data = data[:limit]
                break

        return DataBatch(
            source=self.data_source,
            data=data,
            batch_id=str(uuid.uuid4())
        )

    async def fetch_stream(
        self,
        query: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[DataBatch]:
        """流式接收数据"""
        if not self.is_connected:
            await self.connect()

        if self.stream_type == "websocket":
            async for batch in self._stream_websocket():
                yield batch
        elif self.stream_type == "kafka":
            async for batch in self._stream_kafka():
                yield batch

    async def _connect_websocket(self) -> bool:
        """连接WebSocket"""
        try:
            import websockets
            self._connection = await websockets.connect(self.stream_url)
            self.is_connected = True
            return True
        except ImportError:
            raise ImportError("请安装 websockets 库: pip install websockets")

    async def _connect_kafka(self) -> bool:
        """连接Kafka"""
        try:
            from aiokafka import AIOKafkaConsumer
            # 需要从config中获取topic等信息
            topic = self.config.connection_params.get("topic", "default")
            self._connection = AIOKafkaConsumer(
                topic,
                bootstrap_servers=self.stream_url
            )
            await self._connection.start()
            self.is_connected = True
            return True
        except ImportError:
            raise ImportError("请安装 aiokafka 库: pip install aiokafka")

    async def _stream_websocket(self) -> AsyncIterator[DataBatch]:
        """从WebSocket流式接收"""
        batch_data = []
        batch_size = self.config.batch_size

        async for message in self._connection:
            try:
                data = json.loads(message)
                batch_data.append(data)

                if len(batch_data) >= batch_size:
                    yield DataBatch(
                        source=self.data_source,
                        data=batch_data,
                        batch_id=str(uuid.uuid4())
                    )
                    batch_data = []
            except json.JSONDecodeError:
                continue

    async def _stream_kafka(self) -> AsyncIterator[DataBatch]:
        """从Kafka流式接收"""
        batch_data = []
        batch_size = self.config.batch_size

        async for message in self._connection:
            try:
                data = json.loads(message.value.decode('utf-8'))
                batch_data.append(data)

                if len(batch_data) >= batch_size:
                    yield DataBatch(
                        source=self.data_source,
                        data=batch_data,
                        batch_id=str(uuid.uuid4())
                    )
                    batch_data = []
            except Exception:
                continue


__all__ = [
    'FileConnector',
    'DatabaseConnector',
    'APIConnector',
    'StreamConnector',
]
