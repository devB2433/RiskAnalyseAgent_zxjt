"""
数据拉取Job基类和具体实现
"""
import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime

from ..base import BaseJob
from ...data_ingestion.manager import DataIngestionManager
from ...data_ingestion.connectors import (
    FileConnector,
    DatabaseConnector,
    APIConnector
)


class BaseFetchJob(BaseJob):
    """
    数据拉取Job基类

    所有数据拉取任务都应该继承此类
    """

    def __init__(
        self,
        job_id: str,
        name: str,
        description: str = "",
        max_retries: int = 3,
        retry_delay: int = 60
    ):
        super().__init__(
            job_id=job_id,
            name=name,
            description=description,
            max_retries=max_retries,
            retry_delay=retry_delay
        )
        self.data_manager = DataIngestionManager()
        self.fetched_data: List[Any] = []

    async def fetch_data(self, context: Dict[str, Any]) -> List[Any]:
        """
        拉取数据（子类需要实现）

        Args:
            context: 执行上下文

        Returns:
            拉取到的数据列表
        """
        raise NotImplementedError("Subclass must implement fetch_data method")

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行数据拉取

        Args:
            context: 执行上下文

        Returns:
            拉取结果
        """
        start_time = datetime.now()

        # 拉取数据
        self.fetched_data = await self.fetch_data(context)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        result = {
            "job_id": self.job_id,
            "job_name": self.name,
            "record_count": len(self.fetched_data),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration": duration,
            "data": self.fetched_data
        }

        return result

    async def on_success(self, result: Any, context: Dict[str, Any]):
        """数据拉取成功回调"""
        print(f"[{datetime.now()}] {self.name} 成功拉取 {result['record_count']} 条记录")

    async def on_failure(self, error: Exception, context: Dict[str, Any]):
        """数据拉取失败回调"""
        print(f"[{datetime.now()}] {self.name} 拉取失败: {error}")

    async def on_retry(self, error: Exception, retry_count: int, context: Dict[str, Any]):
        """数据拉取重试回调"""
        print(f"[{datetime.now()}] {self.name} 第{retry_count}次重试...")


class DatabaseFetchJob(BaseFetchJob):
    """
    数据库数据拉取Job

    从数据库拉取数据
    """

    def __init__(
        self,
        job_id: str,
        db_config: Dict[str, Any],
        query: str,
        name: str = "Database Fetch Job"
    ):
        """
        初始化数据库拉取Job

        Args:
            job_id: 任务ID
            db_config: 数据库配置
            query: SQL查询语句
            name: 任务名称
        """
        super().__init__(
            job_id=job_id,
            name=name,
            description=f"从数据库拉取数据: {query[:50]}..."
        )
        self.db_config = db_config
        self.query = query

    async def fetch_data(self, context: Dict[str, Any]) -> List[Any]:
        """从数据库拉取数据"""
        # 创建数据库连接器
        connector = DatabaseConnector(self.db_config)

        # 连接数据库
        await connector.connect()

        try:
            # 执行查询
            data = await connector.fetch(self.query)
            return data
        finally:
            # 关闭连接
            await connector.disconnect()


class APIFetchJob(BaseFetchJob):
    """
    API数据拉取Job

    从API拉取数据
    """

    def __init__(
        self,
        job_id: str,
        api_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        name: str = "API Fetch Job"
    ):
        """
        初始化API拉取Job

        Args:
            job_id: 任务ID
            api_url: API URL
            method: HTTP方法
            headers: HTTP头
            params: 请求参数
            name: 任务名称
        """
        super().__init__(
            job_id=job_id,
            name=name,
            description=f"从API拉取数据: {api_url}"
        )
        self.api_url = api_url
        self.method = method
        self.headers = headers or {}
        self.params = params or {}

    async def fetch_data(self, context: Dict[str, Any]) -> List[Any]:
        """从API拉取数据"""
        # 创建API连接器
        connector = APIConnector({
            "base_url": self.api_url,
            "headers": self.headers
        })

        # 连接API
        await connector.connect()

        try:
            # 发送请求
            data = await connector.fetch(
                endpoint="",
                method=self.method,
                params=self.params
            )

            # 如果返回的是字典，转换为列表
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
            else:
                return [data]
        finally:
            # 关闭连接
            await connector.disconnect()


class FileFetchJob(BaseFetchJob):
    """
    文件数据拉取Job

    从文件拉取数据
    """

    def __init__(
        self,
        job_id: str,
        file_path: str,
        file_type: str = "json",
        name: str = "File Fetch Job"
    ):
        """
        初始化文件拉取Job

        Args:
            job_id: 任务ID
            file_path: 文件路径
            file_type: 文件类型 (json, csv, xml, excel)
            name: 任务名称
        """
        super().__init__(
            job_id=job_id,
            name=name,
            description=f"从文件拉取数据: {file_path}"
        )
        self.file_path = file_path
        self.file_type = file_type

    async def fetch_data(self, context: Dict[str, Any]) -> List[Any]:
        """从文件拉取数据"""
        # 创建文件连接器
        connector = FileConnector({
            "base_path": "."
        })

        # 连接（文件连接器不需要实际连接）
        await connector.connect()

        try:
            # 读取文件
            data = await connector.fetch(self.file_path)

            # 根据文件类型解析数据
            if self.file_type == "json":
                from ...data_ingestion.parsers import JSONParser
                parser = JSONParser()
                parsed_data = await parser.parse(data)
            elif self.file_type == "csv":
                from ...data_ingestion.parsers import CSVParser
                parser = CSVParser()
                parsed_data = await parser.parse(data)
            elif self.file_type == "xml":
                from ...data_ingestion.parsers import XMLParser
                parser = XMLParser()
                parsed_data = await parser.parse(data)
            elif self.file_type == "excel":
                from ...data_ingestion.parsers import ExcelParser
                parser = ExcelParser()
                parsed_data = await parser.parse(data)
            else:
                # 默认返回原始数据
                parsed_data = [data]

            return parsed_data
        finally:
            # 关闭连接
            await connector.disconnect()


class BatchFetchJob(BaseFetchJob):
    """
    批量数据拉取Job

    支持从多个数据源批量拉取数据
    """

    def __init__(
        self,
        job_id: str,
        fetch_jobs: List[BaseFetchJob],
        name: str = "Batch Fetch Job"
    ):
        """
        初始化批量拉取Job

        Args:
            job_id: 任务ID
            fetch_jobs: 要执行的拉取任务列表
            name: 任务名称
        """
        super().__init__(
            job_id=job_id,
            name=name,
            description=f"批量拉取数据，共{len(fetch_jobs)}个任务"
        )
        self.fetch_jobs = fetch_jobs

    async def fetch_data(self, context: Dict[str, Any]) -> List[Any]:
        """批量拉取数据"""
        all_data = []

        # 并发执行所有拉取任务
        tasks = [job.fetch_data(context) for job in self.fetch_jobs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 收集所有成功的结果
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"任务 {self.fetch_jobs[i].name} 失败: {result}")
            else:
                all_data.extend(result)

        return all_data
