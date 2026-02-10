"""
分析任务Job

负责触发安全分析
"""
from typing import Any, Dict, List, Optional
from datetime import datetime

from ..base import BaseJob
from ...core.base import AgentState
from security_analysis.architecture_v2 import (
    SecurityAnalysisSystem,
    SecurityLog,
    AnalysisType
)


class AnalysisJob(BaseJob):
    """
    安全分析Job

    执行安全分析任务
    """

    def __init__(
        self,
        job_id: str,
        analysis_type: str,
        use_mock: bool = True,
        api_keys: Optional[Dict[str, str]] = None,
        name: str = "Analysis Job"
    ):
        """
        初始化分析Job

        Args:
            job_id: 任务ID
            analysis_type: 分析类型
            use_mock: 是否使用模拟模式
            api_keys: API密钥
            name: 任务名称
        """
        super().__init__(
            job_id=job_id,
            name=name,
            description=f"执行{analysis_type}分析"
        )
        self.analysis_type = analysis_type
        self.use_mock = use_mock
        self.api_keys = api_keys or {}

        # 初始化分析系统
        self.analysis_system = SecurityAnalysisSystem(
            use_mock=use_mock,
            api_keys=api_keys
        )

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行分析

        Args:
            context: 执行上下文，应包含 'logs' 键

        Returns:
            分析结果
        """
        # 从上下文获取日志数据
        logs_data = context.get("logs", [])

        if not logs_data:
            raise ValueError("No logs data provided in context")

        # 转换为SecurityLog对象
        logs = self._convert_to_security_logs(logs_data)

        # 执行分析
        start_time = datetime.now()
        result = await self.analysis_system.analyze(
            self.analysis_type,
            logs
        )
        end_time = datetime.now()

        # 构建返回结果
        return {
            "job_id": self.job_id,
            "analysis_type": self.analysis_type,
            "log_count": len(logs),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration": (end_time - start_time).total_seconds(),
            "confidence": result.confidence,
            "findings_count": len(result.findings),
            "evidence_count": len(result.evidence),
            "result": result
        }

    def _convert_to_security_logs(self, logs_data: List[Dict]) -> List[SecurityLog]:
        """
        将原始日志数据转换为SecurityLog对象

        Args:
            logs_data: 原始日志数据

        Returns:
            SecurityLog对象列表
        """
        security_logs = []

        for log_data in logs_data:
            try:
                # 解析时间戳
                timestamp = log_data.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp)
                elif not isinstance(timestamp, datetime):
                    timestamp = datetime.now()

                # 创建SecurityLog对象
                security_log = SecurityLog(
                    log_type=log_data.get("log_type", "unknown"),
                    timestamp=timestamp,
                    source_ip=log_data.get("source_ip", "0.0.0.0"),
                    dest_ip=log_data.get("dest_ip", "0.0.0.0"),
                    source_port=log_data.get("source_port"),
                    dest_port=log_data.get("dest_port"),
                    protocol=log_data.get("protocol"),
                    action=log_data.get("action"),
                    raw_data=log_data.get("raw_data", {})
                )

                security_logs.append(security_log)
            except Exception as e:
                print(f"警告: 无法解析日志数据: {e}")
                continue

        return security_logs

    async def on_success(self, result: Any, context: Dict[str, Any]):
        """分析成功回调"""
        print(f"[{datetime.now()}] {self.name} 完成")
        print(f"  - 分析类型: {result['analysis_type']}")
        print(f"  - 日志数量: {result['log_count']}")
        print(f"  - 置信度: {result['confidence']}")
        print(f"  - 发现数: {result['findings_count']}")
        print(f"  - 执行时长: {result['duration']:.2f}秒")

    async def on_failure(self, error: Exception, context: Dict[str, Any]):
        """分析失败回调"""
        print(f"[{datetime.now()}] {self.name} 失败: {error}")


class BatchAnalysisJob(BaseJob):
    """
    批量分析Job

    支持对同一批日志执行多种分析
    """

    def __init__(
        self,
        job_id: str,
        analysis_types: List[str],
        use_mock: bool = True,
        api_keys: Optional[Dict[str, str]] = None,
        name: str = "Batch Analysis Job"
    ):
        """
        初始化批量分析Job

        Args:
            job_id: 任务ID
            analysis_types: 分析类型列表
            use_mock: 是否使用模拟模式
            api_keys: API密钥
            name: 任务名称
        """
        super().__init__(
            job_id=job_id,
            name=name,
            description=f"批量执行{len(analysis_types)}种分析"
        )
        self.analysis_types = analysis_types
        self.use_mock = use_mock
        self.api_keys = api_keys or {}

        # 初始化分析系统
        self.analysis_system = SecurityAnalysisSystem(
            use_mock=use_mock,
            api_keys=api_keys
        )

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行批量分析

        Args:
            context: 执行上下文，应包含 'logs' 键

        Returns:
            批量分析结果
        """
        # 从上下文获取日志数据
        logs_data = context.get("logs", [])

        if not logs_data:
            raise ValueError("No logs data provided in context")

        # 转换为SecurityLog对象
        logs = self._convert_to_security_logs(logs_data)

        # 执行批量分析
        start_time = datetime.now()
        results = await self.analysis_system.batch_analyze(
            self.analysis_types,
            logs
        )
        end_time = datetime.now()

        # 构建返回结果
        return {
            "job_id": self.job_id,
            "analysis_types": self.analysis_types,
            "log_count": len(logs),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration": (end_time - start_time).total_seconds(),
            "results": results
        }

    def _convert_to_security_logs(self, logs_data: List[Dict]) -> List[SecurityLog]:
        """将原始日志数据转换为SecurityLog对象"""
        security_logs = []

        for log_data in logs_data:
            try:
                timestamp = log_data.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp)
                elif not isinstance(timestamp, datetime):
                    timestamp = datetime.now()

                security_log = SecurityLog(
                    log_type=log_data.get("log_type", "unknown"),
                    timestamp=timestamp,
                    source_ip=log_data.get("source_ip", "0.0.0.0"),
                    dest_ip=log_data.get("dest_ip", "0.0.0.0"),
                    source_port=log_data.get("source_port"),
                    dest_port=log_data.get("dest_port"),
                    protocol=log_data.get("protocol"),
                    action=log_data.get("action"),
                    raw_data=log_data.get("raw_data", {})
                )

                security_logs.append(security_log)
            except Exception as e:
                print(f"警告: 无法解析日志数据: {e}")
                continue

        return security_logs

    async def on_success(self, result: Any, context: Dict[str, Any]):
        """批量分析成功回调"""
        print(f"[{datetime.now()}] {self.name} 完成")
        print(f"  - 分析类型数: {len(result['analysis_types'])}")
        print(f"  - 日志数量: {result['log_count']}")
        print(f"  - 执行时长: {result['duration']:.2f}秒")

        for analysis_type, analysis_result in result['results'].items():
            print(f"  - {analysis_type}: 置信度 {analysis_result.confidence}")


class DataFetchAndAnalysisJob(BaseJob):
    """
    数据拉取和分析组合Job

    先拉取数据，然后自动触发分析
    """

    def __init__(
        self,
        job_id: str,
        fetch_job: 'BaseFetchJob',
        analysis_types: List[str],
        use_mock: bool = True,
        api_keys: Optional[Dict[str, str]] = None,
        name: str = "Fetch and Analysis Job"
    ):
        """
        初始化组合Job

        Args:
            job_id: 任务ID
            fetch_job: 数据拉取Job
            analysis_types: 分析类型列表
            use_mock: 是否使用模拟模式
            api_keys: API密钥
            name: 任务名称
        """
        super().__init__(
            job_id=job_id,
            name=name,
            description="拉取数据并执行分析"
        )
        self.fetch_job = fetch_job
        self.analysis_types = analysis_types
        self.use_mock = use_mock
        self.api_keys = api_keys or {}

        # 初始化分析系统
        self.analysis_system = SecurityAnalysisSystem(
            use_mock=use_mock,
            api_keys=api_keys
        )

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行数据拉取和分析

        Args:
            context: 执行上下文

        Returns:
            组合执行结果
        """
        # 第一步：拉取数据
        print(f"[{datetime.now()}] 开始拉取数据...")
        fetch_result = await self.fetch_job.execute(context)
        logs_data = fetch_result.get("data", [])

        print(f"[{datetime.now()}] 拉取到 {len(logs_data)} 条记录")

        # 第二步：执行分析
        print(f"[{datetime.now()}] 开始执行分析...")

        # 转换为SecurityLog对象
        logs = self._convert_to_security_logs(logs_data)

        # 执行批量分析
        start_time = datetime.now()
        results = await self.analysis_system.batch_analyze(
            self.analysis_types,
            logs
        )
        end_time = datetime.now()

        # 构建返回结果
        return {
            "job_id": self.job_id,
            "fetch_result": fetch_result,
            "analysis_types": self.analysis_types,
            "log_count": len(logs),
            "analysis_start_time": start_time.isoformat(),
            "analysis_end_time": end_time.isoformat(),
            "analysis_duration": (end_time - start_time).total_seconds(),
            "analysis_results": results
        }

    def _convert_to_security_logs(self, logs_data: List[Dict]) -> List[SecurityLog]:
        """将原始日志数据转换为SecurityLog对象"""
        security_logs = []

        for log_data in logs_data:
            try:
                timestamp = log_data.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp)
                elif not isinstance(timestamp, datetime):
                    timestamp = datetime.now()

                security_log = SecurityLog(
                    log_type=log_data.get("log_type", "unknown"),
                    timestamp=timestamp,
                    source_ip=log_data.get("source_ip", "0.0.0.0"),
                    dest_ip=log_data.get("dest_ip", "0.0.0.0"),
                    source_port=log_data.get("source_port"),
                    dest_port=log_data.get("dest_port"),
                    protocol=log_data.get("protocol"),
                    action=log_data.get("action"),
                    raw_data=log_data.get("raw_data", {})
                )

                security_logs.append(security_log)
            except Exception as e:
                print(f"警告: 无法解析日志数据: {e}")
                continue

        return security_logs

    async def on_success(self, result: Any, context: Dict[str, Any]):
        """组合任务成功回调"""
        print(f"[{datetime.now()}] {self.name} 完成")
        print(f"  - 拉取记录数: {result['fetch_result']['record_count']}")
        print(f"  - 分析类型数: {len(result['analysis_types'])}")
        print(f"  - 分析时长: {result['analysis_duration']:.2f}秒")
