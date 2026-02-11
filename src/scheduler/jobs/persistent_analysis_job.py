"""
持久化分析Job

集成存储系统，分析结果自动保存到数据库
"""
from typing import Any, Dict, List, Optional
from datetime import datetime

from ..base import BaseJob
from ...storage.service import StorageService
from security_analysis.architecture_v2 import (
    SecurityAnalysisSystem,
    SecurityLog,
    AnalysisType
)


class PersistentAnalysisJob(BaseJob):
    """
    持久化分析Job

    执行分析后自动将结果保存到数据库，
    并根据置信度自动生成告警
    """

    def __init__(
        self,
        job_id: str,
        analysis_type: str,
        storage_service: StorageService,
        use_mock: bool = True,
        api_keys: Optional[Dict[str, str]] = None,
        alert_threshold: float = 0.6,
        name: str = "Persistent Analysis Job"
    ):
        super().__init__(
            job_id=job_id,
            name=name,
            description=f"执行{analysis_type}分析并持久化结果"
        )
        self.analysis_type = analysis_type
        self.storage = storage_service
        self.alert_threshold = alert_threshold
        self.analysis_system = SecurityAnalysisSystem(
            use_mock=use_mock,
            api_keys=api_keys
        )

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logs_data = context.get("logs", [])
        if not logs_data:
            raise ValueError("No logs data provided in context")

        logs = self._convert_to_security_logs(logs_data)

        # 保存任务开始记录
        self.storage.save_task_history(
            job_id=self.job_id,
            job_name=self.name,
            job_type="analysis",
            status="running",
            start_time=datetime.now()
        )

        start_time = datetime.now()
        try:
            result = await self.analysis_system.analyze(self.analysis_type, logs)
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # 保存分析结果到数据库
            result_id = self.storage.save_analysis_result(
                job_id=self.job_id,
                analysis_type=self.analysis_type,
                status="success",
                confidence=result.confidence,
                log_count=len(logs),
                findings_count=len(result.findings),
                evidence_count=len(result.evidence),
                result_data={"recommendations": result.recommendations},
                trace_data=result.trace if hasattr(result, 'trace') else None,
                start_time=start_time,
                end_time=end_time,
                duration=duration
            )

            # 根据置信度自动生成告警
            alert_id = None
            if result.confidence >= self.alert_threshold:
                severity = self._determine_severity(result.confidence)
                alert_id = self.storage.save_alert(
                    analysis_result_id=result_id,
                    alert_type=self.analysis_type,
                    severity=severity,
                    title=f"[{severity.upper()}] {self.analysis_type} 检测到安全威胁",
                    description=f"置信度: {result.confidence:.2f}, 发现 {len(result.findings)} 个问题",
                    confidence=result.confidence,
                    evidence=result.evidence[:10] if result.evidence else None,
                    recommendations=result.recommendations
                )

            # 保存IOC记录
            self._save_ioc_records(result, result_id)

            # 更新任务历史
            self.storage.save_task_history(
                job_id=self.job_id,
                job_name=self.name,
                job_type="analysis",
                status="success",
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                result_data={
                    "result_id": result_id,
                    "alert_id": alert_id,
                    "confidence": result.confidence
                }
            )

            return {
                "job_id": self.job_id,
                "analysis_type": self.analysis_type,
                "result_id": result_id,
                "alert_id": alert_id,
                "log_count": len(logs),
                "confidence": result.confidence,
                "findings_count": len(result.findings),
                "duration": duration,
                "persisted": True
            }

        except Exception as e:
            end_time = datetime.now()
            self.storage.save_task_history(
                job_id=self.job_id,
                job_name=self.name,
                job_type="analysis",
                status="failed",
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                error_message=str(e)
            )
            raise

    def _determine_severity(self, confidence: float) -> str:
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.75:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        return "low"

    def _save_ioc_records(self, result, result_id: int):
        """从分析结果中提取并保存IOC"""
        if not hasattr(result, 'evidence') or not result.evidence:
            return

        for evidence_item in result.evidence:
            if isinstance(evidence_item, dict):
                ioc_type = evidence_item.get("ioc_type") or evidence_item.get("type")
                ioc_value = evidence_item.get("ioc_value") or evidence_item.get("ip") or evidence_item.get("value")
                if ioc_type and ioc_value:
                    self.storage.save_ioc(
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        is_malicious=evidence_item.get("is_malicious", False),
                        threat_score=evidence_item.get("threat_score", 0.0),
                        threat_types=evidence_item.get("threat_types"),
                        provider=evidence_item.get("provider"),
                        analysis_result_id=result_id
                    )

    def _convert_to_security_logs(self, logs_data: List[Dict]) -> List[SecurityLog]:
        security_logs = []
        for log_data in logs_data:
            try:
                timestamp = log_data.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp)
                elif not isinstance(timestamp, datetime):
                    timestamp = datetime.now()

                security_logs.append(SecurityLog(
                    log_type=log_data.get("log_type", "unknown"),
                    timestamp=timestamp,
                    source_ip=log_data.get("source_ip", "0.0.0.0"),
                    dest_ip=log_data.get("dest_ip", "0.0.0.0"),
                    source_port=log_data.get("source_port"),
                    dest_port=log_data.get("dest_port"),
                    protocol=log_data.get("protocol"),
                    action=log_data.get("action"),
                    raw_data=log_data.get("raw_data", {})
                ))
            except Exception:
                continue
        return security_logs
