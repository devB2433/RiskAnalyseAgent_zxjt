"""
存储服务层

提供高级存储API，整合Repository操作
"""
import csv
import json
import os
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from contextlib import contextmanager

from .database import Database, get_database
from .models import (
    AnalysisResult, Alert, TaskHistory, IOCRecord,
    AnalysisStatus, SeverityLevel
)
from .repository import (
    AnalysisResultRepository,
    AlertRepository,
    TaskHistoryRepository,
    IOCRecordRepository,
    SystemConfigRepository
)


class StorageService:
    """
    存储服务

    提供统一的高级存储API，封装数据库操作
    """

    def __init__(self, database_url: str = "sqlite:///./security_analysis.db"):
        self.db = get_database(database_url)

    @contextmanager
    def _session(self):
        with self.db.get_session() as session:
            yield session

    # ==================== 分析结果 ====================

    def save_analysis_result(
        self,
        job_id: str,
        analysis_type: str,
        status: str = "success",
        confidence: float = 0.0,
        log_count: int = 0,
        findings_count: int = 0,
        evidence_count: int = 0,
        result_data: Optional[Dict] = None,
        trace_data: Optional[Dict] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        duration: Optional[float] = None
    ) -> int:
        """保存分析结果，返回记录ID"""
        with self._session() as session:
            repo = AnalysisResultRepository(session)
            record = AnalysisResult(
                job_id=job_id,
                analysis_type=analysis_type,
                status=AnalysisStatus(status),
                confidence=confidence,
                log_count=log_count,
                findings_count=findings_count,
                evidence_count=evidence_count,
                result_data=result_data,
                trace_data=trace_data,
                start_time=start_time or datetime.now(),
                end_time=end_time,
                duration=duration
            )
            repo.create(record)
            return record.id

    def get_analysis_results(
        self,
        analysis_type: Optional[str] = None,
        days: int = 7,
        limit: int = 100
    ) -> List[Dict]:
        """获取分析结果列表"""
        with self._session() as session:
            repo = AnalysisResultRepository(session)
            if analysis_type:
                results = repo.get_by_type(analysis_type, limit=limit)
            else:
                results = repo.get_recent(days=days, limit=limit)
            return [self._result_to_dict(r) for r in results]

    def get_analysis_statistics(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """获取分析统计"""
        with self._session() as session:
            repo = AnalysisResultRepository(session)
            start_time = datetime.now() - timedelta(days=days)
            return repo.get_statistics(start_time=start_time)

    # ==================== 告警 ====================

    def save_alert(
        self,
        analysis_result_id: int,
        alert_type: str,
        severity: str,
        title: str,
        description: str = "",
        confidence: float = 0.0,
        evidence: Optional[List] = None,
        recommendations: Optional[List] = None
    ) -> int:
        """保存告警，返回告警ID"""
        with self._session() as session:
            repo = AlertRepository(session)
            alert = Alert(
                analysis_result_id=analysis_result_id,
                alert_type=alert_type,
                severity=SeverityLevel(severity),
                title=title,
                description=description,
                confidence=confidence,
                evidence=evidence,
                recommendations=recommendations
            )
            repo.create(alert)
            return alert.id

    def get_pending_alerts(self, limit: int = 100) -> List[Dict]:
        """获取待通知的告警"""
        with self._session() as session:
            repo = AlertRepository(session)
            alerts = repo.get_unnotified(limit=limit)
            return [self._alert_to_dict(a) for a in alerts]

    def get_unresolved_alerts(
        self,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """获取未解决的告警"""
        with self._session() as session:
            repo = AlertRepository(session)
            sev = SeverityLevel(severity) if severity else None
            alerts = repo.get_unresolved(severity=sev, limit=limit)
            return [self._alert_to_dict(a) for a in alerts]

    def mark_alert_notified(
        self,
        alert_id: int,
        channels: List[str],
        status: str = "success"
    ):
        """标记告警为已通知"""
        with self._session() as session:
            repo = AlertRepository(session)
            repo.mark_as_notified(alert_id, channels, status)

    def resolve_alert(
        self,
        alert_id: int,
        resolved_by: str,
        notes: Optional[str] = None
    ):
        """解决告警"""
        with self._session() as session:
            repo = AlertRepository(session)
            repo.resolve(alert_id, resolved_by, notes)

    def get_alert_statistics(self, days: int = 30) -> Dict[str, Any]:
        """获取告警统计"""
        with self._session() as session:
            repo = AlertRepository(session)
            start_time = datetime.now() - timedelta(days=days)
            return repo.get_statistics(start_time=start_time)

    # ==================== 任务历史 ====================

    def save_task_history(
        self,
        job_id: str,
        job_name: str,
        job_type: str,
        status: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        duration: Optional[float] = None,
        result_data: Optional[Dict] = None,
        error_message: Optional[str] = None,
        retry_count: int = 0
    ) -> int:
        """保存任务历史"""
        with self._session() as session:
            repo = TaskHistoryRepository(session)
            record = TaskHistory(
                job_id=job_id,
                job_name=job_name,
                job_type=job_type,
                status=status,
                start_time=start_time or datetime.now(),
                end_time=end_time,
                duration=duration,
                result_data=result_data,
                error_message=error_message,
                retry_count=retry_count
            )
            repo.create(record)
            return record.id

    def get_task_history(
        self,
        job_id: Optional[str] = None,
        days: int = 7,
        limit: int = 100
    ) -> List[Dict]:
        """获取任务历史"""
        with self._session() as session:
            repo = TaskHistoryRepository(session)
            if job_id:
                records = repo.get_by_job_id(job_id, limit=limit)
            else:
                records = repo.get_recent(days=days, limit=limit)
            return [self._task_to_dict(r) for r in records]

    def get_task_statistics(self, days: int = 30) -> Dict[str, Any]:
        """获取任务统计"""
        with self._session() as session:
            repo = TaskHistoryRepository(session)
            start_time = datetime.now() - timedelta(days=days)
            return repo.get_statistics(start_time=start_time)

    # ==================== IOC记录 ====================

    def save_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        is_malicious: bool = False,
        threat_score: float = 0.0,
        threat_types: Optional[List[str]] = None,
        provider: Optional[str] = None,
        analysis_result_id: Optional[int] = None
    ) -> int:
        """保存IOC记录（自动去重）"""
        with self._session() as session:
            repo = IOCRecordRepository(session)
            record = repo.get_or_create(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                is_malicious=is_malicious,
                threat_score=threat_score,
                threat_types=threat_types,
                provider=provider,
                analysis_result_id=analysis_result_id
            )
            return record.id

    def get_malicious_iocs(
        self,
        ioc_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """获取恶意IOC列表"""
        with self._session() as session:
            repo = IOCRecordRepository(session)
            records = repo.get_malicious(ioc_type=ioc_type, limit=limit)
            return [self._ioc_to_dict(r) for r in records]

    def get_ioc_statistics(self) -> Dict[str, Any]:
        """获取IOC统计"""
        with self._session() as session:
            repo = IOCRecordRepository(session)
            return repo.get_statistics()

    # ==================== 数据导出 ====================

    def export_to_csv(
        self,
        data_type: str,
        output_path: str,
        days: int = 30,
        limit: int = 10000
    ) -> str:
        """
        导出数据为CSV

        Args:
            data_type: 数据类型 (analysis_results, alerts, task_history, ioc_records)
            output_path: 输出文件路径
            days: 导出最近N天的数据
            limit: 最大记录数
        """
        if data_type == "analysis_results":
            data = self.get_analysis_results(days=days, limit=limit)
        elif data_type == "alerts":
            data = self.get_unresolved_alerts(limit=limit)
        elif data_type == "task_history":
            data = self.get_task_history(days=days, limit=limit)
        elif data_type == "ioc_records":
            data = self.get_malicious_iocs(limit=limit)
        else:
            raise ValueError(f"Unknown data type: {data_type}")

        if not data:
            return output_path

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

        return output_path

    def export_to_json(
        self,
        data_type: str,
        output_path: str,
        days: int = 30,
        limit: int = 10000
    ) -> str:
        """导出数据为JSON"""
        if data_type == "analysis_results":
            data = self.get_analysis_results(days=days, limit=limit)
        elif data_type == "alerts":
            data = self.get_unresolved_alerts(limit=limit)
        elif data_type == "task_history":
            data = self.get_task_history(days=days, limit=limit)
        elif data_type == "ioc_records":
            data = self.get_malicious_iocs(limit=limit)
        else:
            raise ValueError(f"Unknown data type: {data_type}")

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)

        return output_path

    # ==================== 数据清理 ====================

    def cleanup_old_data(self, retention_days: int = 90):
        """清理过期数据"""
        cutoff = datetime.now() - timedelta(days=retention_days)

        with self._session() as session:
            # 清理旧的任务历史
            session.query(TaskHistory).filter(
                TaskHistory.start_time < cutoff
            ).delete()

            # 清理旧的分析结果（级联删除关联的告警和IOC）
            session.query(AnalysisResult).filter(
                AnalysisResult.start_time < cutoff
            ).delete()

    # ==================== 内部方法 ====================

    @staticmethod
    def _result_to_dict(r: AnalysisResult) -> Dict:
        return {
            "id": r.id,
            "job_id": r.job_id,
            "analysis_type": r.analysis_type,
            "status": r.status.value if r.status else None,
            "start_time": str(r.start_time) if r.start_time else None,
            "end_time": str(r.end_time) if r.end_time else None,
            "duration": r.duration,
            "confidence": r.confidence,
            "log_count": r.log_count,
            "findings_count": r.findings_count,
            "evidence_count": r.evidence_count,
            "created_at": str(r.created_at) if r.created_at else None,
        }

    @staticmethod
    def _alert_to_dict(a: Alert) -> Dict:
        return {
            "id": a.id,
            "analysis_result_id": a.analysis_result_id,
            "alert_type": a.alert_type,
            "severity": a.severity.value if a.severity else None,
            "title": a.title,
            "description": a.description,
            "confidence": a.confidence,
            "notified": a.notified,
            "notification_status": a.notification_status,
            "resolved": a.resolved,
            "created_at": str(a.created_at) if a.created_at else None,
        }

    @staticmethod
    def _task_to_dict(t: TaskHistory) -> Dict:
        return {
            "id": t.id,
            "job_id": t.job_id,
            "job_name": t.job_name,
            "job_type": t.job_type,
            "status": t.status,
            "start_time": str(t.start_time) if t.start_time else None,
            "end_time": str(t.end_time) if t.end_time else None,
            "duration": t.duration,
            "error_message": t.error_message,
            "retry_count": t.retry_count,
            "created_at": str(t.created_at) if t.created_at else None,
        }

    @staticmethod
    def _ioc_to_dict(r: IOCRecord) -> Dict:
        return {
            "id": r.id,
            "ioc_type": r.ioc_type,
            "ioc_value": r.ioc_value,
            "is_malicious": r.is_malicious,
            "threat_score": r.threat_score,
            "threat_types": r.threat_types,
            "provider": r.provider,
            "first_seen": str(r.first_seen) if r.first_seen else None,
            "last_seen": str(r.last_seen) if r.last_seen else None,
            "occurrence_count": r.occurrence_count,
        }
