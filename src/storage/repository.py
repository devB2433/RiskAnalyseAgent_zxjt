"""
数据库Repository类

提供数据访问层，封装所有数据库操作
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.orm import Session

from .models import (
    AnalysisResult, Alert, TaskHistory, IOCRecord, SystemConfig,
    AnalysisStatus, SeverityLevel
)


class AnalysisResultRepository:
    """分析结果Repository"""

    def __init__(self, session: Session):
        self.session = session

    def create(self, analysis_result: AnalysisResult) -> AnalysisResult:
        """创建分析结果"""
        self.session.add(analysis_result)
        self.session.flush()
        return analysis_result

    def get_by_id(self, result_id: int) -> Optional[AnalysisResult]:
        """根据ID获取分析结果"""
        return self.session.query(AnalysisResult).filter(
            AnalysisResult.id == result_id
        ).first()

    def get_by_job_id(self, job_id: str) -> List[AnalysisResult]:
        """根据任务ID获取分析结果"""
        return self.session.query(AnalysisResult).filter(
            AnalysisResult.job_id == job_id
        ).order_by(desc(AnalysisResult.start_time)).all()

    def get_by_type(
        self,
        analysis_type: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[AnalysisResult]:
        """根据分析类型获取结果"""
        return self.session.query(AnalysisResult).filter(
            AnalysisResult.analysis_type == analysis_type
        ).order_by(desc(AnalysisResult.start_time)).limit(limit).offset(offset).all()

    def get_by_time_range(
        self,
        start_time: datetime,
        end_time: datetime,
        analysis_type: Optional[str] = None
    ) -> List[AnalysisResult]:
        """根据时间范围获取结果"""
        query = self.session.query(AnalysisResult).filter(
            and_(
                AnalysisResult.start_time >= start_time,
                AnalysisResult.start_time <= end_time
            )
        )

        if analysis_type:
            query = query.filter(AnalysisResult.analysis_type == analysis_type)

        return query.order_by(desc(AnalysisResult.start_time)).all()

    def get_recent(self, days: int = 7, limit: int = 100) -> List[AnalysisResult]:
        """获取最近N天的结果"""
        start_time = datetime.now() - timedelta(days=days)
        return self.session.query(AnalysisResult).filter(
            AnalysisResult.start_time >= start_time
        ).order_by(desc(AnalysisResult.start_time)).limit(limit).all()

    def update(self, analysis_result: AnalysisResult) -> AnalysisResult:
        """更新分析结果"""
        analysis_result.updated_at = datetime.now()
        self.session.flush()
        return analysis_result

    def delete(self, result_id: int) -> bool:
        """删除分析结果"""
        result = self.get_by_id(result_id)
        if result:
            self.session.delete(result)
            self.session.flush()
            return True
        return False

    def get_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """获取统计信息"""
        query = self.session.query(AnalysisResult)

        if start_time:
            query = query.filter(AnalysisResult.start_time >= start_time)
        if end_time:
            query = query.filter(AnalysisResult.start_time <= end_time)

        total = query.count()
        success = query.filter(AnalysisResult.status == AnalysisStatus.SUCCESS).count()
        failed = query.filter(AnalysisResult.status == AnalysisStatus.FAILED).count()

        # 按类型统计
        type_stats = self.session.query(
            AnalysisResult.analysis_type,
            func.count(AnalysisResult.id).label('count')
        ).group_by(AnalysisResult.analysis_type).all()

        return {
            "total": total,
            "success": success,
            "failed": failed,
            "success_rate": success / total if total > 0 else 0,
            "by_type": {t: c for t, c in type_stats}
        }


class AlertRepository:
    """告警Repository"""

    def __init__(self, session: Session):
        self.session = session

    def create(self, alert: Alert) -> Alert:
        """创建告警"""
        self.session.add(alert)
        self.session.flush()
        return alert

    def get_by_id(self, alert_id: int) -> Optional[Alert]:
        """根据ID获取告警"""
        return self.session.query(Alert).filter(Alert.id == alert_id).first()

    def get_by_analysis_result(self, analysis_result_id: int) -> List[Alert]:
        """根据分析结果ID获取告警"""
        return self.session.query(Alert).filter(
            Alert.analysis_result_id == analysis_result_id
        ).all()

    def get_by_severity(
        self,
        severity: SeverityLevel,
        limit: int = 100,
        offset: int = 0
    ) -> List[Alert]:
        """根据严重级别获取告警"""
        return self.session.query(Alert).filter(
            Alert.severity == severity
        ).order_by(desc(Alert.created_at)).limit(limit).offset(offset).all()

    def get_unnotified(self, limit: int = 100) -> List[Alert]:
        """获取未通知的告警"""
        return self.session.query(Alert).filter(
            Alert.notified == False
        ).order_by(Alert.created_at).limit(limit).all()

    def get_unresolved(
        self,
        severity: Optional[SeverityLevel] = None,
        limit: int = 100
    ) -> List[Alert]:
        """获取未解决的告警"""
        query = self.session.query(Alert).filter(Alert.resolved == False)

        if severity:
            query = query.filter(Alert.severity == severity)

        return query.order_by(desc(Alert.created_at)).limit(limit).all()

    def mark_as_notified(
        self,
        alert_id: int,
        channels: List[str],
        status: str = "success"
    ) -> Optional[Alert]:
        """标记为已通知"""
        alert = self.get_by_id(alert_id)
        if alert:
            alert.notified = True
            alert.notification_channels = channels
            alert.notification_time = datetime.now()
            alert.notification_status = status
            alert.updated_at = datetime.now()
            self.session.flush()
        return alert

    def acknowledge(
        self,
        alert_id: int,
        acknowledged_by: str
    ) -> Optional[Alert]:
        """确认告警"""
        alert = self.get_by_id(alert_id)
        if alert:
            alert.acknowledged = True
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = datetime.now()
            alert.updated_at = datetime.now()
            self.session.flush()
        return alert

    def resolve(
        self,
        alert_id: int,
        resolved_by: str,
        resolution_notes: Optional[str] = None
    ) -> Optional[Alert]:
        """解决告警"""
        alert = self.get_by_id(alert_id)
        if alert:
            alert.resolved = True
            alert.resolved_by = resolved_by
            alert.resolved_at = datetime.now()
            alert.resolution_notes = resolution_notes
            alert.updated_at = datetime.now()
            self.session.flush()
        return alert

    def get_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """获取告警统计"""
        query = self.session.query(Alert)

        if start_time:
            query = query.filter(Alert.created_at >= start_time)
        if end_time:
            query = query.filter(Alert.created_at <= end_time)

        total = query.count()
        notified = query.filter(Alert.notified == True).count()
        resolved = query.filter(Alert.resolved == True).count()

        # 按严重级别统计
        severity_stats = self.session.query(
            Alert.severity,
            func.count(Alert.id).label('count')
        ).group_by(Alert.severity).all()

        return {
            "total": total,
            "notified": notified,
            "resolved": resolved,
            "unresolved": total - resolved,
            "by_severity": {s.value: c for s, c in severity_stats}
        }


class TaskHistoryRepository:
    """任务历史Repository"""

    def __init__(self, session: Session):
        self.session = session

    def create(self, task_history: TaskHistory) -> TaskHistory:
        """创建任务历史"""
        self.session.add(task_history)
        self.session.flush()
        return task_history

    def get_by_id(self, history_id: int) -> Optional[TaskHistory]:
        """根据ID获取任务历史"""
        return self.session.query(TaskHistory).filter(
            TaskHistory.id == history_id
        ).first()

    def get_by_job_id(
        self,
        job_id: str,
        limit: int = 100
    ) -> List[TaskHistory]:
        """根据任务ID获取历史"""
        return self.session.query(TaskHistory).filter(
            TaskHistory.job_id == job_id
        ).order_by(desc(TaskHistory.start_time)).limit(limit).all()

    def get_by_job_type(
        self,
        job_type: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[TaskHistory]:
        """根据任务类型获取历史"""
        return self.session.query(TaskHistory).filter(
            TaskHistory.job_type == job_type
        ).order_by(desc(TaskHistory.start_time)).limit(limit).offset(offset).all()

    def get_recent(self, days: int = 7, limit: int = 100) -> List[TaskHistory]:
        """获取最近N天的任务历史"""
        start_time = datetime.now() - timedelta(days=days)
        return self.session.query(TaskHistory).filter(
            TaskHistory.start_time >= start_time
        ).order_by(desc(TaskHistory.start_time)).limit(limit).all()

    def get_failed_tasks(self, limit: int = 100) -> List[TaskHistory]:
        """获取失败的任务"""
        return self.session.query(TaskHistory).filter(
            TaskHistory.status == "failed"
        ).order_by(desc(TaskHistory.start_time)).limit(limit).all()

    def get_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """获取任务统计"""
        query = self.session.query(TaskHistory)

        if start_time:
            query = query.filter(TaskHistory.start_time >= start_time)
        if end_time:
            query = query.filter(TaskHistory.start_time <= end_time)

        total = query.count()
        success = query.filter(TaskHistory.status == "success").count()
        failed = query.filter(TaskHistory.status == "failed").count()

        # 按类型统计
        type_stats = self.session.query(
            TaskHistory.job_type,
            func.count(TaskHistory.id).label('count')
        ).group_by(TaskHistory.job_type).all()

        # 平均执行时长
        avg_duration = self.session.query(
            func.avg(TaskHistory.duration)
        ).filter(TaskHistory.duration.isnot(None)).scalar()

        return {
            "total": total,
            "success": success,
            "failed": failed,
            "success_rate": success / total if total > 0 else 0,
            "avg_duration": float(avg_duration) if avg_duration else 0,
            "by_type": {t: c for t, c in type_stats}
        }


class IOCRecordRepository:
    """IOC记录Repository"""

    def __init__(self, session: Session):
        self.session = session

    def create(self, ioc_record: IOCRecord) -> IOCRecord:
        """创建IOC记录"""
        self.session.add(ioc_record)
        self.session.flush()
        return ioc_record

    def get_by_id(self, record_id: int) -> Optional[IOCRecord]:
        """根据ID获取IOC记录"""
        return self.session.query(IOCRecord).filter(
            IOCRecord.id == record_id
        ).first()

    def get_by_value(self, ioc_type: str, ioc_value: str) -> Optional[IOCRecord]:
        """根据IOC值获取记录"""
        return self.session.query(IOCRecord).filter(
            and_(
                IOCRecord.ioc_type == ioc_type,
                IOCRecord.ioc_value == ioc_value
            )
        ).first()

    def get_or_create(
        self,
        ioc_type: str,
        ioc_value: str,
        **kwargs
    ) -> IOCRecord:
        """获取或创建IOC记录"""
        record = self.get_by_value(ioc_type, ioc_value)

        if record:
            # 更新最后发现时间和出现次数
            record.last_seen = datetime.now()
            record.occurrence_count += 1
            record.updated_at = datetime.now()

            # 更新其他字段
            for key, value in kwargs.items():
                if hasattr(record, key):
                    setattr(record, key, value)

            self.session.flush()
        else:
            # 创建新记录
            record = IOCRecord(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                **kwargs
            )
            self.session.add(record)
            self.session.flush()

        return record

    def get_malicious(
        self,
        ioc_type: Optional[str] = None,
        limit: int = 100
    ) -> List[IOCRecord]:
        """获取恶意IOC"""
        query = self.session.query(IOCRecord).filter(
            IOCRecord.is_malicious == True
        )

        if ioc_type:
            query = query.filter(IOCRecord.ioc_type == ioc_type)

        return query.order_by(desc(IOCRecord.threat_score)).limit(limit).all()

    def get_by_threat_score(
        self,
        min_score: float,
        ioc_type: Optional[str] = None,
        limit: int = 100
    ) -> List[IOCRecord]:
        """根据威胁评分获取IOC"""
        query = self.session.query(IOCRecord).filter(
            IOCRecord.threat_score >= min_score
        )

        if ioc_type:
            query = query.filter(IOCRecord.ioc_type == ioc_type)

        return query.order_by(desc(IOCRecord.threat_score)).limit(limit).all()

    def get_statistics(self) -> Dict[str, Any]:
        """获取IOC统计"""
        total = self.session.query(IOCRecord).count()
        malicious = self.session.query(IOCRecord).filter(
            IOCRecord.is_malicious == True
        ).count()

        # 按类型统计
        type_stats = self.session.query(
            IOCRecord.ioc_type,
            func.count(IOCRecord.id).label('count')
        ).group_by(IOCRecord.ioc_type).all()

        return {
            "total": total,
            "malicious": malicious,
            "benign": total - malicious,
            "by_type": {t: c for t, c in type_stats}
        }


class SystemConfigRepository:
    """系统配置Repository"""

    def __init__(self, session: Session):
        self.session = session

    def get(self, config_key: str) -> Optional[SystemConfig]:
        """获取配置"""
        return self.session.query(SystemConfig).filter(
            SystemConfig.config_key == config_key
        ).first()

    def set(
        self,
        config_key: str,
        config_value: str,
        config_type: str = "string",
        description: Optional[str] = None
    ) -> SystemConfig:
        """设置配置"""
        config = self.get(config_key)

        if config:
            config.config_value = config_value
            config.config_type = config_type
            if description:
                config.description = description
            config.updated_at = datetime.now()
        else:
            config = SystemConfig(
                config_key=config_key,
                config_value=config_value,
                config_type=config_type,
                description=description
            )
            self.session.add(config)

        self.session.flush()
        return config

    def delete(self, config_key: str) -> bool:
        """删除配置"""
        config = self.get(config_key)
        if config:
            self.session.delete(config)
            self.session.flush()
            return True
        return False

    def get_all(self) -> List[SystemConfig]:
        """获取所有配置"""
        return self.session.query(SystemConfig).all()
