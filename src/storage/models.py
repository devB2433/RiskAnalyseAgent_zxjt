"""
数据库模型定义

使用SQLAlchemy ORM定义所有数据库表
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Text, Float, DateTime,
    Boolean, JSON, ForeignKey, Index, Enum as SQLEnum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


class AnalysisStatus(enum.Enum):
    """分析状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class SeverityLevel(enum.Enum):
    """严重级别枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisResult(Base):
    """分析结果表"""
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(255), nullable=False, index=True)
    analysis_type = Column(String(100), nullable=False, index=True)
    status = Column(SQLEnum(AnalysisStatus), nullable=False, default=AnalysisStatus.PENDING)

    # 时间信息
    start_time = Column(DateTime, nullable=False, default=datetime.now)
    end_time = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)

    # 分析结果
    confidence = Column(Float, nullable=True)
    log_count = Column(Integer, nullable=True)
    findings_count = Column(Integer, nullable=True)
    evidence_count = Column(Integer, nullable=True)

    # 详细结果（JSON格式）
    result_data = Column(JSON, nullable=True)
    trace_data = Column(JSON, nullable=True)

    # 元数据
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    updated_at = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    # 关系
    alerts = relationship("Alert", back_populates="analysis_result", cascade="all, delete-orphan")
    ioc_records = relationship("IOCRecord", back_populates="analysis_result", cascade="all, delete-orphan")

    # 索引
    __table_args__ = (
        Index("idx_analysis_type_time", "analysis_type", "start_time"),
        Index("idx_analysis_status_time", "status", "start_time"),
    )


class Alert(Base):
    """告警记录表"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_result_id = Column(Integer, ForeignKey("analysis_results.id"), nullable=False, index=True)

    # 告警信息
    alert_type = Column(String(100), nullable=False, index=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # 告警详情
    confidence = Column(Float, nullable=True)
    evidence = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)

    # 通知状态
    notified = Column(Boolean, default=False, index=True)
    notification_channels = Column(JSON, nullable=True)
    notification_time = Column(DateTime, nullable=True)
    notification_status = Column(String(50), nullable=True)

    # 处理状态
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(255), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved = Column(Boolean, default=False)
    resolved_by = Column(String(255), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # 元数据
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    updated_at = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    # 关系
    analysis_result = relationship("AnalysisResult", back_populates="alerts")

    # 索引
    __table_args__ = (
        Index("idx_severity_time", "severity", "created_at"),
        Index("idx_notified_time", "notified", "created_at"),
        Index("idx_resolved_time", "resolved", "created_at"),
    )


class TaskHistory(Base):
    """任务执行历史表"""
    __tablename__ = "task_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(255), nullable=False, index=True)
    job_name = Column(String(500), nullable=False)
    job_type = Column(String(100), nullable=False, index=True)

    # 执行信息
    status = Column(String(50), nullable=False, index=True)
    start_time = Column(DateTime, nullable=False, default=datetime.now)
    end_time = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)

    # 执行结果
    result_data = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)

    # 元数据
    created_at = Column(DateTime, nullable=False, default=datetime.now)

    # 索引
    __table_args__ = (
        Index("idx_task_job_id_time", "job_id", "start_time"),
        Index("idx_task_status_time", "status", "start_time"),
        Index("idx_job_type_time", "job_type", "start_time"),
    )


class IOCRecord(Base):
    """IOC（威胁指标）记录表"""
    __tablename__ = "ioc_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_result_id = Column(Integer, ForeignKey("analysis_results.id"), nullable=True, index=True)

    # IOC信息
    ioc_type = Column(String(50), nullable=False, index=True)
    ioc_value = Column(String(500), nullable=False, index=True)

    # 威胁情报
    is_malicious = Column(Boolean, nullable=True, index=True)
    threat_score = Column(Float, nullable=True)
    threat_types = Column(JSON, nullable=True)

    # 来源信息
    provider = Column(String(100), nullable=True)
    provider_results = Column(JSON, nullable=True)

    # 首次和最后发现时间
    first_seen = Column(DateTime, nullable=False, default=datetime.now)
    last_seen = Column(DateTime, nullable=False, default=datetime.now)
    occurrence_count = Column(Integer, default=1)

    # 元数据
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    updated_at = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    # 关系
    analysis_result = relationship("AnalysisResult", back_populates="ioc_records")

    # 索引
    __table_args__ = (
        Index("idx_ioc_type_value", "ioc_type", "ioc_value"),
        Index("idx_malicious_time", "is_malicious", "last_seen"),
        Index("idx_threat_score", "threat_score"),
    )


class SystemConfig(Base):
    """系统配置表"""
    __tablename__ = "system_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String(255), nullable=False, unique=True, index=True)
    config_value = Column(Text, nullable=True)
    config_type = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)

    # 元数据
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    updated_at = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
