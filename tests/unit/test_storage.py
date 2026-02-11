"""
存储系统单元测试
"""
import os
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from src.storage.models import (
    Base, AnalysisResult, Alert, TaskHistory, IOCRecord,
    AnalysisStatus, SeverityLevel,
)
from src.storage.database import Database
from src.storage.repository import (
    AnalysisResultRepository, AlertRepository,
    TaskHistoryRepository, IOCRecordRepository,
    SystemConfigRepository,
)
from src.storage.service import StorageService


@pytest.fixture
def db():
    """创建内存测试数据库"""
    url = "sqlite:///:memory:"
    database = Database(url)
    database.init_db()
    yield database, url


@pytest.fixture
def session(db):
    database, url = db
    with database.get_session() as s:
        yield s


class TestAnalysisResultRepository:
    def test_create_and_get(self, session):
        repo = AnalysisResultRepository(session)
        record = AnalysisResult(
            job_id="test-job-1",
            analysis_type="compromised_host",
            status=AnalysisStatus.SUCCESS,
            confidence=0.95,
            result_data={"risk": "high"},
        )
        result = repo.create(record)
        assert result.id is not None
        fetched = repo.get_by_id(result.id)
        assert fetched.analysis_type == "compromised_host"
        assert fetched.confidence == 0.95

    def test_get_by_type(self, session):
        repo = AnalysisResultRepository(session)
        for i in range(3):
            repo.create(AnalysisResult(
                job_id=f"job-{i}",
                analysis_type="test_type",
                status=AnalysisStatus.SUCCESS,
                confidence=0.5 + i * 0.1,
            ))
        results = repo.get_by_type("test_type", limit=10)
        assert len(results) == 3

    def test_get_statistics(self, session):
        repo = AnalysisResultRepository(session)
        repo.create(AnalysisResult(
            job_id="s1", analysis_type="a", status=AnalysisStatus.SUCCESS,
        ))
        repo.create(AnalysisResult(
            job_id="s2", analysis_type="a", status=AnalysisStatus.FAILED,
        ))
        stats = repo.get_statistics()
        assert stats["total"] == 2
        assert stats["success"] == 1
        assert stats["failed"] == 1


def _create_analysis_result(session):
    """辅助：创建一个分析结果用于关联告警"""
    repo = AnalysisResultRepository(session)
    return repo.create(AnalysisResult(
        job_id="alert-test-job",
        analysis_type="test",
        status=AnalysisStatus.SUCCESS,
    ))


class TestAlertRepository:
    def test_create_alert(self, session):
        ar = _create_analysis_result(session)
        repo = AlertRepository(session)
        alert = repo.create(Alert(
            analysis_result_id=ar.id,
            alert_type="compromised_host",
            severity=SeverityLevel.HIGH,
            title="Test Alert",
            description="Test description",
        ))
        assert alert.id is not None
        assert alert.severity == SeverityLevel.HIGH

    def test_mark_as_notified(self, session):
        ar = _create_analysis_result(session)
        repo = AlertRepository(session)
        alert = repo.create(Alert(
            analysis_result_id=ar.id,
            alert_type="test",
            severity=SeverityLevel.MEDIUM,
            title="Notify Test",
        ))
        assert alert.notified is False
        repo.mark_as_notified(alert.id, channels=["feishu"])
        updated = repo.get_by_id(alert.id)
        assert updated.notified is True
        assert updated.notification_channels == ["feishu"]

    def test_get_unnotified(self, session):
        ar = _create_analysis_result(session)
        repo = AlertRepository(session)
        repo.create(Alert(
            analysis_result_id=ar.id, alert_type="a",
            severity=SeverityLevel.HIGH, title="A",
        ))
        repo.create(Alert(
            analysis_result_id=ar.id, alert_type="b",
            severity=SeverityLevel.LOW, title="B",
        ))
        unnotified = repo.get_unnotified()
        assert len(unnotified) == 2

        repo.mark_as_notified(unnotified[0].id, channels=["email"])
        unnotified2 = repo.get_unnotified()
        assert len(unnotified2) == 1

    def test_acknowledge_and_resolve(self, session):
        ar = _create_analysis_result(session)
        repo = AlertRepository(session)
        alert = repo.create(Alert(
            analysis_result_id=ar.id, alert_type="test",
            severity=SeverityLevel.CRITICAL, title="Resolve Test",
        ))
        repo.acknowledge(alert.id, "analyst-1")
        acked = repo.get_by_id(alert.id)
        assert acked.acknowledged_by == "analyst-1"

        repo.resolve(alert.id, "analyst-1", "False positive")
        resolved = repo.get_by_id(alert.id)
        assert resolved.resolved_at is not None
        assert resolved.resolution_notes == "False positive"


class TestIOCRecordRepository:
    def test_get_or_create(self, session):
        repo = IOCRecordRepository(session)
        ioc1 = repo.get_or_create(
            ioc_type="ip",
            ioc_value="10.0.0.1",
            threat_score=85.0,
            provider="test",
        )
        assert ioc1.id is not None

        # 重复创建应返回同一记录，occurrence_count递增
        ioc2 = repo.get_or_create(
            ioc_type="ip",
            ioc_value="10.0.0.1",
            threat_score=90.0,
            provider="test2",
        )
        assert ioc1.id == ioc2.id
        assert ioc2.occurrence_count == 2

    def test_get_malicious(self, session):
        repo = IOCRecordRepository(session)
        repo.get_or_create("ip", "1.2.3.4", is_malicious=True, threat_score=90.0)
        repo.get_or_create("ip", "5.6.7.8", is_malicious=False, threat_score=10.0)
        malicious = repo.get_malicious()
        assert len(malicious) == 1
        assert malicious[0].ioc_value == "1.2.3.4"


class TestSystemConfigRepository:
    def test_set_and_get(self, session):
        repo = SystemConfigRepository(session)
        repo.set("test_key", "test_value", config_type="string")
        config = repo.get("test_key")
        assert config is not None
        assert config.config_value == "test_value"

    def test_update_existing(self, session):
        repo = SystemConfigRepository(session)
        repo.set("key1", "value1", config_type="string")
        repo.set("key1", "value2", config_type="string")
        config = repo.get("key1")
        assert config.config_value == "value2"

    def test_delete(self, session):
        repo = SystemConfigRepository(session)
        repo.set("del_key", "val", config_type="string")
        assert repo.delete("del_key") is True
        assert repo.get("del_key") is None


class TestStorageService:
    def test_service_init(self, db):
        database, url = db
        with patch("src.storage.service.get_database", return_value=database):
            service = StorageService(url)
            assert service is not None

    def test_save_analysis_result(self, db):
        database, url = db
        with patch("src.storage.service.get_database", return_value=database):
            service = StorageService(url)
            result_id = service.save_analysis_result(
                job_id="svc-test-1",
                analysis_type="malware",
                status="success",
                confidence=0.99,
            )
            assert result_id is not None

    def test_save_alert(self, db):
        database, url = db
        with patch("src.storage.service.get_database", return_value=database):
            service = StorageService(url)
            result_id = service.save_analysis_result(
                job_id="svc-alert-1",
                analysis_type="test",
                status="success",
            )
            alert_id = service.save_alert(
                analysis_result_id=result_id,
                alert_type="test",
                severity="high",
                title="Service Alert Test",
            )
            assert alert_id is not None
