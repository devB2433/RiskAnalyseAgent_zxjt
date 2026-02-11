"""
监控指标系统单元测试
"""
import time
import pytest
from src.monitoring.metrics import (
    TimerMetric, CounterMetric, MetricsCollector, get_metrics,
)
from src.monitoring.health import HealthChecker, HealthStatus, ComponentHealth


class TestTimerMetric:
    def test_initial_state(self):
        t = TimerMetric()
        assert t.count == 0
        assert t.avg_seconds == 0.0
        assert t.last_at is None

    def test_record(self):
        t = TimerMetric()
        t.record(1.5)
        t.record(2.5)
        assert t.count == 2
        assert t.total_seconds == 4.0
        assert t.avg_seconds == 2.0
        assert t.min_seconds == 1.5
        assert t.max_seconds == 2.5
        assert t.last_at is not None

    def test_to_dict(self):
        t = TimerMetric()
        t.record(1.0)
        d = t.to_dict()
        assert d["count"] == 1
        assert d["avg_seconds"] == 1.0
        assert d["last_at"] is not None

    def test_to_dict_empty(self):
        t = TimerMetric()
        d = t.to_dict()
        assert d["count"] == 0
        assert d["min_seconds"] is None


class TestCounterMetric:
    def test_initial_state(self):
        c = CounterMetric()
        assert c.count == 0
        assert c.last_at is None

    def test_increment(self):
        c = CounterMetric()
        c.increment()
        c.increment(5)
        assert c.count == 6
        assert c.last_at is not None

    def test_to_dict(self):
        c = CounterMetric()
        c.increment(3)
        d = c.to_dict()
        assert d["count"] == 3
        assert d["last_at"] is not None


class TestMetricsCollector:
    def test_record_analysis_success(self):
        m = MetricsCollector()
        m.record_analysis("compromised_host", 1.5, True)
        assert m.analysis_timers["compromised_host"].count == 1
        assert m.analysis_success["compromised_host"].count == 1
        assert m.analysis_failure["compromised_host"].count == 0

    def test_record_analysis_failure(self):
        m = MetricsCollector()
        m.record_analysis("ddos_detection", 0.5, False)
        assert m.analysis_failure["ddos_detection"].count == 1
        assert m.analysis_success["ddos_detection"].count == 0

    def test_record_alert(self):
        m = MetricsCollector()
        m.record_alert("high")
        m.record_alert("high")
        m.record_alert("critical")
        assert m.alerts_triggered.count == 3
        assert m.alerts_by_severity["high"].count == 2
        assert m.alerts_by_severity["critical"].count == 1

    def test_record_alert_notified(self):
        m = MetricsCollector()
        m.record_alert_notified()
        assert m.alerts_notified.count == 1

    def test_record_threat_intel_cache_hit(self):
        m = MetricsCollector()
        m.record_threat_intel_query(cache_hit=True)
        assert m.threat_intel_queries.count == 1
        assert m.threat_intel_cache_hits.count == 1
        assert m.threat_intel_cache_misses.count == 0

    def test_record_threat_intel_cache_miss(self):
        m = MetricsCollector()
        m.record_threat_intel_query(cache_hit=False)
        assert m.threat_intel_cache_misses.count == 1

    def test_record_threat_intel_error(self):
        m = MetricsCollector()
        m.record_threat_intel_error()
        assert m.threat_intel_errors.count == 1

    def test_record_job(self):
        m = MetricsCollector()
        m.record_job_executed(success=True)
        m.record_job_executed(success=False)
        assert m.jobs_executed.count == 2
        assert m.jobs_failed.count == 1

    def test_record_job_retried(self):
        m = MetricsCollector()
        m.record_job_retried()
        assert m.jobs_retried.count == 1

    def test_record_prefilter(self):
        m = MetricsCollector()
        m.record_prefilter(input_count=1000, output_count=50)
        assert m.prefilter_runs.count == 1
        assert m.prefilter_total_input.count == 1000
        assert m.prefilter_total_output.count == 50

    def test_snapshot(self):
        m = MetricsCollector()
        m.record_analysis("compromised_host", 2.0, True)
        m.record_alert("high")
        m.record_threat_intel_query(cache_hit=True)
        m.record_threat_intel_query(cache_hit=False)
        m.record_job_executed(success=True)
        m.record_prefilter(500, 30)

        snap = m.snapshot()
        assert "uptime_seconds" in snap
        assert "compromised_host" in snap["analysis"]
        assert snap["alerts"]["triggered"]["count"] == 1
        assert snap["threat_intel"]["cache_hit_rate"] == 0.5
        assert snap["scheduler"]["executed"]["count"] == 1
        assert snap["preprocessing"]["total_input_logs"] == 500

    def test_snapshot_empty(self):
        m = MetricsCollector()
        snap = m.snapshot()
        assert snap["threat_intel"]["cache_hit_rate"] == 0
        assert snap["preprocessing"]["avg_filter_ratio"] == 0

    def test_reset(self):
        m = MetricsCollector()
        m.record_analysis("test", 1.0, True)
        m.reset()
        assert m.analysis_timers["test"].count == 0
        assert m.jobs_executed.count == 0

    def test_uptime(self):
        m = MetricsCollector()
        assert m.uptime_seconds >= 0


class TestHealthChecker:
    def test_no_components(self):
        hc = HealthChecker()
        result = hc.check_all()
        assert result["status"] == "unhealthy"

    def test_check_database_none(self):
        hc = HealthChecker(db=None)
        h = hc.check_database()
        assert h.status == HealthStatus.UNHEALTHY

    def test_check_scheduler_none(self):
        hc = HealthChecker(scheduler=None)
        h = hc.check_scheduler()
        assert h.status == HealthStatus.UNHEALTHY

    def test_component_health_to_dict(self):
        ch = ComponentHealth(name="test", status=HealthStatus.HEALTHY, message="ok")
        d = ch.to_dict()
        assert d["name"] == "test"
        assert d["status"] == "healthy"
        assert d["message"] == "ok"


class TestMonitoringConfig:
    def test_defaults(self):
        from src.config.settings import MonitoringConfig
        cfg = MonitoringConfig()
        assert cfg.enabled is True
        assert cfg.health_check_interval == 60
        assert cfg.metrics_log_interval == 300

    def test_from_dict(self):
        from src.config.settings import MonitoringConfig
        cfg = MonitoringConfig.from_dict({"enabled": False, "health_check_interval": 30})
        assert cfg.enabled is False
        assert cfg.health_check_interval == 30

    def test_settings_has_monitoring(self):
        from src.config.settings import Settings
        s = Settings()
        assert hasattr(s, "monitoring")
        assert s.monitoring.enabled is True
