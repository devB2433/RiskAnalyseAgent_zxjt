"""
指标收集器

收集和管理系统运行指标：任务执行、告警、威胁情报、缓存等
"""
import time
import threading
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class TimerMetric:
    """计时指标"""
    count: int = 0
    total_seconds: float = 0.0
    min_seconds: float = float("inf")
    max_seconds: float = 0.0
    last_at: Optional[datetime] = None

    @property
    def avg_seconds(self) -> float:
        return self.total_seconds / self.count if self.count else 0.0

    def record(self, duration: float) -> None:
        self.count += 1
        self.total_seconds += duration
        self.min_seconds = min(self.min_seconds, duration)
        self.max_seconds = max(self.max_seconds, duration)
        self.last_at = datetime.now()

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "total_seconds": round(self.total_seconds, 3),
            "avg_seconds": round(self.avg_seconds, 3),
            "min_seconds": round(self.min_seconds, 3) if self.count else None,
            "max_seconds": round(self.max_seconds, 3) if self.count else None,
            "last_at": self.last_at.isoformat() if self.last_at else None,
        }


@dataclass
class CounterMetric:
    """计数指标"""
    count: int = 0
    last_at: Optional[datetime] = None

    def increment(self, n: int = 1) -> None:
        self.count += n
        self.last_at = datetime.now()

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "last_at": self.last_at.isoformat() if self.last_at else None,
        }


class MetricsCollector:
    """全局指标收集器（线程安全单例）"""

    def __init__(self):
        self._lock = threading.Lock()
        self._start_time = datetime.now()
        # 分析任务指标 - 按分析类型
        self.analysis_timers: Dict[str, TimerMetric] = defaultdict(TimerMetric)
        self.analysis_success: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        self.analysis_failure: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        # 告警指标
        self.alerts_triggered = CounterMetric()
        self.alerts_notified = CounterMetric()
        self.alerts_by_severity: Dict[str, CounterMetric] = defaultdict(CounterMetric)
        # 威胁情报指标
        self.threat_intel_queries = CounterMetric()
        self.threat_intel_cache_hits = CounterMetric()
        self.threat_intel_cache_misses = CounterMetric()
        self.threat_intel_errors = CounterMetric()
        # 调度指标
        self.jobs_executed = CounterMetric()
        self.jobs_failed = CounterMetric()
        self.jobs_retried = CounterMetric()
        # 预处理指标
        self.prefilter_runs = CounterMetric()
        self.prefilter_total_input = CounterMetric()
        self.prefilter_total_output = CounterMetric()

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now() - self._start_time).total_seconds()

    def record_analysis(self, analysis_type: str, duration: float, success: bool) -> None:
        """记录一次分析任务执行"""
        with self._lock:
            self.analysis_timers[analysis_type].record(duration)
            if success:
                self.analysis_success[analysis_type].increment()
            else:
                self.analysis_failure[analysis_type].increment()

    def record_alert(self, severity: str) -> None:
        with self._lock:
            self.alerts_triggered.increment()
            self.alerts_by_severity[severity].increment()

    def record_alert_notified(self) -> None:
        with self._lock:
            self.alerts_notified.increment()

    def record_threat_intel_query(self, cache_hit: bool) -> None:
        with self._lock:
            self.threat_intel_queries.increment()
            if cache_hit:
                self.threat_intel_cache_hits.increment()
            else:
                self.threat_intel_cache_misses.increment()

    def record_threat_intel_error(self) -> None:
        with self._lock:
            self.threat_intel_errors.increment()

    def record_job_executed(self, success: bool) -> None:
        with self._lock:
            self.jobs_executed.increment()
            if not success:
                self.jobs_failed.increment()

    def record_job_retried(self) -> None:
        with self._lock:
            self.jobs_retried.increment()

    def record_prefilter(self, input_count: int, output_count: int) -> None:
        with self._lock:
            self.prefilter_runs.increment()
            self.prefilter_total_input.increment(input_count)
            self.prefilter_total_output.increment(output_count)

    def snapshot(self) -> Dict[str, Any]:
        """获取当前所有指标快照"""
        with self._lock:
            return {
                "uptime_seconds": round(self.uptime_seconds, 1),
                "collected_at": datetime.now().isoformat(),
                "analysis": {
                    atype: {
                        "timer": self.analysis_timers[atype].to_dict(),
                        "success": self.analysis_success[atype].to_dict(),
                        "failure": self.analysis_failure[atype].to_dict(),
                    }
                    for atype in set(
                        list(self.analysis_timers) +
                        list(self.analysis_success) +
                        list(self.analysis_failure)
                    )
                },
                "alerts": {
                    "triggered": self.alerts_triggered.to_dict(),
                    "notified": self.alerts_notified.to_dict(),
                    "by_severity": {
                        s: c.to_dict() for s, c in self.alerts_by_severity.items()
                    },
                },
                "threat_intel": {
                    "queries": self.threat_intel_queries.to_dict(),
                    "cache_hits": self.threat_intel_cache_hits.to_dict(),
                    "cache_misses": self.threat_intel_cache_misses.to_dict(),
                    "cache_hit_rate": (
                        round(self.threat_intel_cache_hits.count /
                              self.threat_intel_queries.count, 3)
                        if self.threat_intel_queries.count else 0
                    ),
                    "errors": self.threat_intel_errors.to_dict(),
                },
                "scheduler": {
                    "executed": self.jobs_executed.to_dict(),
                    "failed": self.jobs_failed.to_dict(),
                    "retried": self.jobs_retried.to_dict(),
                },
                "preprocessing": {
                    "runs": self.prefilter_runs.to_dict(),
                    "total_input_logs": self.prefilter_total_input.count,
                    "total_output_logs": self.prefilter_total_output.count,
                    "avg_filter_ratio": (
                        round(1 - self.prefilter_total_output.count /
                              self.prefilter_total_input.count, 3)
                        if self.prefilter_total_input.count else 0
                    ),
                },
            }

    def reset(self) -> None:
        """重置所有指标"""
        with self._lock:
            self.__init__()


# 全局单例
_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """获取全局指标收集器"""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics
