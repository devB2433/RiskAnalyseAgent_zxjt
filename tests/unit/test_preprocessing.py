"""
日志预处理模块单元测试
测试 LogPreFilter 和 LogPreprocessor
"""
import pytest
from datetime import datetime
from security_analysis.architecture_v2 import SecurityLog
from security_analysis.prefilter import (
    LogPreFilter, FilterReason, FilteredLog, FilterResult,
)
from security_analysis.preprocessor import LogPreprocessor, LogSummary


# ==================== 测试数据工厂 ====================

def make_log(
    log_type="firewall",
    timestamp=None,
    source_ip="10.0.1.50",
    dest_ip="203.0.113.10",
    source_port=12345,
    dest_port=443,
    protocol="TCP",
    action="allow",
    raw_data=None,
):
    return SecurityLog(
        log_type=log_type,
        timestamp=timestamp or datetime(2024, 1, 15, 14, 30, 0),
        source_ip=source_ip,
        dest_ip=dest_ip,
        source_port=source_port,
        dest_port=dest_port,
        protocol=protocol,
        action=action,
        raw_data=raw_data or {},
    )


def make_logs(n, **overrides):
    """批量生成日志"""
    logs = []
    for i in range(n):
        kw = dict(overrides)
        kw.setdefault("source_ip", f"10.0.1.{i % 256}")
        kw.setdefault("timestamp", datetime(2024, 1, 15, 10 + i % 8, i % 60, 0))
        logs.append(make_log(**kw))
    return logs


# ==================== LogPreFilter 测试 ====================

class TestLogPreFilter:

    def test_empty_logs(self):
        pf = LogPreFilter()
        result = pf.filter([], "compromised_host")
        assert result.total_input == 0
        assert len(result.suspicious_logs) == 0

    def test_disabled_returns_all(self):
        pf = LogPreFilter(enabled=False)
        logs = make_logs(10)
        result = pf.filter(logs, "compromised_host")
        assert len(result.suspicious_logs) == 10
        # 禁用时不应有 reason
        for fl in result.suspicious_logs:
            assert fl.reasons == []

    def test_alert_action_rule(self):
        pf = LogPreFilter()
        logs = [
            make_log(action="alert"),
            make_log(action="block"),
            make_log(action="allow"),
        ]
        result = pf.filter(logs, "compromised_host")
        alert_logs = [
            fl for fl in result.suspicious_logs
            if FilterReason.ALERT_ACTION in fl.reasons
        ]
        assert len(alert_logs) >= 2

    def test_off_hours_rule(self):
        pf = LogPreFilter(work_hours=(8, 20))
        logs = [
            make_log(timestamp=datetime(2024, 1, 15, 3, 0, 0)),   # 凌晨3点
            make_log(timestamp=datetime(2024, 1, 15, 22, 0, 0)),  # 晚上10点
            make_log(timestamp=datetime(2024, 1, 15, 12, 0, 0)),  # 中午12点
        ]
        result = pf.filter(logs, "compromised_host")
        off_hours = [
            fl for fl in result.suspicious_logs
            if FilterReason.OFF_HOURS in fl.reasons
        ]
        assert len(off_hours) == 2

    def test_known_bad_port_rule(self):
        pf = LogPreFilter()
        logs = [
            make_log(dest_port=4444),
            make_log(dest_port=1337),
            make_log(dest_port=80),
        ]
        result = pf.filter(logs, "compromised_host")
        bad_port = [
            fl for fl in result.suspicious_logs
            if FilterReason.KNOWN_BAD_PORT in fl.reasons
        ]
        assert len(bad_port) == 2

    def test_high_freq_source_rule(self):
        pf = LogPreFilter(high_freq_threshold=5)
        logs = [make_log(source_ip="10.0.1.99") for _ in range(10)]
        logs.append(make_log(source_ip="10.0.1.1"))
        result = pf.filter(logs, "compromised_host")
        hf = [
            fl for fl in result.suspicious_logs
            if FilterReason.HIGH_FREQ_SOURCE in fl.reasons
        ]
        assert len(hf) == 10  # 只有 10.0.1.99 触发

    def test_failed_auth_rule_anomalous_login(self):
        pf = LogPreFilter()
        logs = [
            make_log(action="failed", source_ip="8.8.8.8"),
            make_log(action="success", source_ip="10.0.1.1"),
        ]
        result = pf.filter(logs, "anomalous_login")
        failed = [
            fl for fl in result.suspicious_logs
            if FilterReason.FAILED_AUTH in fl.reasons
        ]
        assert len(failed) == 1

    def test_large_transfer_rule_data_exfiltration(self):
        pf = LogPreFilter(large_transfer_threshold=1000)
        logs = [
            make_log(raw_data={"bytes": 5000}),
            make_log(raw_data={"bytes": 100}),
        ]
        result = pf.filter(logs, "data_exfiltration")
        large = [
            fl for fl in result.suspicious_logs
            if FilterReason.LARGE_TRANSFER in fl.reasons
        ]
        assert len(large) == 1

    def test_filter_ratio(self):
        pf = LogPreFilter()
        logs = [
            make_log(action="alert"),
            make_log(action="allow", timestamp=datetime(2024, 1, 15, 12, 0, 0)),
        ]
        result = pf.filter(logs, "compromised_host")
        assert result.total_input == 2
        assert 0.0 <= result.filter_ratio <= 1.0

    def test_format_filter_summary(self):
        pf = LogPreFilter()
        logs = [make_log(action="alert"), make_log(action="block")]
        result = pf.filter(logs, "compromised_host")
        summary_text = result.format_filter_summary()
        assert "规则预过滤结果" in summary_text
        assert "输入日志" in summary_text

    def test_risk_score_increases_with_reasons(self):
        pf = LogPreFilter()
        # 多条规则触发 -> 更高风险分
        log = make_log(
            action="alert",
            dest_port=4444,
            timestamp=datetime(2024, 1, 15, 3, 0, 0),
        )
        result = pf.filter([log], "compromised_host")
        assert len(result.suspicious_logs) == 1
        assert result.suspicious_logs[0].risk_score > 3.0


# ==================== LogPreprocessor 测试 ====================

class TestLogPreprocessor:

    def test_empty_logs(self):
        pp = LogPreprocessor()
        summary = pp.summarize([], "compromised_host")
        assert summary.total_count == 0
        assert summary.sampled_logs == []

    def test_disabled_returns_minimal(self):
        pp = LogPreprocessor(enabled=False)
        logs = make_logs(10)
        summary = pp.summarize(logs, "compromised_host")
        assert summary.total_count == 10
        assert summary.ip_freq == {}
        assert summary.sampled_logs == []

    def test_common_stats(self):
        pp = LogPreprocessor()
        logs = [
            make_log(source_ip="10.0.1.1", dest_ip="8.8.8.8", protocol="TCP", action="allow"),
            make_log(source_ip="10.0.1.1", dest_ip="8.8.4.4", protocol="UDP", action="block"),
            make_log(source_ip="10.0.1.2", dest_ip="8.8.8.8", protocol="TCP", action="allow"),
        ]
        summary = pp.summarize(logs, "compromised_host")
        assert summary.total_count == 3
        assert summary.ip_freq["10.0.1.1"] == 2
        assert summary.ip_freq["10.0.1.2"] == 1
        assert "TCP" in summary.protocol_dist
        assert "UDP" in summary.protocol_dist
        assert summary.time_range is not None

    def test_sampling_priority(self):
        pp = LogPreprocessor(sample_size=5)
        logs = [
            make_log(action="alert"),
            make_log(action="block"),
            make_log(action="fail"),
            make_log(action="allow"),
            make_log(action="allow"),
            make_log(action="allow"),
            make_log(action="allow"),
        ]
        summary = pp.summarize(logs, "compromised_host")
        assert len(summary.sampled_logs) == 5
        # 优先采样告警日志
        alert_samples = [s for s in summary.sampled_logs if "[alert]" in s or "[block]" in s or "[fail]" in s]
        assert len(alert_samples) >= 3

    def test_anomalous_login_stats(self):
        pp = LogPreprocessor()
        logs = [
            make_log(action="failed", raw_data={"username": "admin"}),
            make_log(action="failed", raw_data={"username": "admin"}),
            make_log(action="success", raw_data={"username": "user1"}),
        ]
        summary = pp.summarize(logs, "anomalous_login")
        assert "登录失败数" in summary.analysis_specific
        assert summary.analysis_specific["登录失败数"] == 2
        assert summary.analysis_specific["登录成功数"] == 1

    def test_ddos_stats(self):
        pp = LogPreprocessor()
        logs = [
            make_log(
                source_ip=f"8.8.8.{i}",
                timestamp=datetime(2024, 1, 15, 10, 0, i),
                raw_data={"flags": "SYN"},
            )
            for i in range(10)
        ]
        summary = pp.summarize(logs, "ddos_detection")
        assert "估算RPS" in summary.analysis_specific
        assert "SYN包数" in summary.analysis_specific
        assert summary.analysis_specific["SYN包数"] == 10

    def test_data_exfiltration_stats(self):
        pp = LogPreprocessor()
        logs = [
            make_log(dest_ip="8.8.8.8", raw_data={"bytes": 15_000_000}),
            make_log(dest_ip="10.0.1.1", raw_data={"bytes": 500}),
        ]
        summary = pp.summarize(logs, "data_exfiltration")
        assert "总传输字节" in summary.analysis_specific
        assert summary.analysis_specific["大数据传输(>10MB)"] == 1
        assert summary.analysis_specific["外部目标连接数"] == 1

    def test_lateral_movement_stats(self):
        pp = LogPreprocessor()
        logs = [
            make_log(dest_ip="10.0.1.5", dest_port=22),
            make_log(dest_ip="10.0.1.6", dest_port=3389),
            make_log(dest_ip="10.0.1.7", dest_port=445),
            make_log(dest_ip="8.8.8.8", dest_port=80),
        ]
        summary = pp.summarize(logs, "lateral_movement")
        assert summary.analysis_specific["内网连接数"] == 3
        assert summary.analysis_specific["SSH/RDP连接数"] == 2
        assert summary.analysis_specific["SMB连接数"] == 1

    def test_format_for_llm_output(self):
        pp = LogPreprocessor()
        logs = make_logs(5, action="alert")
        summary = pp.summarize(logs, "compromised_host", filtered_from=100)
        text = summary.format_for_llm()
        assert "日志统计摘要" in text
        assert "从100条中筛选" in text
        assert "Top源IP" in text
        assert "代表性日志采样" in text

    def test_filtered_from_tracking(self):
        pp = LogPreprocessor()
        logs = make_logs(3)
        summary = pp.summarize(logs, "compromised_host", filtered_from=500)
        assert summary.filtered_from == 500
        assert summary.total_count == 3

    def test_unknown_analysis_type_no_crash(self):
        """未知分析类型不应崩溃，只跳过专属统计"""
        pp = LogPreprocessor()
        logs = make_logs(5)
        summary = pp.summarize(logs, "unknown_type")
        assert summary.total_count == 5
        assert summary.analysis_specific == {}
        assert len(summary.sampled_logs) > 0
