"""
预处理流程集成测试

验证 SecurityLog → PreFilter → Preprocessor → Analyzer 的端到端流程
"""
import pytest
import asyncio
from datetime import datetime
from security_analysis.architecture_v2 import SecurityLog, SecurityAnalysisRouter
from security_analysis.prefilter import LogPreFilter, FilterResult
from security_analysis.preprocessor import LogPreprocessor, LogSummary


def _make_logs(n=50, analysis_type="compromised_host"):
    """生成测试日志"""
    logs = []
    for i in range(n):
        logs.append(SecurityLog(
            log_type="firewall",
            timestamp=datetime(2024, 1, 15, 10 + i % 12, i % 60),
            source_ip=f"192.168.1.{i % 20 + 10}",
            dest_ip=f"10.0.0.{i % 10 + 1}",
            dest_port=[80, 443, 4444, 8080, 22][i % 5],
            protocol="TCP",
            action=["allow", "block", "alert", "deny"][i % 4],
            raw_data={"bytes": (i + 1) * 1000},
        ))
    return logs


class TestPrefilterPreprocessorPipeline:
    """测试 PreFilter → Preprocessor 管道"""

    def test_full_pipeline_compromised_host(self):
        logs = _make_logs(100, "compromised_host")
        pf = LogPreFilter()
        pp = LogPreprocessor()

        fr = pf.filter(logs, "compromised_host")
        assert isinstance(fr, FilterResult)
        assert len(fr.suspicious_logs) > 0
        assert len(fr.suspicious_logs) <= len(logs)

        suspicious = [fl.log for fl in fr.suspicious_logs]
        summary = pp.summarize(suspicious, "compromised_host", filtered_from=len(logs))
        assert isinstance(summary, LogSummary)
        assert summary.total_count == len(suspicious)
        assert summary.filtered_from == 100
        assert len(summary.sampled_logs) > 0

    def test_full_pipeline_anomalous_login(self):
        logs = []
        for i in range(60):
            logs.append(SecurityLog(
                log_type="auth",
                timestamp=datetime(2024, 1, 15, 3 + i % 20, i % 60),
                source_ip=f"192.168.1.{i % 10 + 1}",
                dest_ip="10.0.0.1",
                dest_port=22,
                protocol="TCP",
                action=["failed", "success", "failed", "failed"][i % 4],
                raw_data={"username": f"user{i % 5}"},
            ))
        pf = LogPreFilter()
        pp = LogPreprocessor()

        fr = pf.filter(logs, "anomalous_login")
        suspicious = [fl.log for fl in fr.suspicious_logs]
        summary = pp.summarize(suspicious, "anomalous_login", filtered_from=len(logs))

        assert "登录失败数" in summary.analysis_specific
        assert summary.filtered_from == 60

    def test_full_pipeline_all_analysis_types(self):
        """验证所有8种分析类型都能走通管道"""
        types = [
            "compromised_host", "anomalous_login", "data_exfiltration",
            "malware_detection", "insider_threat", "ddos_detection",
            "lateral_movement", "phishing_detection",
        ]
        logs = _make_logs(30)
        pf = LogPreFilter()
        pp = LogPreprocessor()

        for atype in types:
            fr = pf.filter(logs, atype)
            suspicious = [fl.log for fl in fr.suspicious_logs]
            summary = pp.summarize(suspicious, atype, filtered_from=len(logs))
            # 每种类型都应该能生成摘要文本
            text = summary.format_for_llm()
            assert "日志统计摘要" in text
            assert summary.filtered_from == 30

    def test_disabled_prefilter_passes_all(self):
        """PreFilter禁用时应返回所有日志"""
        logs = _make_logs(20)
        pf = LogPreFilter(enabled=False)
        fr = pf.filter(logs, "compromised_host")
        assert len(fr.suspicious_logs) == 20

    def test_disabled_preprocessor_returns_minimal(self):
        """Preprocessor禁用时应返回最小摘要"""
        logs = _make_logs(20)
        pp = LogPreprocessor(enabled=False)
        summary = pp.summarize(logs, "compromised_host")
        assert summary.total_count == 20
        assert len(summary.sampled_logs) == 0

    def test_format_output_contains_filter_and_summary(self):
        """验证组合输出包含过滤摘要和统计摘要"""
        logs = _make_logs(50)
        pf = LogPreFilter()
        pp = LogPreprocessor()

        fr = pf.filter(logs, "compromised_host")
        suspicious = [fl.log for fl in fr.suspicious_logs]
        summary = pp.summarize(suspicious, "compromised_host", filtered_from=50)

        combined = fr.format_filter_summary() + "\n\n" + summary.format_for_llm()
        assert "规则预过滤结果" in combined
        assert "日志统计摘要" in combined
        assert "代表性日志采样" in combined

    def test_empty_logs_pipeline(self):
        """空日志输入不应报错"""
        pf = LogPreFilter()
        pp = LogPreprocessor()

        fr = pf.filter([], "compromised_host")
        assert len(fr.suspicious_logs) == 0

        summary = pp.summarize([], "compromised_host")
        assert summary.total_count == 0
