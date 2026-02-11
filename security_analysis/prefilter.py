"""
日志预过滤器 - 规则过滤
基于规则筛出可疑日志子集，减少 LLM 处理量
"""
from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from security_analysis.architecture_v2 import SecurityLog


class FilterReason(Enum):
    """过滤原因枚举"""
    ALERT_ACTION = "alert_action"
    OFF_HOURS = "off_hours"
    HIGH_FREQ_SOURCE = "high_freq_source"
    KNOWN_BAD_PORT = "known_bad_port"
    LARGE_TRANSFER = "large_transfer"
    FAILED_AUTH = "failed_auth"
    INTERNAL_SCAN = "internal_scan"
    NON_STANDARD_PORT = "non_standard_port"
    EXTERNAL_CONNECTION = "external_connection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_PROTOCOL = "suspicious_protocol"
    HIGH_FREQUENCY_DEST = "high_frequency_dest"


@dataclass
class FilteredLog:
    """过滤后的日志条目"""
    log: SecurityLog
    reasons: List[FilterReason] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class FilterResult:
    """过滤结果"""
    total_input: int = 0
    suspicious_logs: List[FilteredLog] = field(default_factory=list)
    reason_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def filter_ratio(self) -> float:
        if self.total_input == 0:
            return 0.0
        return 1.0 - len(self.suspicious_logs) / self.total_input

    def format_filter_summary(self) -> str:
        lines = ["=== 规则预过滤结果 ==="]
        lines.append(f"输入日志: {self.total_input}条")
        lines.append(f"可疑日志: {len(self.suspicious_logs)}条")
        lines.append(f"过滤比例: {self.filter_ratio*100:.1f}%")

        if self.reason_counts:
            sorted_reasons = sorted(self.reason_counts.items(), key=lambda x: -x[1])
            lines.append("触发规则: " + ", ".join(
                f"{r}: {c}次" for r, c in sorted_reasons
            ))

        # 高风险日志 Top 10
        top_risk = sorted(self.suspicious_logs, key=lambda x: -x.risk_score)[:10]
        if top_risk:
            lines.append(f"\n高风险日志 (Top {len(top_risk)}):")
            for fl in top_risk:
                log = fl.log
                reasons_str = ",".join(r.value for r in fl.reasons)
                lines.append(
                    f"  [{log.log_type}] {log.timestamp} {log.source_ip}->{log.dest_ip}"
                    f":{log.dest_port} [{log.action}] 风险={fl.risk_score:.1f} ({reasons_str})"
                )

        return "\n".join(lines)


class LogPreFilter:
    """日志预过滤器 - 基于规则筛选可疑日志"""

    # 已知恶意/可疑端口
    KNOWN_BAD_PORTS = {4444, 5555, 1337, 31337, 6667, 6668, 6669, 8888, 9999}
    # 标准服务端口
    STANDARD_PORTS = {
        22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        3306, 3389, 5432, 8080, 8443,
    }
    # 告警关键词
    ALERT_KEYWORDS = ("alert", "block", "deny", "drop", "reject", "fail", "threat", "malicious")

    def __init__(
        self,
        enabled: bool = True,
        work_hours: tuple = (8, 20),
        large_transfer_threshold: int = 10_000_000,
        high_freq_threshold: int = 50,
    ):
        self.enabled = enabled
        self.work_hours = work_hours
        self.large_transfer_threshold = large_transfer_threshold
        self.high_freq_threshold = high_freq_threshold

    def filter(self, logs: List[SecurityLog], analysis_type: str) -> FilterResult:
        """对日志执行规则过滤，返回可疑子集"""
        result = FilterResult(total_input=len(logs))

        if not self.enabled or not logs:
            # 禁用时全部保留
            result.suspicious_logs = [FilteredLog(log=l) for l in logs]
            return result

        # 预计算频次表
        from collections import Counter
        src_freq = Counter(l.source_ip for l in logs)
        dst_freq = Counter(l.dest_ip for l in logs)

        # 获取分析器专属规则
        specific_rules = getattr(self, f"_rules_{analysis_type}", None)

        reason_counts: Dict[str, int] = {}

        for log in logs:
            reasons: List[FilterReason] = []

            # 通用规则
            self._apply_common_rules(log, reasons, src_freq, dst_freq)

            # 专属规则
            if specific_rules:
                specific_rules(log, reasons, src_freq, dst_freq)

            if reasons:
                score = self._calc_risk_score(reasons)
                result.suspicious_logs.append(
                    FilteredLog(log=log, reasons=reasons, risk_score=score)
                )
                for r in reasons:
                    reason_counts[r.value] = reason_counts.get(r.value, 0) + 1

        result.reason_counts = reason_counts
        return result

    def _apply_common_rules(self, log: SecurityLog, reasons: List[FilterReason],
                            src_freq, dst_freq):
        """通用过滤规则"""
        # 告警动作
        if log.action and any(kw in log.action.lower() for kw in self.ALERT_KEYWORDS):
            reasons.append(FilterReason.ALERT_ACTION)

        # 非工作时间
        if log.timestamp.hour < self.work_hours[0] or log.timestamp.hour >= self.work_hours[1]:
            reasons.append(FilterReason.OFF_HOURS)

        # 高频源IP
        if src_freq.get(log.source_ip, 0) >= self.high_freq_threshold:
            reasons.append(FilterReason.HIGH_FREQ_SOURCE)

        # 已知恶意端口
        if log.dest_port in self.KNOWN_BAD_PORTS:
            reasons.append(FilterReason.KNOWN_BAD_PORT)

    @staticmethod
    def _calc_risk_score(reasons: List[FilterReason]) -> float:
        """根据触发规则数量和类型计算风险分"""
        weights = {
            FilterReason.ALERT_ACTION: 3.0,
            FilterReason.KNOWN_BAD_PORT: 2.5,
            FilterReason.FAILED_AUTH: 2.5,
            FilterReason.PRIVILEGE_ESCALATION: 3.0,
            FilterReason.LARGE_TRANSFER: 2.0,
            FilterReason.INTERNAL_SCAN: 2.0,
            FilterReason.EXTERNAL_CONNECTION: 1.5,
            FilterReason.HIGH_FREQ_SOURCE: 1.5,
            FilterReason.HIGH_FREQUENCY_DEST: 1.5,
            FilterReason.OFF_HOURS: 1.0,
            FilterReason.NON_STANDARD_PORT: 1.0,
            FilterReason.SUSPICIOUS_PROTOCOL: 1.5,
        }
        return sum(weights.get(r, 1.0) for r in reasons)

    # ---- 分析器专属规则 ----

    def _rules_compromised_host(self, log, reasons, src_freq, dst_freq):
        c2_ports = {443, 8443, 4444, 5555, 8080, 1337}
        if log.dest_port in c2_ports and not log.dest_ip.startswith(("10.", "192.168.", "172.")):
            reasons.append(FilterReason.EXTERNAL_CONNECTION)
        if log.log_type == "dns" and log.raw_data.get("query_type") == "TXT":
            reasons.append(FilterReason.SUSPICIOUS_PROTOCOL)
        if log.dest_port and log.dest_port not in self.STANDARD_PORTS and log.dest_port not in self.KNOWN_BAD_PORTS:
            reasons.append(FilterReason.NON_STANDARD_PORT)
        if dst_freq.get(log.dest_ip, 0) >= self.high_freq_threshold:
            reasons.append(FilterReason.HIGH_FREQUENCY_DEST)

    def _rules_anomalous_login(self, log, reasons, src_freq, dst_freq):
        if log.action and "fail" in log.action.lower():
            reasons.append(FilterReason.FAILED_AUTH)
        if not log.source_ip.startswith(("10.", "192.168.", "172.")):
            reasons.append(FilterReason.EXTERNAL_CONNECTION)
        if src_freq.get(log.source_ip, 0) >= 10:
            reasons.append(FilterReason.HIGH_FREQ_SOURCE)
        if log.raw_data.get("geo_anomaly"):
            reasons.append(FilterReason.SUSPICIOUS_PROTOCOL)

    def _rules_data_exfiltration(self, log, reasons, src_freq, dst_freq):
        if log.raw_data.get("bytes", 0) > self.large_transfer_threshold:
            reasons.append(FilterReason.LARGE_TRANSFER)
        if not log.dest_ip.startswith(("10.", "192.168.", "172.")):
            reasons.append(FilterReason.EXTERNAL_CONNECTION)
        if log.dest_port and log.dest_port not in self.STANDARD_PORTS:
            reasons.append(FilterReason.NON_STANDARD_PORT)
        if log.protocol and log.protocol.upper() in ("DNS", "ICMP"):
            reasons.append(FilterReason.SUSPICIOUS_PROTOCOL)

    def _rules_malware_detection(self, log, reasons, src_freq, dst_freq):
        if log.log_type == "edr":
            reasons.append(FilterReason.ALERT_ACTION)
        if log.raw_data.get("file_hash") or log.raw_data.get("hash"):
            reasons.append(FilterReason.SUSPICIOUS_PROTOCOL)
        if log.dest_port in self.KNOWN_BAD_PORTS:
            reasons.append(FilterReason.KNOWN_BAD_PORT)
        if log.raw_data.get("registry_modified") or log.raw_data.get("service_created"):
            reasons.append(FilterReason.PRIVILEGE_ESCALATION)

    def _rules_insider_threat(self, log, reasons, src_freq, dst_freq):
        if log.raw_data.get("privilege_escalation"):
            reasons.append(FilterReason.PRIVILEGE_ESCALATION)
        if not log.dest_ip.startswith(("10.", "192.168.", "172.")):
            reasons.append(FilterReason.EXTERNAL_CONNECTION)
        if log.raw_data.get("bytes", 0) > self.large_transfer_threshold:
            reasons.append(FilterReason.LARGE_TRANSFER)
        if log.raw_data.get("unauthorized_access"):
            reasons.append(FilterReason.FAILED_AUTH)

    def _rules_ddos_detection(self, log, reasons, src_freq, dst_freq):
        if src_freq.get(log.source_ip, 0) >= self.high_freq_threshold:
            reasons.append(FilterReason.HIGH_FREQ_SOURCE)
        if log.raw_data.get("flags") == "SYN":
            reasons.append(FilterReason.SUSPICIOUS_PROTOCOL)
        if not log.source_ip.startswith(("10.", "192.168.", "172.")):
            reasons.append(FilterReason.EXTERNAL_CONNECTION)
        if dst_freq.get(log.dest_ip, 0) >= self.high_freq_threshold:
            reasons.append(FilterReason.HIGH_FREQUENCY_DEST)

    def _rules_lateral_movement(self, log, reasons, src_freq, dst_freq):
        if log.dest_port in {22, 3389, 445, 139, 5985, 5986}:
            reasons.append(FilterReason.INTERNAL_SCAN)
        if log.dest_ip.startswith(("10.", "192.168.", "172.")) and \
           dst_freq.get(log.dest_ip, 0) >= 5:
            reasons.append(FilterReason.HIGH_FREQUENCY_DEST)
        if not log.dest_ip.startswith(("10.", "192.168.", "172.")):
            reasons.append(FilterReason.EXTERNAL_CONNECTION)
        if log.raw_data.get("wmi") or log.raw_data.get("psexec"):
            reasons.append(FilterReason.SUSPICIOUS_PROTOCOL)

    def _rules_phishing_detection(self, log, reasons, src_freq, dst_freq):
        if log.action and "click" in log.action.lower():
            reasons.append(FilterReason.ALERT_ACTION)
        url = log.raw_data.get("url", "")
        if url and any(kw in url.lower() for kw in ("login", "signin", "verify", "secure", "account")):
            reasons.append(FilterReason.SUSPICIOUS_PROTOCOL)
        if not log.dest_ip.startswith(("10.", "192.168.", "172.")):
            reasons.append(FilterReason.EXTERNAL_CONNECTION)
        if log.raw_data.get("attachment"):
            reasons.append(FilterReason.KNOWN_BAD_PORT)
