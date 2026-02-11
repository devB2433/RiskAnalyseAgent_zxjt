"""
日志预处理器 - 统计摘要 + 采样
将海量日志压缩为结构化摘要供 LLM 分析
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from security_analysis.architecture_v2 import SecurityLog


@dataclass
class LogSummary:
    """日志统计摘要"""
    total_count: int = 0
    filtered_from: int = 0
    time_range: Optional[str] = None
    ip_freq: Dict[str, int] = field(default_factory=dict)
    dest_ip_freq: Dict[str, int] = field(default_factory=dict)
    protocol_dist: Dict[str, int] = field(default_factory=dict)
    action_dist: Dict[str, int] = field(default_factory=dict)
    port_dist: Dict[str, int] = field(default_factory=dict)
    top_connections: List[str] = field(default_factory=list)
    analysis_specific: Dict[str, Any] = field(default_factory=dict)
    sampled_logs: List[str] = field(default_factory=list)

    def format_for_llm(self) -> str:
        lines = ["=== 日志统计摘要 ==="]
        if self.filtered_from > 0:
            lines.append(f"日志总数: {self.total_count} (从{self.filtered_from}条中筛选)")
        else:
            lines.append(f"日志总数: {self.total_count}")

        if self.time_range:
            lines.append(f"时间范围: {self.time_range}")

        if self.ip_freq:
            top = sorted(self.ip_freq.items(), key=lambda x: -x[1])[:15]
            lines.append("Top源IP: " + ", ".join(f"{ip}: {c}次" for ip, c in top))

        if self.dest_ip_freq:
            top = sorted(self.dest_ip_freq.items(), key=lambda x: -x[1])[:15]
            lines.append("Top目标IP: " + ", ".join(f"{ip}: {c}次" for ip, c in top))

        if self.protocol_dist:
            lines.append("协议分布: " + ", ".join(f"{k}: {v}" for k, v in self.protocol_dist.items()))

        if self.action_dist:
            lines.append("动作分布: " + ", ".join(f"{k}: {v}" for k, v in self.action_dist.items()))

        if self.port_dist:
            top = sorted(self.port_dist.items(), key=lambda x: -x[1])[:10]
            lines.append("Top端口: " + ", ".join(f"{p}: {c}次" for p, c in top))

        if self.top_connections:
            lines.append("高频连接对: " + ", ".join(self.top_connections[:10]))

        if self.analysis_specific:
            lines.append("专项统计:")
            for k, v in self.analysis_specific.items():
                lines.append(f"  {k}: {v}")

        if self.sampled_logs:
            lines.append(f"\n代表性日志采样 ({len(self.sampled_logs)}条):")
            for log_line in self.sampled_logs:
                lines.append(f"  {log_line}")

        return "\n".join(lines)


class LogPreprocessor:
    """日志预处理器 - 生成统计摘要 + 采样"""

    def __init__(self, enabled: bool = True, sample_size: int = 20, top_n: int = 15):
        self.enabled = enabled
        self.sample_size = sample_size
        self.top_n = top_n

    def summarize(self, logs: List[SecurityLog], analysis_type: str,
                  filtered_from: int = 0) -> LogSummary:
        if not self.enabled or not logs:
            return LogSummary(total_count=len(logs))

        summary = LogSummary(
            total_count=len(logs),
            filtered_from=filtered_from,
        )

        # 通用统计
        self._compute_common_stats(logs, summary)

        # 分析器专属统计
        specific_method = getattr(self, f"_stats_{analysis_type}", None)
        if specific_method:
            specific_method(logs, summary)

        # 采样
        summary.sampled_logs = self._sample_logs(logs, analysis_type)

        return summary

    def _compute_common_stats(self, logs: List[SecurityLog], summary: LogSummary):
        """通用统计：IP频次、时间、协议、动作、端口、连接对"""
        src_counter = Counter()
        dst_counter = Counter()
        proto_counter = Counter()
        action_counter = Counter()
        port_counter = Counter()
        conn_counter = Counter()
        timestamps = []

        for log in logs:
            src_counter[log.source_ip] += 1
            dst_counter[log.dest_ip] += 1
            if log.protocol:
                proto_counter[log.protocol] += 1
            if log.action:
                action_counter[log.action] += 1
            if log.dest_port is not None:
                port_counter[str(log.dest_port)] += 1
            conn_counter[f"{log.source_ip}->{log.dest_ip}"] += 1
            timestamps.append(log.timestamp)

        summary.ip_freq = dict(src_counter.most_common(self.top_n))
        summary.dest_ip_freq = dict(dst_counter.most_common(self.top_n))
        summary.protocol_dist = dict(proto_counter)
        summary.action_dist = dict(action_counter)
        summary.port_dist = dict(port_counter.most_common(self.top_n))

        top_conns = conn_counter.most_common(10)
        summary.top_connections = [f"{pair}: {c}次" for pair, c in top_conns]

        if timestamps:
            ts_sorted = sorted(timestamps)
            summary.time_range = f"{ts_sorted[0]} ~ {ts_sorted[-1]}"

    # ---- 分析器专属统计 ----

    def _stats_compromised_host(self, logs: List[SecurityLog], summary: LogSummary):
        c2_ports = {443, 8443, 4444, 5555, 8080, 1337}
        c2_connections = sum(1 for l in logs if l.dest_port in c2_ports)
        blocked = sum(1 for l in logs if l.action and "block" in l.action.lower())
        dns_logs = [l for l in logs if l.log_type == "dns"]
        summary.analysis_specific = {
            "C2常见端口连接数": c2_connections,
            "被阻断连接数": blocked,
            "DNS查询数": len(dns_logs),
            "唯一目标IP数": len(set(l.dest_ip for l in logs)),
        }

    def _stats_anomalous_login(self, logs: List[SecurityLog], summary: LogSummary):
        failed = sum(1 for l in logs if l.action and "fail" in l.action.lower())
        success = sum(1 for l in logs if l.action and "success" in l.action.lower())
        total_auth = failed + success
        users = Counter(l.raw_data.get("username", "unknown") for l in logs)
        summary.analysis_specific = {
            "登录失败数": failed,
            "登录成功数": success,
            "失败率": f"{failed/total_auth*100:.1f}%" if total_auth else "N/A",
            "涉及用户数": len(users),
            "Top用户": ", ".join(f"{u}: {c}" for u, c in users.most_common(5)),
        }

    def _stats_data_exfiltration(self, logs: List[SecurityLog], summary: LogSummary):
        total_bytes = sum(l.raw_data.get("bytes", 0) for l in logs)
        large = sum(1 for l in logs if l.raw_data.get("bytes", 0) > 10_000_000)
        ext_dest = sum(1 for l in logs if not l.dest_ip.startswith(("10.", "192.168.", "172.")))
        summary.analysis_specific = {
            "总传输字节": total_bytes,
            "大数据传输(>10MB)": large,
            "外部目标连接数": ext_dest,
        }

    def _stats_malware_detection(self, logs: List[SecurityLog], summary: LogSummary):
        alerts = sum(1 for l in logs if l.action and "alert" in l.action.lower())
        edr_logs = sum(1 for l in logs if l.log_type == "edr")
        hashes = set()
        for l in logs:
            h = l.raw_data.get("file_hash") or l.raw_data.get("hash")
            if h:
                hashes.add(h)
        summary.analysis_specific = {
            "告警数": alerts,
            "EDR日志数": edr_logs,
            "唯一文件哈希数": len(hashes),
        }

    def _stats_insider_threat(self, logs: List[SecurityLog], summary: LogSummary):
        priv_esc = sum(1 for l in logs if l.raw_data.get("privilege_escalation"))
        after_hours = sum(1 for l in logs if l.timestamp.hour < 8 or l.timestamp.hour >= 20)
        users = Counter(l.raw_data.get("username", "unknown") for l in logs)
        summary.analysis_specific = {
            "权限提升事件": priv_esc,
            "非工作时间操作": after_hours,
            "涉及用户数": len(users),
        }

    def _stats_ddos_detection(self, logs: List[SecurityLog], summary: LogSummary):
        if len(logs) >= 2:
            ts = sorted(l.timestamp for l in logs)
            duration = (ts[-1] - ts[0]).total_seconds()
            rps = len(logs) / duration if duration > 0 else len(logs)
        else:
            rps = len(logs)
            duration = 0
        syn_count = sum(1 for l in logs if l.raw_data.get("flags") == "SYN")
        summary.analysis_specific = {
            "估算RPS": f"{rps:.1f}",
            "持续时间(秒)": f"{duration:.0f}",
            "SYN包数": syn_count,
            "唯一源IP数": len(set(l.source_ip for l in logs)),
        }

    def _stats_lateral_movement(self, logs: List[SecurityLog], summary: LogSummary):
        internal = [l for l in logs if l.dest_ip.startswith(("10.", "192.168.", "172."))]
        ssh_rdp = sum(1 for l in logs if l.dest_port in {22, 3389})
        smb = sum(1 for l in logs if l.dest_port in {445, 139})
        summary.analysis_specific = {
            "内网连接数": len(internal),
            "SSH/RDP连接数": ssh_rdp,
            "SMB连接数": smb,
            "涉及内网主机数": len(set(l.dest_ip for l in internal)),
        }

    def _stats_phishing_detection(self, logs: List[SecurityLog], summary: LogSummary):
        urls = Counter(l.raw_data.get("url", "") for l in logs if l.raw_data.get("url"))
        clicked = sum(1 for l in logs if l.action and "click" in l.action.lower())
        users = set(l.raw_data.get("username") for l in logs if l.raw_data.get("username"))
        summary.analysis_specific = {
            "唯一URL数": len(urls),
            "点击事件数": clicked,
            "涉及用户数": len(users),
            "Top URL": ", ".join(f"{u}: {c}" for u, c in urls.most_common(3)),
        }

    # ---- 采样策略 ----

    def _sample_logs(self, logs: List[SecurityLog], analysis_type: str) -> List[str]:
        """优先采样告警/异常日志，补充均匀采样"""
        if not logs:
            return []

        sample_size = min(self.sample_size, len(logs))

        # 优先：告警/失败/阻断日志
        priority = [
            l for l in logs
            if l.action and any(
                kw in l.action.lower()
                for kw in ("alert", "block", "deny", "fail", "drop", "reject")
            )
        ]

        sampled = priority[:sample_size]

        # 补充均匀采样
        if len(sampled) < sample_size:
            remaining = [l for l in logs if l not in sampled]
            if remaining:
                step = max(1, len(remaining) // (sample_size - len(sampled)))
                sampled.extend(remaining[::step][:sample_size - len(sampled)])

        return [self._format_one_log(l) for l in sampled]

    @staticmethod
    def _format_one_log(log: SecurityLog) -> str:
        parts = [f"[{log.log_type}]", str(log.timestamp)]
        parts.append(f"{log.source_ip} -> {log.dest_ip}")
        if log.dest_port is not None:
            parts.append(f":{log.dest_port}")
        if log.protocol:
            parts.append(f"({log.protocol})")
        if log.action:
            parts.append(f"[{log.action}]")
        if log.raw_data:
            extras = " ".join(f"{k}={v}" for k, v in list(log.raw_data.items())[:3])
            if extras:
                parts.append(extras)
        return " ".join(parts)
