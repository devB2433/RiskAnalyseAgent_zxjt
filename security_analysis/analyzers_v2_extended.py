"""
安全分析器V2扩展 - 剩余5个分析器

使用真实威胁情报进行验证
"""
import re
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field

from src.core.base import AgentState, BaseAgent, AgentConfig
from src.agent_framework import UniversalAgentFramework

# 复用V2的数据模型和工具
from security_analysis.architecture_v2 import (
    SecurityLog, Finding, AnalysisResult, ThreatIntelToolkit,
)


class AnomalousLoginAnalyzer(BaseAgent):
    """异常登录检测分析器V2"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(name="anomalous_login_analyzer", description="检测异常登录行为")
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start", "analyzer": self.config.name,
            "log_count": len(logs),
        })

        chain = self.framework.create_chain([
            """分析以下安全日志，识别异常登录行为。
重点关注：
1. 异地登录（地理位置异常）
2. 非工作时间登录
3. 暴力破解尝试（短时间多次失败）
4. 同一账号多地同时登录
5. 使用已知恶意IP登录

日志数据：{input}""",
            """基于分析结果，提取：
1. 异常登录事件列表
2. 涉及的用户账号
3. 来源IP地址
4. 异常原因分类
5. 风险评分

分析结果：{input}""",
        ])

        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 威胁情报验证登录来源IP
        suspicious_ips = self._extract_ips(analysis_text)
        verified = []
        for ip in suspicious_ips[:10]:
            try:
                intel = await self.threat_intel.query_ip(ip)
                verified.append(intel)
            except Exception:
                pass

        malicious_ips = [v for v in verified if v.get("is_malicious")]
        confidence = min(0.5 + len(malicious_ips) * 0.15, 1.0) if suspicious_ips else 0.2

        findings = []
        for v in malicious_ips:
            findings.append(Finding(
                type="malicious_login_source",
                severity="high",
                description=f"来自恶意IP {v['ip']} 的登录尝试 (威胁评分: {v.get('threat_score', 0)})",
                evidence=[f"IP: {v['ip']}", f"威胁类型: {v.get('threat_types', [])}"],
                confidence=v.get("threat_score", 0) / 100,
            ))

        state["analysis_result"] = AnalysisResult(
            analysis_type="anomalous_login",
            findings=findings,
            confidence=confidence,
            evidence=[f"检查了 {len(suspicious_ips)} 个IP, {len(malicious_ips)} 个恶意"],
            recommendations=["封锁恶意IP", "强制相关账号重置密码", "启用MFA"],
            trace=trace,
        )
        return state

    def _format_logs(self, logs):
        return "\n".join(str(l) for l in logs[:50])

    def _extract_ips(self, text):
        return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))


class DataExfiltrationAnalyzer(BaseAgent):
    """数据外泄检测分析器V2"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(name="data_exfiltration_analyzer", description="检测数据外泄行为")
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({"type": "analyzer_start", "analyzer": self.config.name, "log_count": len(logs)})

        chain = self.framework.create_chain([
            """分析以下安全日志，识别数据外泄行为。
重点关注：
1. 异常大量数据传输（上传流量远超正常）
2. 向外部IP/域名传输敏感数据
3. 非工作时间的大量数据访问
4. 使用非标准端口传输数据
5. DNS隧道数据外泄

日志数据：{input}""",
            """生成数据外泄检测报告：
1. 可疑数据传输事件
2. 涉及的源/目标地址
3. 传输数据量估算
4. 外泄渠道分析
5. 风险评估

分析结果：{input}""",
        ])

        logs_text = "\n".join(str(l) for l in logs[:50])
        chain_state = AgentState()
        chain_state["input"] = logs_text
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 验证目标IP/域名
        dest_ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', analysis_text)))
        verified = []
        for ip in dest_ips[:10]:
            try:
                intel = await self.threat_intel.query_ip(ip)
                verified.append(intel)
            except Exception:
                pass

        malicious = [v for v in verified if v.get("is_malicious")]
        confidence = min(0.4 + len(malicious) * 0.2, 1.0) if dest_ips else 0.1

        findings = []
        for v in malicious:
            findings.append(Finding(
                type="data_exfiltration_target",
                severity="critical",
                description=f"数据传输目标 {v['ip']} 为已知恶意地址",
                evidence=[f"IP: {v['ip']}", f"威胁评分: {v.get('threat_score', 0)}"],
                confidence=v.get("threat_score", 0) / 100,
            ))

        state["analysis_result"] = AnalysisResult(
            analysis_type="data_exfiltration",
            findings=findings,
            confidence=confidence,
            evidence=[f"检查了 {len(dest_ips)} 个目标地址"],
            recommendations=["立即阻断可疑传输", "审查涉及账号权限", "检查DLP策略"],
            trace=trace,
        )
        return state


class InsiderThreatAnalyzer(BaseAgent):
    """内部威胁检测分析器V2"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(name="insider_threat_analyzer", description="检测内部威胁行为")
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({"type": "analyzer_start", "analyzer": self.config.name, "log_count": len(logs)})

        chain = self.framework.create_chain([
            """分析以下安全日志，识别内部威胁行为。
重点关注：
1. 权限提升尝试
2. 访问非授权资源
3. 异常数据下载/复制行为
4. 账号共享或凭证滥用
5. 离职前异常行为模式

日志数据：{input}""",
            """生成内部威胁检测报告：
1. 可疑内部行为事件
2. 涉及的用户和资源
3. 行为模式分析
4. 风险评级
5. 建议措施

分析结果：{input}""",
        ])

        logs_text = "\n".join(str(l) for l in logs[:50])
        chain_state = AgentState()
        chain_state["input"] = logs_text
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 内部威胁主要基于行为分析，威胁情报辅助验证外部连接
        ext_ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', analysis_text)))
        ext_ips = [ip for ip in ext_ips if not ip.startswith(("10.", "192.168.", "172."))]

        verified = []
        for ip in ext_ips[:5]:
            try:
                intel = await self.threat_intel.query_ip(ip)
                verified.append(intel)
            except Exception:
                pass

        malicious = [v for v in verified if v.get("is_malicious")]
        confidence = 0.5 if logs else 0.1
        if malicious:
            confidence = min(confidence + len(malicious) * 0.15, 1.0)

        findings = []
        if malicious:
            for v in malicious:
                findings.append(Finding(
                    type="insider_external_contact",
                    severity="high",
                    description=f"内部用户与恶意外部地址 {v['ip']} 通信",
                    evidence=[f"IP: {v['ip']}"],
                    confidence=v.get("threat_score", 0) / 100,
                ))

        state["analysis_result"] = AnalysisResult(
            analysis_type="insider_threat",
            findings=findings,
            confidence=confidence,
            evidence=[f"分析了 {len(logs)} 条日志"],
            recommendations=["审查用户权限", "加强访问控制", "启用UEBA监控"],
            trace=trace,
        )
        return state


class DDoSDetectionAnalyzer(BaseAgent):
    """DDoS攻击检测分析器V2"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(name="ddos_detection_analyzer", description="检测DDoS攻击")
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({"type": "analyzer_start", "analyzer": self.config.name, "log_count": len(logs)})

        chain = self.framework.create_chain([
            """分析以下安全日志，识别DDoS攻击。
重点关注：
1. 短时间内大量请求（SYN Flood, UDP Flood）
2. 来自多个IP的协同攻击
3. 异常流量模式（带宽突增）
4. 应用层攻击（HTTP Flood, Slowloris）
5. DNS放大攻击

日志数据：{input}""",
            """生成DDoS检测报告：
1. 攻击类型判定
2. 攻击源IP列表
3. 攻击目标
4. 攻击规模估算
5. 缓解建议

分析结果：{input}""",
        ])

        logs_text = "\n".join(str(l) for l in logs[:50])
        chain_state = AgentState()
        chain_state["input"] = logs_text
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 批量验证攻击源IP
        attack_ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', analysis_text)))
        attack_ips = [ip for ip in attack_ips if not ip.startswith(("10.", "192.168.", "172."))]

        verified = []
        for ip in attack_ips[:20]:
            try:
                intel = await self.threat_intel.query_ip(ip)
                verified.append(intel)
            except Exception:
                pass

        malicious = [v for v in verified if v.get("is_malicious")]
        confidence = min(0.3 + len(malicious) * 0.05, 1.0) if attack_ips else 0.1

        findings = []
        if len(malicious) >= 3:
            findings.append(Finding(
                type="ddos_attack",
                severity="critical",
                description=f"检测到来自 {len(malicious)} 个已知恶意IP的协同攻击",
                evidence=[f"恶意IP: {v['ip']}" for v in malicious[:5]],
                confidence=confidence,
            ))

        state["analysis_result"] = AnalysisResult(
            analysis_type="ddos_detection",
            findings=findings,
            confidence=confidence,
            evidence=[f"检查了 {len(attack_ips)} 个攻击源IP, {len(malicious)} 个已知恶意"],
            recommendations=["启用DDoS防护", "配置速率限制", "联系ISP协助缓解"],
            trace=trace,
        )
        return state


class LateralMovementAnalyzer(BaseAgent):
    """横向移动检测分析器V2"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(name="lateral_movement_analyzer", description="检测横向移动行为")
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({"type": "analyzer_start", "analyzer": self.config.name, "log_count": len(logs)})

        chain = self.framework.create_chain([
            """分析以下安全日志，识别横向移动行为。
重点关注：
1. 内网主机间异常RDP/SSH连接
2. Pass-the-Hash/Pass-the-Ticket攻击
3. WMI/PSExec远程执行
4. 异常的SMB文件共享访问
5. 内网扫描行为（端口扫描、服务发现）

日志数据：{input}""",
            """生成横向移动检测报告：
1. 横向移动路径图
2. 涉及的主机和账号
3. 使用的攻击技术
4. 攻击阶段判定
5. 遏制建议

分析结果：{input}""",
        ])

        logs_text = "\n".join(str(l) for l in logs[:50])
        chain_state = AgentState()
        chain_state["input"] = logs_text
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 横向移动主要涉及内网IP，但验证是否有外部C2通信
        all_ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', analysis_text)))
        external_ips = [ip for ip in all_ips if not ip.startswith(("10.", "192.168.", "172."))]
        internal_ips = [ip for ip in all_ips if ip.startswith(("10.", "192.168.", "172."))]

        verified = []
        for ip in external_ips[:5]:
            try:
                intel = await self.threat_intel.query_ip(ip)
                verified.append(intel)
            except Exception:
                pass

        malicious = [v for v in verified if v.get("is_malicious")]
        confidence = 0.4 if internal_ips else 0.1
        if malicious:
            confidence = min(confidence + 0.3, 1.0)

        findings = []
        if len(internal_ips) >= 3:
            findings.append(Finding(
                type="lateral_movement",
                severity="high",
                description=f"检测到涉及 {len(internal_ips)} 台内网主机的横向移动行为",
                evidence=[f"内网IP: {ip}" for ip in internal_ips[:5]],
                confidence=confidence,
            ))
        if malicious:
            findings.append(Finding(
                type="c2_communication",
                severity="critical",
                description=f"横向移动过程中发现与 {len(malicious)} 个C2服务器通信",
                evidence=[f"C2: {v['ip']}" for v in malicious],
                confidence=min(confidence + 0.2, 1.0),
            ))

        state["analysis_result"] = AnalysisResult(
            analysis_type="lateral_movement",
            findings=findings,
            confidence=confidence,
            evidence=[f"内网主机: {len(internal_ips)}, 外部C2: {len(malicious)}"],
            recommendations=["隔离受影响主机", "重置相关凭证", "检查域控安全"],
            trace=trace,
        )
        return state
