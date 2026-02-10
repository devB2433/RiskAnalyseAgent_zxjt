"""
网络安全日志分析系统 - 架构实现 V2
集成真实威胁情报系统
"""
import sys
import os
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import re

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.agent_framework import UniversalAgentFramework
from src.core.base import AgentState, BaseTool, BaseAgent, AgentConfig
from src.patterns.multi_agent import CollaborationMode, MultiAgentSystem

# 导入威胁情报系统
from src.threat_intel.manager import ThreatIntelManager
from src.threat_intel.base import IOCType, ThreatIntelConfig
from src.threat_intel.providers import VirusTotalProvider, AbuseIPDBProvider


# ==================== 数据模型 ====================

@dataclass
class SecurityLog:
    """安全日志数据结构"""
    log_type: str  # "firewall", "ids", "edr", "auth", "dns", etc.
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    raw_data: Dict = field(default_factory=dict)


@dataclass
class Finding:
    """安全发现项"""
    type: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0-1
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AnalysisResult:
    """分析结果"""
    analysis_type: str
    findings: List[Finding] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    trace: List[Dict[str, Any]] = field(default_factory=list)


class AnalysisType(Enum):
    """分析类型枚举"""
    COMPROMISED_HOST = "compromised_host"
    ANOMALOUS_LOGIN = "anomalous_login"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_DETECTION = "malware_detection"
    INSIDER_THREAT = "insider_threat"
    DDOS_DETECTION = "ddos_detection"
    LATERAL_MOVEMENT = "lateral_movement"
    PHISHING_DETECTION = "phishing_detection"


# ==================== 威胁情报工具包装器 ====================

class ThreatIntelToolkit:
    """威胁情报工具包 - 封装ThreatIntelManager供分析器使用"""

    def __init__(self, use_mock: bool = True, api_keys: Optional[Dict[str, str]] = None):
        """
        初始化威胁情报工具包

        Args:
            use_mock: 是否使用模拟模式（开发/测试用）
            api_keys: API密钥字典，格式: {"virustotal": "key", "abuseipdb": "key"}
        """
        self.use_mock = use_mock
        self.api_keys = api_keys or {}

        # 初始化威胁情报管理器
        providers = []

        # 配置VirusTotal
        if "virustotal" in self.api_keys or use_mock:
            vt_config = ThreatIntelConfig(
                provider_name="virustotal",
                api_key=self.api_keys.get("virustotal", ""),
                use_mock=use_mock
            )
            providers.append(VirusTotalProvider(vt_config))

        # 配置AbuseIPDB
        if "abuseipdb" in self.api_keys or use_mock:
            abuse_config = ThreatIntelConfig(
                provider_name="abuseipdb",
                api_key=self.api_keys.get("abuseipdb", ""),
                use_mock=use_mock
            )
            providers.append(AbuseIPDBProvider(abuse_config))

        self.manager = ThreatIntelManager(providers)

    async def query_ip(self, ip: str) -> Dict:
        """查询IP威胁情报"""
        result = await self.manager.query(IOCType.IP, ip)
        return {
            "ip": ip,
            "is_malicious": result.is_malicious,
            "threat_score": result.threat_score,
            "threat_types": result.threat_types,
            "sources": [r.provider for r in result.provider_results],
            "details": result.details
        }

    async def query_domain(self, domain: str) -> Dict:
        """查询域名威胁情报"""
        result = await self.manager.query(IOCType.DOMAIN, domain)
        return {
            "domain": domain,
            "is_malicious": result.is_malicious,
            "threat_score": result.threat_score,
            "threat_types": result.threat_types,
            "sources": [r.provider for r in result.provider_results],
            "details": result.details
        }

    async def query_url(self, url: str) -> Dict:
        """查询URL威胁情报"""
        result = await self.manager.query(IOCType.URL, url)
        return {
            "url": url,
            "is_malicious": result.is_malicious,
            "threat_score": result.threat_score,
            "threat_types": result.threat_types,
            "sources": [r.provider for r in result.provider_results],
            "details": result.details
        }

    async def query_file_hash(self, file_hash: str) -> Dict:
        """查询文件哈希威胁情报"""
        result = await self.manager.query(IOCType.FILE_HASH, file_hash)
        return {
            "hash": file_hash,
            "is_malicious": result.is_malicious,
            "threat_score": result.threat_score,
            "threat_types": result.threat_types,
            "malware_type": result.threat_types[0] if result.threat_types else None,
            "sources": [r.provider for r in result.provider_results],
            "details": result.details
        }

    async def batch_query_ips(self, ips: List[str]) -> List[Dict]:
        """批量查询IP"""
        results = await self.manager.batch_query(IOCType.IP, ips)
        return [
            {
                "ip": ioc,
                "is_malicious": result.is_malicious,
                "threat_score": result.threat_score,
                "threat_types": result.threat_types,
            }
            for ioc, result in zip(ips, results)
        ]


# ==================== 分析智能体 ====================

class CompromisedHostAnalyzer(BaseAgent):
    """失陷主机检测智能体 - 使用真实威胁情报"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(
            name="compromised_host_analyzer",
            description="检测失陷主机"
        )
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        """执行失陷主机检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
            "threat_intel_mode": "mock" if self.threat_intel.use_mock else "real"
        })

        # 创建分析链
        chain = self.framework.create_chain([
            """分析以下安全日志，识别可能的失陷主机。
重点关注：
1. 异常网络连接（连接已知C2服务器）
2. 异常进程启动
3. 异常文件访问
4. 异常DNS查询

日志数据：{input}""",

            """基于以上分析，提取以下信息：
1. 可疑IP地址列表
2. 可疑域名列表
3. 可疑文件哈希列表
4. 异常行为描述

分析结果：{input}""",

            """生成失陷主机检测报告，包括：
1. 失陷主机IP列表
2. 置信度评分
3. 证据链
4. 建议措施

提取的信息：{input}"""
        ])

        # 准备日志数据
        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "compromised_host_analysis",
            "steps": 3,
            "phase": "start",
        })

        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "compromised_host_analysis",
            "phase": "end",
            "output_preview": analysis_text[:200],
        })

        # 使用真实威胁情报验证IOC
        suspicious_ips = self._extract_ips(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "threat_intel_verification",
            "suspicious_ip_count": len(suspicious_ips),
        })

        verified_results = []
        for ip in suspicious_ips[:5]:  # 限制查询数量
            try:
                intel_result = await self.threat_intel.query_ip(ip)
                verified_results.append(intel_result)
                trace.append({
                    "type": "tool_call",
                    "tool": "ThreatIntelToolkit.query_ip",
                    "params": {"ip": ip},
                    "result_summary": {
                        "is_malicious": intel_result.get("is_malicious"),
                        "threat_score": intel_result.get("threat_score"),
                        "sources": intel_result.get("sources"),
                    },
                })
            except Exception as e:
                trace.append({
                    "type": "tool_error",
                    "tool": "ThreatIntelToolkit.query_ip",
                    "params": {"ip": ip},
                    "error": str(e),
                })

        state["analysis_result"] = {
            "type": AnalysisType.COMPROMISED_HOST.value,
            "report": result.get("output", ""),
            "verified_iocs": verified_results
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.COMPROMISED_HOST.value,
        })

        return state

    def _format_logs(self, logs: List[SecurityLog]) -> str:
        """格式化日志"""
        return "\n".join([
            f"[{log.log_type}] {log.timestamp} {log.source_ip} -> {log.dest_ip} "
            f"({log.protocol}/{log.dest_port}) {log.action}"
            for log in logs[:100]  # 限制日志数量
        ])

    def _extract_ips(self, text: str) -> List[str]:
        """简单提取IP地址"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))

    def get_output_key(self) -> str:
        return "analysis_result"


class MalwareDetectionAnalyzer(BaseAgent):
    """恶意软件检测智能体 - 使用真实威胁情报"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(
            name="malware_detection_analyzer",
            description="检测恶意软件"
        )
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        """执行恶意软件检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
        })

        chain = self.framework.create_chain([
            """分析以下EDR和系统日志，识别恶意软件活动。
重点关注：
1. 可疑进程启动（未知程序、异常路径）
2. 文件哈希匹配已知恶意软件
3. 异常系统行为（注册表修改、服务创建）
4. 网络通信特征（C2连接、DGA域名）
5. 持久化机制（启动项、计划任务）

日志数据：{input}""",

            """基于以上分析，提取以下信息：
1. 可疑进程列表（进程名、路径、哈希、父进程）
2. 可疑文件列表（路径、哈希、创建时间）
3. 网络连接记录（目标IP、域名、端口）
4. 系统修改记录（注册表、文件系统）
5. 恶意软件特征匹配

分析结果：{input}""",

            """生成恶意软件检测报告，包括：
1. 检测到的恶意软件列表
2. 恶意软件类型（木马、勒索软件、挖矿等）
3. 感染主机列表
4. 攻击时间线
5. 建议措施（如：隔离主机、清除恶意软件、修复漏洞）

提取的信息：{input}"""
        ])

        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "malware_detection_analysis",
            "steps": 3,
            "phase": "start",
        })

        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "malware_detection_analysis",
            "phase": "end",
            "output_preview": analysis_text[:200],
        })

        # 使用真实威胁情报验证文件哈希
        suspicious_hashes = self._extract_hashes(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "hash_verification",
            "suspicious_hash_count": len(suspicious_hashes),
        })

        verified_results = []
        for file_hash in suspicious_hashes[:5]:
            try:
                hash_result = await self.threat_intel.query_file_hash(file_hash)
                verified_results.append(hash_result)
                trace.append({
                    "type": "tool_call",
                    "tool": "ThreatIntelToolkit.query_file_hash",
                    "params": {"file_hash": file_hash},
                    "result_summary": {
                        "is_malicious": hash_result.get("is_malicious"),
                        "malware_type": hash_result.get("malware_type"),
                        "sources": hash_result.get("sources"),
                    },
                })
            except Exception as e:
                trace.append({
                    "type": "tool_error",
                    "tool": "ThreatIntelToolkit.query_file_hash",
                    "params": {"file_hash": file_hash},
                    "error": str(e),
                })

        state["analysis_result"] = {
            "type": AnalysisType.MALWARE_DETECTION.value,
            "report": result.get("output", ""),
            "verified_hashes": verified_results
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.MALWARE_DETECTION.value,
        })

        return state

    def _format_logs(self, logs: List[SecurityLog]) -> str:
        """格式化日志"""
        return "\n".join([
            f"[{log.log_type}] {log.timestamp} {log.source_ip} "
            f"action={log.action} data={log.raw_data}"
            for log in logs[:100]
        ])

    def _extract_hashes(self, text: str) -> List[str]:
        """提取文件哈希"""
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        return list(set(re.findall(hash_pattern, text)))

    def get_output_key(self) -> str:
        return "analysis_result"


class PhishingDetectionAnalyzer(BaseAgent):
    """钓鱼攻击检测智能体 - 使用真实威胁情报"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        config = AgentConfig(
            name="phishing_detection_analyzer",
            description="检测钓鱼攻击"
        )
        super().__init__(config)
        self.framework = framework
        self.threat_intel = threat_intel

    async def execute(self, state: AgentState) -> AgentState:
        """执行钓鱼攻击检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
        })

        chain = self.framework.create_chain([
            """分析以下邮件和Web访问日志，识别钓鱼攻击。
重点关注：
1. 可疑邮件（伪造发件人、钓鱼链接、恶意附件）
2. 钓鱼网站访问（仿冒域名、SSL证书异常）
3. 凭证输入行为（在可疑网站输入密码）
4. 点击率分析（大量用户点击同一链接）
5. 攻击时间和目标

日志数据：{input}""",

            """基于以上分析，提取以下信息：
1. 钓鱼邮件特征（发件人、主题、内容特征）
2. 钓鱼网站列表（域名、IP、相似度分析）
3. 受害用户列表（点击链接、输入凭证）
4. 攻击活动（时间、规模、目标部门）
5. 钓鱼技术（域名仿冒、URL混淆、社工话术）

分析结果：{input}""",

            """生成钓鱼攻击检测报告，包括：
1. 钓鱼活动概述
2. 钓鱼邮件和网站列表
3. 受影响用户和凭证泄露风险
4. 攻击者画像
5. 建议措施（如：封禁域名、重置密码、安全培训）

提取的信息：{input}"""
        ])

        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "phishing_detection_analysis",
            "steps": 3,
            "phase": "start",
        })

        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "phishing_detection_analysis",
            "phase": "end",
            "output_preview": analysis_text[:200],
        })

        # 使用真实威胁情报验证域名和URL
        suspicious_domains = self._extract_domains(analysis_text)
        suspicious_urls = self._extract_urls(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "domain_url_verification",
            "suspicious_domain_count": len(suspicious_domains),
            "suspicious_url_count": len(suspicious_urls),
        })

        verified_results = []

        # 验证域名
        for domain in suspicious_domains[:3]:
            try:
                domain_result = await self.threat_intel.query_domain(domain)
                verified_results.append({"type": "domain", "result": domain_result})
                trace.append({
                    "type": "tool_call",
                    "tool": "ThreatIntelToolkit.query_domain",
                    "params": {"domain": domain},
                    "result_summary": {
                        "is_malicious": domain_result.get("is_malicious"),
                        "threat_score": domain_result.get("threat_score"),
                    },
                })
            except Exception as e:
                trace.append({
                    "type": "tool_error",
                    "tool": "ThreatIntelToolkit.query_domain",
                    "params": {"domain": domain},
                    "error": str(e),
                })

        # 验证URL
        for url in suspicious_urls[:3]:
            try:
                url_result = await self.threat_intel.query_url(url)
                verified_results.append({"type": "url", "result": url_result})
                trace.append({
                    "type": "tool_call",
                    "tool": "ThreatIntelToolkit.query_url",
                    "params": {"url": url},
                    "result_summary": {
                        "is_malicious": url_result.get("is_malicious"),
                        "threat_score": url_result.get("threat_score"),
                    },
                })
            except Exception as e:
                trace.append({
                    "type": "tool_error",
                    "tool": "ThreatIntelToolkit.query_url",
                    "params": {"url": url},
                    "error": str(e),
                })

        state["analysis_result"] = {
            "type": AnalysisType.PHISHING_DETECTION.value,
            "report": result.get("output", ""),
            "verified_indicators": verified_results
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.PHISHING_DETECTION.value,
        })

        return state

    def _format_logs(self, logs: List[SecurityLog]) -> str:
        """格式化日志"""
        return "\n".join([
            f"[{log.log_type}] {log.timestamp} user={log.raw_data.get('username', 'unknown')} "
            f"url={log.raw_data.get('url', 'unknown')} action={log.action}"
            for log in logs[:100]
        ])

    def _extract_domains(self, text: str) -> List[str]:
        """提取域名"""
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        return list(set(re.findall(domain_pattern, text)))

    def _extract_urls(self, text: str) -> List[str]:
        """提取URL"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return list(set(re.findall(url_pattern, text)))

    def get_output_key(self) -> str:
        return "analysis_result"


# ==================== 路由系统 ====================

class SecurityAnalysisRouter:
    """安全分析路由系统 - V2版本使用真实威胁情报"""

    def __init__(self, framework: UniversalAgentFramework, threat_intel: ThreatIntelToolkit):
        self.framework = framework
        self.threat_intel = threat_intel
        self.analyzers = {
            AnalysisType.COMPROMISED_HOST.value: CompromisedHostAnalyzer(framework, threat_intel),
            AnalysisType.MALWARE_DETECTION.value: MalwareDetectionAnalyzer(framework, threat_intel),
            AnalysisType.PHISHING_DETECTION.value: PhishingDetectionAnalyzer(framework, threat_intel),
            # 可以继续添加其他分析器...
        }

    async def route_analysis(
        self,
        analysis_type: str,
        logs: List[SecurityLog]
    ) -> AnalysisResult:
        """路由到对应的分析器"""
        analyzer = self.analyzers.get(analysis_type)

        if not analyzer:
            raise ValueError(f"不支持的分析类型: {analysis_type}")

        state = AgentState()
        state["logs"] = logs
        state["analysis_type"] = analysis_type
        state["trace"] = []

        state["trace"].append({
            "type": "router",
            "router": "SecurityAnalysisRouter",
            "analysis_type": analysis_type,
            "selected_analyzer": analyzer.config.name,
        })

        result_state = await analyzer.execute(state)
        analysis_result = result_state.get("analysis_result", {})
        trace = result_state.get("trace", [])

        return AnalysisResult(
            analysis_type=analysis_type,
            findings=[],  # 可以从报告中解析
            confidence=0.8,  # 可以从分析结果中提取
            evidence=analysis_result.get("verified_iocs", []),
            recommendations=["建议1", "建议2"],
            timestamp=datetime.now(),
            trace=trace,
        )


# ==================== 主系统 ====================

class SecurityAnalysisSystem:
    """安全分析系统主类 - V2版本集成真实威胁情报"""

    def __init__(self, use_mock: bool = True, api_keys: Optional[Dict[str, str]] = None):
        """
        初始化安全分析系统

        Args:
            use_mock: 是否使用模拟模式（开发/测试用）
            api_keys: API密钥字典，格式: {"virustotal": "key", "abuseipdb": "key"}
        """
        self.framework = UniversalAgentFramework()
        self.threat_intel = ThreatIntelToolkit(use_mock=use_mock, api_keys=api_keys)
        self.router = SecurityAnalysisRouter(self.framework, self.threat_intel)

    async def analyze(
        self,
        analysis_type: str,
        logs: List[SecurityLog]
    ) -> AnalysisResult:
        """执行安全分析"""
        return await self.router.route_analysis(analysis_type, logs)

    async def batch_analyze(
        self,
        analysis_types: List[str],
        logs: List[SecurityLog]
    ) -> Dict[str, AnalysisResult]:
        """批量分析多个类型"""
        tasks = [
            self.analyze(analysis_type, logs)
            for analysis_type in analysis_types
        ]

        results = await asyncio.gather(*tasks)

        return {
            analysis_type: result
            for analysis_type, result in zip(analysis_types, results)
        }

    def get_cache_stats(self) -> Dict:
        """获取缓存统计信息"""
        return self.threat_intel.manager.get_cache_stats()

    async def clear_cache(self):
        """清除缓存"""
        await self.threat_intel.manager.clear_cache()

