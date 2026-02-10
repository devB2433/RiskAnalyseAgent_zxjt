"""
网络安全日志分析系统 - 架构实现
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


# ==================== 工具实现 ====================

class IOCLookupTool(BaseTool):
    """IOC查询工具"""
    
    def __init__(self):
        super().__init__("ioc_lookup", "查询IOC（IP、域名、文件哈希）的威胁情报")
        self.cache: Dict[str, Dict] = {}  # 简单缓存
    
    async def execute(self, ioc_type: str, ioc_value: str) -> Dict:
        """
        查询IOC
        
        Args:
            ioc_type: "ip", "domain", "hash", "url"
            ioc_value: IOC值
        
        Returns:
            威胁情报字典
        """
        cache_key = f"{ioc_type}:{ioc_value}"
        
        # 检查缓存
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # 模拟API调用
        await asyncio.sleep(0.2)
        
        # 模拟返回结果
        result = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "is_malicious": ioc_value.startswith("192.168.1.100"),  # 模拟逻辑
            "threat_score": 0.8 if ioc_value.startswith("192.168.1.100") else 0.1,
            "threat_types": ["C2", "Malware"] if ioc_value.startswith("192.168.1.100") else [],
            "sources": ["ThreatIntel API", "Local DB"],
            "first_seen": "2024-01-01",
            "last_seen": "2024-12-31"
        }
        
        # 缓存结果
        self.cache[cache_key] = result
        return result


class BlacklistIPTool(BaseTool):
    """黑产IP查询工具"""
    
    def __init__(self):
        super().__init__("blacklist_ip", "查询IP是否为已知黑产IP")
        self.cache: Dict[str, Dict] = {}
    
    async def execute(self, ip: str) -> Dict:
        """查询黑产IP"""
        if ip in self.cache:
            return self.cache[ip]
        
        await asyncio.sleep(0.2)
        
        # 模拟黑产IP检测
        is_blacklist = ip.startswith("10.0.0.") or ip == "192.168.1.100"
        
        result = {
            "ip": ip,
            "is_blacklist": is_blacklist,
            "blacklist_type": "C2 Server" if is_blacklist else None,
            "source": "Blacklist DB",
            "first_seen": "2024-01-01" if is_blacklist else None,
            "reputation_score": 0.0 if is_blacklist else 0.8
        }
        
        self.cache[ip] = result
        return result


class ThreatIntelligenceTool(BaseTool):
    """威胁情报查询工具"""
    
    def __init__(self):
        super().__init__("threat_intel", "查询综合威胁情报")
    
    async def execute(self, entity: str, entity_type: str) -> Dict:
        """查询威胁情报"""
        await asyncio.sleep(0.3)
        
        return {
            "entity": entity,
            "entity_type": entity_type,
            "threat_score": 0.7,
            "threat_types": ["APT", "Malware"],
            "related_attacks": ["Operation XYZ"],
            "timeline": [
                {"date": "2024-01-01", "event": "First seen"},
                {"date": "2024-06-01", "event": "Active campaign"}
            ]
        }


class GeoIPTool(BaseTool):
    """地理位置查询工具"""
    
    def __init__(self):
        super().__init__("geoip", "查询IP地理位置信息")
    
    async def execute(self, ip: str) -> Dict:
        """查询地理位置"""
        await asyncio.sleep(0.1)
        
        # 模拟地理位置查询
        return {
            "ip": ip,
            "country": "CN" if ip.startswith("192.168") else "US",
            "city": "Beijing" if ip.startswith("192.168") else "New York",
            "isp": "China Telecom",
            "latitude": 39.9042,
            "longitude": 116.4074
        }


class DomainAnalysisTool(BaseTool):
    """域名分析工具"""
    
    def __init__(self):
        super().__init__("domain_analysis", "分析域名特征")
    
    async def execute(self, domain: str) -> Dict:
        """分析域名"""
        await asyncio.sleep(0.2)
        
        return {
            "domain": domain,
            "registration_date": "2024-01-01",
            "registrar": "Example Registrar",
            "dns_records": ["A", "AAAA", "MX"],
            "is_suspicious": domain.count(".") > 2,  # 简单规则
            "reputation_score": 0.3 if domain.count(".") > 2 else 0.8
        }


class FileHashTool(BaseTool):
    """文件哈希查询工具"""
    
    def __init__(self):
        super().__init__("file_hash", "查询文件哈希的威胁情报")
    
    async def execute(self, file_hash: str, hash_type: str = "sha256") -> Dict:
        """查询文件哈希"""
        await asyncio.sleep(0.2)
        
        # 模拟恶意文件检测
        is_malicious = file_hash.startswith("abc")
        
        return {
            "hash": file_hash,
            "hash_type": hash_type,
            "is_malicious": is_malicious,
            "malware_type": "Trojan" if is_malicious else None,
            "detection_engines": ["VirusTotal", "Local AV"],
            "first_seen": "2024-01-01" if is_malicious else None
        }


# ==================== 分析智能体 ====================

class CompromisedHostAnalyzer(BaseAgent):
    """失陷主机检测智能体"""
    
    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="compromised_host_analyzer",
            description="检测失陷主机"
        )
        super().__init__(config)
        self.framework = framework
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行失陷主机检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
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
            "steps": len(chain.steps) if hasattr(chain, "steps") else None,
            "phase": "start",
        })
        trace.append({
            "type": "prompt_chain_steps",
            "analyzer": self.config.name,
            "pattern": "compromised_host_analysis",
            "steps": [
                {"index": 1, "label": "初步日志分析"},
                {"index": 2, "label": "提取可疑IOC"},
                {"index": 3, "label": "生成失陷主机报告"},
            ],
        })
        
        result = await chain.execute(chain_state)

        analysis_text = result.get("output", "")
        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "compromised_host_analysis",
            "steps": len(chain.steps) if hasattr(chain, "steps") else None,
            "phase": "end",
            "output_preview": analysis_text[:200],
        })
        
        # 使用工具验证IOC
        ioc_tool = IOCLookupTool()
        blacklist_tool = BlacklistIPTool()
        
        # 提取IP进行验证
        suspicious_ips = self._extract_ips(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "ioc_verification",
            "suspicious_ip_count": len(suspicious_ips),
        })
        
        verified_results = []
        for ip in suspicious_ips[:5]:  # 限制查询数量
            ioc_result = await ioc_tool.execute("ip", ip)
            blacklist_result = await blacklist_tool.execute(ip)
            verified_results.append({
                "ip": ip,
                "ioc": ioc_result,
                "blacklist": blacklist_result
            })
            trace.append({
                "type": "tool_call",
                "tool": "IOCLookupTool",
                "params": {"ioc_type": "ip", "ioc_value": ip},
                "result_summary": {
                    "is_malicious": ioc_result.get("is_malicious"),
                    "threat_score": ioc_result.get("threat_score"),
                },
            })
            trace.append({
                "type": "tool_call",
                "tool": "BlacklistIPTool",
                "params": {"ip": ip},
                "result_summary": {
                    "is_blacklist": blacklist_result.get("is_blacklist"),
                    "blacklist_type": blacklist_result.get("blacklist_type"),
                },
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
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))
    
    def get_output_key(self) -> str:
        return "analysis_result"


class AnomalousLoginAnalyzer(BaseAgent):
    """异常登录检测智能体"""
    
    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="anomalous_login_analyzer",
            description="检测异常登录"
        )
        super().__init__(config)
        self.framework = framework
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行异常登录检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
        })
        
        # 创建分析链
        chain = self.framework.create_chain([
            """分析以下登录日志，识别异常登录行为。
重点关注：
1. 异常时间登录（非工作时间）
2. 异常地点登录（地理位置异常）
3. 异常设备登录（新设备）
4. 异常登录频率（暴力破解）

登录日志：{input}""",
            
            """建立正常登录基线，然后识别偏离基线的异常登录。
包括：
1. 正常登录时间范围
2. 正常登录地理位置
3. 正常登录设备列表
4. 异常登录列表及原因

日志数据：{input}""",
            
            """生成异常登录报告，包括：
1. 异常登录列表
2. 风险评分（0-100）
3. 异常原因
4. 建议措施（如：要求二次验证、锁定账户等）

异常登录分析：{input}"""
        ])
        
        logs_text = self._format_login_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "anomalous_login_analysis",
            "steps": len(chain.steps) if hasattr(chain, "steps") else None,
            "phase": "start",
        })
        trace.append({
            "type": "prompt_chain_steps",
            "analyzer": self.config.name,
            "pattern": "anomalous_login_analysis",
            "steps": [
                {"index": 1, "label": "分析登录行为"},
                {"index": 2, "label": "建立基线并识别异常"},
                {"index": 3, "label": "生成异常登录报告"},
            ],
        })
        
        result = await chain.execute(chain_state)

        analysis_text = result.get("output", "")
        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "anomalous_login_analysis",
            "steps": len(chain.steps) if hasattr(chain, "steps") else None,
            "phase": "end",
            "output_preview": analysis_text[:200],
        })
        
        # 使用地理位置工具验证
        geo_tool = GeoIPTool()
        suspicious_ips = self._extract_ips(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "geoip_verification",
            "suspicious_ip_count": len(suspicious_ips),
        })
        
        geo_results = []
        for ip in suspicious_ips[:5]:
            geo_result = await geo_tool.execute(ip)
            geo_results.append(geo_result)
            trace.append({
                "type": "tool_call",
                "tool": "GeoIPTool",
                "params": {"ip": ip},
                "result_summary": {
                    "country": geo_result.get("country"),
                    "city": geo_result.get("city"),
                },
            })
        
        state["analysis_result"] = {
            "type": AnalysisType.ANOMALOUS_LOGIN.value,
            "report": result.get("output", ""),
            "geo_analysis": geo_results
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.ANOMALOUS_LOGIN.value,
        })
        
        return state
    
    def _format_login_logs(self, logs: List[SecurityLog]) -> str:
        """格式化登录日志"""
        return "\n".join([
            f"[LOGIN] {log.timestamp} User: {log.raw_data.get('username', 'unknown')} "
            f"IP: {log.source_ip} Location: {log.raw_data.get('location', 'unknown')} "
            f"Device: {log.raw_data.get('device', 'unknown')} Status: {log.action}"
            for log in logs if log.log_type == "auth"
        ])
    
    def _extract_ips(self, text: str) -> List[str]:
        """提取IP地址"""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))
    
    def get_output_key(self) -> str:
        return "analysis_result"


class DataExfiltrationAnalyzer(BaseAgent):
    """数据外泄检测智能体"""

    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="data_exfiltration_analyzer",
            description="检测数据外泄"
        )
        super().__init__(config)
        self.framework = framework

    async def execute(self, state: AgentState) -> AgentState:
        """执行数据外泄检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
        })

        # 创建分析链
        chain = self.framework.create_chain([
            """分析以下网络日志，识别可能的数据外泄行为。
重点关注：
1. 异常大量数据传输（上传）
2. 向外部/未知目标传输敏感数据
3. 非工作时间的大量数据传输
4. 使用加密隧道或代理传输数据
5. 访问敏感数据后立即外传

日志数据：{input}""",

            """基于以上分析，提取以下信息：
1. 可疑的数据传输记录（源IP、目标IP、数据量、时间）
2. 传输的数据类型和敏感级别
3. 传输方式（HTTP、FTP、云存储等）
4. 异常特征（时间、频率、目标）

分析结果：{input}""",

            """生成数据外泄检测报告，包括：
1. 疑似外泄事件列表
2. 外泄数据量估算
3. 风险评分（0-100）
4. 证据链
5. 建议措施（如：阻断连接、隔离主机、调查用户）

提取的信息：{input}"""
        ])

        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "data_exfiltration_analysis",
            "steps": 3,
            "phase": "start",
        })

        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "data_exfiltration_analysis",
            "phase": "end",
            "output_preview": analysis_text[:200],
        })

        # 使用工具验证可疑目标
        ioc_tool = IOCLookupTool()
        suspicious_ips = self._extract_ips(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "destination_verification",
            "suspicious_ip_count": len(suspicious_ips),
        })

        verified_results = []
        for ip in suspicious_ips[:5]:
            ioc_result = await ioc_tool.execute("ip", ip)
            verified_results.append({"ip": ip, "ioc": ioc_result})
            trace.append({
                "type": "tool_call",
                "tool": "IOCLookupTool",
                "params": {"ioc_type": "ip", "ioc_value": ip},
                "result_summary": {
                    "is_malicious": ioc_result.get("is_malicious"),
                    "threat_score": ioc_result.get("threat_score"),
                },
            })

        state["analysis_result"] = {
            "type": AnalysisType.DATA_EXFILTRATION.value,
            "report": result.get("output", ""),
            "verified_destinations": verified_results
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.DATA_EXFILTRATION.value,
        })

        return state

    def _format_logs(self, logs: List[SecurityLog]) -> str:
        """格式化日志"""
        return "\n".join([
            f"[{log.log_type}] {log.timestamp} {log.source_ip} -> {log.dest_ip} "
            f"({log.protocol}/{log.dest_port}) {log.action} "
            f"bytes={log.raw_data.get('bytes', 0)}"
            for log in logs[:100]
        ])

    def _extract_ips(self, text: str) -> List[str]:
        """提取IP地址"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))

    def get_output_key(self) -> str:
        return "analysis_result"


class MalwareDetectionAnalyzer(BaseAgent):
    """恶意软件检测智能体"""

    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="malware_detection_analyzer",
            description="检测恶意软件"
        )
        super().__init__(config)
        self.framework = framework

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

        # 使用文件哈希工具验证
        hash_tool = FileHashTool()
        suspicious_hashes = self._extract_hashes(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "hash_verification",
            "suspicious_hash_count": len(suspicious_hashes),
        })

        verified_results = []
        for file_hash in suspicious_hashes[:5]:
            hash_result = await hash_tool.execute(file_hash)
            verified_results.append({"hash": file_hash, "result": hash_result})
            trace.append({
                "type": "tool_call",
                "tool": "FileHashTool",
                "params": {"file_hash": file_hash},
                "result_summary": {
                    "is_malicious": hash_result.get("is_malicious"),
                    "malware_type": hash_result.get("malware_type"),
                },
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
        # 简单提取，实际应该用更精确的正则
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        return list(set(re.findall(hash_pattern, text)))

    def get_output_key(self) -> str:
        return "analysis_result"


class InsiderThreatAnalyzer(BaseAgent):
    """内部威胁检测智能体"""

    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="insider_threat_analyzer",
            description="检测内部威胁"
        )
        super().__init__(config)
        self.framework = framework

    async def execute(self, state: AgentState) -> AgentState:
        """执行内部威胁检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
        })

        chain = self.framework.create_chain([
            """分析以下用户行为日志，识别内部威胁。
重点关注：
1. 异常数据访问（访问敏感数据、越权访问）
2. 数据下载/复制行为（大量下载、使用U盘）
3. 异常工作时间（非工作时间活动）
4. 权限提升尝试
5. 离职前异常行为

日志数据：{input}""",

            """基于以上分析，建立用户行为基线并识别异常：
1. 正常行为模式（工作时间、访问资源、操作频率）
2. 异常行为列表（偏离基线的行为）
3. 风险用户列表
4. 行为时间线
5. 动机分析（离职、不满、经济压力）

分析结果：{input}""",

            """生成内部威胁检测报告，包括：
1. 高风险用户列表
2. 威胁类型（数据窃取、破坏、间谍）
3. 风险评分（0-100）
4. 证据链
5. 建议措施（如：限制权限、监控行为、HR介入）

异常行为分析：{input}"""
        ])

        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "insider_threat_analysis",
            "steps": 3,
            "phase": "start",
        })

        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "insider_threat_analysis",
            "phase": "end",
            "output_preview": analysis_text[:200],
        })

        state["analysis_result"] = {
            "type": AnalysisType.INSIDER_THREAT.value,
            "report": result.get("output", ""),
            "risk_users": self._extract_users(analysis_text)
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.INSIDER_THREAT.value,
        })

        return state

    def _format_logs(self, logs: List[SecurityLog]) -> str:
        """格式化日志"""
        return "\n".join([
            f"[{log.log_type}] {log.timestamp} user={log.raw_data.get('username', 'unknown')} "
            f"action={log.action} resource={log.raw_data.get('resource', 'unknown')}"
            for log in logs[:100]
        ])

    def _extract_users(self, text: str) -> List[str]:
        """提取用户名"""
        # 简单提取，实际应该更精确
        return []

    def get_output_key(self) -> str:
        return "analysis_result"


class DDoSDetectionAnalyzer(BaseAgent):
    """DDoS攻击检测智能体"""

    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="ddos_detection_analyzer",
            description="检测DDoS攻击"
        )
        super().__init__(config)
        self.framework = framework

    async def execute(self, state: AgentState) -> AgentState:
        """执行DDoS攻击检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
        })

        chain = self.framework.create_chain([
            """分析以下网络流量日志，识别DDoS攻击。
重点关注：
1. 流量异常激增（请求数、带宽）
2. 来源IP分布（大量不同IP、地理分布）
3. 请求特征（相似请求、异常User-Agent）
4. 攻击类型（SYN Flood、HTTP Flood、DNS放大）
5. 目标服务和端口

日志数据：{input}""",

            """基于以上分析，提取以下信息：
1. 流量统计（正常基线、当前流量、增长倍数）
2. 攻击源分析（IP数量、地理分布、僵尸网络特征）
3. 攻击模式（攻击类型、目标、持续时间）
4. 受影响的服务和资源
5. 攻击时间线

分析结果：{input}""",

            """生成DDoS攻击检测报告，包括：
1. 攻击类型和规模
2. 攻击源信息（IP列表、地理分布）
3. 受影响的服务
4. 攻击持续时间和峰值
5. 建议措施（如：启用DDoS防护、限流、黑洞路由）

提取的信息：{input}"""
        ])

        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "ddos_detection_analysis",
            "steps": 3,
            "phase": "start",
        })

        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "ddos_detection_analysis",
            "phase": "end",
            "output_preview": analysis_text[:200],
        })

        # 统计流量特征
        traffic_stats = self._analyze_traffic(logs)

        state["analysis_result"] = {
            "type": AnalysisType.DDOS_DETECTION.value,
            "report": result.get("output", ""),
            "traffic_stats": traffic_stats
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.DDOS_DETECTION.value,
        })

        return state

    def _format_logs(self, logs: List[SecurityLog]) -> str:
        """格式化日志"""
        return "\n".join([
            f"[{log.log_type}] {log.timestamp} {log.source_ip} -> {log.dest_ip}:{log.dest_port} "
            f"{log.protocol} {log.action}"
            for log in logs[:100]
        ])

    def _analyze_traffic(self, logs: List[SecurityLog]) -> Dict:
        """分析流量统计"""
        source_ips = set()
        dest_ports = {}
        for log in logs:
            source_ips.add(log.source_ip)
            port = log.dest_port
            if port:
                dest_ports[port] = dest_ports.get(port, 0) + 1

        return {
            "total_requests": len(logs),
            "unique_sources": len(source_ips),
            "top_ports": sorted(dest_ports.items(), key=lambda x: x[1], reverse=True)[:5]
        }

    def get_output_key(self) -> str:
        return "analysis_result"


class LateralMovementAnalyzer(BaseAgent):
    """横向移动检测智能体"""

    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="lateral_movement_analyzer",
            description="检测横向移动"
        )
        super().__init__(config)
        self.framework = framework

    async def execute(self, state: AgentState) -> AgentState:
        """执行横向移动检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])
        trace.append({
            "type": "analyzer_start",
            "analyzer": self.config.name,
            "description": self.config.description,
            "log_count": len(logs),
        })

        chain = self.framework.create_chain([
            """分析以下网络和认证日志，识别横向移动行为。
重点关注：
1. 内网扫描行为（端口扫描、主机发现）
2. 横向认证尝试（多主机登录、Pass-the-Hash）
3. 远程执行（PSExec、WMI、RDP）
4. 文件共享访问（SMB、NFS）
5. 凭证窃取和使用

日志数据：{input}""",

            """基于以上分析，构建攻击路径：
1. 初始入侵点（首个失陷主机）
2. 横向移动路径（主机跳转序列）
3. 使用的技术和工具
4. 目标主机（最终目标、高价值资产）
5. 时间线和攻击速度

分析结果：{input}""",

            """生成横向移动检测报告，包括：
1. 攻击路径图
2. 失陷主机列表
3. 使用的横向移动技术
4. 攻击者目标分析
5. 建议措施（如：隔离网络、重置凭证、加固防御）

攻击路径分析：{input}"""
        ])

        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "lateral_movement_analysis",
            "steps": 3,
            "phase": "start",
        })

        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        trace.append({
            "type": "prompt_chain",
            "analyzer": self.config.name,
            "pattern": "lateral_movement_analysis",
            "phase": "end",
            "output_preview": analysis_text[:200],
        })

        # 构建主机关系图
        host_graph = self._build_host_graph(logs)

        state["analysis_result"] = {
            "type": AnalysisType.LATERAL_MOVEMENT.value,
            "report": result.get("output", ""),
            "host_graph": host_graph
        }

        trace.append({
            "type": "analyzer_end",
            "analyzer": self.config.name,
            "analysis_type": AnalysisType.LATERAL_MOVEMENT.value,
        })

        return state

    def _format_logs(self, logs: List[SecurityLog]) -> str:
        """格式化日志"""
        return "\n".join([
            f"[{log.log_type}] {log.timestamp} {log.source_ip} -> {log.dest_ip}:{log.dest_port} "
            f"{log.protocol} {log.action}"
            for log in logs[:100]
        ])

    def _build_host_graph(self, logs: List[SecurityLog]) -> Dict:
        """构建主机关系图"""
        connections = {}
        for log in logs:
            src = log.source_ip
            dst = log.dest_ip
            if src and dst:
                if src not in connections:
                    connections[src] = set()
                connections[src].add(dst)

        return {
            "nodes": list(set(list(connections.keys()) +
                         [dst for dsts in connections.values() for dst in dsts])),
            "edges": [(src, dst) for src, dsts in connections.items() for dst in dsts]
        }

    def get_output_key(self) -> str:
        return "analysis_result"


class PhishingDetectionAnalyzer(BaseAgent):
    """钓鱼攻击检测智能体"""

    def __init__(self, framework: UniversalAgentFramework):
        config = AgentConfig(
            name="phishing_detection_analyzer",
            description="检测钓鱼攻击"
        )
        super().__init__(config)
        self.framework = framework

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

        # 使用域名分析工具
        domain_tool = DomainAnalysisTool()
        suspicious_domains = self._extract_domains(analysis_text)

        trace.append({
            "type": "tool_phase",
            "analyzer": self.config.name,
            "phase": "domain_verification",
            "suspicious_domain_count": len(suspicious_domains),
        })

        verified_results = []
        for domain in suspicious_domains[:5]:
            domain_result = await domain_tool.execute(domain)
            verified_results.append({"domain": domain, "result": domain_result})
            trace.append({
                "type": "tool_call",
                "tool": "DomainAnalysisTool",
                "params": {"domain": domain},
                "result_summary": {
                    "is_suspicious": domain_result.get("is_suspicious"),
                    "reputation_score": domain_result.get("reputation_score"),
                },
            })

        state["analysis_result"] = {
            "type": AnalysisType.PHISHING_DETECTION.value,
            "report": result.get("output", ""),
            "verified_domains": verified_results
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

    def get_output_key(self) -> str:
        return "analysis_result"


# ==================== 路由系统 ====================

class SecurityAnalysisRouter:
    """安全分析路由系统"""
    
    def __init__(self, framework: UniversalAgentFramework):
        self.framework = framework
        self.analyzers = {
            AnalysisType.COMPROMISED_HOST.value: CompromisedHostAnalyzer(framework),
            AnalysisType.ANOMALOUS_LOGIN.value: AnomalousLoginAnalyzer(framework),
            AnalysisType.DATA_EXFILTRATION.value: DataExfiltrationAnalyzer(framework),
            AnalysisType.MALWARE_DETECTION.value: MalwareDetectionAnalyzer(framework),
            AnalysisType.INSIDER_THREAT.value: InsiderThreatAnalyzer(framework),
            AnalysisType.DDOS_DETECTION.value: DDoSDetectionAnalyzer(framework),
            AnalysisType.LATERAL_MOVEMENT.value: LateralMovementAnalyzer(framework),
            AnalysisType.PHISHING_DETECTION.value: PhishingDetectionAnalyzer(framework),
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
    """安全分析系统主类"""
    
    def __init__(self):
        self.framework = UniversalAgentFramework()
        self.router = SecurityAnalysisRouter(self.framework)
        self.tools = [
            IOCLookupTool(),
            BlacklistIPTool(),
            ThreatIntelligenceTool(),
            GeoIPTool(),
            DomainAnalysisTool(),
            FileHashTool()
        ]
    
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
