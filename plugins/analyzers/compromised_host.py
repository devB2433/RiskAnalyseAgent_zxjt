"""
失陷主机检测插件

检测可能被攻击者控制的主机
"""
import re
from typing import List
from src.core.base import AgentState
from src.plugins import AnalyzerPlugin


class CompromisedHostPlugin(AnalyzerPlugin):
    """失陷主机检测分析器插件"""

    plugin_name = "compromised_host"
    plugin_version = "2.0.0"
    plugin_description = "检测失陷主机，识别被攻击者控制的系统"
    plugin_author = "RiskAnalyseAgent Team"

    async def analyze(self, state: AgentState) -> AgentState:
        """执行失陷主机检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])

        trace.append({
            "type": "plugin_start",
            "plugin": self.plugin_name,
            "version": self.plugin_version,
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

提取的信息：{input}""",
        ])

        # 准备日志数据
        logs_text = self._format_logs(logs)
        chain_state = AgentState()
        chain_state["input"] = logs_text

        # 执行分析链
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 使用威胁情报验证IOC
        suspicious_ips = self._extract_ips(analysis_text)
        verified_results = []

        if self.threat_intel:
            for ip in suspicious_ips[:5]:  # 限制查询数量
                try:
                    intel_result = await self.threat_intel.query_ip(ip)
                    verified_results.append(intel_result)
                    trace.append({
                        "type": "threat_intel_query",
                        "ioc_type": "ip",
                        "ioc_value": ip,
                        "is_malicious": intel_result.get("is_malicious"),
                        "threat_score": intel_result.get("threat_score"),
                    })
                except Exception as e:
                    trace.append({
                        "type": "threat_intel_error",
                        "ioc": ip,
                        "error": str(e),
                    })

        # 计算置信度
        malicious_count = sum(1 for r in verified_results if r.get("is_malicious"))
        confidence = min(0.5 + malicious_count * 0.15, 1.0) if suspicious_ips else 0.2

        # 生成发现项
        from security_analysis.architecture_v2 import Finding, AnalysisResult

        findings = []
        for result in verified_results:
            if result.get("is_malicious"):
                findings.append(Finding(
                    type="compromised_host",
                    severity="critical",
                    description=f"主机连接到恶意IP {result['ip']} (威胁评分: {result.get('threat_score', 0)})",
                    evidence=[
                        f"IP: {result['ip']}",
                        f"威胁类型: {result.get('threat_types', [])}",
                        f"来源: {result.get('sources', [])}",
                    ],
                    confidence=result.get("threat_score", 0) / 100,
                ))

        # 构建分析结果
        state["analysis_result"] = AnalysisResult(
            analysis_type=self.plugin_name,
            findings=findings,
            confidence=confidence,
            evidence=[
                f"检查了 {len(suspicious_ips)} 个可疑IP",
                f"发现 {malicious_count} 个已知恶意IP",
            ],
            recommendations=[
                "立即隔离受影响主机",
                "检查主机上的异常进程和文件",
                "重置相关账号凭证",
                "进行完整的恶意软件扫描",
            ],
            trace=trace,
        )

        trace.append({
            "type": "plugin_end",
            "plugin": self.plugin_name,
            "confidence": confidence,
            "findings_count": len(findings),
        })

        return state

    def _format_logs(self, logs: List) -> str:
        """格式化日志"""
        return "\n".join(str(log) for log in logs[:50])

    def _extract_ips(self, text: str) -> List[str]:
        """从文本中提取IP地址"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))
