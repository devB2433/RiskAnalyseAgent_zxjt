"""
异常登录检测插件

检测异常的登录行为和暴力破解尝试
"""
import re
from typing import List
from src.core.base import AgentState
from src.plugins import AnalyzerPlugin


class AnomalousLoginPlugin(AnalyzerPlugin):
    """异常登录检测分析器插件"""

    plugin_name = "anomalous_login"
    plugin_version = "2.0.0"
    plugin_description = "检测异常登录行为，包括异地登录、暴力破解等"
    plugin_author = "RiskAnalyseAgent Team"

    async def analyze(self, state: AgentState) -> AgentState:
        """执行异常登录检测"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])

        trace.append({
            "type": "plugin_start",
            "plugin": self.plugin_name,
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

        logs_text = "\n".join(str(l) for l in logs[:50])
        chain_state = AgentState()
        chain_state["input"] = logs_text
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 威胁情报验证登录来源IP
        suspicious_ips = self._extract_ips(analysis_text)
        verified = []

        if self.threat_intel:
            for ip in suspicious_ips[:10]:
                try:
                    intel = await self.threat_intel.query_ip(ip)
                    verified.append(intel)
                except Exception:
                    pass

        malicious_ips = [v for v in verified if v.get("is_malicious")]
        confidence = min(0.5 + len(malicious_ips) * 0.15, 1.0) if suspicious_ips else 0.2

        from security_analysis.architecture_v2 import Finding, AnalysisResult

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
            analysis_type=self.plugin_name,
            findings=findings,
            confidence=confidence,
            evidence=[f"检查了 {len(suspicious_ips)} 个IP, {len(malicious_ips)} 个恶意"],
            recommendations=["封锁恶意IP", "强制相关账号重置密码", "启用MFA"],
            trace=trace,
        )

        return state

    def _extract_ips(self, text: str) -> List[str]:
        """提取IP地址"""
        return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
