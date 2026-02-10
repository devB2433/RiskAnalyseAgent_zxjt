"""
完整的安全分析示例
展示所有8种检测规则的使用
"""
import sys
import os
import asyncio
from datetime import datetime, timedelta

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from security_analysis.architecture import (
    SecurityAnalysisSystem,
    SecurityLog,
    AnalysisType
)


async def example_data_exfiltration():
    """示例：数据外泄检测"""
    print("\n" + "="*60)
    print("示例1：数据外泄检测")
    print("="*60)

    system = SecurityAnalysisSystem()

    # 模拟数据外泄日志
    logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now() - timedelta(hours=2),
            source_ip="192.168.1.50",
            dest_ip="203.0.113.100",  # 外部IP
            dest_port=443,
            protocol="HTTPS",
            action="allow",
            raw_data={"bytes": 1073741824}  # 1GB数据传输
        ),
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now() - timedelta(hours=1),
            source_ip="192.168.1.50",
            dest_ip="203.0.113.100",
            dest_port=443,
            protocol="HTTPS",
            action="allow",
            raw_data={"bytes": 2147483648}  # 2GB数据传输
        ),
        SecurityLog(
            log_type="proxy",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="203.0.113.100",
            dest_port=443,
            protocol="HTTPS",
            action="upload",
            raw_data={"url": "https://cloud-storage.example.com/upload", "bytes": 536870912}
        )
    ]

    result = await system.analyze(
        AnalysisType.DATA_EXFILTRATION.value,
        logs
    )

    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")
    print(f"证据数量：{len(result.evidence)}")
    print(f"建议措施：{result.recommendations}")


async def example_malware_detection():
    """示例：恶意软件检测"""
    print("\n" + "="*60)
    print("示例2：恶意软件检测")
    print("="*60)

    system = SecurityAnalysisSystem()

    logs = [
        SecurityLog(
            log_type="edr",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="",
            protocol="",
            action="process_start",
            raw_data={
                "process": "suspicious.exe",
                "path": "C:\\Users\\Public\\suspicious.exe",
                "hash": "abc123def456789",
                "parent_process": "explorer.exe"
            }
        ),
        SecurityLog(
            log_type="edr",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="",
            protocol="",
            action="registry_modify",
            raw_data={
                "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "Malware",
                "data": "C:\\Users\\Public\\suspicious.exe"
            }
        ),
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.100",  # C2服务器
            dest_port=8080,
            protocol="TCP",
            action="allow",
            raw_data={"connection_type": "outbound"}
        )
    ]

    result = await system.analyze(
        AnalysisType.MALWARE_DETECTION.value,
        logs
    )

    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")


async def example_insider_threat():
    """示例：内部威胁检测"""
    print("\n" + "="*60)
    print("示例3：内部威胁检测")
    print("="*60)

    system = SecurityAnalysisSystem()

    logs = [
        SecurityLog(
            log_type="file_access",
            timestamp=datetime.now() - timedelta(days=1),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.10",
            protocol="SMB",
            action="read",
            raw_data={
                "username": "john.doe",
                "file": "//fileserver/confidential/salary_data.xlsx",
                "department": "HR"
            }
        ),
        SecurityLog(
            log_type="file_access",
            timestamp=datetime.now() - timedelta(hours=12),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.10",
            protocol="SMB",
            action="copy",
            raw_data={
                "username": "john.doe",
                "file": "//fileserver/confidential/customer_database.db",
                "destination": "E:\\",  # U盘
                "size": 524288000  # 500MB
            }
        ),
        SecurityLog(
            log_type="auth",
            timestamp=datetime.now() - timedelta(hours=2),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.10",
            protocol="SSH",
            action="success",
            raw_data={
                "username": "john.doe",
                "time": "03:00 AM",  # 非工作时间
                "resource": "production_server"
            }
        )
    ]

    result = await system.analyze(
        AnalysisType.INSIDER_THREAT.value,
        logs
    )

    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")


async def example_ddos_detection():
    """示例：DDoS攻击检测"""
    print("\n" + "="*60)
    print("示例4：DDoS攻击检测")
    print("="*60)

    system = SecurityAnalysisSystem()

    # 模拟大量请求
    logs = []
    base_time = datetime.now()
    for i in range(100):
        logs.append(SecurityLog(
            log_type="firewall",
            timestamp=base_time + timedelta(seconds=i),
            source_ip=f"10.0.{i//256}.{i%256}",  # 不同的源IP
            dest_ip="192.168.1.100",  # 目标服务器
            dest_port=80,
            protocol="TCP",
            action="syn",
            raw_data={"flags": "SYN"}
        ))

    result = await system.analyze(
        AnalysisType.DDOS_DETECTION.value,
        logs
    )

    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")
    print(f"检测到的请求数：{len(logs)}")


async def example_lateral_movement():
    """示例：横向移动检测"""
    print("\n" + "="*60)
    print("示例5：横向移动检测")
    print("="*60)

    system = SecurityAnalysisSystem()

    logs = [
        # 初始失陷主机扫描内网
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now() - timedelta(hours=2),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.51",
            dest_port=445,
            protocol="TCP",
            action="scan"
        ),
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now() - timedelta(hours=2),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.52",
            dest_port=445,
            protocol="TCP",
            action="scan"
        ),
        # 横向认证
        SecurityLog(
            log_type="auth",
            timestamp=datetime.now() - timedelta(hours=1),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.51",
            dest_port=445,
            protocol="SMB",
            action="success",
            raw_data={"method": "NTLM", "username": "admin"}
        ),
        # 远程执行
        SecurityLog(
            log_type="edr",
            timestamp=datetime.now(),
            source_ip="192.168.1.51",
            dest_ip="192.168.1.52",
            protocol="WMI",
            action="remote_exec",
            raw_data={"command": "powershell.exe", "source": "192.168.1.50"}
        )
    ]

    result = await system.analyze(
        AnalysisType.LATERAL_MOVEMENT.value,
        logs
    )

    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")


async def example_phishing_detection():
    """示例：钓鱼攻击检测"""
    print("\n" + "="*60)
    print("示例6：钓鱼攻击检测")
    print("="*60)

    system = SecurityAnalysisSystem()

    logs = [
        SecurityLog(
            log_type="email",
            timestamp=datetime.now() - timedelta(hours=1),
            source_ip="203.0.113.50",
            dest_ip="192.168.1.10",
            protocol="SMTP",
            action="received",
            raw_data={
                "from": "admin@micros0ft.com",  # 仿冒域名
                "to": "user@company.com",
                "subject": "Urgent: Verify Your Account",
                "links": ["http://micros0ft-login.com/verify"]
            }
        ),
        SecurityLog(
            log_type="web",
            timestamp=datetime.now() - timedelta(minutes=30),
            source_ip="192.168.1.50",
            dest_ip="203.0.113.100",
            dest_port=80,
            protocol="HTTP",
            action="visit",
            raw_data={
                "url": "http://micros0ft-login.com/verify",
                "username": "user@company.com",
                "referrer": "email"
            }
        ),
        SecurityLog(
            log_type="web",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="203.0.113.100",
            dest_port=80,
            protocol="HTTP",
            action="submit",
            raw_data={
                "url": "http://micros0ft-login.com/verify",
                "form_data": "username=user&password=***",
                "credential_entered": True
            }
        )
    ]

    result = await system.analyze(
        AnalysisType.PHISHING_DETECTION.value,
        logs
    )

    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")


async def example_comprehensive_analysis():
    """示例：综合分析（所有类型）"""
    print("\n" + "="*60)
    print("示例7：综合安全分析（所有8种检测）")
    print("="*60)

    system = SecurityAnalysisSystem()

    # 准备综合日志数据
    logs = [
        # 失陷主机
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.100",
            dest_port=443,
            protocol="TCP",
            action="allow"
        ),
        # 异常登录
        SecurityLog(
            log_type="auth",
            timestamp=datetime.now(),
            source_ip="10.0.0.100",
            dest_ip="192.168.1.10",
            dest_port=22,
            protocol="SSH",
            action="success",
            raw_data={"username": "admin", "time": "02:00 AM"}
        )
    ]

    # 批量分析所有类型
    analysis_types = [
        AnalysisType.COMPROMISED_HOST.value,
        AnalysisType.ANOMALOUS_LOGIN.value,
        AnalysisType.DATA_EXFILTRATION.value,
        AnalysisType.MALWARE_DETECTION.value,
        AnalysisType.INSIDER_THREAT.value,
        AnalysisType.DDOS_DETECTION.value,
        AnalysisType.LATERAL_MOVEMENT.value,
        AnalysisType.PHISHING_DETECTION.value,
    ]

    print("\n执行批量分析...")
    results = await system.batch_analyze(analysis_types, logs)

    print("\n分析结果汇总:")
    for analysis_type, result in results.items():
        print(f"  - {analysis_type:25s}: 置信度 {result.confidence:.2f}")


async def main():
    """主函数"""
    print("="*60)
    print("完整安全分析系统 - 8种检测规则演示")
    print("="*60)

    await example_data_exfiltration()
    await example_malware_detection()
    await example_insider_threat()
    await example_ddos_detection()
    await example_lateral_movement()
    await example_phishing_detection()
    await example_comprehensive_analysis()

    print("\n" + "="*60)
    print("所有检测规则演示完成")
    print("="*60)

    print("\n支持的检测类型:")
    print("  1. ✅ 失陷主机检测 (Compromised Host)")
    print("  2. ✅ 异常登录检测 (Anomalous Login)")
    print("  3. ✅ 数据外泄检测 (Data Exfiltration)")
    print("  4. ✅ 恶意软件检测 (Malware Detection)")
    print("  5. ✅ 内部威胁检测 (Insider Threat)")
    print("  6. ✅ DDoS攻击检测 (DDoS Detection)")
    print("  7. ✅ 横向移动检测 (Lateral Movement)")
    print("  8. ✅ 钓鱼攻击检测 (Phishing Detection)")


if __name__ == "__main__":
    asyncio.run(main())