"""
安全分析系统使用示例
"""
import sys
import os
import asyncio
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from security_analysis.architecture import (
    SecurityAnalysisSystem,
    SecurityLog,
    AnalysisType
)


def print_trace(trace, interactive: bool = True):
    """在终端中打印分析执行轨迹

    Args:
        trace: 执行轨迹列表
        interactive: 是否交互式逐步展示（默认逐步按回车）
    """
    if not trace:
        print("\n[执行轨迹] 无可用轨迹数据")
        return

    total = len(trace)
    print(f"\n[执行轨迹] 共 {total} 步")
    for idx, event in enumerate(trace, 1):
        etype = event.get("type")
        if etype == "router":
            print(f"  {idx}. 路由 -> 分析类型={event.get('analysis_type')} 使用分析器={event.get('selected_analyzer')}")
        elif etype == "analyzer_start":
            print(
                f"  {idx}. 分析器开始 -> {event.get('analyzer')} ({event.get('description')})，"
                f"日志数量={event.get('log_count')}"
            )
        elif etype == "prompt_chain" and event.get("phase") == "start":
            print(
                f"  {idx}. 提示链开始 -> 模式={event.get('pattern')}，"
                f"步骤数={event.get('steps')}"
            )
        elif etype == "prompt_chain_steps":
            steps = event.get("steps") or []
            print(f"  {idx}. 提示链步骤定义 -> 模式={event.get('pattern')}")
            for step in steps:
                print(f"       - 第{step.get('index')}步：{step.get('label')}")
        elif etype == "prompt_chain" and event.get("phase") == "end":
            preview = event.get("output_preview")
            if preview:
                print(
                    f"  {idx}. 提示链结束 -> 模式={event.get('pattern')} 输出预览={preview}"
                )
            else:
                print(f"  {idx}. 提示链结束 -> 模式={event.get('pattern')}")
        elif etype == "tool_phase":
            print(
                f"  {idx}. 工具验证阶段 -> {event.get('phase')}，"
                f"可疑IP数量={event.get('suspicious_ip_count')}"
            )
        elif etype == "tool_call":
            print(
                f"  {idx}. 工具调用 -> {event.get('tool')} "
                f"参数={event.get('params')} 结果摘要={event.get('result_summary')}"
            )
        elif etype == "analyzer_end":
            print(
                f"  {idx}. 分析器结束 -> {event.get('analyzer')}，"
                f"类型={event.get('analysis_type')}"
            )
        else:
            print(f"  {idx}. 事件 -> {event}")

        if interactive and idx < total:
            cmd = input("    按回车查看下一步，输入 q 后回车退出：").strip().lower()
            if cmd == "q":
                print("    已中止后续步骤展示。")
                break


async def example_compromised_host_detection():
    """示例：失陷主机检测"""
    print("\n" + "="*60)
    print("示例1：失陷主机检测")
    print("="*60)
    
    # 创建系统
    system = SecurityAnalysisSystem()
    
    # 准备日志数据
    logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.100",  # 可疑C2服务器
            dest_port=443,
            protocol="TCP",
            action="allow",
            raw_data={"bytes": 1024}
        ),
        SecurityLog(
            log_type="ids",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="8.8.8.8",
            dest_port=53,
            protocol="UDP",
            action="alert",
            raw_data={"dns_query": "malicious-domain.com"}
        ),
        SecurityLog(
            log_type="edr",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="",
            protocol="",
            action="process_start",
            raw_data={"process": "suspicious.exe", "hash": "abc123..."}
        )
    ]
    
    # 执行分析
    result = await system.analyze(
        AnalysisType.COMPROMISED_HOST.value,
        logs
    )
    
    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")
    print(f"\n分析报告：\n{result.evidence}")
    print(f"\n建议措施：{result.recommendations}")
    print_trace(getattr(result, "trace", []))


async def example_anomalous_login_detection():
    """示例：异常登录检测"""
    print("\n" + "="*60)
    print("示例2：异常登录检测")
    print("="*60)
    
    system = SecurityAnalysisSystem()
    
    # 准备登录日志
    logs = [
        SecurityLog(
            log_type="auth",
            timestamp=datetime(2024, 1, 15, 2, 30, 0),  # 凌晨2:30
            source_ip="10.0.0.100",  # 异常IP
            dest_ip="192.168.1.10",
            dest_port=22,
            protocol="SSH",
            action="success",
            raw_data={
                "username": "admin",
                "location": "Unknown",
                "device": "New Device"
            }
        ),
        SecurityLog(
            log_type="auth",
            timestamp=datetime(2024, 1, 15, 3, 0, 0),
            source_ip="10.0.0.100",
            dest_ip="192.168.1.10",
            dest_port=22,
            protocol="SSH",
            action="success",
            raw_data={
                "username": "admin",
                "location": "Unknown",
                "device": "New Device"
            }
        ),
        SecurityLog(
            log_type="auth",
            timestamp=datetime(2024, 1, 15, 3, 30, 0),
            source_ip="10.0.0.100",
            dest_ip="192.168.1.10",
            dest_port=22,
            protocol="SSH",
            action="success",
            raw_data={
                "username": "admin",
                "location": "Unknown",
                "device": "New Device"
            }
        )
    ]
    
    # 执行分析
    result = await system.analyze(
        AnalysisType.ANOMALOUS_LOGIN.value,
        logs
    )
    
    print(f"\n分析类型：{result.analysis_type}")
    print(f"置信度：{result.confidence}")
    print(f"\n分析报告：\n{result.evidence}")
    print(f"\n建议措施：{result.recommendations}")
    print_trace(getattr(result, "trace", []))


async def example_batch_analysis():
    """示例：批量分析"""
    print("\n" + "="*60)
    print("示例3：批量分析多个类型")
    print("="*60)
    
    system = SecurityAnalysisSystem()
    
    # 准备日志
    logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            dest_ip="192.168.1.100",
            dest_port=443,
            protocol="TCP",
            action="allow"
        ),
        SecurityLog(
            log_type="auth",
            timestamp=datetime(2024, 1, 15, 2, 30, 0),
            source_ip="10.0.0.100",
            dest_ip="192.168.1.10",
            dest_port=22,
            protocol="SSH",
            action="success",
            raw_data={"username": "admin"}
        )
    ]
    
    # 批量分析
    analysis_types = [
        AnalysisType.COMPROMISED_HOST.value,
        AnalysisType.ANOMALOUS_LOGIN.value
    ]
    
    results = await system.batch_analyze(analysis_types, logs)
    
    for analysis_type, result in results.items():
        print(f"\n{analysis_type}:")
        print(f"  置信度：{result.confidence}")
        print(f"  发现数：{len(result.findings)}")


async def main():
    """主函数"""
    print("="*60)
    print("网络安全日志分析系统 - 使用示例")
    print("="*60)
    
    await example_compromised_host_detection()
    await example_anomalous_login_detection()
    await example_batch_analysis()


if __name__ == "__main__":
    asyncio.run(main())
