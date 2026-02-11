"""
插件系统使用示例

演示如何使用插件管理器加载和运行分析器插件
"""
import asyncio
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.agent_framework import UniversalAgentFramework
from src.core.base import AgentState
from src.plugins import PluginManager
from src.threat_intel.manager import ThreatIntelManager
from src.threat_intel.base import ThreatIntelConfig
from src.threat_intel.providers import VirusTotalProvider, AbuseIPDBProvider
from security_analysis.architecture_v2 import ThreatIntelToolkit, SecurityLog
from datetime import datetime


async def main():
    print("=" * 60)
    print("插件系统示例")
    print("=" * 60)

    # 1. 初始化Agent框架
    framework = UniversalAgentFramework()
    print("\n✓ Agent框架初始化完成")

    # 2. 初始化威胁情报工具包（Mock模式）
    threat_intel = ThreatIntelToolkit(use_mock=True)
    print("✓ 威胁情报工具包初始化完成 (Mock模式)")

    # 3. 创建插件管理器
    plugin_manager = PluginManager(plugin_dirs=["plugins/analyzers"])
    print("✓ 插件管理器创建完成")

    # 4. 发现所有可用插件
    print("\n" + "=" * 60)
    print("发现插件")
    print("=" * 60)
    discovered = plugin_manager.discover_plugins()
    print(f"\n发现 {len(discovered)} 个插件:")
    for plugin_name in discovered:
        plugin_class = plugin_manager.plugins[plugin_name]
        print(f"  - {plugin_name} (v{plugin_class.plugin_version})")
        print(f"    {plugin_class.plugin_description}")

    # 5. 加载所有插件
    print("\n" + "=" * 60)
    print("加载插件")
    print("=" * 60)
    plugin_manager.load_all_plugins(framework, threat_intel)
    print(f"\n已加载 {len(plugin_manager.instances)} 个插件")

    # 6. 列出已加载的插件
    print("\n" + "=" * 60)
    print("已加载插件列表")
    print("=" * 60)
    for metadata in plugin_manager.list_plugins():
        print(f"\n插件: {metadata['name']}")
        print(f"  版本: {metadata['version']}")
        print(f"  描述: {metadata['description']}")
        print(f"  作者: {metadata['author']}")
        print(f"  状态: {'启用' if metadata['enabled'] else '禁用'}")

    # 7. 准备测试数据
    print("\n" + "=" * 60)
    print("准备测试数据")
    print("=" * 60)
    test_logs = [
        SecurityLog(
            log_type="firewall",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="185.220.101.1",  # 已知Tor出口节点
            dest_port=443,
            protocol="TCP",
            action="allow",
        ),
        SecurityLog(
            log_type="auth",
            timestamp=datetime.now(),
            source_ip="45.142.212.61",  # 可疑IP
            dest_ip="192.168.1.10",
            action="login_failed",
        ),
    ]
    print(f"准备了 {len(test_logs)} 条测试日志")

    # 8. 运行单个插件分析
    print("\n" + "=" * 60)
    print("运行单个插件: compromised_host")
    print("=" * 60)
    state = AgentState()
    state["logs"] = test_logs

    result = await plugin_manager.run_analysis("compromised_host", state)
    if result:
        analysis_result = result.get("analysis_result")
        if analysis_result:
            print(f"\n分析类型: {analysis_result.analysis_type}")
            print(f"置信度: {analysis_result.confidence:.2f}")
            print(f"发现项数量: {len(analysis_result.findings)}")
            print(f"\n建议措施:")
            for rec in analysis_result.recommendations:
                print(f"  - {rec}")

    # 9. 运行所有插件分析（并行）
    print("\n" + "=" * 60)
    print("运行所有插件（并行模式）")
    print("=" * 60)
    state = AgentState()
    state["logs"] = test_logs

    all_results = await plugin_manager.run_all_analyses(state, parallel=True)
    print(f"\n完成 {len(all_results)} 个插件的分析:")
    for plugin_name, result in all_results.items():
        analysis_result = result.get("analysis_result")
        if analysis_result:
            print(f"\n  {plugin_name}:")
            print(f"    置信度: {analysis_result.confidence:.2f}")
            print(f"    发现项: {len(analysis_result.findings)}")

    # 10. 动态启用/禁用插件
    print("\n" + "=" * 60)
    print("动态控制插件")
    print("=" * 60)
    print("\n禁用 anomalous_login 插件...")
    plugin_manager.disable_plugin("anomalous_login")

    print("再次运行所有插件...")
    all_results = await plugin_manager.run_all_analyses(state, parallel=False)
    print(f"完成 {len(all_results)} 个插件的分析 (anomalous_login 已跳过)")

    print("\n重新启用 anomalous_login 插件...")
    plugin_manager.enable_plugin("anomalous_login")

    print("\n" + "=" * 60)
    print("示例完成")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
