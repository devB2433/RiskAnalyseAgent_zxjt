"""
分析器插件系统

支持动态加载和管理安全分析器插件
"""
import os
import importlib
import inspect
import logging
from typing import Dict, List, Type, Optional
from pathlib import Path
from abc import ABC, abstractmethod

from src.core.base import AgentState, BaseAgent, AgentConfig
from src.agent_framework import UniversalAgentFramework

logger = logging.getLogger(__name__)


class AnalyzerPlugin(ABC):
    """分析器插件基类"""

    # 插件元数据
    plugin_name: str = ""
    plugin_version: str = "1.0.0"
    plugin_description: str = ""
    plugin_author: str = ""

    def __init__(self, framework: UniversalAgentFramework, threat_intel=None):
        """
        初始化插件

        Args:
            framework: Agent框架实例
            threat_intel: 威胁情报工具包（可选）
        """
        self.framework = framework
        self.threat_intel = threat_intel
        self._enabled = True

    @abstractmethod
    async def analyze(self, state: AgentState) -> AgentState:
        """
        执行分析

        Args:
            state: 包含日志数据的状态

        Returns:
            包含分析结果的状态
        """
        pass

    @property
    def enabled(self) -> bool:
        """插件是否启用"""
        return self._enabled

    def enable(self):
        """启用插件"""
        self._enabled = True

    def disable(self):
        """禁用插件"""
        self._enabled = False

    def get_metadata(self) -> Dict:
        """获取插件元数据"""
        return {
            "name": self.plugin_name,
            "version": self.plugin_version,
            "description": self.plugin_description,
            "author": self.plugin_author,
            "enabled": self.enabled,
        }


class PluginManager:
    """插件管理器"""

    def __init__(self, plugin_dirs: List[str] = None):
        """
        初始化插件管理器

        Args:
            plugin_dirs: 插件目录列表
        """
        self.plugin_dirs = plugin_dirs or ["plugins/analyzers"]
        self.plugins: Dict[str, Type[AnalyzerPlugin]] = {}
        self.instances: Dict[str, AnalyzerPlugin] = {}

    def discover_plugins(self) -> List[str]:
        """
        发现所有可用的插件

        Returns:
            插件名称列表
        """
        discovered = []

        for plugin_dir in self.plugin_dirs:
            plugin_path = Path(plugin_dir)
            if not plugin_path.exists():
                logger.warning(f"插件目录不存在: {plugin_dir}")
                continue

            # 遍历所有Python文件
            for py_file in plugin_path.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue

                try:
                    # 动态导入模块
                    module_name = f"{plugin_dir.replace('/', '.')}.{py_file.stem}"
                    module = importlib.import_module(module_name)

                    # 查找AnalyzerPlugin的子类
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if (issubclass(obj, AnalyzerPlugin) and
                            obj is not AnalyzerPlugin and
                            hasattr(obj, 'plugin_name') and
                            obj.plugin_name):

                            plugin_name = obj.plugin_name
                            self.plugins[plugin_name] = obj
                            discovered.append(plugin_name)
                            logger.info(f"发现插件: {plugin_name} (v{obj.plugin_version})")

                except Exception as e:
                    logger.error(f"加载插件文件失败 {py_file}: {e}")

        return discovered

    def load_plugin(
        self,
        plugin_name: str,
        framework: UniversalAgentFramework,
        threat_intel=None
    ) -> Optional[AnalyzerPlugin]:
        """
        加载并实例化插件

        Args:
            plugin_name: 插件名称
            framework: Agent框架
            threat_intel: 威胁情报工具包

        Returns:
            插件实例
        """
        if plugin_name not in self.plugins:
            logger.error(f"插件不存在: {plugin_name}")
            return None

        try:
            plugin_class = self.plugins[plugin_name]
            instance = plugin_class(framework, threat_intel)
            self.instances[plugin_name] = instance
            logger.info(f"加载插件: {plugin_name}")
            return instance

        except Exception as e:
            logger.error(f"实例化插件失败 {plugin_name}: {e}")
            return None

    def load_all_plugins(
        self,
        framework: UniversalAgentFramework,
        threat_intel=None,
        enabled_only: List[str] = None
    ) -> Dict[str, AnalyzerPlugin]:
        """
        加载所有插件或指定的插件

        Args:
            framework: Agent框架
            threat_intel: 威胁情报工具包
            enabled_only: 仅加载指定的插件列表（None表示加载全部）

        Returns:
            插件实例字典
        """
        self.discover_plugins()

        for plugin_name in self.plugins.keys():
            # 如果指定了enabled_only，只加载列表中的插件
            if enabled_only is not None and plugin_name not in enabled_only:
                logger.info(f"跳过未启用的插件: {plugin_name}")
                continue

            self.load_plugin(plugin_name, framework, threat_intel)

        return self.instances

    def get_plugin(self, plugin_name: str) -> Optional[AnalyzerPlugin]:
        """获取插件实例"""
        return self.instances.get(plugin_name)

    def list_plugins(self) -> List[Dict]:
        """列出所有已加载的插件"""
        return [plugin.get_metadata() for plugin in self.instances.values()]

    def enable_plugin(self, plugin_name: str):
        """启用插件"""
        if plugin_name in self.instances:
            self.instances[plugin_name].enable()
            logger.info(f"启用插件: {plugin_name}")

    def disable_plugin(self, plugin_name: str):
        """禁用插件"""
        if plugin_name in self.instances:
            self.instances[plugin_name].disable()
            logger.info(f"禁用插件: {plugin_name}")

    async def run_analysis(
        self,
        plugin_name: str,
        state: AgentState
    ) -> Optional[AgentState]:
        """
        运行指定插件的分析

        Args:
            plugin_name: 插件名称
            state: 输入状态

        Returns:
            分析结果状态
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            logger.error(f"插件未加载: {plugin_name}")
            return None

        if not plugin.enabled:
            logger.warning(f"插件已禁用: {plugin_name}")
            return None

        try:
            return await plugin.analyze(state)
        except Exception as e:
            logger.error(f"插件执行失败 {plugin_name}: {e}")
            return None

    async def run_all_analyses(
        self,
        state: AgentState,
        parallel: bool = False
    ) -> Dict[str, AgentState]:
        """
        运行所有启用插件的分析

        Args:
            state: 输入状态
            parallel: 是否并行执行

        Returns:
            插件名称 -> 分析结果的字典
        """
        results = {}

        if parallel:
            import asyncio
            tasks = []
            for name, plugin in self.instances.items():
                if plugin.enabled:
                    tasks.append((name, plugin.analyze(state.copy())))

            completed = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
            for (name, _), result in zip(tasks, completed):
                if isinstance(result, Exception):
                    logger.error(f"插件执行失败 {name}: {result}")
                else:
                    results[name] = result
        else:
            for name, plugin in self.instances.items():
                if plugin.enabled:
                    try:
                        results[name] = await plugin.analyze(state.copy())
                    except Exception as e:
                        logger.error(f"插件执行失败 {name}: {e}")

        return results
