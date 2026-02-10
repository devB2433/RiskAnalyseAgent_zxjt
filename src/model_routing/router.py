"""
模型路由器
统一的模型路由管理
"""
from typing import Dict, List, Optional, Union
from langchain_openai import ChatOpenAI

from .base import (
    RoutingStrategy,
    RoutingContext,
    RoutingDecision,
    ModelConfig,
    TaskComplexity,
    ModelCapability
)
from .registry import ModelRegistry
from .strategies import (
    RuleBasedRoutingStrategy,
    IntelligentRoutingStrategy,
    ConfigBasedRoutingStrategy
)


class ModelRouter:
    """模型路由器"""

    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        default_strategy: str = "rule_based"
    ):
        """
        初始化模型路由器

        Args:
            registry: 模型注册表
            default_strategy: 默认路由策略 (rule_based/intelligent/config_based)
        """
        self.registry = registry or ModelRegistry()
        self.strategies: Dict[str, RoutingStrategy] = {}
        self.default_strategy_name = default_strategy

        # 初始化默认策略
        self._initialize_strategies()

    def _initialize_strategies(self):
        """初始化路由策略"""
        self.strategies["rule_based"] = RuleBasedRoutingStrategy()
        self.strategies["intelligent"] = IntelligentRoutingStrategy()
        self.strategies["config_based"] = ConfigBasedRoutingStrategy()

    def register_strategy(self, name: str, strategy: RoutingStrategy):
        """注册自定义策略"""
        self.strategies[name] = strategy

    def set_default_strategy(self, strategy_name: str):
        """设置默认策略"""
        if strategy_name not in self.strategies:
            raise ValueError(f"策略不存在: {strategy_name}")
        self.default_strategy_name = strategy_name

    def get_strategy(self, strategy_name: Optional[str] = None) -> RoutingStrategy:
        """获取策略"""
        name = strategy_name or self.default_strategy_name
        strategy = self.strategies.get(name)
        if not strategy:
            raise ValueError(f"策略不存在: {name}")
        return strategy

    async def route(
        self,
        task_type: str,
        task_description: Optional[str] = None,
        complexity: Optional[TaskComplexity] = None,
        required_capabilities: Optional[List[ModelCapability]] = None,
        agent_name: Optional[str] = None,
        strategy: Optional[str] = None,
        max_cost: Optional[float] = None,
        min_quality: Optional[float] = None,
        prefer_speed: bool = False,
        filter_models: Optional[List[str]] = None
    ) -> RoutingDecision:
        """
        路由到最优模型

        Args:
            task_type: 任务类型
            task_description: 任务描述
            complexity: 任务复杂度
            required_capabilities: 需要的能力
            agent_name: Agent名称
            strategy: 使用的策略（不指定则使用默认策略）
            max_cost: 最大成本限制
            min_quality: 最小质量要求
            prefer_speed: 优先速度
            filter_models: 限制可用模型列表

        Returns:
            路由决策
        """
        # 1. 构建路由上下文
        context = RoutingContext(
            task_type=task_type,
            task_description=task_description,
            complexity=complexity,
            required_capabilities=required_capabilities or [],
            max_cost=max_cost,
            min_quality=min_quality,
            prefer_speed=prefer_speed,
            agent_name=agent_name
        )

        # 2. 获取可用模型
        available_models = self._get_available_models(
            context,
            filter_models
        )

        if not available_models:
            raise ValueError("没有满足条件的可用模型")

        # 3. 选择策略并执行路由
        routing_strategy = self.get_strategy(strategy)
        decision = await routing_strategy.select_model(context, available_models)

        return decision

    def _get_available_models(
        self,
        context: RoutingContext,
        filter_models: Optional[List[str]] = None
    ) -> List[ModelConfig]:
        """获取可用模型列表"""
        # 1. 获取所有模型
        if filter_models:
            models = [
                self.registry.get_model(name)
                for name in filter_models
                if self.registry.get_model(name)
            ]
        else:
            models = self.registry.list_models()

        # 2. 按能力过滤
        if context.required_capabilities:
            models = [
                m for m in models
                if all(cap in m.capabilities for cap in context.required_capabilities)
            ]

        # 3. 按成本过滤
        if context.max_cost:
            models = [m for m in models if m.cost_per_1k_tokens <= context.max_cost]

        # 4. 按质量过滤
        if context.min_quality:
            models = [m for m in models if m.quality_score >= context.min_quality]

        return models

    async def create_llm_for_task(
        self,
        task_type: str,
        task_description: Optional[str] = None,
        complexity: Optional[TaskComplexity] = None,
        agent_name: Optional[str] = None,
        strategy: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> ChatOpenAI:
        """
        为任务创建LLM实例

        Args:
            task_type: 任务类型
            task_description: 任务描述
            complexity: 任务复杂度
            agent_name: Agent名称
            strategy: 路由策略
            temperature: 温度参数
            max_tokens: 最大token数
            **kwargs: 其他路由参数

        Returns:
            LLM实例
        """
        # 1. 路由到最优模型
        decision = await self.route(
            task_type=task_type,
            task_description=task_description,
            complexity=complexity,
            agent_name=agent_name,
            strategy=strategy,
            **kwargs
        )

        # 2. 创建LLM
        llm = self.registry.create_llm(
            decision.selected_model,
            temperature=temperature,
            max_tokens=max_tokens
        )

        return llm

    def get_rule_based_strategy(self) -> RuleBasedRoutingStrategy:
        """获取规则路由策略"""
        return self.strategies["rule_based"]

    def get_intelligent_strategy(self) -> IntelligentRoutingStrategy:
        """获取智能路由策略"""
        return self.strategies["intelligent"]

    def get_config_based_strategy(self) -> ConfigBasedRoutingStrategy:
        """获取配置路由策略"""
        return self.strategies["config_based"]

    def add_rule(self, task_type: str, model_name: str):
        """添加规则（快捷方法）"""
        strategy = self.get_rule_based_strategy()
        strategy.add_rule(task_type, model_name)

    def set_agent_model(self, agent_name: str, model_name: str):
        """设置Agent模型（快捷方法）"""
        strategy = self.get_config_based_strategy()
        strategy.set_agent_model(agent_name, model_name)

    def load_agent_config(self, config_file: str):
        """加载Agent配置（快捷方法）"""
        strategy = self.get_config_based_strategy()
        strategy.load_config_from_file(config_file)

    def save_agent_config(self, config_file: str):
        """保存Agent配置（快捷方法）"""
        strategy = self.get_config_based_strategy()
        strategy.save_config_to_file(config_file)

    async def route_with_fallback(
        self,
        task_type: str,
        strategies: List[str],
        **kwargs
    ) -> RoutingDecision:
        """
        使用多个策略进行路由，带回退机制

        Args:
            task_type: 任务类型
            strategies: 策略列表（按优先级）
            **kwargs: 其他路由参数

        Returns:
            路由决策
        """
        last_error = None

        for strategy_name in strategies:
            try:
                decision = await self.route(
                    task_type=task_type,
                    strategy=strategy_name,
                    **kwargs
                )
                return decision
            except Exception as e:
                last_error = e
                continue

        raise ValueError(f"所有策略都失败了: {last_error}")

    def get_model_stats(self) -> Dict:
        """获取模型统计信息"""
        models = self.registry.list_models()

        return {
            "total_models": len(models),
            "by_provider": {
                provider.value: len([m for m in models if m.provider == provider])
                for provider in set(m.provider for m in models)
            },
            "cost_range": {
                "min": min(m.cost_per_1k_tokens for m in models),
                "max": max(m.cost_per_1k_tokens for m in models),
                "avg": sum(m.cost_per_1k_tokens for m in models) / len(models)
            },
            "quality_range": {
                "min": min(m.quality_score for m in models),
                "max": max(m.quality_score for m in models),
                "avg": sum(m.quality_score for m in models) / len(models)
            }
        }


__all__ = ['ModelRouter']