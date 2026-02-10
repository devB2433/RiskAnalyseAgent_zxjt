"""
模型路由层
支持多模型自动路由和配置化管理
"""
from .base import (
    ModelConfig,
    ModelProvider,
    ModelCapability,
    RoutingStrategy,
    TaskComplexity
)
from .registry import ModelRegistry
from .strategies import (
    RuleBasedRoutingStrategy,
    IntelligentRoutingStrategy,
    ConfigBasedRoutingStrategy
)
from .router import ModelRouter

__all__ = [
    # Base classes
    'ModelConfig',
    'ModelProvider',
    'ModelCapability',
    'RoutingStrategy',
    'TaskComplexity',

    # Registry
    'ModelRegistry',

    # Strategies
    'RuleBasedRoutingStrategy',
    'IntelligentRoutingStrategy',
    'ConfigBasedRoutingStrategy',

    # Router
    'ModelRouter',
]
