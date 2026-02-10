"""
模型路由层基础类定义
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class ModelProvider(Enum):
    """模型提供商"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    ZHIPU = "zhipu"
    ALIBABA = "alibaba"
    BAIDU = "baidu"
    GOOGLE = "google"
    LOCAL = "local"


class ModelCapability(Enum):
    """模型能力"""
    TEXT_GENERATION = "text_generation"
    CODE_GENERATION = "code_generation"
    REASONING = "reasoning"
    ANALYSIS = "analysis"
    TRANSLATION = "translation"
    SUMMARIZATION = "summarization"
    CONVERSATION = "conversation"
    TOOL_USE = "tool_use"
    VISION = "vision"
    EMBEDDING = "embedding"


class TaskComplexity(Enum):
    """任务复杂度"""
    SIMPLE = "simple"          # 简单任务（分类、简单问答）
    MEDIUM = "medium"          # 中等任务（摘要、翻译）
    COMPLEX = "complex"        # 复杂任务（推理、分析）
    VERY_COMPLEX = "very_complex"  # 极复杂任务（多步推理、代码生成）


@dataclass
class ModelConfig:
    """模型配置"""
    name: str                                    # 模型名称
    provider: ModelProvider                      # 提供商
    model_id: str                               # 模型ID
    api_key: Optional[str] = None               # API密钥
    base_url: Optional[str] = None              # API基础URL
    temperature: float = 0.7                    # 温度参数
    max_tokens: Optional[int] = None            # 最大token数
    capabilities: List[ModelCapability] = field(default_factory=list)  # 能力列表
    cost_per_1k_tokens: float = 0.0            # 每1k token成本
    speed_score: float = 1.0                    # 速度评分（1-10）
    quality_score: float = 1.0                  # 质量评分（1-10）
    context_window: int = 4096                  # 上下文窗口
    supports_streaming: bool = True             # 是否支持流式输出
    supports_function_calling: bool = False     # 是否支持函数调用
    metadata: Dict[str, Any] = field(default_factory=dict)  # 其他元数据

    def __post_init__(self):
        """初始化后处理"""
        if not self.capabilities:
            self.capabilities = [ModelCapability.TEXT_GENERATION]


@dataclass
class RoutingContext:
    """路由上下文"""
    task_type: str                              # 任务类型
    task_description: Optional[str] = None      # 任务描述
    complexity: Optional[TaskComplexity] = None # 任务复杂度
    required_capabilities: List[ModelCapability] = field(default_factory=list)
    max_cost: Optional[float] = None            # 最大成本限制
    min_quality: Optional[float] = None         # 最小质量要求
    prefer_speed: bool = False                  # 优先速度
    agent_name: Optional[str] = None            # Agent名称
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoutingDecision:
    """路由决策结果"""
    selected_model: ModelConfig                 # 选中的模型
    reason: str                                 # 选择原因
    confidence: float = 1.0                     # 置信度
    alternatives: List[ModelConfig] = field(default_factory=list)  # 备选模型
    metadata: Dict[str, Any] = field(default_factory=dict)


class RoutingStrategy(ABC):
    """路由策略基类"""

    @abstractmethod
    async def select_model(
        self,
        context: RoutingContext,
        available_models: List[ModelConfig]
    ) -> RoutingDecision:
        """选择模型"""
        pass

    @abstractmethod
    def get_strategy_name(self) -> str:
        """获取策略名称"""
        pass
