"""
模型注册表
管理所有可用的模型
"""
from typing import Dict, List, Optional
from langchain_openai import ChatOpenAI
import os

from .base import ModelConfig, ModelProvider, ModelCapability


class ModelRegistry:
    """模型注册表"""

    def __init__(self):
        self.models: Dict[str, ModelConfig] = {}
        self._initialize_default_models()

    def _initialize_default_models(self):
        """初始化默认模型"""

        # OpenAI 模型
        self.register(ModelConfig(
            name="gpt-4o",
            provider=ModelProvider.OPENAI,
            model_id="gpt-4o",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CODE_GENERATION,
                ModelCapability.REASONING,
                ModelCapability.ANALYSIS,
                ModelCapability.TOOL_USE,
                ModelCapability.VISION
            ],
            cost_per_1k_tokens=0.03,
            speed_score=7.0,
            quality_score=9.5,
            context_window=128000,
            supports_function_calling=True
        ))

        self.register(ModelConfig(
            name="gpt-4o-mini",
            provider=ModelProvider.OPENAI,
            model_id="gpt-4o-mini",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CODE_GENERATION,
                ModelCapability.REASONING,
                ModelCapability.TOOL_USE
            ],
            cost_per_1k_tokens=0.0015,
            speed_score=9.0,
            quality_score=8.0,
            context_window=128000,
            supports_function_calling=True
        ))

        self.register(ModelConfig(
            name="gpt-3.5-turbo",
            provider=ModelProvider.OPENAI,
            model_id="gpt-3.5-turbo",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CONVERSATION
            ],
            cost_per_1k_tokens=0.001,
            speed_score=9.5,
            quality_score=7.0,
            context_window=16385,
            supports_function_calling=True
        ))

        # Anthropic Claude 模型
        self.register(ModelConfig(
            name="claude-3-opus",
            provider=ModelProvider.ANTHROPIC,
            model_id="claude-3-opus-20240229",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CODE_GENERATION,
                ModelCapability.REASONING,
                ModelCapability.ANALYSIS,
                ModelCapability.VISION
            ],
            cost_per_1k_tokens=0.075,
            speed_score=6.0,
            quality_score=10.0,
            context_window=200000,
            supports_function_calling=True
        ))

        self.register(ModelConfig(
            name="claude-3-sonnet",
            provider=ModelProvider.ANTHROPIC,
            model_id="claude-3-sonnet-20240229",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CODE_GENERATION,
                ModelCapability.REASONING,
                ModelCapability.ANALYSIS
            ],
            cost_per_1k_tokens=0.015,
            speed_score=8.0,
            quality_score=9.0,
            context_window=200000,
            supports_function_calling=True
        ))

        self.register(ModelConfig(
            name="claude-3-haiku",
            provider=ModelProvider.ANTHROPIC,
            model_id="claude-3-haiku-20240307",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CONVERSATION
            ],
            cost_per_1k_tokens=0.0025,
            speed_score=9.5,
            quality_score=7.5,
            context_window=200000,
            supports_function_calling=True
        ))

        # 智谱 GLM 模型
        self.register(ModelConfig(
            name="glm-4",
            provider=ModelProvider.ZHIPU,
            model_id="glm-4",
            base_url="https://open.bigmodel.cn/api/paas/v4/",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.REASONING,
                ModelCapability.ANALYSIS,
                ModelCapability.TOOL_USE
            ],
            cost_per_1k_tokens=0.01,
            speed_score=7.5,
            quality_score=8.5,
            context_window=128000,
            supports_function_calling=True
        ))

        self.register(ModelConfig(
            name="glm-4-flash",
            provider=ModelProvider.ZHIPU,
            model_id="glm-4-flash",
            base_url="https://open.bigmodel.cn/api/paas/v4/",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CONVERSATION
            ],
            cost_per_1k_tokens=0.0001,
            speed_score=10.0,
            quality_score=7.0,
            context_window=128000,
            supports_function_calling=True
        ))

        self.register(ModelConfig(
            name="glm-3-turbo",
            provider=ModelProvider.ZHIPU,
            model_id="glm-3-turbo",
            base_url="https://open.bigmodel.cn/api/paas/v4/",
            capabilities=[
                ModelCapability.TEXT_GENERATION,
                ModelCapability.CONVERSATION
            ],
            cost_per_1k_tokens=0.0005,
            speed_score=9.0,
            quality_score=6.5,
            context_window=128000
        ))

    def register(self, model_config: ModelConfig):
        """注册模型"""
        self.models[model_config.name] = model_config

    def unregister(self, model_name: str):
        """注销模型"""
        if model_name in self.models:
            del self.models[model_name]

    def get_model(self, model_name: str) -> Optional[ModelConfig]:
        """获取模型配置"""
        return self.models.get(model_name)

    def list_models(
        self,
        provider: Optional[ModelProvider] = None,
        capability: Optional[ModelCapability] = None
    ) -> List[ModelConfig]:
        """列出模型"""
        models = list(self.models.values())

        if provider:
            models = [m for m in models if m.provider == provider]

        if capability:
            models = [m for m in models if capability in m.capabilities]

        return models

    def get_models_by_capability(
        self,
        capabilities: List[ModelCapability]
    ) -> List[ModelConfig]:
        """根据能力获取模型"""
        return [
            model for model in self.models.values()
            if all(cap in model.capabilities for cap in capabilities)
        ]

    def get_models_by_cost(
        self,
        max_cost: float
    ) -> List[ModelConfig]:
        """根据成本限制获取模型"""
        return [
            model for model in self.models.values()
            if model.cost_per_1k_tokens <= max_cost
        ]

    def create_llm(
        self,
        model_config: ModelConfig,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> ChatOpenAI:
        """创建LLM实例"""
        # 获取API密钥
        if model_config.provider == ModelProvider.OPENAI:
            api_key = model_config.api_key or os.getenv("OPENAI_API_KEY")
        elif model_config.provider == ModelProvider.ANTHROPIC:
            api_key = model_config.api_key or os.getenv("ANTHROPIC_API_KEY")
        elif model_config.provider == ModelProvider.ZHIPU:
            api_key = model_config.api_key or os.getenv("ZHIPU_API_KEY")
        else:
            api_key = model_config.api_key

        if not api_key:
            raise ValueError(f"未找到 {model_config.provider.value} 的API密钥")

        # 创建LLM
        llm_params = {
            "model": model_config.model_id,
            "temperature": temperature or model_config.temperature,
            "api_key": api_key,
        }

        if model_config.base_url:
            llm_params["base_url"] = model_config.base_url

        if max_tokens or model_config.max_tokens:
            llm_params["max_tokens"] = max_tokens or model_config.max_tokens

        return ChatOpenAI(**llm_params)

    def get_best_model_for_task(
        self,
        task_type: str,
        prefer_speed: bool = False,
        max_cost: Optional[float] = None
    ) -> Optional[ModelConfig]:
        """为任务获取最佳模型（简单启发式）"""
        models = list(self.models.values())

        # 应用成本限制
        if max_cost:
            models = [m for m in models if m.cost_per_1k_tokens <= max_cost]

        if not models:
            return None

        # 根据偏好排序
        if prefer_speed:
            models.sort(key=lambda m: m.speed_score, reverse=True)
        else:
            models.sort(key=lambda m: m.quality_score, reverse=True)

        return models[0] if models else None
