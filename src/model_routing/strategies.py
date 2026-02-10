"""
路由策略实现
包括：规则路由、智能路由、配置路由
"""
from typing import Dict, List, Optional, Callable
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import json

from .base import (
    RoutingStrategy,
    RoutingContext,
    RoutingDecision,
    ModelConfig,
    TaskComplexity,
    ModelCapability
)


class RuleBasedRoutingStrategy(RoutingStrategy):
    """基于规则的路由策略"""

    def __init__(self, rules: Optional[Dict[str, str]] = None):
        """
        初始化规则路由策略

        Args:
            rules: 规则映射 {task_type: model_name}
        """
        self.rules = rules or self._default_rules()

    def _default_rules(self) -> Dict[str, str]:
        """默认规则"""
        return {
            # 按任务类型
            "simple_qa": "glm-4-flash",
            "translation": "gpt-3.5-turbo",
            "summarization": "gpt-4o-mini",
            "code_generation": "claude-3-sonnet",
            "complex_reasoning": "gpt-4o",
            "analysis": "claude-3-opus",

            # 按复杂度
            "simple": "glm-4-flash",
            "medium": "gpt-4o-mini",
            "complex": "gpt-4o",
            "very_complex": "claude-3-opus",

            # 默认
            "default": "gpt-4o-mini"
        }

    def add_rule(self, task_type: str, model_name: str):
        """添加规则"""
        self.rules[task_type] = model_name

    def remove_rule(self, task_type: str):
        """移除规则"""
        if task_type in self.rules:
            del self.rules[task_type]

    async def select_model(
        self,
        context: RoutingContext,
        available_models: List[ModelConfig]
    ) -> RoutingDecision:
        """根据规则选择模型"""

        # 1. 尝试按任务类型匹配
        target_model_name = self.rules.get(context.task_type)

        # 2. 如果没有匹配，尝试按复杂度匹配
        if not target_model_name and context.complexity:
            target_model_name = self.rules.get(context.complexity.value)

        # 3. 使用默认规则
        if not target_model_name:
            target_model_name = self.rules.get("default", "gpt-4o-mini")

        # 4. 在可用模型中查找
        selected_model = None
        for model in available_models:
            if model.name == target_model_name:
                selected_model = model
                break

        # 5. 如果找不到，选择第一个可用模型
        if not selected_model and available_models:
            selected_model = available_models[0]

        if not selected_model:
            raise ValueError("没有可用的模型")

        # 6. 查找备选模型
        alternatives = [m for m in available_models if m.name != selected_model.name][:3]

        return RoutingDecision(
            selected_model=selected_model,
            reason=f"规则匹配: {context.task_type} -> {selected_model.name}",
            confidence=1.0,
            alternatives=alternatives,
            metadata={"strategy": "rule_based", "matched_rule": context.task_type}
        )

    def get_strategy_name(self) -> str:
        return "RuleBasedRouting"


class IntelligentRoutingStrategy(RoutingStrategy):
    """智能路由策略（使用小模型分析任务，选择最优大模型）"""

    def __init__(self, analyzer_model: Optional[ModelConfig] = None):
        """
        初始化智能路由策略

        Args:
            analyzer_model: 用于分析任务的小模型
        """
        self.analyzer_model = analyzer_model
        self._analyzer_llm = None

    def _get_analyzer_llm(self):
        """获取分析器LLM"""
        if not self._analyzer_llm:
            from .registry import ModelRegistry
            registry = ModelRegistry()

            if self.analyzer_model:
                self._analyzer_llm = registry.create_llm(self.analyzer_model)
            else:
                # 使用快速便宜的模型作为分析器
                fast_model = registry.get_model("glm-4-flash")
                if not fast_model:
                    fast_model = registry.get_model("gpt-3.5-turbo")
                self._analyzer_llm = registry.create_llm(fast_model)

        return self._analyzer_llm

    async def select_model(
        self,
        context: RoutingContext,
        available_models: List[ModelConfig]
    ) -> RoutingDecision:
        """使用AI分析任务并选择最优模型"""

        # 1. 构建分析提示
        models_info = "\n".join([
            f"- {m.name}: "
            f"质量={m.quality_score}/10, "
            f"速度={m.speed_score}/10, "
            f"成本=${m.cost_per_1k_tokens}/1k tokens, "
            f"能力={[c.value for c in m.capabilities]}"
            for m in available_models
        ])

        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一个AI模型路由专家。根据任务特征，从可用模型中选择最合适的模型。

考虑因素：
1. 任务复杂度：简单任务用快速便宜的模型，复杂任务用高质量模型
2. 任务类型：代码生成、推理、分析等需要不同的模型能力
3. 成本效益：在满足质量要求的前提下，优先选择性价比高的模型
4. 速度要求：如果需要快速响应，优先选择速度快的模型

输出JSON格式：
{{
    "selected_model": "模型名称",
    "reason": "选择原因",
    "confidence": 0.0-1.0,
    "task_complexity": "simple/medium/complex/very_complex"
}}"""),
            ("user", """任务信息：
- 任务类型: {task_type}
- 任务描述: {task_description}
- 复杂度: {complexity}
- 需要的能力: {capabilities}
- 最大成本: {max_cost}
- 最小质量: {min_quality}
- 优先速度: {prefer_speed}

可用模型：
{models_info}

请选择最合适的模型。""")
        ])

        # 2. 执行分析
        chain = prompt | self._get_analyzer_llm() | StrOutputParser()

        result_text = await chain.ainvoke({
            "task_type": context.task_type,
            "task_description": context.task_description or "无",
            "complexity": context.complexity.value if context.complexity else "未知",
            "capabilities": [c.value for c in context.required_capabilities] if context.required_capabilities else "无特殊要求",
            "max_cost": context.max_cost or "无限制",
            "min_quality": context.min_quality or "无要求",
            "prefer_speed": "是" if context.prefer_speed else "否",
            "models_info": models_info
        })

        # 3. 解析结果
        try:
            # 尝试提取JSON
            import re
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = json.loads(result_text)

            selected_model_name = result.get("selected_model")
            reason = result.get("reason", "AI分析推荐")
            confidence = float(result.get("confidence", 0.8))

        except (json.JSONDecodeError, ValueError):
            # 如果解析失败，使用启发式方法
            selected_model_name = available_models[0].name
            reason = "AI分析失败，使用默认模型"
            confidence = 0.5

        # 4. 查找选中的模型
        selected_model = None
        for model in available_models:
            if model.name == selected_model_name:
                selected_model = model
                break

        if not selected_model:
            selected_model = available_models[0]
            reason += " (回退到第一个可用模型)"

        # 5. 查找备选模型
        alternatives = [m for m in available_models if m.name != selected_model.name][:3]

        return RoutingDecision(
            selected_model=selected_model,
            reason=reason,
            confidence=confidence,
            alternatives=alternatives,
            metadata={
                "strategy": "intelligent",
                "analyzer_response": result_text[:200]
            }
        )

    def get_strategy_name(self) -> str:
        return "IntelligentRouting"


class ConfigBasedRoutingStrategy(RoutingStrategy):
    """基于配置的路由策略"""

    def __init__(self, config: Optional[Dict[str, str]] = None):
        """
        初始化配置路由策略

        Args:
            config: 配置映射 {agent_name: model_name}
        """
        self.config = config or {}
        self.default_model = "gpt-4o-mini"

    def set_agent_model(self, agent_name: str, model_name: str):
        """设置Agent使用的模型"""
        self.config[agent_name] = model_name

    def remove_agent_config(self, agent_name: str):
        """移除Agent配置"""
        if agent_name in self.config:
            del self.config[agent_name]

    def set_default_model(self, model_name: str):
        """设置默认模型"""
        self.default_model = model_name

    def load_config_from_file(self, config_file: str):
        """从文件加载配置"""
        import json
        with open(config_file, 'r', encoding='utf-8') as f:
            self.config = json.load(f)

    def save_config_to_file(self, config_file: str):
        """保存配置到文件"""
        import json
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)

    async def select_model(
        self,
        context: RoutingContext,
        available_models: List[ModelConfig]
    ) -> RoutingDecision:
        """根据配置选择模型"""

        # 1. 查找Agent配置
        target_model_name = None
        if context.agent_name:
            target_model_name = self.config.get(context.agent_name)

        # 2. 使用默认模型
        if not target_model_name:
            target_model_name = self.default_model

        # 3. 在可用模型中查找
        selected_model = None
        for model in available_models:
            if model.name == target_model_name:
                selected_model = model
                break

        # 4. 如果找不到，选择第一个可用模型
        if not selected_model and available_models:
            selected_model = available_models[0]

        if not selected_model:
            raise ValueError("没有可用的模型")

        # 5. 查找备选模型
        alternatives = [m for m in available_models if m.name != selected_model.name][:3]

        reason = f"配置指定: {context.agent_name} -> {selected_model.name}" if context.agent_name else f"使用默认模型: {selected_model.name}"

        return RoutingDecision(
            selected_model=selected_model,
            reason=reason,
            confidence=1.0,
            alternatives=alternatives,
            metadata={
                "strategy": "config_based",
                "agent_name": context.agent_name,
                "config_exists": context.agent_name in self.config if context.agent_name else False
            }
        )

    def get_strategy_name(self) -> str:
        return "ConfigBasedRouting"


__all__ = [
    'RuleBasedRoutingStrategy',
    'IntelligentRoutingStrategy',
    'ConfigBasedRoutingStrategy',
]