"""
通用智能体框架（增强版）
整合所有设计模式 + 模型路由支持
"""
from typing import Optional, List, Dict, Any
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
import os

from .core.base import AgentState, AgentConfig, BaseAgent, BaseTool
from .patterns.prompt_chaining import PromptChain
from .patterns.routing import Router, RuleBasedRouter
from .patterns.parallelization import ParallelExecutor
from .patterns.reflection import ReflectionAgent
from .patterns.tool_use import ToolUsingAgent, ToolRegistry
from .patterns.planning import PlanningAgent
from .patterns.multi_agent import MultiAgentSystem, CollaborationMode
from .model_routing import ModelRouter, TaskComplexity, ModelCapability

# 加载环境变量
load_dotenv()

# 智谱 GLM OpenAI 兼容 API
ZHIPU_BASE_URL = "https://open.bigmodel.cn/api/paas/v4/"
ZHIPU_DEFAULT_MODEL = "glm-4-flash"  # 可选: glm-4, glm-4-flash, glm-3-turbo


class UniversalAgentFramework:
    """通用智能体框架（支持模型路由）"""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        temperature: float = 0.7,
        use_openai: bool = False,
        enable_model_routing: bool = True,
        default_routing_strategy: str = "rule_based"
    ):
        """
        初始化框架

        Args:
            model: 模型名称（如果不启用路由，则使用此固定模型）
            api_key: API 密钥（不提供则从环境变量读取）
            temperature: 温度参数
            use_openai: 若为 True 则使用 OpenAI，否则使用智谱 GLM
            enable_model_routing: 是否启用模型路由
            default_routing_strategy: 默认路由策略 (rule_based/intelligent/config_based)
        """
        self.temperature = temperature
        self.enable_model_routing = enable_model_routing

        # 初始化模型路由器
        if enable_model_routing:
            self.model_router = ModelRouter(default_strategy=default_routing_strategy)
            self.llm = None  # 使用路由时，LLM动态创建
        else:
            # 传统模式：使用固定模型
            self.model_router = None
            if use_openai:
                self.api_key = api_key or os.getenv("OPENAI_API_KEY")
                if not self.api_key:
                    raise ValueError("使用 OpenAI 时需设置 OPENAI_API_KEY 环境变量或 api_key 参数")
                self.llm = ChatOpenAI(
                    model=model or "gpt-4o-mini",
                    temperature=temperature,
                    api_key=self.api_key,
                )
            else:
                self.api_key = api_key or os.getenv("ZHIPU_API_KEY")
                if not self.api_key:
                    raise ValueError("使用 GLM 时需设置 ZHIPU_API_KEY 环境变量或 api_key 参数")
                self.llm = ChatOpenAI(
                    model=model or ZHIPU_DEFAULT_MODEL,
                    temperature=temperature,
                    api_key=self.api_key,
                    base_url=ZHIPU_BASE_URL,
                )

        self.tool_registry = ToolRegistry()

    async def get_llm(
        self,
        task_type: Optional[str] = None,
        complexity: Optional[TaskComplexity] = None,
        agent_name: Optional[str] = None,
        routing_strategy: Optional[str] = None
    ) -> ChatOpenAI:
        """
        获取LLM实例（支持路由）

        Args:
            task_type: 任务类型
            complexity: 任务复杂度
            agent_name: Agent名称
            routing_strategy: 路由策略

        Returns:
            LLM实例
        """
        if not self.enable_model_routing:
            return self.llm

        # 使用模型路由
        if not task_type:
            task_type = "general"

        llm = await self.model_router.create_llm_for_task(
            task_type=task_type,
            complexity=complexity,
            agent_name=agent_name,
            strategy=routing_strategy,
            temperature=self.temperature
        )

        return llm

    def create_chain(
        self,
        steps: List[str],
        output_key: Optional[str] = None,
        task_type: Optional[str] = None,
        complexity: Optional[TaskComplexity] = None
    ) -> PromptChain:
        """创建提示链"""
        # 如果启用路由，需要在执行时动态获取LLM
        if self.enable_model_routing:
            # 这里返回一个包装器，在执行时才获取LLM
            return PromptChainWithRouting(
                self,
                steps,
                output_key,
                task_type or "prompt_chain",
                complexity
            )
        else:
            return PromptChain(self.llm, steps, output_key)

    def create_router(
        self,
        routes: Dict[str, Any],
        default_route: Optional[str] = None,
        use_llm: bool = True,
        task_type: Optional[str] = None
    ):
        """创建路由器"""
        if use_llm:
            if self.enable_model_routing:
                # 使用路由时需要特殊处理
                return RouterWithModelRouting(
                    self,
                    routes,
                    default_route,
                    task_type or "routing"
                )
            else:
                return Router(self.llm, routes, default_route)
        else:
            # 规则路由不需要LLM
            rules = {name: lambda x, name=name: name.lower() in x.lower()
                    for name in routes.keys()}
            return RuleBasedRouter(rules, routes, default_route)

    def create_parallel_executor(
        self,
        tasks: Dict[str, Any]
    ) -> ParallelExecutor:
        """创建并行执行器"""
        return ParallelExecutor(tasks, self.llm if not self.enable_model_routing else None)

    def create_reflection_agent(
        self,
        producer_prompt: str,
        critic_prompt: str,
        max_iterations: int = 3,
        task_type: Optional[str] = None,
        complexity: Optional[TaskComplexity] = None
    ) -> ReflectionAgent:
        """创建反思智能体"""
        if self.enable_model_routing:
            return ReflectionAgentWithRouting(
                self,
                producer_prompt,
                critic_prompt,
                max_iterations,
                task_type or "reflection",
                complexity
            )
        else:
            return ReflectionAgent(
                self.llm,
                producer_prompt,
                critic_prompt,
                max_iterations
            )

    def create_tool_agent(
        self,
        tools: List[BaseTool],
        system_prompt: Optional[str] = None,
        agent_name: Optional[str] = None
    ) -> ToolUsingAgent:
        """创建工具使用智能体"""
        if self.enable_model_routing:
            return ToolUsingAgentWithRouting(
                self,
                tools,
                system_prompt,
                agent_name or "tool_agent"
            )
        else:
            return ToolUsingAgent(self.llm, tools, system_prompt)

    def create_planning_agent(
        self,
        step_executor: Optional[Any] = None,
        agent_name: Optional[str] = None
    ) -> PlanningAgent:
        """创建规划智能体"""
        if self.enable_model_routing:
            return PlanningAgentWithRouting(
                self,
                step_executor,
                agent_name or "planning_agent"
            )
        else:
            return PlanningAgent(self.llm, step_executor)

    def create_multi_agent_system(
        self,
        agents: List[BaseAgent],
        mode: CollaborationMode = CollaborationMode.SEQUENTIAL,
        coordinator: Optional[BaseAgent] = None
    ) -> MultiAgentSystem:
        """创建多智能体系统"""
        return MultiAgentSystem(agents, mode, coordinator)

    def register_tool(self, tool: BaseTool):
        """注册工具"""
        self.tool_registry.register(tool)

    async def execute(
        self,
        component: Any,
        input_data: Any
    ) -> AgentState:
        """执行组件"""
        state = AgentState()
        state["input"] = input_data

        if hasattr(component, 'execute'):
            result = await component.execute(state)
        elif hasattr(component, 'route'):
            result = await component.route(state)
        elif hasattr(component, '__call__'):
            result = await component(state)
        else:
            raise ValueError(f"组件 {component} 不支持执行")

        return result

    # 模型路由相关方法
    def add_routing_rule(self, task_type: str, model_name: str):
        """添加路由规则"""
        if self.model_router:
            self.model_router.add_rule(task_type, model_name)

    def set_agent_model(self, agent_name: str, model_name: str):
        """设置Agent使用的模型"""
        if self.model_router:
            self.model_router.set_agent_model(agent_name, model_name)

    def load_agent_config(self, config_file: str):
        """加载Agent配置"""
        if self.model_router:
            self.model_router.load_agent_config(config_file)

    def save_agent_config(self, config_file: str):
        """保存Agent配置"""
        if self.model_router:
            self.model_router.save_agent_config(config_file)


# 支持模型路由的包装类
class PromptChainWithRouting:
    """支持模型路由的提示链"""

    def __init__(self, framework, steps, output_key, task_type, complexity):
        self.framework = framework
        self.steps = steps
        self.output_key = output_key
        self.task_type = task_type
        self.complexity = complexity

    async def execute(self, state: AgentState) -> AgentState:
        llm = await self.framework.get_llm(
            task_type=self.task_type,
            complexity=self.complexity
        )
        chain = PromptChain(llm, self.steps, self.output_key)
        return await chain.execute(state)


class RouterWithModelRouting:
    """支持模型路由的路由器"""

    def __init__(self, framework, routes, default_route, task_type):
        self.framework = framework
        self.routes = routes
        self.default_route = default_route
        self.task_type = task_type

    async def route(self, state: AgentState) -> AgentState:
        llm = await self.framework.get_llm(task_type=self.task_type)
        router = Router(llm, self.routes, self.default_route)
        return await router.route(state)


class ReflectionAgentWithRouting:
    """支持模型路由的反思智能体"""

    def __init__(self, framework, producer_prompt, critic_prompt,
                 max_iterations, task_type, complexity):
        self.framework = framework
        self.producer_prompt = producer_prompt
        self.critic_prompt = critic_prompt
        self.max_iterations = max_iterations
        self.task_type = task_type
        self.complexity = complexity

    async def execute(self, state: AgentState) -> AgentState:
        llm = await self.framework.get_llm(
            task_type=self.task_type,
            complexity=self.complexity
        )
        agent = ReflectionAgent(
            llm,
            self.producer_prompt,
            self.critic_prompt,
            self.max_iterations
        )
        return await agent.execute(state)


class ToolUsingAgentWithRouting:
    """支持模型路由的工具使用智能体"""

    def __init__(self, framework, tools, system_prompt, agent_name):
        self.framework = framework
        self.tools = tools
        self.system_prompt = system_prompt
        self.agent_name = agent_name

    async def execute(self, state: AgentState) -> AgentState:
        llm = await self.framework.get_llm(
            task_type="tool_use",
            agent_name=self.agent_name
        )
        agent = ToolUsingAgent(llm, self.tools, self.system_prompt)
        return await agent.execute(state)


class PlanningAgentWithRouting:
    """支持模型路由的规划智能体"""

    def __init__(self, framework, step_executor, agent_name):
        self.framework = framework
        self.step_executor = step_executor
        self.agent_name = agent_name

    async def execute(self, state: AgentState) -> AgentState:
        llm = await self.framework.get_llm(
            task_type="planning",
            complexity=TaskComplexity.COMPLEX,
            agent_name=self.agent_name
        )
        agent = PlanningAgent(llm, self.step_executor)
        return await agent.execute(state)