"""
通用智能体框架
整合所有设计模式
默认使用智谱 GLM 模型（可切换为 OpenAI）
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

# 加载环境变量
load_dotenv()

# 智谱 GLM OpenAI 兼容 API
ZHIPU_BASE_URL = "https://open.bigmodel.cn/api/paas/v4/"
ZHIPU_DEFAULT_MODEL = "glm-4-flash"  # 可选: glm-4, glm-4-flash, glm-3-turbo


class UniversalAgentFramework:
    """通用智能体框架（默认使用智谱 GLM）"""
    
    def __init__(
        self,
        model: str = ZHIPU_DEFAULT_MODEL,
        api_key: Optional[str] = None,
        temperature: float = 0.7,
        use_openai: bool = False,
    ):
        """
        初始化框架
        
        Args:
            model: 模型名称。默认 GLM：glm-4-flash；若 use_openai=True 则为 gpt-4o-mini 等
            api_key: API 密钥（不提供则从环境变量读取）
            temperature: 温度参数
            use_openai: 若为 True 则使用 OpenAI，否则使用智谱 GLM
        """
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
    
    def create_chain(
        self,
        steps: List[str],
        output_key: Optional[str] = None
    ) -> PromptChain:
        """创建提示链"""
        return PromptChain(self.llm, steps, output_key)
    
    def create_router(
        self,
        routes: Dict[str, Any],
        default_route: Optional[str] = None,
        use_llm: bool = True
    ):
        """创建路由器"""
        if use_llm:
            return Router(self.llm, routes, default_route)
        else:
            # 规则路由需要rules字典
            rules = {name: lambda x, name=name: name.lower() in x.lower() 
                    for name in routes.keys()}
            return RuleBasedRouter(rules, routes, default_route)
    
    def create_parallel_executor(
        self,
        tasks: Dict[str, Any]
    ) -> ParallelExecutor:
        """创建并行执行器"""
        return ParallelExecutor(tasks, self.llm)
    
    def create_reflection_agent(
        self,
        producer_prompt: str,
        critic_prompt: str,
        max_iterations: int = 3
    ) -> ReflectionAgent:
        """创建反思智能体"""
        return ReflectionAgent(
            self.llm,
            producer_prompt,
            critic_prompt,
            max_iterations
        )
    
    def create_tool_agent(
        self,
        tools: List[BaseTool],
        system_prompt: Optional[str] = None
    ) -> ToolUsingAgent:
        """创建工具使用智能体"""
        return ToolUsingAgent(self.llm, tools, system_prompt)
    
    def create_planning_agent(
        self,
        step_executor: Optional[Any] = None
    ) -> PlanningAgent:
        """创建规划智能体"""
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
