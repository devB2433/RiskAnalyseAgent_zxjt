"""
工具使用模式实现
让智能体调用外部函数和API
"""
from typing import List, Dict, Any, Optional
from langchain_core.tools import tool as langchain_tool
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

try:
    from langchain.agents import create_tool_calling_agent, AgentExecutor
except ImportError:  # 兼容旧版本或不完整安装的langchain
    create_tool_calling_agent = None
    AgentExecutor = None

from ..core.base import BaseTool, AgentState


class ToolRegistry:
    """工具注册表"""
    
    def __init__(self):
        self.tools: Dict[str, BaseTool] = {}
        self.langchain_tools: List[Any] = []
    
    def register(self, tool: BaseTool):
        """注册工具"""
        self.tools[tool.name] = tool
        
        # 转换为LangChain工具
        @langchain_tool
        async def tool_wrapper(**kwargs):
            return await tool.execute(**kwargs)
        
        tool_wrapper.name = tool.name
        tool_wrapper.description = tool.description
        self.langchain_tools.append(tool_wrapper)
    
    def get_tool(self, name: str) -> Optional[BaseTool]:
        """获取工具"""
        return self.tools.get(name)
    
    def get_all_tools(self) -> List[Any]:
        """获取所有LangChain工具"""
        return self.langchain_tools


class ToolUsingAgent:
    """使用工具的智能体"""
    
    def __init__(
        self,
        llm: ChatOpenAI,
        tools: List[BaseTool],
        system_prompt: Optional[str] = None
    ):
        """
        初始化工具使用智能体
        
        Args:
            llm: 语言模型
            tools: 工具列表
            system_prompt: 系统提示
        """
        if create_tool_calling_agent is None or AgentExecutor is None:
            raise ImportError(
                "当前环境中的 langchain.agents 不包含 create_tool_calling_agent / AgentExecutor，"
                "请安装或升级 langchain>=0.2.0，或根据项目 requirements.txt 重新安装依赖。"
            )

        self.llm = llm
        self.tool_registry = ToolRegistry()
        
        # 注册所有工具
        for tool in tools:
            self.tool_registry.register(tool)
        
        # 创建智能体
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt or "You are a helpful assistant with access to tools."),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        
        self.agent = create_tool_calling_agent(
            llm,
            self.tool_registry.get_all_tools(),
            prompt
        )
        
        self.executor = AgentExecutor(
            agent=self.agent,
            tools=self.tool_registry.get_all_tools(),
            verbose=True
        )
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行工具调用"""
        input_data = state.get("input", "")
        
        result = await self.executor.ainvoke({"input": input_data})
        
        state["output"] = result.get("output", "")
        state["tool_calls"] = result.get("intermediate_steps", [])
        
        return state
