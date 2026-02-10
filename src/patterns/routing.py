"""
路由模式实现
根据条件动态选择执行路径
"""
import asyncio
from typing import Dict, Callable, Optional, List
from langchain_core.runnables import RunnableBranch, RunnablePassthrough
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser

from ..core.base import AgentState, ExecutionMode


class Router:
    """路由器：根据条件选择执行路径"""
    
    def __init__(
        self,
        llm: ChatOpenAI,
        routes: Dict[str, Callable],
        default_route: Optional[str] = None
    ):
        """
        初始化路由器
        
        Args:
            llm: 语言模型
            routes: 路由映射 {route_name: handler_function}
            default_route: 默认路由名称
        """
        self.llm = llm
        self.routes = routes
        self.default_route = default_route or list(routes.keys())[0]
        self._router_chain = self._build_router()
    
    def _build_router(self) -> RunnableBranch:
        """构建路由决策链"""
        # 创建路由决策提示
        route_names = list(self.routes.keys())
        router_prompt = ChatPromptTemplate.from_messages([
            ("system", f"""分析用户请求并选择最合适的处理路径。
可用路径：{', '.join(route_names)}
只输出路径名称，不要输出其他内容。"""),
            ("user", "{input}")
        ])
        
        router_chain = router_prompt | self.llm | StrOutputParser()
        
        # 构建分支
        branches = []
        for route_name, handler in self.routes.items():
            condition = lambda x, name=route_name: x.get('decision', '').strip() == name
            branches.append((
                condition,
                RunnablePassthrough.assign(
                    output=lambda x, h=handler: h(x.get('input', x))
                )
            ))
        
        # 默认分支
        default_handler = self.routes.get(self.default_route)
        if default_handler:
            branches.append(
                RunnablePassthrough.assign(
                    output=lambda x, h=default_handler: h(x.get('input', x))
                )
            )
        
        return {
            "decision": router_chain,
            "input": RunnablePassthrough()
        } | RunnableBranch(*branches)
    
    async def route(self, state: AgentState) -> AgentState:
        """执行路由决策"""
        input_data = state.get("input", state)
        result = await self._router_chain.ainvoke({"input": input_data})
        
        output = result.get("output", result)
        # 若 handler 是 async，output 可能是协程，需要 await
        if asyncio.iscoroutine(output):
            output = await output
        if isinstance(output, dict) and "output" in output:
            output = output.get("output", output)
        state["output"] = output
        state["route_decision"] = result.get("decision", self.default_route)
        
        return state


class RuleBasedRouter:
    """基于规则的路由器（更快，更确定）"""
    
    def __init__(
        self,
        rules: Dict[str, Callable[[str], bool]],
        routes: Dict[str, Callable],
        default_route: Optional[str] = None
    ):
        """
        初始化规则路由器
        
        Args:
            rules: 规则映射 {route_name: condition_function}
            routes: 路由处理函数 {route_name: handler_function}
            default_route: 默认路由
        """
        self.rules = rules
        self.routes = routes
        self.default_route = default_route
    
    async def route(self, state: AgentState) -> AgentState:
        """基于规则执行路由"""
        input_data = str(state.get("input", ""))
        
        # 检查每个规则
        selected_route = self.default_route
        for route_name, condition in self.rules.items():
            if condition(input_data):
                selected_route = route_name
                break
        
        # 执行选定的路由
        handler = self.routes.get(selected_route)
        if handler:
            result = await handler(state) if asyncio.iscoroutinefunction(handler) else handler(state)
            state["output"] = result.get("output", result) if isinstance(result, dict) else result
            state["route_decision"] = selected_route
        
        return state
