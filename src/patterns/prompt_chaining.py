"""
提示链模式实现
将复杂任务分解为顺序执行的子任务
"""
from typing import List, Callable, Optional
from langchain_core.runnables import Runnable
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser

from ..core.base import AgentState, BaseAgent


class PromptChain:
    """提示链：顺序执行多个提示"""
    
    def __init__(
        self,
        llm: ChatOpenAI,
        steps: List[Callable],
        output_key: Optional[str] = None
    ):
        self.llm = llm
        self.steps = steps
        self.output_key = output_key
        self._chain = self._build_chain()
    
    def _build_chain(self) -> Runnable:
        """构建链式执行流程"""
        chain = None
        
        for i, step in enumerate(self.steps):
            if isinstance(step, str):
                # 如果是字符串，创建提示模板
                prompt = ChatPromptTemplate.from_template(step)
                step_chain = prompt | self.llm | StrOutputParser()
            elif isinstance(step, Callable):
                # 如果是函数，直接使用
                step_chain = step
            else:
                step_chain = step
            
            if chain is None:
                chain = step_chain
            else:
                # 将前一步的输出作为下一步的输入
                chain = chain | step_chain
        
        return chain
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行链式流程"""
        input_data = state.get("input", state)
        result = await self._chain.ainvoke(input_data)
        
        if self.output_key:
            state[self.output_key] = result
        else:
            state["output"] = result
        
        return state


class ChainStep:
    """链步骤定义"""
    
    def __init__(
        self,
        prompt_template: str,
        input_key: Optional[str] = None,
        output_key: Optional[str] = None
    ):
        self.prompt_template = prompt_template
        self.input_key = input_key
        self.output_key = output_key
