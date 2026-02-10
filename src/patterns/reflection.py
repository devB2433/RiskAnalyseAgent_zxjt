"""
反思模式实现
自我评估和改进输出
"""
from typing import Optional, Callable
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser

from ..core.base import AgentState


class ReflectionAgent:
    """反思智能体：生成-评估-改进循环"""
    
    def __init__(
        self,
        llm: ChatOpenAI,
        producer_prompt: str,
        critic_prompt: str,
        max_iterations: int = 3,
        improvement_threshold: str = "PERFECT"
    ):
        """
        初始化反思智能体
        
        Args:
            llm: 语言模型
            producer_prompt: 生产者提示模板
            critic_prompt: 评论者提示模板
            max_iterations: 最大迭代次数
            improvement_threshold: 停止改进的阈值
        """
        self.llm = llm
        self.producer_prompt = producer_prompt
        self.critic_prompt = critic_prompt
        self.max_iterations = max_iterations
        self.improvement_threshold = improvement_threshold
        
        self.producer_chain = ChatPromptTemplate.from_template(
            producer_prompt
        ) | llm | StrOutputParser()
        
        self.critic_chain = ChatPromptTemplate.from_messages([
            ("system", critic_prompt),
            ("user", "{output}")
        ]) | llm | StrOutputParser()
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行反思循环"""
        input_data = state.get("input", "")
        current_output = None
        
        for iteration in range(self.max_iterations):
            # 1. 生成/改进阶段
            if iteration == 0:
                # 首次生成
                prompt_input = {"input": input_data}
            else:
                # 基于反馈改进
                prompt_input = {
                    "input": input_data,
                    "previous_output": current_output,
                    "critique": state.get("critique", "")
                }
            
            current_output = await self.producer_chain.ainvoke(prompt_input)
            state[f"output_iteration_{iteration}"] = current_output
            
            # 2. 评估阶段
            critique = await self.critic_chain.ainvoke({"output": current_output})
            state["critique"] = critique
            
            # 3. 检查是否达到阈值
            if self.improvement_threshold in critique.upper():
                state["output"] = current_output
                state["iterations"] = iteration + 1
                state["reflection_complete"] = True
                break
        
        if not state.get("reflection_complete"):
            state["output"] = current_output
            state["iterations"] = self.max_iterations
            state["reflection_complete"] = False
        
        return state


class ProducerCriticPair:
    """生产者-评论者配对"""
    
    def __init__(
        self,
        producer: Callable,
        critic: Callable,
        max_iterations: int = 3
    ):
        self.producer = producer
        self.critic = critic
        self.max_iterations = max_iterations
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行生产者-评论者循环"""
        input_data = state.get("input", "")
        current_output = None
        
        for iteration in range(self.max_iterations):
            # 生产者生成
            if iteration == 0:
                current_output = await self.producer(state)
            else:
                state["previous_output"] = current_output
                current_output = await self.producer(state)
            
            state[f"output_iteration_{iteration}"] = current_output
            
            # 评论者评估
            state["current_output"] = current_output
            critique = await self.critic(state)
            state["critique"] = critique
            
            # 检查是否完美
            if critique.get("status") == "PERFECT":
                break
        
        state["output"] = current_output
        state["iterations"] = iteration + 1
        
        return state
