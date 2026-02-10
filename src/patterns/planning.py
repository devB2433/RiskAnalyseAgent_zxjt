"""
规划模式实现
制定多步骤计划实现目标
"""
from typing import List, Dict, Optional, Callable, Any
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser
import json

from ..core.base import AgentState


class Planner:
    """规划器：制定执行计划"""
    
    def __init__(
        self,
        llm: ChatOpenAI,
        plan_format: str = "json"
    ):
        """
        初始化规划器
        
        Args:
            llm: 语言模型
            plan_format: 计划格式（json/text）
        """
        self.llm = llm
        self.plan_format = plan_format
        
        self.planning_prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一个专业的任务规划专家。
分析用户的目标，将其分解为一系列可执行的步骤。
每个步骤应该：
1. 清晰明确
2. 可执行
3. 有明确的输入输出
4. 考虑依赖关系

输出格式：JSON数组，每个元素包含：
- step: 步骤编号
- description: 步骤描述
- input: 需要的输入
- output: 预期输出
- dependencies: 依赖的步骤编号列表"""),
            ("user", "目标：{goal}\n约束条件：{constraints}")
        ])
        
        self.planning_chain = self.planning_prompt | llm | StrOutputParser()
    
    async def create_plan(self, state: AgentState) -> AgentState:
        """创建执行计划"""
        goal = state.get("goal", state.get("input", ""))
        constraints = state.get("constraints", "")
        
        plan_text = await self.planning_chain.ainvoke({
            "goal": goal,
            "constraints": constraints
        })
        
        # 解析计划
        try:
            if self.plan_format == "json":
                plan = json.loads(plan_text)
            else:
                plan = self._parse_text_plan(plan_text)
        except:
            plan = self._parse_text_plan(plan_text)
        
        state["plan"] = plan
        state["plan_text"] = plan_text
        
        return state
    
    def _parse_text_plan(self, text: str) -> List[Dict]:
        """解析文本格式的计划"""
        # 简单的文本解析逻辑
        steps = []
        lines = text.split('\n')
        current_step = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith(('步骤', 'Step', '1.', '2.', '3.')):
                if current_step:
                    steps.append(current_step)
                current_step = {"description": line}
            elif current_step:
                if 'input' not in current_step:
                    current_step['input'] = line
                elif 'output' not in current_step:
                    current_step['output'] = line
        
        if current_step:
            steps.append(current_step)
        
        return steps


class PlanExecutor:
    """计划执行器：按计划执行步骤"""
    
    def __init__(
        self,
        llm: ChatOpenAI,
        step_executor: Optional[Callable] = None
    ):
        """
        初始化计划执行器
        
        Args:
            llm: 语言模型
            step_executor: 步骤执行函数
        """
        self.llm = llm
        self.step_executor = step_executor or self._default_step_executor
        
        self.execution_prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一个任务执行专家。
根据给定的步骤描述，执行该步骤并返回结果。
确保：
1. 理解步骤要求
2. 使用必要的输入
3. 产生预期的输出"""),
            ("user", "步骤：{step_description}\n输入：{step_input}")
        ])
        
        self.execution_chain = self.execution_prompt | llm | StrOutputParser()
    
    async def execute_plan(self, state: AgentState) -> AgentState:
        """执行计划"""
        plan = state.get("plan", [])
        execution_results = []
        step_outputs = {}
        
        for step in plan:
            step_num = step.get("step", len(execution_results) + 1)
            step_desc = step.get("description", "")
            step_input = step.get("input", "")
            
            # 检查依赖
            dependencies = step.get("dependencies", [])
            if dependencies:
                # 收集依赖步骤的输出
                dep_inputs = [step_outputs.get(dep, "") for dep in dependencies]
                step_input = f"{step_input}\n依赖步骤输出：{dep_inputs}"
            
            # 执行步骤
            result = await self.step_executor(
                step_desc,
                step_input,
                state
            )
            
            step_outputs[step_num] = result
            execution_results.append({
                "step": step_num,
                "result": result
            })
        
        state["execution_results"] = execution_results
        state["final_output"] = execution_results[-1]["result"] if execution_results else ""
        
        return state
    
    async def _default_step_executor(
        self,
        step_description: str,
        step_input: str,
        state: AgentState
    ) -> str:
        """默认步骤执行器"""
        result = await self.execution_chain.ainvoke({
            "step_description": step_description,
            "step_input": step_input
        })
        return result


class PlanningAgent:
    """规划智能体：整合规划器和执行器"""
    
    def __init__(
        self,
        llm: ChatOpenAI,
        step_executor: Optional[Callable] = None
    ):
        self.planner = Planner(llm)
        self.executor = PlanExecutor(llm, step_executor)
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行完整的规划流程"""
        # 1. 创建计划
        state = await self.planner.create_plan(state)
        
        # 2. 执行计划
        state = await self.executor.execute_plan(state)
        
        return state
