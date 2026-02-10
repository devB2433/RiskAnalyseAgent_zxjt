"""
多智能体协作模式实现
多个智能体协同完成复杂任务
"""
from typing import List, Dict, Optional, Callable
from enum import Enum
from langchain_openai import ChatOpenAI

from ..core.base import BaseAgent, AgentState, ExecutionMode


class CollaborationMode(Enum):
    """协作模式"""
    SEQUENTIAL = "sequential"      # 顺序协作
    PARALLEL = "parallel"          # 并行协作
    HIERARCHICAL = "hierarchical"  # 层级协作
    DEBATE = "debate"              # 辩论协作


class MultiAgentSystem:
    """多智能体系统"""
    
    def __init__(
        self,
        agents: List[BaseAgent],
        mode: CollaborationMode = CollaborationMode.SEQUENTIAL,
        coordinator: Optional[BaseAgent] = None
    ):
        """
        初始化多智能体系统
        
        Args:
            agents: 智能体列表
            mode: 协作模式
            coordinator: 协调者智能体（用于层级模式）
        """
        self.agents = agents
        self.mode = mode
        self.coordinator = coordinator
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行多智能体协作"""
        if self.mode == CollaborationMode.SEQUENTIAL:
            return await self._execute_sequential(state)
        elif self.mode == CollaborationMode.PARALLEL:
            return await self._execute_parallel(state)
        elif self.mode == CollaborationMode.HIERARCHICAL:
            return await self._execute_hierarchical(state)
        elif self.mode == CollaborationMode.DEBATE:
            return await self._execute_debate(state)
        else:
            return await self._execute_sequential(state)
    
    async def _execute_sequential(self, state: AgentState) -> AgentState:
        """顺序执行：一个接一个"""
        current_state = state.copy()
        
        for agent in self.agents:
            current_state = await agent.execute(current_state)
            # 将前一个智能体的输出作为下一个的输入
            if "output" in current_state:
                current_state["input"] = current_state["output"]
        
        return current_state
    
    async def _execute_parallel(self, state: AgentState) -> AgentState:
        """并行执行：同时运行所有智能体"""
        import asyncio
        
        tasks = [agent.execute(state.copy()) for agent in self.agents]
        results = await asyncio.gather(*tasks)
        
        # 合并所有结果
        merged_state = state.copy()
        for i, result in enumerate(results):
            agent_name = self.agents[i].name
            merged_state[f"agent_{agent_name}_output"] = result.get("output", "")
        
        # 如果有合成器，使用它合并结果
        merged_state["parallel_outputs"] = [
            r.get("output", "") for r in results
        ]
        
        return merged_state
    
    async def _execute_hierarchical(self, state: AgentState) -> AgentState:
        """层级执行：协调者分配任务"""
        if not self.coordinator:
            # 如果没有协调者，回退到顺序模式
            return await self._execute_sequential(state)
        
        # 协调者决定任务分配
        coordinator_state = await self.coordinator.execute(state)
        
        # 根据协调者的决策执行子任务
        task_assignments = coordinator_state.get("task_assignments", {})
        
        results = {}
        for agent_name, task in task_assignments.items():
            agent = next((a for a in self.agents if a.name == agent_name), None)
            if agent:
                task_state = state.copy()
                task_state["input"] = task
                result = await agent.execute(task_state)
                results[agent_name] = result.get("output", "")
        
        # 协调者合成最终结果
        final_state = state.copy()
        final_state["sub_results"] = results
        final_state = await self.coordinator.execute(final_state)
        
        return final_state
    
    async def _execute_debate(self, state: AgentState) -> AgentState:
        """辩论执行：多个智能体讨论并达成共识"""
        # 第一轮：每个智能体提出观点
        initial_state = state.copy()
        viewpoints = []
        
        for agent in self.agents:
            agent_state = initial_state.copy()
            agent_state["input"] = f"请提出你对以下问题的观点：{initial_state.get('input', '')}"
            result = await agent.execute(agent_state)
            viewpoints.append({
                "agent": agent.name,
                "viewpoint": result.get("output", "")
            })
        
        # 第二轮：每个智能体评估其他观点
        debate_state = state.copy()
        debate_state["viewpoints"] = viewpoints
        
        evaluations = []
        for agent in self.agents:
            agent_state = debate_state.copy()
            agent_state["input"] = f"请评估以下观点并给出你的最终判断：{viewpoints}"
            result = await agent.execute(agent_state)
            evaluations.append({
                "agent": agent.name,
                "evaluation": result.get("output", "")
            })
        
        # 合成最终共识
        final_state = state.copy()
        final_state["viewpoints"] = viewpoints
        final_state["evaluations"] = evaluations
        final_state["consensus"] = self._synthesize_consensus(viewpoints, evaluations)
        
        return final_state
    
    def _synthesize_consensus(
        self,
        viewpoints: List[Dict],
        evaluations: List[Dict]
    ) -> str:
        """合成共识（简单实现：返回多数观点）"""
        # 这里可以实现更复杂的共识算法
        return viewpoints[0]["viewpoint"] if viewpoints else ""


class AgentTeam:
    """智能体团队：预定义的专家团队"""
    
    def __init__(
        self,
        name: str,
        agents: List[BaseAgent],
        collaboration_mode: CollaborationMode = CollaborationMode.SEQUENTIAL
    ):
        self.name = name
        self.system = MultiAgentSystem(agents, collaboration_mode)
    
    async def execute(self, state: AgentState) -> AgentState:
        """执行团队任务"""
        return await self.system.execute(state)
