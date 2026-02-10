"""
并行化模式实现
同时执行多个独立任务
"""
from typing import List, Dict, Callable, Any, Optional
from langchain_core.runnables import RunnableParallel, RunnablePassthrough
from langchain_openai import ChatOpenAI

from ..core.base import AgentState


class ParallelExecutor:
    """并行执行器：同时执行多个任务"""
    
    def __init__(
        self,
        tasks: Dict[str, Callable],
        llm: Optional[ChatOpenAI] = None
    ):
        """
        初始化并行执行器
        
        Args:
            tasks: 任务映射 {task_name: task_function}
            llm: 可选的语言模型（如果任务需要）
        """
        self.tasks = tasks
        self.llm = llm
        self._parallel_chain = self._build_parallel_chain()
    
    def _build_parallel_chain(self) -> RunnableParallel:
        """构建并行执行链"""
        runnables = {}
        
        for task_name, task_func in self.tasks.items():
            if callable(task_func):
                runnables[task_name] = task_func
            else:
                runnables[task_name] = RunnablePassthrough()
        
        return RunnableParallel(runnables)
    
    async def execute(self, state: AgentState) -> AgentState:
        """并行执行所有任务"""
        input_data = state.get("input", state)
        
        # 执行并行任务
        results = await self._parallel_chain.ainvoke(input_data)
        
        # 将结果合并到状态中
        for key, value in results.items():
            state[f"parallel_{key}"] = value
        
        state["parallel_results"] = results
        
        return state


class ParallelTask:
    """并行任务定义"""
    
    def __init__(
        self,
        name: str,
        executor: Callable,
        input_key: Optional[str] = None,
        output_key: Optional[str] = None
    ):
        self.name = name
        self.executor = executor
        self.input_key = input_key
        self.output_key = output_key
