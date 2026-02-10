"""
基础类和接口定义
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum


class AgentState(dict):
    """智能体状态，继承自dict以便在LangGraph中使用"""
    pass


class ExecutionMode(Enum):
    """执行模式"""
    SEQUENTIAL = "sequential"  # 顺序执行
    PARALLEL = "parallel"      # 并行执行
    ROUTING = "routing"        # 路由执行


@dataclass
class AgentConfig:
    """智能体配置"""
    name: str
    description: str
    model: str = "gpt-4o-mini"
    temperature: float = 0.7
    max_iterations: int = 10
    verbose: bool = True
    tools: List[Any] = field(default_factory=list)
    system_prompt: Optional[str] = None


class BaseAgent(ABC):
    """智能体基类"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.name = config.name
        self.description = config.description
        
    @abstractmethod
    async def execute(self, state: AgentState) -> AgentState:
        """执行智能体任务"""
        pass
    
    @abstractmethod
    def get_output_key(self) -> Optional[str]:
        """返回输出在状态中的键名"""
        pass


class BaseTool(ABC):
    """工具基类"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    async def execute(self, **kwargs) -> Any:
        """执行工具"""
        pass
