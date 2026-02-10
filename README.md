# Agent开发框架

一个基于LangChain的通用智能体开发框架，支持多种Agent设计模式和完整的数据接入能力。

## 🎯 特性

### 核心框架
- ✅ **7种Agent设计模式**: 提示链、路由、并行化、反思、工具使用、规划、多智能体
- ✅ **统一的框架接口**: 简单易用的API设计
- ✅ **模型切换支持**: 支持智谱GLM和OpenAI模型
- ✅ **异步执行**: 全面支持异步操作

### 模型路由层 🆕
- ✅ **三种路由策略**: 规则路由、智能路由、配置路由
- ✅ **多模型支持**: OpenAI、Anthropic、智谱AI等
- ✅ **自动选择**: 根据任务特征自动选择最优模型
- ✅ **成本优化**: 在质量和成本间智能平衡

### 数据接入层
- ✅ **多数据源支持**: 文件、数据库、API、流数据
- ✅ **多格式解析**: JSON、CSV、XML、Excel、日志
- ✅ **灵活的转换器**: 支持自定义数据转换
- ✅ **流式处理**: 支持大数据流式接入

### 应用示例
- ✅ **安全分析系统**: 完整的网络安全日志分析应用
- ✅ **失陷主机检测**: 基于多模式的威胁检测
- ✅ **异常登录分析**: 行为基线和异常识别

## 📦 安装

```bash
# 克隆项目
git clone <repository-url>
cd AgentsTest

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件，添加API密钥
```

## 🚀 快速开始

### 1. 基础使用

```python
from src.agent_framework_v2 import UniversalAgentFramework
from src.core.base import AgentState

# 创建框架实例（启用模型路由）
framework = UniversalAgentFramework(
    enable_model_routing=True,
    default_routing_strategy="intelligent"
)

# 创建提示链（自动选择最优模型）
chain = framework.create_chain([
    "分析以下文本：{input}",
    "总结上述分析：{input}"
])

# 执行
state = AgentState()
state["input"] = "这是一段需要分析的文本"
result = await framework.execute(chain, state)
```

### 2. 模型路由

```python
from src.model_routing import ModelRouter, TaskComplexity

# 创建路由器
router = ModelRouter(default_strategy="rule_based")

# 自动路由到最优模型
decision = await router.route(
    task_type="code_generation",
    complexity=TaskComplexity.COMPLEX
)

print(f"选择模型: {decision.selected_model.name}")

# 为Agent配置专用模型
router.set_agent_model("security_analyzer", "gpt-4o")
router.set_agent_model("log_parser", "glm-4-flash")
```

### 3. 数据接入

```python
from src.data_ingestion import DataIngestionManager, DataFormat

# 创建数据接入管理器
manager = DataIngestionManager()

# 从JSON文件接入
data = await manager.ingest_from_file(
    file_path="data.json",
    format=DataFormat.JSON,
    transformer_name='security_log'
)

# 从API接入
data = await manager.ingest_from_api(
    base_url="https://api.example.com",
    endpoint="/logs",
    auth={"type": "bearer", "token": "your_token"}
)

# 从数据库接入
data = await manager.ingest_from_database(
    connection_string="postgresql://user:pass@localhost/db",
    query={"sql": "SELECT * FROM logs"}
)
```

### 3. 安全分析

```python
from security_analysis.architecture import SecurityAnalysisSystem, AnalysisType

# 创建分析系统
system = SecurityAnalysisSystem()

# 执行分析
result = await system.analyze(
    AnalysisType.COMPROMISED_HOST.value,
    logs  # SecurityLog对象列表
)

print(f"置信度: {result.confidence}")
print(f"发现: {result.findings}")
```

## 📚 文档

### 核心模块

- [Agent框架文档](src/README.md)
- [数据接入层文档](src/data_ingestion/README.md)
- [安全分析系统文档](security_analysis/README.md)

### 设计模式

1. **提示链 (Prompt Chaining)**: 顺序执行多个提示
2. **路由 (Routing)**: 动态选择执行路径
3. **并行化 (Parallelization)**: 并发执行多个任务
4. **反思 (Reflection)**: 自我评估和改进
5. **工具使用 (Tool Use)**: 调用外部工具和API
6. **规划 (Planning)**: 任务分解和执行
7. **多智能体 (Multi-Agent)**: 多个Agent协作

## 🎓 示例

### 运行示例

```bash
# 数据接入示例
python examples/data_ingestion_examples.py

# 集成分析示例
python examples/integrated_analysis_example.py

# 安全分析示例
python security_analysis/example_usage.py
```

### 示例代码

查看 `examples/` 目录获取更多示例：
- `data_ingestion_examples.py`: 数据接入层使用示例
- `integrated_analysis_example.py`: 数据接入与分析集成示例

## 🏗️ 项目结构

```
AgentsTest/
├── src/
│   ├── agent_framework.py      # 主框架
│   ├── core/                   # 核心基础类
│   │   ├── base.py
│   │   └── __init__.py
│   ├── patterns/               # 设计模式实现
│   │   ├── prompt_chaining.py
│   │   ├── routing.py
│   │   ├── parallelization.py
│   │   ├── reflection.py
│   │   ├── tool_use.py
│   │   ├── planning.py
│   │   ├── multi_agent.py
│   │   └── __init__.py
│   └── data_ingestion/         # 数据接入层
│       ├── base.py
│       ├── manager.py
│       ├── connectors/
│       ├── parsers/
│       ├── transformers/
│       └── README.md
├── security_analysis/          # 安全分析应用
│   ├── architecture.py
│   └── example_usage.py
├── examples/                   # 示例代码
│   ├── data_ingestion_examples.py
│   └── integrated_analysis_example.py
├── requirements.txt            # 依赖列表
├── .env                        # 环境配置
└── README.md                   # 本文件
```

## 🔧 配置

### 环境变量

创建 `.env` 文件：

```bash
# 智谱AI API密钥（默认）
ZHIPU_API_KEY=your_zhipu_api_key

# OpenAI API密钥（可选）
OPENAI_API_KEY=your_openai_api_key
```

### 模型切换

```python
# 使用智谱GLM（默认）
framework = UniversalAgentFramework()

# 使用OpenAI
framework = UniversalAgentFramework(
    use_openai=True,
    model="gpt-4o-mini"
)
```

## 📊 支持的数据源

### 文件
- JSON
- CSV
- XML
- Excel (.xlsx, .xls)
- 日志文件 (Syslog, Apache, JSON logs)

### 数据库
- PostgreSQL (需要 `asyncpg`)
- MySQL (需要 `aiomysql`)
- SQLite (需要 `aiosqlite`)
- MongoDB (需要 `motor`)

### API
- REST API
- 支持多种认证方式 (Bearer, Basic)
- 自动分页处理

### 流数据
- WebSocket (需要 `websockets`)
- Kafka (需要 `aiokafka`)
- RabbitMQ

## 🛠️ 开发

### 添加自定义连接器

```python
from src.data_ingestion.base import BaseConnector

class MyConnector(BaseConnector):
    async def connect(self):
        # 实现连接逻辑
        pass

    async def fetch_data(self, query=None, limit=None):
        # 实现数据获取
        pass
```

### 添加自定义Agent

```python
from src.core.base import BaseAgent, AgentConfig

class MyAgent(BaseAgent):
    def __init__(self):
        config = AgentConfig(
            name="my_agent",
            description="My custom agent"
        )
        super().__init__(config)

    async def execute(self, state):
        # 实现Agent逻辑
        return state
```

## 📝 待办事项

- [ ] 添加单元测试
- [ ] 添加更多安全分析器
- [ ] 支持更多数据库类型
- [ ] 添加性能监控
- [ ] 完善错误处理
- [ ] 添加日志系统
- [ ] 支持配置文件
- [ ] 添加Web界面

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

## 📄 许可证

MIT License

## 📧 联系方式

如有问题或建议，请提交Issue。