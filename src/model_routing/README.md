# 模型路由层 (Model Routing Layer)

## 概述

模型路由层为Agent框架提供智能的多模型管理和自动路由能力，支持根据任务特征自动选择最优模型。

## 核心特性

### 🎯 三种路由策略

1. **基于规则的路由** (Rule-Based Routing)
   - 预定义任务类型到模型的映射规则
   - 快速、确定性强
   - 适合已知任务类型

2. **智能路由** (Intelligent Routing)
   - 使用小模型分析任务特征
   - 自动选择最优大模型
   - 适合未知或复杂任务

3. **配置化路由** (Config-Based Routing)
   - 为每个Agent配置专用模型
   - 灵活、可持久化
   - 适合多Agent系统

### 📊 支持的模型

#### OpenAI
- GPT-4o (最强大)
- GPT-4o-mini (性价比高)
- GPT-3.5-turbo (快速便宜)

#### Anthropic Claude
- Claude-3-opus (质量最高)
- Claude-3-sonnet (平衡)
- Claude-3-haiku (快速)

#### 智谱AI
- GLM-4 (强大)
- GLM-4-flash (极速)
- GLM-3-turbo (经济)

## 快速开始

### 基本使用

```python
from src.model_routing import ModelRouter, TaskComplexity

# 创建路由器
router = ModelRouter(default_strategy="rule_based")

# 路由到最优模型
decision = await router.route(
    task_type="code_generation",
    complexity=TaskComplexity.COMPLEX
)

print(f"选择模型: {decision.selected_model.name}")
print(f"原因: {decision.reason}")
```

## 详细使用

### 1. 基于规则的路由

```python
router = ModelRouter(default_strategy="rule_based")

# 使用默认规则
decision = await router.route(
    task_type="simple_qa"  # 自动选择 glm-4-flash
)

# 添加自定义规则
router.add_rule("security_analysis", "gpt-4o")
router.add_rule("translation", "gpt-3.5-turbo")

# 按复杂度路由
decision = await router.route(
    task_type="general",
    complexity=TaskComplexity.VERY_COMPLEX  # 自动选择 claude-3-opus
)
```

#### 默认规则

| 任务类型 | 模型 | 原因 |
|---------|------|------|
| simple_qa | glm-4-flash | 快速便宜 |
| translation | gpt-3.5-turbo | 翻译能力强 |
| code_generation | claude-3-sonnet | 代码能力优秀 |
| complex_reasoning | gpt-4o | 推理能力强 |
| analysis | claude-3-opus | 分析质量最高 |

### 2. 智能路由

```python
router = ModelRouter(default_strategy="intelligent")

# AI自动分析任务并选择模型
decision = await router.route(
    task_type="unknown_task",
    task_description="分析这段代码的安全漏洞，并提供修复建议",
    complexity=TaskComplexity.VERY_COMPLEX,
    required_capabilities=[
        ModelCapability.CODE_GENERATION,
        ModelCapability.REASONING
    ],
    strategy="intelligent"
)

print(f"AI选择: {decision.selected_model.name}")
print(f"原因: {decision.reason}")
print(f"置信度: {decision.confidence}")
```

#### 智能路由考虑因素

1. **任务复杂度**: 简单任务用快速模型，复杂任务用高质量模型
2. **任务类型**: 代码生成、推理、分析等需要不同能力
3. **成本效益**: 在满足质量要求下优先性价比
4. **速度要求**: 优先速度时选择快速模型

### 3. 配置化路由

```python
router = ModelRouter(default_strategy="config_based")

# 为不同Agent配置不同模型
router.set_agent_model("compromised_host_analyzer", "gpt-4o")
router.set_agent_model("anomalous_login_analyzer", "claude-3-sonnet")
router.set_agent_model("simple_classifier", "glm-4-flash")

# 路由时指定Agent名称
decision = await router.route(
    task_type="analysis",
    agent_name="compromised_host_analyzer",
    strategy="config_based"
)

# 保存配置
router.save_agent_config("agent_models.json")

# 加载配置
router.load_agent_config("agent_models.json")
```

#### 配置文件格式

```json
{
  "compromised_host_analyzer": "gpt-4o",
  "anomalous_login_analyzer": "claude-3-sonnet",
  "simple_classifier": "glm-4-flash"
}
```

### 4. 混合使用策略

```python
router = ModelRouter()

# 场景1：已知Agent，使用配置路由
router.set_agent_model("security_analyzer", "gpt-4o")
decision = await router.route(
    task_type="security_analysis",
    agent_name="security_analyzer",
    strategy="config_based"
)

# 场景2：已知任务类型，使用规则路由
router.add_rule("translation", "gpt-3.5-turbo")
decision = await router.route(
    task_type="translation",
    strategy="rule_based"
)

# 场景3：未知任务，使用智能路由
decision = await router.route(
    task_type="unknown_task",
    task_description="复杂的推理任务",
    strategy="intelligent"
)
```

### 5. 带回退的路由

```python
# 尝试多个策略，直到成功
decision = await router.route_with_fallback(
    task_type="my_task",
    strategies=["config_based", "rule_based", "intelligent"],
    agent_name="my_agent"
)
```

### 6. 直接创建LLM

```python
# 为任务创建LLM实例
llm = await router.create_llm_for_task(
    task_type="code_generation",
    complexity=TaskComplexity.COMPLEX,
    temperature=0.3
)

# 使用LLM
from langchain_core.messages import HumanMessage
response = await llm.ainvoke([
    HumanMessage(content="写一个快速排序算法")
])
```

## 与Agent框架集成

### 启用模型路由

```python
from src.agent_framework_v2 import UniversalAgentFramework

# 创建启用路由的框架
framework = UniversalAgentFramework(
    enable_model_routing=True,
    default_routing_strategy="intelligent"
)

# 添加路由规则
framework.add_routing_rule("security_analysis", "gpt-4o")

# 为Agent配置模型
framework.set_agent_model("compromised_host_analyzer", "claude-3-opus")

# 创建组件时会自动使用路由
chain = framework.create_chain(
    steps=["分析: {input}", "总结: {input}"],
    task_type="analysis",
    complexity=TaskComplexity.COMPLEX
)
```

### 传统模式（固定模型）

```python
# 不启用路由，使用固定模型
framework = UniversalAgentFramework(
    model="gpt-4o-mini",
    enable_model_routing=False
)
```

## 高级功能

### 1. 成本和质量控制

```python
decision = await router.route(
    task_type="analysis",
    max_cost=0.01,        # 最多 $0.01/1k tokens
    min_quality=8.0,      # 最低质量 8/10
    prefer_speed=True     # 优先速度
)
```

### 2. 能力要求

```python
from src.model_routing import ModelCapability

decision = await router.route(
    task_type="complex_task",
    required_capabilities=[
        ModelCapability.CODE_GENERATION,
        ModelCapability.REASONING,
        ModelCapability.TOOL_USE
    ]
)
```

### 3. 模型统计

```python
stats = router.get_model_stats()

print(f"总模型数: {stats['total_models']}")
print(f"成本范围: ${stats['cost_range']['min']} - ${stats['cost_range']['max']}")
print(f"质量范围: {stats['quality_range']['min']} - {stats['quality_range']['max']}")
```

### 4. 自定义模型

```python
from src.model_routing import ModelConfig, ModelProvider, ModelCapability

# 注册自定义模型
custom_model = ModelConfig(
    name="my-custom-model",
    provider=ModelProvider.LOCAL,
    model_id="custom-model-v1",
    capabilities=[ModelCapability.TEXT_GENERATION],
    cost_per_1k_tokens=0.0,
    speed_score=9.0,
    quality_score=7.0
)

router.registry.register(custom_model)
```

## 最佳实践

### 1. 选择合适的策略

- **规则路由**: 任务类型明确、需要快速决策
- **智能路由**: 任务类型不确定、需要最优选择
- **配置路由**: 多Agent系统、需要精细控制

### 2. 成本优化

```python
# 简单任务用便宜模型
router.add_rule("simple_qa", "glm-4-flash")

# 复杂任务才用贵模型
router.add_rule("complex_reasoning", "gpt-4o")

# 设置成本上限
decision = await router.route(
    task_type="general",
    max_cost=0.005  # 限制成本
)
```

### 3. 质量保证

```python
# 关键任务设置最低质量
decision = await router.route(
    task_type="critical_analysis",
    min_quality=9.0  # 只选择高质量模型
)
```

### 4. 速度优化

```python
# 实时应用优先速度
decision = await router.route(
    task_type="realtime_task",
    prefer_speed=True
)
```

## 配置示例

### agent_models.json

```json
{
  "compromised_host_analyzer": "gpt-4o",
  "anomalous_login_analyzer": "claude-3-sonnet",
  "data_exfiltration_analyzer": "gpt-4o",
  "malware_detector": "claude-3-opus",
  "simple_classifier": "glm-4-flash",
  "log_parser": "gpt-3.5-turbo"
}
```

## 性能对比

| 模型 | 质量 | 速度 | 成本 | 适用场景 |
|------|------|------|------|----------|
| claude-3-opus | 10/10 | 6/10 | $0.075 | 极复杂任务 |
| gpt-4o | 9.5/10 | 7/10 | $0.03 | 复杂任务 |
| claude-3-sonnet | 9/10 | 8/10 | $0.015 | 平衡任务 |
| gpt-4o-mini | 8/10 | 9/10 | $0.0015 | 中等任务 |
| glm-4 | 8.5/10 | 7.5/10 | $0.01 | 通用任务 |
| glm-4-flash | 7/10 | 10/10 | $0.0001 | 简单任务 |
| gpt-3.5-turbo | 7/10 | 9.5/10 | $0.001 | 简单任务 |

## 故障排除

### 常见问题

1. **API密钥未配置**
   ```bash
   # 设置环境变量
   export OPENAI_API_KEY=your_key
   export ANTHROPIC_API_KEY=your_key
   export ZHIPU_API_KEY=your_key
   ```

2. **没有可用模型**
   - 检查是否设置了过严的过滤条件
   - 确认模型注册表中有可用模型

3. **智能路由失败**
   - 确保分析器模型可用
   - 检查任务描述是否清晰

## 示例代码

完整示例请参考: `examples/model_routing_examples.py`

```bash
python examples/model_routing_examples.py
```