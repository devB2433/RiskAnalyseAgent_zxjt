# 分析器插件系统

## 概述

插件系统允许你以模块化的方式添加新的安全分析器，无需修改核心代码。

## 架构

```
plugins/
└── analyzers/              # 分析器插件目录
    ├── compromised_host.py # 失陷主机检测插件
    ├── anomalous_login.py  # 异常登录检测插件
    └── your_plugin.py      # 你的自定义插件
```

## 快速开始

### 1. 创建插件

创建一个新的Python文件在 `plugins/analyzers/` 目录：

```python
# plugins/analyzers/my_analyzer.py

from src.core.base import AgentState
from src.plugins import AnalyzerPlugin

class MyAnalyzerPlugin(AnalyzerPlugin):
    """我的自定义分析器"""

    # 插件元数据
    plugin_name = "my_analyzer"
    plugin_version = "1.0.0"
    plugin_description = "我的自定义安全分析器"
    plugin_author = "Your Name"

    async def analyze(self, state: AgentState) -> AgentState:
        """执行分析逻辑"""
        logs = state.get("logs", [])

        # 你的分析逻辑
        # ...

        # 返回包含分析结果的状态
        state["analysis_result"] = your_result
        return state
```

### 2. 使用插件管理器

```python
from src.plugins import PluginManager
from src.agent_framework import UniversalAgentFramework

# 创建插件管理器
plugin_manager = PluginManager(plugin_dirs=["plugins/analyzers"])

# 发现所有插件
discovered = plugin_manager.discover_plugins()
print(f"发现 {len(discovered)} 个插件")

# 加载所有插件
framework = UniversalAgentFramework()
threat_intel = ThreatIntelToolkit(use_mock=True)
plugin_manager.load_all_plugins(framework, threat_intel)

# 运行分析
state = AgentState()
state["logs"] = your_logs
result = await plugin_manager.run_analysis("my_analyzer", state)
```

### 3. 配置启用的插件

在 `config/default.yaml` 中配置：

```yaml
analysis:
  enabled_analyzers:
    - compromised_host
    - anomalous_login
    - my_analyzer  # 你的插件
```

然后只加载启用的插件：

```python
from src.config import get_settings

settings = get_settings()
plugin_manager.load_all_plugins(
    framework,
    threat_intel,
    enabled_only=settings.analysis.enabled_analyzers
)
```

## 插件接口

### AnalyzerPlugin 基类

所有插件必须继承 `AnalyzerPlugin` 并实现 `analyze()` 方法。

#### 必需属性

- `plugin_name`: 插件唯一标识符
- `plugin_version`: 版本号
- `plugin_description`: 插件描述
- `plugin_author`: 作者信息

#### 必需方法

```python
async def analyze(self, state: AgentState) -> AgentState:
    """
    执行分析

    Args:
        state: 包含日志数据的状态
            - state["logs"]: 日志列表
            - state["trace"]: 执行跟踪（可选）

    Returns:
        包含分析结果的状态
            - state["analysis_result"]: AnalysisResult对象
    """
    pass
```

#### 可用资源

- `self.framework`: UniversalAgentFramework实例
- `self.threat_intel`: ThreatIntelToolkit实例（可选）
- `self.enabled`: 插件是否启用

## 插件管理器API

### 发现插件

```python
discovered = plugin_manager.discover_plugins()
# 返回: ['compromised_host', 'anomalous_login', ...]
```

### 加载插件

```python
# 加载单个插件
plugin = plugin_manager.load_plugin("my_analyzer", framework, threat_intel)

# 加载所有插件
all_plugins = plugin_manager.load_all_plugins(framework, threat_intel)

# 只加载指定插件
enabled_plugins = plugin_manager.load_all_plugins(
    framework,
    threat_intel,
    enabled_only=["compromised_host", "anomalous_login"]
)
```

### 运行分析

```python
# 运行单个插件
result = await plugin_manager.run_analysis("my_analyzer", state)

# 运行所有插件（串行）
results = await plugin_manager.run_all_analyses(state, parallel=False)

# 运行所有插件（并行）
results = await plugin_manager.run_all_analyses(state, parallel=True)
```

### 控制插件

```python
# 启用/禁用插件
plugin_manager.enable_plugin("my_analyzer")
plugin_manager.disable_plugin("my_analyzer")

# 列出所有插件
plugins = plugin_manager.list_plugins()
for plugin in plugins:
    print(f"{plugin['name']} v{plugin['version']} - {plugin['enabled']}")
```

## 最佳实践

### 1. 使用威胁情报验证

```python
async def analyze(self, state: AgentState) -> AgentState:
    # 提取IOC
    suspicious_ips = self._extract_ips(analysis_text)

    # 威胁情报验证
    if self.threat_intel:
        for ip in suspicious_ips[:10]:  # 限制查询数量
            intel = await self.threat_intel.query_ip(ip)
            if intel.get("is_malicious"):
                # 处理恶意IOC
                pass
```

### 2. 添加执行跟踪

```python
trace = state.setdefault("trace", [])
trace.append({
    "type": "plugin_start",
    "plugin": self.plugin_name,
    "timestamp": datetime.now().isoformat(),
})
```

### 3. 错误处理

```python
try:
    result = await self.threat_intel.query_ip(ip)
except Exception as e:
    logger.error(f"威胁情报查询失败: {e}")
    # 继续执行，不要让单个查询失败影响整体分析
```

### 4. 资源限制

```python
# 限制处理的日志数量
logs = state.get("logs", [])[:100]

# 限制威胁情报查询数量
for ip in suspicious_ips[:10]:  # 最多查询10个
    pass
```

## 示例

查看 `examples/plugin_system_example.py` 获取完整示例。

运行示例：

```bash
python examples/plugin_system_example.py
```

## 插件开发模板

```python
"""
[插件名称]

[插件描述]
"""
import re
from typing import List
from src.core.base import AgentState
from src.plugins import AnalyzerPlugin
from security_analysis.architecture_v2 import Finding, AnalysisResult


class YourPlugin(AnalyzerPlugin):
    """[插件描述]"""

    plugin_name = "your_plugin"
    plugin_version = "1.0.0"
    plugin_description = "[详细描述]"
    plugin_author = "Your Name"

    async def analyze(self, state: AgentState) -> AgentState:
        """执行分析"""
        logs = state.get("logs", [])
        trace = state.setdefault("trace", [])

        trace.append({
            "type": "plugin_start",
            "plugin": self.plugin_name,
            "log_count": len(logs),
        })

        # 1. LLM分析
        chain = self.framework.create_chain([
            """[你的分析提示词]

日志数据：{input}""",
        ])

        logs_text = "\n".join(str(l) for l in logs[:50])
        chain_state = AgentState()
        chain_state["input"] = logs_text
        result = await chain.execute(chain_state)
        analysis_text = result.get("output", "")

        # 2. 威胁情报验证
        suspicious_items = self._extract_iocs(analysis_text)
        verified = []
        if self.threat_intel:
            for item in suspicious_items[:10]:
                try:
                    intel = await self.threat_intel.query_ip(item)
                    verified.append(intel)
                except Exception:
                    pass

        # 3. 生成结果
        malicious = [v for v in verified if v.get("is_malicious")]
        confidence = self._calculate_confidence(suspicious_items, malicious)

        findings = []
        for v in malicious:
            findings.append(Finding(
                type="your_finding_type",
                severity="high",
                description=f"[描述]",
                evidence=[f"[证据]"],
                confidence=v.get("threat_score", 0) / 100,
            ))

        state["analysis_result"] = AnalysisResult(
            analysis_type=self.plugin_name,
            findings=findings,
            confidence=confidence,
            evidence=[f"[证据摘要]"],
            recommendations=["[建议1]", "[建议2]"],
            trace=trace,
        )

        return state

    def _extract_iocs(self, text: str) -> List[str]:
        """提取IOC"""
        # 你的提取逻辑
        pass

    def _calculate_confidence(self, total, malicious) -> float:
        """计算置信度"""
        if not total:
            return 0.1
        return min(0.5 + len(malicious) * 0.15, 1.0)
```

## 故障排查

### 插件未被发现

- 确保插件文件在 `plugins/analyzers/` 目录
- 确保文件名不以下划线开头
- 确保类继承自 `AnalyzerPlugin`
- 确保设置了 `plugin_name` 属性

### 插件加载失败

- 检查导入语句是否正确
- 确保所有依赖都已安装
- 查看日志中的错误信息

### 插件执行失败

- 检查 `analyze()` 方法的实现
- 确保返回的是 `AgentState` 对象
- 添加适当的错误处理
