# 威胁情报集成系统文档

## 概述

本文档介绍Agent开发框架中的威胁情报集成系统，该系统提供了统一的接口来查询多个威胁情报源，支持IP、域名、URL和文件哈希的威胁情报查询。

## 系统架构

```
┌─────────────────────────────────────────────────────────┐
│           Security Analysis System V2                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │         ThreatIntelToolkit                        │  │
│  │  ┌─────────────────────────────────────────────┐ │  │
│  │  │      ThreatIntelManager                     │ │  │
│  │  │  ┌────────────┐  ┌────────────┐            │ │  │
│  │  │  │ VirusTotal │  │ AbuseIPDB  │  ...       │ │  │
│  │  │  │  Provider  │  │  Provider  │            │ │  │
│  │  │  └────────────┘  └────────────┘            │ │  │
│  │  │         │              │                    │ │  │
│  │  │         └──────┬───────┘                    │ │  │
│  │  │                │                            │ │  │
│  │  │         ┌──────▼───────┐                    │ │  │
│  │  │         │ ThreatIntel  │                    │ │  │
│  │  │         │    Cache     │                    │ │  │
│  │  │         └──────────────┘                    │ │  │
│  │  └─────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │         Security Analyzers                        │  │
│  │  ┌──────────────┐  ┌──────────────┐              │  │
│  │  │ Compromised  │  │   Malware    │  ...         │  │
│  │  │    Host      │  │  Detection   │              │  │
│  │  └──────────────┘  └──────────────┘              │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. ThreatIntelProvider (基类)

所有威胁情报提供商的基类，定义了统一的查询接口。

**位置**: `src/threat_intel/base.py`

**主要方法**:
- `query_ip(ip: str)` - 查询IP地址
- `query_domain(domain: str)` - 查询域名
- `query_url(url: str)` - 查询URL
- `query_file_hash(file_hash: str)` - 查询文件哈希

### 2. 威胁情报提供商

#### VirusTotalProvider

集成VirusTotal API，提供全面的威胁情报查询。

**支持的IOC类型**:
- IP地址
- 域名
- URL
- 文件哈希 (MD5, SHA1, SHA256)

**配置示例**:
```python
from src.threat_intel.base import ThreatIntelConfig
from src.threat_intel.providers import VirusTotalProvider

config = ThreatIntelConfig(
    provider_name="virustotal",
    api_key="your_api_key_here",
    use_mock=False  # 设置为True使用模拟模式
)

provider = VirusTotalProvider(config)
```

#### AbuseIPDBProvider

集成AbuseIPDB API，专注于IP地址信誉查询。

**支持的IOC类型**:
- IP地址

**配置示例**:
```python
from src.threat_intel.base import ThreatIntelConfig
from src.threat_intel.providers import AbuseIPDBProvider

config = ThreatIntelConfig(
    provider_name="abuseipdb",
    api_key="your_api_key_here",
    use_mock=False
)

provider = AbuseIPDBProvider(config)
```

### 3. ThreatIntelManager

统一管理多个威胁情报提供商，提供结果聚合和缓存功能。

**位置**: `src/threat_intel/manager.py`

**主要功能**:
- 多提供商查询
- 结果聚合（投票机制）
- 自动缓存
- 批量查询

**使用示例**:
```python
from src.threat_intel.manager import ThreatIntelManager
from src.threat_intel.base import IOCType

# 初始化管理器
manager = ThreatIntelManager([vt_provider, abuse_provider])

# 查询单个IOC
result = await manager.query(IOCType.IP, "1.2.3.4")

# 批量查询
ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
results = await manager.batch_query(IOCType.IP, ips)

# 获取缓存统计
stats = manager.get_cache_stats()
```

### 4. ThreatIntelCache

提供两级缓存机制（内存+文件），减少API调用成本。

**位置**: `src/threat_intel/cache.py`

**缓存策略**:
- 内存缓存：快速访问，进程生命周期内有效
- 文件缓存：持久化存储，跨进程共享
- TTL机制：默认24小时过期

**缓存位置**: `.cache/threat_intel/`

### 5. ThreatIntelToolkit

为安全分析器提供的高级封装，简化威胁情报查询。

**位置**: `security_analysis/architecture_v2.py`

**主要方法**:
- `query_ip(ip: str)` - 查询IP
- `query_domain(domain: str)` - 查询域名
- `query_url(url: str)` - 查询URL
- `query_file_hash(file_hash: str)` - 查询文件哈希
- `batch_query_ips(ips: List[str])` - 批量查询IP

## 使用模式

### 模式1：模拟模式（开发/测试）

无需API密钥，使用模拟数据进行开发和测试。

```python
from security_analysis.architecture_v2 import SecurityAnalysisSystem

# 初始化系统（模拟模式）
system = SecurityAnalysisSystem(use_mock=True)

# 执行分析
result = await system.analyze(
    AnalysisType.COMPROMISED_HOST.value,
    logs
)
```

**优点**:
- 无需API密钥
- 快速响应
- 适合开发和单元测试
- 无API调用成本

**缺点**:
- 数据不真实
- 无法验证真实威胁

### 模式2：真实API模式（生产环境）

使用真实的威胁情报API进行查询。

```python
# 配置API密钥
api_keys = {
    "virustotal": "your_virustotal_api_key",
    "abuseipdb": "your_abuseipdb_api_key"
}

# 初始化系统（真实API模式）
system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)

# 执行分析
result = await system.analyze(
    AnalysisType.MALWARE_DETECTION.value,
    logs
)
```

**优点**:
- 真实威胁情报
- 准确的威胁评分
- 最新的IOC数据

**注意事项**:
- 需要有效的API密钥
- 有API调用限制
- 产生API调用成本
- 建议启用缓存

### 模式3：混合模式

部分提供商使用真实API，部分使用模拟。

```python
# 只配置部分API密钥
api_keys = {
    "virustotal": "your_api_key",
    # abuseipdb 未配置，将使用模拟模式
}

system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)
```

## API密钥获取

### VirusTotal

1. 访问 https://www.virustotal.com/
2. 注册账号
3. 进入 Profile → API Key
4. 复制API密钥

**免费版限制**:
- 每分钟4次请求
- 每天500次请求

### AbuseIPDB

1. 访问 https://www.abuseipdb.com/
2. 注册账号
3. 进入 Account → API
4. 生成API密钥

**免费版限制**:
- 每天1000次请求

## 配置建议

### 开发环境

```python
# 使用模拟模式
system = SecurityAnalysisSystem(use_mock=True)
```

### 测试环境

```python
# 使用真实API但限制查询数量
system = SecurityAnalysisSystem(
    use_mock=False,
    api_keys=api_keys
)

# 在分析器中限制IOC查询数量
# 例如：只查询前3个可疑IP
for ip in suspicious_ips[:3]:
    result = await threat_intel.query_ip(ip)
```

### 生产环境

```python
# 使用真实API + 缓存
system = SecurityAnalysisSystem(
    use_mock=False,
    api_keys={
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY")
    }
)

# 定期清理过期缓存
await system.clear_cache()
```

## 缓存管理

### 查看缓存统计

```python
stats = system.get_cache_stats()
print(f"缓存命中率: {stats.get('hit_rate', 0):.2%}")
print(f"缓存大小: {stats.get('size', 0)}")
```

### 清除缓存

```python
# 清除所有缓存
await system.clear_cache()

# 或直接操作缓存
from src.threat_intel.cache import ThreatIntelCache

cache = ThreatIntelCache()
await cache.clear()
```

### 缓存配置

修改 `src/threat_intel/cache.py` 中的配置：

```python
class ThreatIntelCache:
    def __init__(
        self,
        cache_dir: str = ".cache/threat_intel",
        ttl: int = 86400,  # 24小时
        max_memory_size: int = 1000  # 内存缓存最大条目数
    ):
        ...
```

## 性能优化

### 1. 批量查询

使用批量查询接口减少API调用次数：

```python
# 不推荐：逐个查询
for ip in ip_list:
    result = await threat_intel.query_ip(ip)

# 推荐：批量查询
results = await threat_intel.batch_query_ips(ip_list)
```

### 2. 限制查询数量

在分析器中限制IOC查询数量：

```python
# 只查询前5个可疑IP
for ip in suspicious_ips[:5]:
    result = await threat_intel.query_ip(ip)
```

### 3. 启用缓存

确保缓存已启用（默认启用）：

```python
# 缓存会自动工作，无需额外配置
# 相同的IOC查询会直接从缓存返回
```

### 4. 异步并发

利用异步特性并发查询：

```python
# 并发查询多个IOC
tasks = [
    threat_intel.query_ip(ip)
    for ip in ip_list
]
results = await asyncio.gather(*tasks)
```

## 错误处理

### API错误

```python
try:
    result = await threat_intel.query_ip(ip)
except Exception as e:
    print(f"查询失败: {e}")
    # 降级处理：使用模拟数据或跳过
```

### 速率限制

```python
from src.threat_intel.base import RateLimitError

try:
    result = await threat_intel.query_ip(ip)
except RateLimitError:
    print("API速率限制，等待后重试")
    await asyncio.sleep(60)
    result = await threat_intel.query_ip(ip)
```

### 网络超时

```python
# 在provider配置中设置超时
config = ThreatIntelConfig(
    provider_name="virustotal",
    api_key="your_key",
    timeout=30  # 30秒超时
)
```

## 扩展新的提供商

### 步骤1：创建Provider类

```python
from src.threat_intel.base import ThreatIntelProvider, ThreatIntelResult, IOCType

class MyThreatIntelProvider(ThreatIntelProvider):
    def __init__(self, config: ThreatIntelConfig):
        super().__init__(config)
        self.api_url = "https://api.example.com"

    async def query_ip(self, ip: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_ip_result(ip)

        # 实现真实API调用
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.api_url}/ip/{ip}",
                headers={"Authorization": f"Bearer {self.api_key}"}
            ) as response:
                data = await response.json()
                return self._parse_response(ip, data)

    def _parse_response(self, ip: str, data: Dict) -> ThreatIntelResult:
        return ThreatIntelResult(
            ioc_type=IOCType.IP,
            ioc_value=ip,
            is_malicious=data.get("malicious", False),
            threat_score=data.get("score", 0.0),
            threat_types=data.get("types", []),
            provider="my_provider",
            details=data
        )
```

### 步骤2：注册到Manager

```python
# 创建provider实例
my_config = ThreatIntelConfig(
    provider_name="my_provider",
    api_key="your_key"
)
my_provider = MyThreatIntelProvider(my_config)

# 添加到manager
manager = ThreatIntelManager([
    vt_provider,
    abuse_provider,
    my_provider  # 新增的provider
])
```

## 最佳实践

### 1. 环境变量管理API密钥

```python
import os

api_keys = {
    "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY")
}

system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)
```

### 2. 分层降级策略

```python
# 优先使用真实API，失败时降级到模拟
try:
    system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)
except Exception:
    print("真实API初始化失败，降级到模拟模式")
    system = SecurityAnalysisSystem(use_mock=True)
```

### 3. 监控API使用情况

```python
# 定期检查缓存统计
stats = system.get_cache_stats()
if stats.get("hit_rate", 0) < 0.5:
    print("警告：缓存命中率低，可能产生大量API调用")
```

### 4. 合理设置查询限制

```python
# 根据API限制调整查询数量
MAX_QUERIES_PER_ANALYSIS = 10

for ip in suspicious_ips[:MAX_QUERIES_PER_ANALYSIS]:
    result = await threat_intel.query_ip(ip)
```

## 故障排查

### 问题1：API密钥无效

**症状**: 查询返回401错误

**解决方案**:
1. 检查API密钥是否正确
2. 确认API密钥未过期
3. 验证API密钥权限

### 问题2：速率限制

**症状**: 查询返回429错误

**解决方案**:
1. 启用缓存减少重复查询
2. 限制每次分析的查询数量
3. 实现指数退避重试机制
4. 考虑升级API套餐

### 问题3：缓存未生效

**症状**: 相同查询仍然调用API

**解决方案**:
1. 检查缓存目录权限
2. 确认TTL未过期
3. 查看缓存统计信息

### 问题4：查询超时

**症状**: 查询长时间无响应

**解决方案**:
1. 增加超时时间
2. 检查网络连接
3. 使用异步并发查询

## 示例代码

完整示例请参考：
- `examples/threat_intel_examples.py` - 威胁情报系统基础示例
- `examples/security_analysis_v2_example.py` - 集成到安全分析系统的示例

## 相关文档

- [威胁情报提供商API文档](./THREAT_INTEL_PROVIDERS.md)
- [安全分析器开发指南](./SECURITY_ANALYZERS.md)
- [缓存系统详解](./CACHE_SYSTEM.md)

## 更新日志

### v2.0.0 (2024-12-31)
- 集成真实威胁情报API
- 支持VirusTotal和AbuseIPDB
- 实现两级缓存机制
- 添加批量查询功能
- 支持模拟/真实模式切换

### v1.0.0 (2024-12-01)
- 初始版本
- 仅支持模拟模式
