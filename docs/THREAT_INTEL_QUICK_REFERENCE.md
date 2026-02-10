# 威胁情报集成快速参考

## 快速开始

### 1. 模拟模式（无需API密钥）

```python
from security_analysis.architecture_v2 import SecurityAnalysisSystem, AnalysisType

# 初始化
system = SecurityAnalysisSystem(use_mock=True)

# 执行分析
result = await system.analyze(AnalysisType.COMPROMISED_HOST.value, logs)
```

### 2. 真实API模式

```python
# 配置API密钥
api_keys = {
    "virustotal": "your_virustotal_api_key",
    "abuseipdb": "your_abuseipdb_api_key"
}

# 初始化
system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)

# 执行分析
result = await system.analyze(AnalysisType.MALWARE_DETECTION.value, logs)
```

## 常用操作

### 查询单个IOC

```python
from src.threat_intel.manager import ThreatIntelManager
from src.threat_intel.base import IOCType

# 查询IP
result = await manager.query(IOCType.IP, "1.2.3.4")

# 查询域名
result = await manager.query(IOCType.DOMAIN, "example.com")

# 查询URL
result = await manager.query(IOCType.URL, "https://example.com/malware")

# 查询文件哈希
result = await manager.query(IOCType.FILE_HASH, "abc123...")
```

### 批量查询

```python
# 批量查询IP
ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
results = await manager.batch_query(IOCType.IP, ips)
```

### 缓存管理

```python
# 获取缓存统计
stats = system.get_cache_stats()

# 清除缓存
await system.clear_cache()
```

## 支持的分析类型

| 分析类型 | 枚举值 | 使用的威胁情报 |
|---------|--------|---------------|
| 失陷主机检测 | `COMPROMISED_HOST` | IP地址 |
| 恶意软件检测 | `MALWARE_DETECTION` | 文件哈希 |
| 钓鱼攻击检测 | `PHISHING_DETECTION` | 域名、URL |
| 数据外泄检测 | `DATA_EXFILTRATION` | IP地址 |
| 异常登录检测 | `ANOMALOUS_LOGIN` | IP地址 |
| 内部威胁检测 | `INSIDER_THREAT` | - |
| DDoS检测 | `DDOS_DETECTION` | IP地址 |
| 横向移动检测 | `LATERAL_MOVEMENT` | IP地址 |

## 威胁情报提供商

### VirusTotal

**支持的IOC类型**: IP、域名、URL、文件哈希

**API限制**:
- 免费版：4次/分钟，500次/天
- 需要API密钥

**获取API密钥**: https://www.virustotal.com/

### AbuseIPDB

**支持的IOC类型**: IP地址

**API限制**:
- 免费版：1000次/天
- 需要API密钥

**获取API密钥**: https://www.abuseipdb.com/

## 结果结构

### ThreatIntelResult

```python
{
    "ioc_type": IOCType.IP,
    "ioc_value": "1.2.3.4",
    "is_malicious": True,
    "threat_score": 0.85,  # 0-1
    "threat_types": ["C2", "Malware"],
    "provider": "virustotal",
    "confidence": 0.9,
    "details": {...}  # 原始API响应
}
```

### 聚合结果

当使用多个提供商时，Manager会聚合结果：

```python
{
    "ioc_type": IOCType.IP,
    "ioc_value": "1.2.3.4",
    "is_malicious": True,  # 投票决定
    "threat_score": 0.82,  # 平均值
    "threat_types": ["C2", "Malware", "Botnet"],  # 合并
    "provider_results": [
        {...},  # VirusTotal结果
        {...}   # AbuseIPDB结果
    ]
}
```

## 环境变量配置

### Linux/Mac

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
```

### Windows

```cmd
set VIRUSTOTAL_API_KEY=your_key_here
set ABUSEIPDB_API_KEY=your_key_here
```

### Python代码

```python
import os

api_keys = {
    "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY")
}
```

## 错误处理

```python
try:
    result = await threat_intel.query_ip(ip)
except RateLimitError:
    # API速率限制
    await asyncio.sleep(60)
except AuthenticationError:
    # API密钥无效
    print("请检查API密钥")
except TimeoutError:
    # 查询超时
    print("查询超时，请重试")
except Exception as e:
    # 其他错误
    print(f"查询失败: {e}")
```

## 性能优化技巧

### 1. 使用批量查询

```python
# ❌ 不推荐
for ip in ip_list:
    result = await query_ip(ip)

# ✅ 推荐
results = await batch_query_ips(ip_list)
```

### 2. 限制查询数量

```python
# 只查询前N个可疑IOC
MAX_QUERIES = 10
for ip in suspicious_ips[:MAX_QUERIES]:
    result = await query_ip(ip)
```

### 3. 并发查询

```python
# 并发查询多个IOC
tasks = [query_ip(ip) for ip in ip_list]
results = await asyncio.gather(*tasks)
```

### 4. 启用缓存

```python
# 缓存默认启用，相同查询会直接返回缓存结果
# 缓存有效期：24小时
```

## 常见问题

### Q: 如何在开发时避免消耗API配额？

A: 使用模拟模式：
```python
system = SecurityAnalysisSystem(use_mock=True)
```

### Q: 如何查看API使用情况？

A: 查看缓存统计：
```python
stats = system.get_cache_stats()
print(f"查询次数: {stats.get('total_queries')}")
print(f"缓存命中: {stats.get('cache_hits')}")
print(f"命中率: {stats.get('hit_rate'):.2%}")
```

### Q: 缓存存储在哪里？

A: 默认存储在 `.cache/threat_intel/` 目录

### Q: 如何清除过期缓存？

A: 缓存会自动清除过期条目，也可以手动清除：
```python
await system.clear_cache()
```

### Q: 支持哪些文件哈希类型？

A: 支持 MD5、SHA1、SHA256

### Q: 如何添加新的威胁情报提供商？

A: 参考文档：[扩展新的提供商](./THREAT_INTEL_INTEGRATION.md#扩展新的提供商)

## 示例文件

- `examples/threat_intel_examples.py` - 基础示例
- `examples/security_analysis_v2_example.py` - 完整集成示例

## 相关文档

- [完整文档](./THREAT_INTEL_INTEGRATION.md)
- [API参考](./API_REFERENCE.md)
- [故障排查](./TROUBLESHOOTING.md)
