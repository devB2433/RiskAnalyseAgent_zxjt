# 威胁情报集成系统

## 概述

本系统为Agent开发框架提供了完整的威胁情报集成能力，支持从多个威胁情报源查询IP、域名、URL和文件哈希的威胁信息。系统已集成到安全分析器中，可以在分析过程中自动查询和验证可疑IOC（Indicators of Compromise）。

## 主要特性

✅ **多提供商支持** - 集成VirusTotal和AbuseIPDB，支持扩展更多提供商
✅ **模拟/真实模式** - 开发时使用模拟模式，生产环境切换到真实API
✅ **智能缓存** - 两级缓存（内存+文件）减少API调用成本
✅ **结果聚合** - 多个提供商结果自动聚合，提高准确性
✅ **批量查询** - 支持批量查询提高效率
✅ **异步设计** - 全异步实现，支持高并发查询
✅ **易于扩展** - 清晰的接口设计，方便添加新的提供商

## 快速开始

### 1. 模拟模式（无需API密钥）

适合开发和测试：

```python
from security_analysis.architecture_v2 import SecurityAnalysisSystem, AnalysisType, SecurityLog
from datetime import datetime

# 初始化系统（模拟模式）
system = SecurityAnalysisSystem(use_mock=True)

# 创建测试日志
logs = [
    SecurityLog(
        log_type="firewall",
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        dest_ip="10.0.0.5",
        dest_port=443,
        protocol="TCP",
        action="ALLOW"
    )
]

# 执行分析
result = await system.analyze(AnalysisType.COMPROMISED_HOST.value, logs)
print(f"分析完成，置信度: {result.confidence}")
```

### 2. 真实API模式（生产环境）

使用真实的威胁情报API：

```python
# 配置API密钥
api_keys = {
    "virustotal": "your_virustotal_api_key",
    "abuseipdb": "your_abuseipdb_api_key"
}

# 初始化系统（真实API模式）
system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)

# 执行分析（会调用真实API）
result = await system.analyze(AnalysisType.MALWARE_DETECTION.value, logs)
```

## 系统架构

```
security_analysis/
├── architecture_v2.py          # 集成威胁情报的安全分析器
└── architecture.py             # 原始版本（使用mock）

src/threat_intel/
├── base.py                     # 基础类和接口定义
├── providers/
│   └── __init__.py            # VirusTotal和AbuseIPDB实现
├── cache.py                    # 缓存系统
└── manager.py                  # 威胁情报管理器

examples/
├── threat_intel_examples.py    # 威胁情报系统示例
└── security_analysis_v2_example.py  # 完整集成示例

docs/
├── THREAT_INTEL_INTEGRATION.md      # 完整文档
└── THREAT_INTEL_QUICK_REFERENCE.md  # 快速参考
```

## 支持的威胁情报提供商

### VirusTotal

- **支持的IOC类型**: IP地址、域名、URL、文件哈希
- **API限制**: 免费版 4次/分钟，500次/天
- **获取API密钥**: https://www.virustotal.com/

### AbuseIPDB

- **支持的IOC类型**: IP地址
- **API限制**: 免费版 1000次/天
- **获取API密钥**: https://www.abuseipdb.com/

## 支持的分析类型

| 分析类型 | 使用的威胁情报 | 说明 |
|---------|---------------|------|
| 失陷主机检测 | IP地址 | 检测连接到恶意IP的主机 |
| 恶意软件检测 | 文件哈希 | 验证文件是否为已知恶意软件 |
| 钓鱼攻击检测 | 域名、URL | 识别钓鱼网站和链接 |
| 数据外泄检测 | IP地址 | 检测数据传输到可疑目标 |
| 异常登录检测 | IP地址 | 验证登录来源IP的信誉 |
| DDoS检测 | IP地址 | 识别攻击源IP |
| 横向移动检测 | IP地址 | 检测内网中的恶意活动 |

## 核心功能

### 1. 单个IOC查询

```python
from src.threat_intel.manager import ThreatIntelManager
from src.threat_intel.base import IOCType

# 查询IP
result = await manager.query(IOCType.IP, "1.2.3.4")
print(f"是否恶意: {result.is_malicious}")
print(f"威胁评分: {result.threat_score}")
print(f"威胁类型: {result.threat_types}")
```

### 2. 批量查询

```python
# 批量查询多个IP
ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
results = await manager.batch_query(IOCType.IP, ips)

for ip, result in zip(ips, results):
    print(f"{ip}: {result.threat_score}")
```

### 3. 多提供商聚合

```python
# 自动聚合多个提供商的结果
# 使用投票机制决定是否恶意
# 使用平均值计算威胁评分
result = await manager.query(IOCType.IP, "1.2.3.4")
print(f"聚合结果: {result.is_malicious}")
print(f"提供商数量: {len(result.provider_results)}")
```

### 4. 缓存管理

```python
# 获取缓存统计
stats = system.get_cache_stats()
print(f"缓存命中率: {stats.get('hit_rate', 0):.2%}")

# 清除缓存
await system.clear_cache()
```

## 配置API密钥

### 方式1：环境变量（推荐）

```bash
# Linux/Mac
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"

# Windows
set VIRUSTOTAL_API_KEY=your_key_here
set ABUSEIPDB_API_KEY=your_key_here
```

```python
import os

api_keys = {
    "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY")
}

system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)
```

### 方式2：直接传入

```python
api_keys = {
    "virustotal": "your_virustotal_api_key",
    "abuseipdb": "your_abuseipdb_api_key"
}

system = SecurityAnalysisSystem(use_mock=False, api_keys=api_keys)
```

## 性能优化

### 1. 启用缓存（默认启用）

缓存会自动存储查询结果，相同的IOC查询会直接从缓存返回，避免重复API调用。

- **内存缓存**: 快速访问，进程生命周期内有效
- **文件缓存**: 持久化存储，跨进程共享
- **TTL**: 默认24小时过期

### 2. 批量查询

```python
# ❌ 不推荐：逐个查询
for ip in ip_list:
    result = await query_ip(ip)

# ✅ 推荐：批量查询
results = await batch_query_ips(ip_list)
```

### 3. 限制查询数量

```python
# 在分析器中限制IOC查询数量
MAX_QUERIES = 10
for ip in suspicious_ips[:MAX_QUERIES]:
    result = await threat_intel.query_ip(ip)
```

### 4. 异步并发

```python
# 并发查询多个IOC
tasks = [query_ip(ip) for ip in ip_list]
results = await asyncio.gather(*tasks)
```

## 示例代码

### 示例1：基础威胁情报查询

```bash
python examples/threat_intel_examples.py
```

包含的示例：
- 单个IOC查询
- 批量查询
- 多提供商聚合
- 缓存使用
- 模拟/真实模式切换

### 示例2：完整安全分析集成

```bash
python examples/security_analysis_v2_example.py
```

包含的示例：
- 失陷主机检测
- 恶意软件检测
- 钓鱼攻击检测
- 批量分析
- 缓存管理

## 文档

- **[完整文档](./docs/THREAT_INTEL_INTEGRATION.md)** - 详细的系统文档
- **[快速参考](./docs/THREAT_INTEL_QUICK_REFERENCE.md)** - 常用操作速查表

## 从V1迁移到V2

如果你正在使用旧版本的安全分析器（`architecture.py`），可以按以下步骤迁移到V2：

### 1. 更新导入

```python
# 旧版本
from security_analysis.architecture import SecurityAnalysisSystem

# 新版本
from security_analysis.architecture_v2 import SecurityAnalysisSystem
```

### 2. 初始化系统

```python
# 旧版本（只有mock）
system = SecurityAnalysisSystem()

# 新版本（支持真实API）
system = SecurityAnalysisSystem(
    use_mock=False,  # 或True使用模拟模式
    api_keys=api_keys
)
```

### 3. 其他API保持不变

```python
# 分析接口完全兼容
result = await system.analyze(analysis_type, logs)
```

## 扩展新的提供商

系统设计为易于扩展，添加新的威胁情报提供商只需：

1. 继承 `ThreatIntelProvider` 基类
2. 实现查询方法（`query_ip`, `query_domain`等）
3. 注册到 `ThreatIntelManager`

详细步骤请参考：[扩展新的提供商](./docs/THREAT_INTEL_INTEGRATION.md#扩展新的提供商)

## 常见问题

### Q: 开发时如何避免消耗API配额？

A: 使用模拟模式：
```python
system = SecurityAnalysisSystem(use_mock=True)
```

### Q: 如何查看API使用情况？

A: 查看缓存统计：
```python
stats = system.get_cache_stats()
```

### Q: 缓存存储在哪里？

A: 默认存储在 `.cache/threat_intel/` 目录

### Q: 支持哪些文件哈希类型？

A: 支持 MD5、SHA1、SHA256

更多问题请参考：[完整文档](./docs/THREAT_INTEL_INTEGRATION.md)

## 最佳实践

1. **开发环境使用模拟模式** - 避免消耗API配额
2. **生产环境启用缓存** - 减少API调用成本
3. **使用环境变量管理密钥** - 提高安全性
4. **限制查询数量** - 避免超出API限制
5. **监控缓存命中率** - 优化查询策略

## 更新日志

### v2.0.0 (2024-12-31)
- ✨ 集成真实威胁情报API（VirusTotal、AbuseIPDB）
- ✨ 实现两级缓存机制
- ✨ 支持批量查询
- ✨ 支持模拟/真实模式切换
- ✨ 多提供商结果聚合
- 📝 完整文档和示例

### v1.0.0 (2024-12-01)
- 🎉 初始版本
- 仅支持模拟模式

## 贡献

欢迎贡献新的威胁情报提供商实现！

## 许可证

MIT License
