# 运维手册

## 日常运维

### 查看系统状态

```bash
# Docker 部署
docker compose ps
docker compose logs --tail=50 risk-agent

# 手动部署
tail -50 logs/security_analysis.log
```

### 健康检查

系统内置 `HealthChecker`，检查数据库和调度器状态。健康状态分三级：
- HEALTHY — 所有组件正常
- DEGRADED — 部分组件异常，系统仍可运行
- UNHEALTHY — 关键组件故障

监控指标快照导出到 `data/metrics.json`（可配置路径）。

### 查看监控指标

指标文件包含：
- 各分析器执行耗时、成功/失败次数
- 告警触发和通知计数
- 威胁情报查询次数和缓存命中率
- 预过滤输入/输出比（过滤效率）
- 系统运行时间

## 数据管理

### 自动清理

系统每24小时自动清理超过保留期的数据（默认90天）。

配置项：
```yaml
storage:
  data_retention_days: 90
  auto_cleanup: true
```

### 手动导出数据

通过 `StorageService` API 导出：
```python
from src.storage import StorageService, Database

db = Database("sqlite:///data/security_analysis.db")
storage = StorageService(db)

# 导出为 CSV
storage.export_results_csv("data/exports/results.csv")

# 导出为 JSON
storage.export_results_json("data/exports/results.json")
```

导出目录：`data/exports/`

### 数据库备份

SQLite：
```bash
# 停止服务后复制数据库文件
cp data/security_analysis.db data/backup/security_analysis_$(date +%Y%m%d).db
```

PostgreSQL：
```bash
pg_dump -U risk_agent security_analysis > backup_$(date +%Y%m%d).sql
```

### 数据库恢复

SQLite：
```bash
cp data/backup/security_analysis_20260211.db data/security_analysis.db
```

PostgreSQL：
```bash
psql -U risk_agent security_analysis < backup_20260211.sql
```

## 日志管理

### 日志位置

- 应用日志：`logs/security_analysis.log`
- 日志自动轮转：达到 `max_bytes`（默认10MB）后创建新文件
- 保留文件数：`backup_count`（默认5个）

### 调整日志级别

临时调整（环境变量）：
```bash
RISK_AGENT_LOG_LEVEL=DEBUG python -m src.app
```

永久调整（配置文件）：
```yaml
logging:
  level: "DEBUG"  # DEBUG/INFO/WARNING/ERROR
```

### 关键日志标识

| 日志内容 | 含义 |
|----------|------|
| `应用配置加载完成` | 启动成功 |
| `RiskAnalyseAgent 启动完成` | 所有组件就绪 |
| `注册分析任务: xxx` | 分析器已注册 |
| `告警已通知: xxx` | 告警发送成功 |
| `数据清理完成` | 定期清理执行 |
| `收到信号 xxx，正在关闭` | 优雅关闭中 |

## 故障排查

### 启动失败

| 症状 | 可能原因 | 解决方案 |
|------|----------|----------|
| `ModuleNotFoundError` | 依赖未安装 | `pip install -r requirements.txt` |
| 配置加载报错 | YAML格式错误 | 检查缩进和语法 |
| 数据库连接失败 | 路径不存在或权限不足 | 确认 `data/` 目录存在且可写 |
| 调度器启动失败 | 时区配置错误 | 检查 `scheduler.timezone` |

### 通知发送失败

- 飞书：检查 Webhook URL 是否过期，Secret 是否匹配
- 企业微信：检查 Webhook URL 格式，确认机器人未被禁用
- 邮件：检查 SMTP 凭据，确认端口和 TLS 设置正确

查看通知错误日志：
```bash
grep "通知" logs/security_analysis.log | grep -i error
```

### 分析任务不执行

1. 检查调度器是否启动：日志中应有 `注册分析任务` 记录
2. 检查 `enabled_analyzers` 配置是否包含目标分析器
3. 检查 `max_workers` 是否足够（默认10）
4. 查看任务历史表 `task_history` 中的错误信息

### 磁盘空间不足

1. 检查日志文件大小：`du -sh logs/`
2. 检查数据库大小：`du -sh data/security_analysis.db`
3. 手动触发数据清理或减小 `data_retention_days`
4. 清理威胁情报缓存：`rm -rf data/threat_intel_cache/*`

## 插件管理

### 添加自定义分析器

1. 在 `plugins/analyzers/` 下创建 Python 文件
2. 继承 `AnalyzerPlugin` 基类
3. 实现 `analyze()` 方法
4. 重启服务，`PluginManager` 会自动发现并加载

```python
from src.plugins import AnalyzerPlugin

class MyAnalyzer(AnalyzerPlugin):
    plugin_name = "my_custom_analyzer"
    plugin_version = "1.0.0"

    async def analyze(self, state):
        # 分析逻辑
        return state
```

## 运行测试

```bash
# 全部测试
pytest tests/ -v

# 单元测试
pytest tests/unit/ -v

# 集成测试
pytest tests/integration/ -v

# 指定模块
pytest tests/unit/test_monitoring.py -v
```
