# 配置指南

## 配置加载机制

配置按以下优先级加载（高优先级覆盖低优先级）：

1. 环境变量（最高）
2. 命令行指定的配置文件
3. `config/default.yaml`（最低）

```python
# 使用默认配置
python -m src.app

# 指定配置文件
python -m src.app config/production.yaml
```

## 配置段详解

### database — 数据库

```yaml
database:
  url: "sqlite:///data/security_analysis.db"
  async_url: "sqlite+aiosqlite:///data/security_analysis.db"
  echo: false          # SQL日志输出
  pool_size: 5         # 连接池大小
  max_overflow: 10     # 最大溢出连接
  pool_recycle: 3600   # 连接回收时间(秒)
```

PostgreSQL 示例：
```yaml
database:
  url: "postgresql://user:pass@host:5432/security_analysis"
  async_url: "postgresql+asyncpg://user:pass@host:5432/security_analysis"
  pool_size: 10
  max_overflow: 20
```

环境变量：`RISK_AGENT_DB_URL`

### scheduler — 调度器

```yaml
scheduler:
  timezone: "Asia/Shanghai"
  max_workers: 10              # 最大并发工作线程
  job_defaults_coalesce: true  # 合并错过的执行
  job_defaults_max_instances: 3  # 同一任务最大并发实例
  misfire_grace_time: 60       # 错过执行的宽限时间(秒)
```

### analysis — 分析引擎

```yaml
analysis:
  default_model: "gpt-4"          # 默认LLM模型
  fallback_model: "gpt-3.5-turbo" # 回退模型
  temperature: 0.1                 # 生成温度（低=更确定性）
  max_tokens: 4096
  confidence_threshold: 0.7        # 置信度阈值
  alert_threshold: 0.8             # 告警触发阈值
  batch_size: 50                   # 批量分析大小
  enabled_analyzers:               # 启用的分析器列表
    - compromised_host
    - anomalous_login
    - data_exfiltration
    - malware_detection
    - insider_threat
    - ddos_detection
    - lateral_movement
    - phishing_detection
```

环境变量：`RISK_AGENT_MODEL`

### threat_intel — 威胁情报

```yaml
threat_intel:
  enabled: true
  cache_ttl: 3600                  # 缓存过期时间(秒)
  cache_dir: "data/threat_intel_cache"
  virustotal_api_key: ""           # VirusTotal API密钥
  abuseipdb_api_key: ""            # AbuseIPDB API密钥
  use_mock: true                   # mock模式（开发用）
```

环境变量：`VIRUSTOTAL_API_KEY`、`ABUSEIPDB_API_KEY`

生产环境务必设置 `use_mock: false` 并配置真实API密钥。

### notification — 通知

```yaml
notification:
  min_severity: "medium"           # 最低通知级别 (low/medium/high/critical)
  cooldown_minutes: 30             # 同类告警冷却期(分钟)
  batch_interval_seconds: 60       # 告警检查间隔(秒)

  feishu:
    enabled: false
    webhook_url: ""
    secret: ""
    at_all_on_critical: true       # critical级别@所有人

  wecom:
    enabled: false
    webhook_url: ""
    mentioned_list: []             # @指定用户ID列表
    mentioned_mobile_list: []      # @指定手机号列表

  email:
    enabled: false
    smtp_host: "smtp.example.com"
    smtp_port: 587
    smtp_use_tls: true
    username: ""
    password: ""
    from_addr: ""
    to_addrs: []                   # 收件人列表
    cc_addrs: []                   # 抄送列表
```

环境变量：`FEISHU_WEBHOOK_URL`、`FEISHU_SECRET`、`WECOM_WEBHOOK_URL`、`SMTP_HOST`、`SMTP_PORT`、`SMTP_USERNAME`、`SMTP_PASSWORD`、`SMTP_FROM`

### logging — 日志

```yaml
logging:
  level: "INFO"                    # DEBUG/INFO/WARNING/ERROR
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "logs/security_analysis.log"
  max_bytes: 10485760              # 单文件最大10MB
  backup_count: 5                  # 保留5个轮转文件
  console_output: true
```

环境变量：`RISK_AGENT_LOG_LEVEL`

### storage — 存储

```yaml
storage:
  data_retention_days: 90          # 数据保留天数
  export_dir: "data/exports"       # 导出目录
  auto_cleanup: true               # 自动清理过期数据
  cleanup_cron: "0 2 * * *"        # 清理时间（每天凌晨2点）
```

### preprocessing — 日志预处理

```yaml
preprocessing:
  prefilter_enabled: true          # 启用规则预过滤
  preprocessor_enabled: true       # 启用统计摘要
  sample_size: 20                  # 采样日志数量
  top_n: 15                        # Top-N统计项数
  work_hours: [8, 20]              # 工作时间范围
  large_transfer_threshold: 10000000  # 大数据传输阈值(字节)
  high_freq_threshold: 50          # 高频访问阈值(次)
```

### monitoring — 监控

```yaml
monitoring:
  enabled: true
  health_check_interval: 60        # 健康检查间隔(秒)
  metrics_log_interval: 300        # 指标日志间隔(秒)
  metrics_export_path: "data/metrics.json"
```

## 环境变量汇总

| 环境变量 | 对应配置 | 说明 |
|----------|----------|------|
| `RISK_AGENT_ENV` | `env` | 运行环境 |
| `RISK_AGENT_CONFIG` | — | 配置文件路径 |
| `RISK_AGENT_DB_URL` | `database.url` | 数据库连接串 |
| `RISK_AGENT_MODEL` | `analysis.default_model` | 默认LLM模型 |
| `RISK_AGENT_LOG_LEVEL` | `logging.level` | 日志级别 |
| `VIRUSTOTAL_API_KEY` | `threat_intel.virustotal_api_key` | VirusTotal密钥 |
| `ABUSEIPDB_API_KEY` | `threat_intel.abuseipdb_api_key` | AbuseIPDB密钥 |
| `FEISHU_WEBHOOK_URL` | `notification.feishu.webhook_url` | 飞书Webhook |
| `FEISHU_SECRET` | `notification.feishu.secret` | 飞书签名密钥 |
| `WECOM_WEBHOOK_URL` | `notification.wecom.webhook_url` | 企业微信Webhook |
| `SMTP_HOST` | `notification.email.smtp_host` | SMTP服务器 |
| `SMTP_PORT` | `notification.email.smtp_port` | SMTP端口 |
| `SMTP_USERNAME` | `notification.email.username` | SMTP用户名 |
| `SMTP_PASSWORD` | `notification.email.password` | SMTP密码 |
| `SMTP_FROM` | `notification.email.from_addr` | 发件人地址 |
