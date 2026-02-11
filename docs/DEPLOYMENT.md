# 部署指南

## 环境要求

- Python 3.11+
- Docker 20.10+（容器部署）
- Docker Compose v2+（容器部署）
- 磁盘空间：至少 1GB（含数据库和日志）
- 内存：建议 512MB+

## 快速开始（开发环境）

```bash
# 1. 克隆项目
git clone <repo-url>
cd AgentsTest

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 创建数据目录
mkdir -p data logs data/exports data/threat_intel_cache

# 5. 启动（使用默认配置，mock模式）
python -m src.app
```

默认配置使用 SQLite 和 mock 威胁情报，无需额外服务。

## Docker 部署（推荐）

### 基本部署

```bash
# 构建镜像
docker compose build

# 启动服务
docker compose up -d

# 查看日志
docker compose logs -f risk-agent
```

### 配置环境变量

创建 `.env` 文件：

```env
# 威胁情报 API 密钥
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

# 飞书通知
FEISHU_WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/xxx
FEISHU_SECRET=your_secret

# 企业微信通知
WECOM_WEBHOOK_URL=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx

# 邮件通知
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=alert@example.com
SMTP_PASSWORD=your_password
SMTP_FROM=alert@example.com
```

### 使用 PostgreSQL（生产推荐）

编辑 `docker-compose.yml`，取消 postgres 服务的注释，并更新环境变量：

```env
RISK_AGENT_DB_URL=postgresql://risk_agent:changeme@postgres:5432/security_analysis
DB_USER=risk_agent
DB_PASSWORD=changeme
```

需要额外安装驱动：`pip install asyncpg psycopg2-binary`

### 自定义配置文件

将自定义配置放在 `config/production.yaml`，Docker 会以只读方式挂载 `config/` 目录。

```bash
# 使用自定义配置启动
docker compose up -d
# 或手动指定
python -m src.app config/production.yaml
```

## 生产环境检查清单

- [ ] 设置真实的威胁情报 API 密钥，关闭 `use_mock`
- [ ] 启用至少一个通知渠道（飞书/企业微信/邮件）
- [ ] 配置合适的数据保留天数（`storage.data_retention_days`）
- [ ] 确认日志轮转配置（`logging.max_bytes`、`backup_count`）
- [ ] 设置 `RISK_AGENT_ENV=production`
- [ ] 确保 `data/` 和 `logs/` 目录有写入权限
- [ ] 配置系统级进程管理（systemd 或 Docker restart policy）

## 目录结构

部署后的运行时目录：

```
/app/                       # 或项目根目录
├── config/
│   ├── default.yaml        # 默认配置
│   └── production.yaml     # 生产配置
├── data/
│   ├── security_analysis.db  # SQLite数据库
│   ├── exports/              # 数据导出目录
│   ├── threat_intel_cache/   # 威胁情报缓存
│   └── metrics.json          # 监控指标快照
├── logs/
│   └── security_analysis.log # 应用日志（自动轮转）
└── plugins/
    └── analyzers/            # 自定义分析器插件
```

## 停止和重启

```bash
# Docker
docker compose stop
docker compose restart

# 手动部署 - 发送 SIGTERM 优雅关闭
kill -TERM <pid>
```

系统收到 SIGINT/SIGTERM 后会完成当前任务再关闭。
