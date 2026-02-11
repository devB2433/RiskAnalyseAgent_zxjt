# 系统架构文档

## 概述

RiskAnalyseAgent 是一个基于 LangChain 的企业级安全日志自动化分析系统。系统采用模块化架构，支持无人值守运行，自动完成数据拉取、安全分析、结果存储和告警通知的完整流程。

## 系统架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                     RiskAnalyseApp (主应用)                      │
│                        src/app.py                               │
└──────────┬──────────────┬──────────────┬───────────────┬────────┘
           │              │              │               │
     ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼──────┐ ┌─────▼──────┐
     │  配置管理  │ │  调度系统  │ │  通知管理   │ │  监控指标  │
     │ config/   │ │ scheduler/│ │notification/│ │ monitoring/│
     └─────┬─────┘ └─────┬─────┘ └─────┬──────┘ └────────────┘
           │              │              │
           │        ┌─────▼──────────────┘
           │        │
     ┌─────▼────────▼─────────────────────────────────────────┐
     │              安全分析引擎                                │
     │  ┌──────────┐  ┌────────────┐  ┌──────────────────┐   │
     │  │ PreFilter │→│Preprocessor│→│ 8个安全分析器(LLM) │   │
     │  └──────────┘  └────────────┘  └────────┬─────────┘   │
     │                                          │             │
     │                              ┌───────────▼──────────┐  │
     │                              │  威胁情报 (6个提供商)  │  │
     │                              └──────────────────────┘  │
     └────────────────────────┬───────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   持久化存储层     │
                    │  SQLAlchemy ORM   │
                    │  SQLite/PostgreSQL │
                    └───────────────────┘
```

## 核心模块

### 1. 主应用 (`src/app.py`)

`RiskAnalyseApp` 是系统入口，负责组件编排和生命周期管理。

启动流程：
1. 加载配置（YAML + 环境变量）
2. 初始化日志系统
3. 初始化数据库和存储服务
4. 初始化通知管理器
5. 初始化调度器并注册默认任务
6. 启动后台循环（告警检查 + 数据清理）

信号处理：捕获 SIGINT/SIGTERM 实现优雅关闭。

### 2. 配置管理 (`src/config/`)

基于 dataclass 的类型安全配置系统。

- 配置来源优先级：环境变量 > 自定义YAML > 默认YAML
- 主配置文件：`config/default.yaml`（开发）、`config/production.yaml`（生产）
- 全局单例：`get_settings()` 返回 `Settings` 实例

配置段：database、scheduler、analysis、threat_intel、notification、logging、storage、preprocessing、monitoring。

### 3. 调度系统 (`src/scheduler/`)

基于 APScheduler 的异步任务调度。

- 触发方式：Cron表达式、固定间隔、一次性
- 任务类型：`PersistentAnalysisJob`（定期分析）、`FetchJob`（数据拉取）
- 特性：并发控制、失败重试（指数退避）、执行历史记录
- 默认行为：为每个启用的分析器注册每小时执行的任务

### 4. 安全分析引擎 (`security_analysis/`)

三层处理管道：

```
原始日志 → PreFilter(规则筛选) → Preprocessor(统计摘要+采样) → LLM分析器
```

**PreFilter** (`prefilter.py`)：基于规则的预过滤，12种过滤原因，每种分析器有专属规则集。将数千条日志筛选为可疑子集。

**Preprocessor** (`preprocessor.py`)：对可疑日志生成结构化统计摘要（IP频次、时间分布、协议分布等）+ 优先采样（~20条代表性日志）。每种分析器有专属统计方法。

**8个分析器**：
| 分析器 | 检测目标 |
|--------|----------|
| compromised_host | 被入侵主机 |
| anomalous_login | 异常登录行为 |
| data_exfiltration | 数据外泄 |
| malware_detection | 恶意软件 |
| insider_threat | 内部威胁 |
| ddos_detection | DDoS攻击 |
| lateral_movement | 横向移动 |
| phishing_detection | 钓鱼攻击 |

每个分析器使用 LangChain prompt chain，接收预处理后的结构化输入，输出 Finding 列表。

### 5. 威胁情报 (`src/threat_intel/`)

多源威胁情报查询和缓存。

提供商：VirusTotal、AbuseIPDB、AlienVault OTX、Shodan、GreyNoise、URLhaus

- IOC类型：IP、域名、文件哈希、URL
- 缓存：TTL机制，避免重复查询
- Mock模式：开发测试时无需真实API密钥
- `ThreatIntelManager` 统一管理多个提供商

### 6. 持久化存储 (`src/storage/`)

SQLAlchemy ORM + Repository模式。

数据库表：
- `analysis_results` — 分析执行记录（关联 alerts、ioc_records）
- `alerts` — 安全告警（含通知状态、处理状态跟踪）
- `task_history` — 任务执行历史
- `ioc_records` — 威胁指标记录
- `system_config` — 系统键值配置

`StorageService` 提供高层API：保存结果、查询告警、数据导出（CSV/JSON）、自动清理过期数据。

### 7. 通知系统 (`src/notification/`)

多渠道告警通知。

- 渠道：飞书（Webhook）、企业微信（Webhook）、邮件（SMTP）
- 特性：严重级别过滤、冷却期防刷、告警去重、异步发送
- 流程：告警入库 → 后台循环检测未通知告警 → 发送到启用的渠道 → 标记已通知

### 8. 监控指标 (`src/monitoring/`)

线程安全的运行时指标收集。

- `MetricsCollector`：分析耗时、成功/失败率、告警计数、威胁情报查询统计、预过滤效率
- `HealthChecker`：组件健康检查（数据库、调度器），返回 HEALTHY/DEGRADED/UNHEALTHY
- 全局单例：`get_metrics()`

### 9. 插件系统 (`src/plugins/`)

动态分析器扩展。

- `AnalyzerPlugin` 基类：定义 `analyze()` 接口
- `PluginManager`：自动发现和加载 `plugins/analyzers/` 目录下的插件
- 内置插件：compromised_host、anomalous_login

## 数据流

### 分析流程

```
1. Scheduler 触发 PersistentAnalysisJob
2. Job 拉取待分析日志（SecurityLog[]）
3. PreFilter 规则筛选 → 可疑日志子集
4. Preprocessor 统计摘要 + 采样 → 结构化LLM输入
5. Analyzer (LLM prompt chain) 分析 → Finding[]
6. ThreatIntel 查询IOC → 威胁情报增强
7. StorageService 保存 AnalysisResult + Alert
8. NotificationManager 检测未通知告警 → 发送通知
```

### 告警生命周期

```
分析发现威胁 → Alert入库(notified=false)
  → _alert_check_loop 检测 → 严重级别过滤 + 冷却期检查
  → 发送到启用渠道 → 标记 notified=true
  → 运维人员确认(acknowledged) → 处理完成(resolved)
```

## 技术选型

| 组件 | 技术 | 说明 |
|------|------|------|
| LLM框架 | LangChain | Prompt chain + Tool use |
| 调度 | APScheduler | Cron/Interval/Date触发 |
| ORM | SQLAlchemy 2.0 | 支持SQLite和PostgreSQL |
| 配置 | PyYAML + dataclass | 类型安全，环境变量覆盖 |
| HTTP | aiohttp | 异步HTTP客户端 |
| 邮件 | aiosmtplib | 异步SMTP |
| 容器 | Docker + Compose | 生产部署 |
| 测试 | pytest | 132个测试用例 |
