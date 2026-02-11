"""
日志系统

基于配置的结构化日志，支持文件轮转和控制台输出
"""
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional


_initialized = False


def setup_logging(
    level: str = "INFO",
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    log_file: str = "logs/security_analysis.log",
    max_bytes: int = 10485760,
    backup_count: int = 5,
    console_output: bool = True,
) -> None:
    """初始化日志系统"""
    global _initialized
    if _initialized:
        return

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(log_format)

    # 文件Handler（带轮转）
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # 控制台Handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    _initialized = True
    logging.info(f"日志系统初始化完成 [level={level}, file={log_file}]")


def setup_logging_from_config(config) -> None:
    """从LoggingConfig初始化日志"""
    setup_logging(
        level=config.level,
        log_format=config.format,
        log_file=config.file,
        max_bytes=config.max_bytes,
        backup_count=config.backup_count,
        console_output=config.console_output,
    )


def get_logger(name: str) -> logging.Logger:
    """获取命名Logger"""
    return logging.getLogger(name)
