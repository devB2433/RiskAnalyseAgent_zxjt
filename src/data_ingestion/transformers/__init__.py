"""
数据转换器实现
"""
from typing import Any, Dict, List, Optional
from datetime import datetime
import re

from ..base import BaseTransformer


class GenericTransformer(BaseTransformer):
    """通用数据转换器"""

    def __init__(self, schema: Optional[Dict[str, Any]] = None):
        self.schema = schema or {}

    async def transform(
        self,
        data: List[Dict[str, Any]],
        schema: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """转换数据"""
        schema = schema or self.schema
        result = []

        for item in data:
            transformed = self.transform_single(item, schema)
            if transformed:
                result.append(transformed)

        return result

    def transform_single(
        self,
        item: Dict[str, Any],
        schema: Optional[Dict[str, Any]] = None
    ) -> Any:
        """转换单条数据"""
        schema = schema or self.schema
        if not schema:
            return item

        result = {}
        for target_field, config in schema.items():
            if isinstance(config, str):
                # 简单字段映射
                result[target_field] = item.get(config)
            elif isinstance(config, dict):
                # 复杂转换
                source_field = config.get('source')
                transform_func = config.get('transform')
                default_value = config.get('default')

                value = item.get(source_field, default_value)

                if transform_func and callable(transform_func):
                    value = transform_func(value)

                result[target_field] = value

        return result

    def validate_schema(self, data: Dict[str, Any]) -> bool:
        """验证数据模式"""
        if not self.schema:
            return True

        for field, config in self.schema.items():
            if isinstance(config, dict) and config.get('required', False):
                source_field = config.get('source', field)
                if source_field not in data:
                    return False

        return True


class SecurityLogTransformer(BaseTransformer):
    """安全日志转换器"""

    async def transform(
        self,
        data: List[Dict[str, Any]],
        schema: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """转换为SecurityLog对象"""
        from security_analysis.architecture import SecurityLog

        result = []
        for item in data:
            try:
                log = self.transform_single(item)
                if log:
                    result.append(log)
            except Exception as e:
                # 跳过无法转换的数据
                continue

        return result

    def transform_single(self, item: Dict[str, Any]) -> Any:
        """转换单条数据为SecurityLog"""
        from security_analysis.architecture import SecurityLog

        # 提取字段
        log_type = item.get('log_type', item.get('type', 'unknown'))
        timestamp = self._parse_timestamp(item.get('timestamp', item.get('time')))
        source_ip = item.get('source_ip', item.get('src_ip', item.get('src', '')))
        dest_ip = item.get('dest_ip', item.get('dst_ip', item.get('dst', '')))
        source_port = self._parse_int(item.get('source_port', item.get('src_port')))
        dest_port = self._parse_int(item.get('dest_port', item.get('dst_port')))
        protocol = item.get('protocol', item.get('proto', ''))
        action = item.get('action', item.get('status', ''))

        # 其他字段放入raw_data
        raw_data = {
            k: v for k, v in item.items()
            if k not in ['log_type', 'type', 'timestamp', 'time',
                        'source_ip', 'src_ip', 'src', 'dest_ip', 'dst_ip', 'dst',
                        'source_port', 'src_port', 'dest_port', 'dst_port',
                        'protocol', 'proto', 'action', 'status']
        }

        return SecurityLog(
            log_type=log_type,
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            action=action,
            raw_data=raw_data
        )

    def validate_schema(self, data: Dict[str, Any]) -> bool:
        """验证安全日志必需字段"""
        required_fields = ['timestamp', 'source_ip']

        # 检查是否有必需字段的任一变体
        for field in required_fields:
            if field == 'timestamp':
                if not any(k in data for k in ['timestamp', 'time']):
                    return False
            elif field == 'source_ip':
                if not any(k in data for k in ['source_ip', 'src_ip', 'src']):
                    return False

        return True

    def _parse_timestamp(self, value: Any) -> datetime:
        """解析时间戳"""
        if isinstance(value, datetime):
            return value
        elif isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)
        elif isinstance(value, str):
            # 尝试多种时间格式
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%d/%b/%Y:%H:%M:%S',
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        return datetime.now()

    def _parse_int(self, value: Any) -> Optional[int]:
        """解析整数"""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None


__all__ = [
    'GenericTransformer',
    'SecurityLogTransformer',
]