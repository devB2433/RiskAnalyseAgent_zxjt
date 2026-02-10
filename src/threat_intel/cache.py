"""
威胁情报缓存
"""
import json
import hashlib
from typing import Optional, Dict
from datetime import datetime, timedelta
from pathlib import Path

from .base import ThreatIntelResult, IOCType


class ThreatIntelCache:
    """威胁情报缓存"""

    def __init__(self, cache_dir: str = ".threat_intel_cache", ttl: int = 3600):
        """
        初始化缓存

        Args:
            cache_dir: 缓存目录
            ttl: 缓存时间（秒）
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl = ttl
        self.memory_cache: Dict[str, tuple] = {}  # {key: (result, timestamp)}

    def _get_cache_key(self, ioc_value: str, ioc_type: IOCType, provider: str) -> str:
        """生成缓存键"""
        key_str = f"{provider}:{ioc_type.value}:{ioc_value}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        provider: str
    ) -> Optional[ThreatIntelResult]:
        """获取缓存"""
        cache_key = self._get_cache_key(ioc_value, ioc_type, provider)

        # 1. 检查内存缓存
        if cache_key in self.memory_cache:
            result, timestamp = self.memory_cache[cache_key]
            if datetime.now() - timestamp < timedelta(seconds=self.ttl):
                result.cached = True
                return result
            else:
                del self.memory_cache[cache_key]

        # 2. 检查文件缓存
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # 检查是否过期
                cached_time = datetime.fromisoformat(data['cached_time'])
                if datetime.now() - cached_time < timedelta(seconds=self.ttl):
                    result = self._deserialize_result(data['result'])
                    result.cached = True

                    # 加载到内存缓存
                    self.memory_cache[cache_key] = (result, cached_time)
                    return result
                else:
                    cache_file.unlink()  # 删除过期缓存
            except Exception:
                pass

        return None

    def set(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        provider: str,
        result: ThreatIntelResult
    ):
        """设置缓存"""
        cache_key = self._get_cache_key(ioc_value, ioc_type, provider)
        timestamp = datetime.now()

        # 1. 保存到内存缓存
        self.memory_cache[cache_key] = (result, timestamp)

        # 2. 保存到文件缓存
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            data = {
                'cached_time': timestamp.isoformat(),
                'result': self._serialize_result(result)
            }
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def clear(self):
        """清空缓存"""
        self.memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()

    def _serialize_result(self, result: ThreatIntelResult) -> Dict:
        """序列化结果"""
        return {
            'ioc_value': result.ioc_value,
            'ioc_type': result.ioc_type.value,
            'provider': result.provider,
            'is_malicious': result.is_malicious,
            'threat_level': result.threat_level.value,
            'threat_score': result.threat_score,
            'threat_types': result.threat_types,
            'details': result.details,
            'sources': result.sources,
            'first_seen': result.first_seen.isoformat() if result.first_seen else None,
            'last_seen': result.last_seen.isoformat() if result.last_seen else None,
            'timestamp': result.timestamp.isoformat(),
            'error': result.error
        }

    def _deserialize_result(self, data: Dict) -> ThreatIntelResult:
        """反序列化结果"""
        from .base import ThreatLevel

        return ThreatIntelResult(
            ioc_value=data['ioc_value'],
            ioc_type=IOCType(data['ioc_type']),
            provider=data['provider'],
            is_malicious=data['is_malicious'],
            threat_level=ThreatLevel(data['threat_level']),
            threat_score=data['threat_score'],
            threat_types=data['threat_types'],
            details=data['details'],
            sources=data['sources'],
            first_seen=datetime.fromisoformat(data['first_seen']) if data['first_seen'] else None,
            last_seen=datetime.fromisoformat(data['last_seen']) if data['last_seen'] else None,
            timestamp=datetime.fromisoformat(data['timestamp']),
            error=data['error']
        )


__all__ = ['ThreatIntelCache']