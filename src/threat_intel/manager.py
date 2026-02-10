"""
威胁情报管理器
统一管理多个威胁情报提供商
"""
import asyncio
from typing import Dict, List, Optional
import os

from .base import (
    ThreatIntelProvider,
    ThreatIntelConfig,
    ThreatIntelResult,
    IOCType,
    ThreatLevel
)
from .providers import (
    VirusTotalProvider,
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    ShodanProvider,
    GreyNoiseProvider
)
from .cache import ThreatIntelCache


class ThreatIntelManager:
    """威胁情报管理器"""

    def __init__(
        self,
        use_mock: bool = False,
        enable_cache: bool = True,
        cache_ttl: int = 3600
    ):
        """
        初始化管理器

        Args:
            use_mock: 是否使用Mock模式
            enable_cache: 是否启用缓存
            cache_ttl: 缓存时间（秒）
        """
        self.use_mock = use_mock
        self.enable_cache = enable_cache
        self.providers: Dict[str, ThreatIntelProvider] = {}
        self.cache = ThreatIntelCache(ttl=cache_ttl) if enable_cache else None

        # 初始化提供商
        self._initialize_providers()

    def _initialize_providers(self):
        """初始化威胁情报提供商"""

        # VirusTotal
        vt_config = ThreatIntelConfig(
            provider_name="VirusTotal",
            api_key=os.getenv("VIRUSTOTAL_API_KEY"),
            use_mock=self.use_mock or not os.getenv("VIRUSTOTAL_API_KEY"),
            enable_cache=self.enable_cache
        )
        self.providers["virustotal"] = VirusTotalProvider(vt_config)

        # AbuseIPDB
        abuse_config = ThreatIntelConfig(
            provider_name="AbuseIPDB",
            api_key=os.getenv("ABUSEIPDB_API_KEY"),
            use_mock=self.use_mock or not os.getenv("ABUSEIPDB_API_KEY"),
            enable_cache=self.enable_cache
        )
        self.providers["abuseipdb"] = AbuseIPDBProvider(abuse_config)

        # AlienVault OTX
        otx_config = ThreatIntelConfig(
            provider_name="AlienVault OTX",
            api_key=os.getenv("OTX_API_KEY"),
            use_mock=True,  # 简化实现，默认使用Mock
            enable_cache=self.enable_cache
        )
        self.providers["alienvault"] = AlienVaultOTXProvider(otx_config)

        # Shodan
        shodan_config = ThreatIntelConfig(
            provider_name="Shodan",
            api_key=os.getenv("SHODAN_API_KEY"),
            use_mock=True,  # 简化实现，默认使用Mock
            enable_cache=self.enable_cache
        )
        self.providers["shodan"] = ShodanProvider(shodan_config)

        # GreyNoise
        greynoise_config = ThreatIntelConfig(
            provider_name="GreyNoise",
            api_key=os.getenv("GREYNOISE_API_KEY"),
            use_mock=True,  # 简化实现，默认使用Mock
            enable_cache=self.enable_cache
        )
        self.providers["greynoise"] = GreyNoiseProvider(greynoise_config)

    def register_provider(self, name: str, provider: ThreatIntelProvider):
        """注册自定义提供商"""
        self.providers[name] = provider

    async def query(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        providers: Optional[List[str]] = None
    ) -> List[ThreatIntelResult]:
        """
        查询IOC

        Args:
            ioc_value: IOC值
            ioc_type: IOC类型
            providers: 指定使用的提供商列表（不指定则使用所有）

        Returns:
            查询结果列表
        """
        # 确定使用的提供商
        if providers:
            selected_providers = {
                name: provider
                for name, provider in self.providers.items()
                if name in providers
            }
        else:
            selected_providers = self.providers

        # 并发查询所有提供商
        tasks = []
        for name, provider in selected_providers.items():
            tasks.append(self._query_with_cache(provider, ioc_value, ioc_type))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 过滤异常结果
        valid_results = []
        for result in results:
            if isinstance(result, ThreatIntelResult):
                valid_results.append(result)

        return valid_results

    async def _query_with_cache(
        self,
        provider: ThreatIntelProvider,
        ioc_value: str,
        ioc_type: IOCType
    ) -> ThreatIntelResult:
        """带缓存的查询"""

        # 1. 检查缓存
        if self.cache:
            cached_result = self.cache.get(ioc_value, ioc_type, provider.provider_name)
            if cached_result:
                return cached_result

        # 2. 查询提供商
        result = await provider.query(ioc_value, ioc_type)

        # 3. 保存到缓存
        if self.cache and not result.error:
            self.cache.set(ioc_value, ioc_type, provider.provider_name, result)

        return result

    async def query_ip(
        self,
        ip: str,
        providers: Optional[List[str]] = None
    ) -> List[ThreatIntelResult]:
        """查询IP"""
        return await self.query(ip, IOCType.IP, providers)

    async def query_domain(
        self,
        domain: str,
        providers: Optional[List[str]] = None
    ) -> List[ThreatIntelResult]:
        """查询域名"""
        return await self.query(domain, IOCType.DOMAIN, providers)

    async def query_url(
        self,
        url: str,
        providers: Optional[List[str]] = None
    ) -> List[ThreatIntelResult]:
        """查询URL"""
        return await self.query(url, IOCType.URL, providers)

    async def query_file_hash(
        self,
        file_hash: str,
        providers: Optional[List[str]] = None
    ) -> List[ThreatIntelResult]:
        """查询文件哈希"""
        return await self.query(file_hash, IOCType.FILE_HASH, providers)

    def aggregate_results(
        self,
        results: List[ThreatIntelResult]
    ) -> ThreatIntelResult:
        """
        聚合多个提供商的结果

        Args:
            results: 查询结果列表

        Returns:
            聚合后的结果
        """
        if not results:
            raise ValueError("没有可聚合的结果")

        # 过滤错误结果
        valid_results = [r for r in results if not r.error]
        if not valid_results:
            return results[0]  # 返回第一个错误结果

        # 聚合逻辑
        malicious_count = sum(1 for r in valid_results if r.is_malicious)
        total_count = len(valid_results)

        # 计算平均威胁分数
        avg_score = sum(r.threat_score for r in valid_results) / total_count

        # 收集所有威胁类型
        all_threat_types = []
        for r in valid_results:
            all_threat_types.extend(r.threat_types)
        unique_threat_types = list(set(all_threat_types))

        # 收集所有来源
        all_sources = []
        for r in valid_results:
            all_sources.extend(r.sources)

        # 判断是否恶意（多数投票）
        is_malicious = malicious_count > total_count / 2

        # 计算威胁级别
        threat_level = self._calculate_aggregate_threat_level(avg_score, malicious_count, total_count)

        # 创建聚合结果
        first_result = valid_results[0]
        return ThreatIntelResult(
            ioc_value=first_result.ioc_value,
            ioc_type=first_result.ioc_type,
            provider="Aggregated",
            is_malicious=is_malicious,
            threat_level=threat_level,
            threat_score=avg_score,
            threat_types=unique_threat_types,
            details={
                "malicious_count": malicious_count,
                "total_count": total_count,
                "individual_results": [
                    {
                        "provider": r.provider,
                        "is_malicious": r.is_malicious,
                        "threat_score": r.threat_score
                    }
                    for r in valid_results
                ]
            },
            sources=all_sources
        )

    def _calculate_aggregate_threat_level(
        self,
        avg_score: float,
        malicious_count: int,
        total_count: int
    ) -> ThreatLevel:
        """计算聚合威胁级别"""
        malicious_ratio = malicious_count / total_count

        if malicious_ratio >= 0.8 and avg_score >= 80:
            return ThreatLevel.CRITICAL
        elif malicious_ratio >= 0.6 and avg_score >= 60:
            return ThreatLevel.HIGH
        elif malicious_ratio >= 0.4 and avg_score >= 40:
            return ThreatLevel.MEDIUM
        elif malicious_ratio >= 0.2 or avg_score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.CLEAN

    def clear_cache(self):
        """清空缓存"""
        if self.cache:
            self.cache.clear()

    def get_provider_status(self) -> Dict[str, Dict]:
        """获取提供商状态"""
        status = {}
        for name, provider in self.providers.items():
            status[name] = {
                "provider_name": provider.provider_name,
                "use_mock": provider.config.use_mock,
                "has_api_key": bool(provider.config.api_key),
                "enable_cache": provider.config.enable_cache
            }
        return status


__all__ = ['ThreatIntelManager']