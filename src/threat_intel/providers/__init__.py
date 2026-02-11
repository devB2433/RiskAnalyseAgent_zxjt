"""
威胁情报提供商实现
"""
import aiohttp
import asyncio
from typing import Dict, Any, List
from datetime import datetime

from ..base import (
    ThreatIntelProvider,
    ThreatIntelConfig,
    ThreatIntelResult,
    IOCType,
    ThreatLevel
)


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal威胁情报提供商"""

    def __init__(self, config: ThreatIntelConfig):
        super().__init__(config)
        self.api_url = config.api_url or "https://www.virustotal.com/api/v3"
        self.api_key = config.api_key

    async def query_ip(self, ip: str) -> ThreatIntelResult:
        """查询IP"""
        if self.config.use_mock:
            return self._mock_ip_result(ip)

        try:
            url = f"{self.api_url}/ip_addresses/{ip}"
            headers = {"x-apikey": self.api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_ip_response(ip, data)
                    elif response.status == 404:
                        return self._create_clean_result(ip, IOCType.IP)
                    else:
                        error = f"API错误: {response.status}"
                        return self._create_error_result(ip, IOCType.IP, error)

        except asyncio.TimeoutError:
            return self._create_error_result(ip, IOCType.IP, "请求超时")
        except Exception as e:
            return self._create_error_result(ip, IOCType.IP, str(e))

    async def query_domain(self, domain: str) -> ThreatIntelResult:
        """查询域名"""
        if self.config.use_mock:
            return self._mock_domain_result(domain)

        try:
            url = f"{self.api_url}/domains/{domain}"
            headers = {"x-apikey": self.api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_domain_response(domain, data)
                    elif response.status == 404:
                        return self._create_clean_result(domain, IOCType.DOMAIN)
                    else:
                        error = f"API错误: {response.status}"
                        return self._create_error_result(domain, IOCType.DOMAIN, error)

        except Exception as e:
            return self._create_error_result(domain, IOCType.DOMAIN, str(e))

    async def query_url(self, url: str) -> ThreatIntelResult:
        """查询URL"""
        if self.config.use_mock:
            return self._mock_url_result(url)

        try:
            # VirusTotal URL查询需要先提交URL ID
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            api_url = f"{self.api_url}/urls/{url_id}"
            headers = {"x-apikey": self.api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    api_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_url_response(url, data)
                    else:
                        return self._create_clean_result(url, IOCType.URL)

        except Exception as e:
            return self._create_error_result(url, IOCType.URL, str(e))

    async def query_file_hash(self, file_hash: str) -> ThreatIntelResult:
        """查询文件哈希"""
        if self.config.use_mock:
            return self._mock_hash_result(file_hash)

        try:
            url = f"{self.api_url}/files/{file_hash}"
            headers = {"x-apikey": self.api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_file_response(file_hash, data)
                    elif response.status == 404:
                        return self._create_clean_result(file_hash, IOCType.FILE_HASH)
                    else:
                        error = f"API错误: {response.status}"
                        return self._create_error_result(file_hash, IOCType.FILE_HASH, error)

        except Exception as e:
            return self._create_error_result(file_hash, IOCType.FILE_HASH, str(e))

    def _parse_ip_response(self, ip: str, data: Dict) -> ThreatIntelResult:
        """解析IP响应"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        threat_score = (malicious + suspicious * 0.5) / total * 100 if total > 0 else 0
        is_malicious = malicious > 0

        return ThreatIntelResult(
            ioc_value=ip,
            ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=self._calculate_threat_level(threat_score),
            threat_score=threat_score,
            threat_types=self._extract_threat_types(attributes),
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation", 0),
                "country": attributes.get("country", ""),
                "as_owner": attributes.get("as_owner", "")
            },
            sources=["VirusTotal"]
        )

    def _parse_domain_response(self, domain: str, data: Dict) -> ThreatIntelResult:
        """解析域名响应"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        threat_score = (malicious + suspicious * 0.5) / total * 100 if total > 0 else 0
        is_malicious = malicious > 0

        return ThreatIntelResult(
            ioc_value=domain,
            ioc_type=IOCType.DOMAIN,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=self._calculate_threat_level(threat_score),
            threat_score=threat_score,
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "reputation": attributes.get("reputation", 0),
                "categories": attributes.get("categories", {}),
                "creation_date": attributes.get("creation_date")
            },
            sources=["VirusTotal"]
        )

    def _parse_url_response(self, url: str, data: Dict) -> ThreatIntelResult:
        """解析URL响应"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        threat_score = (malicious + suspicious * 0.5) / total * 100 if total > 0 else 0
        is_malicious = malicious > 0

        return ThreatIntelResult(
            ioc_value=url,
            ioc_type=IOCType.URL,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=self._calculate_threat_level(threat_score),
            threat_score=threat_score,
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "title": attributes.get("title", "")
            },
            sources=["VirusTotal"]
        )

    def _parse_file_response(self, file_hash: str, data: Dict) -> ThreatIntelResult:
        """解析文件响应"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        threat_score = (malicious + suspicious * 0.5) / total * 100 if total > 0 else 0
        is_malicious = malicious > 0

        return ThreatIntelResult(
            ioc_value=file_hash,
            ioc_type=IOCType.FILE_HASH,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=self._calculate_threat_level(threat_score),
            threat_score=threat_score,
            threat_types=self._extract_file_threat_types(attributes),
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "file_type": attributes.get("type_description", ""),
                "size": attributes.get("size", 0),
                "names": attributes.get("names", [])
            },
            sources=["VirusTotal"]
        )

    def _calculate_threat_level(self, score: float) -> ThreatLevel:
        """计算威胁级别"""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.CLEAN

    def _extract_threat_types(self, attributes: Dict) -> List[str]:
        """提取威胁类型"""
        threat_types = []
        categories = attributes.get("categories", {})
        for category in categories.values():
            if category not in threat_types:
                threat_types.append(category)
        return threat_types

    def _extract_file_threat_types(self, attributes: Dict) -> List[str]:
        """提取文件威胁类型"""
        threat_types = []
        results = attributes.get("last_analysis_results", {})
        for engine_result in results.values():
            category = engine_result.get("category")
            if category == "malicious":
                result = engine_result.get("result", "")
                if result and result not in threat_types:
                    threat_types.append(result)
        return threat_types[:5]  # 限制数量

    def _create_clean_result(self, ioc_value: str, ioc_type: IOCType) -> ThreatIntelResult:
        """创建干净结果"""
        return ThreatIntelResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=self.provider_name,
            is_malicious=False,
            threat_level=ThreatLevel.CLEAN,
            threat_score=0.0,
            sources=["VirusTotal"]
        )

    # Mock方法
    def _mock_ip_result(self, ip: str) -> ThreatIntelResult:
        """Mock IP查询"""
        is_malicious = ip.startswith("192.168.1.100")
        return ThreatIntelResult(
            ioc_value=ip,
            ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=ThreatLevel.HIGH if is_malicious else ThreatLevel.CLEAN,
            threat_score=85.0 if is_malicious else 0.0,
            threat_types=["C2", "Malware"] if is_malicious else [],
            sources=["VirusTotal (Mock)"]
        )

    def _mock_domain_result(self, domain: str) -> ThreatIntelResult:
        """Mock域名查询"""
        is_malicious = "malicious" in domain.lower()
        return ThreatIntelResult(
            ioc_value=domain,
            ioc_type=IOCType.DOMAIN,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=ThreatLevel.HIGH if is_malicious else ThreatLevel.CLEAN,
            threat_score=80.0 if is_malicious else 0.0,
            threat_types=["Phishing"] if is_malicious else [],
            sources=["VirusTotal (Mock)"]
        )

    def _mock_url_result(self, url: str) -> ThreatIntelResult:
        """Mock URL查询"""
        is_malicious = "phishing" in url.lower() or "malware" in url.lower()
        return ThreatIntelResult(
            ioc_value=url,
            ioc_type=IOCType.URL,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=ThreatLevel.HIGH if is_malicious else ThreatLevel.CLEAN,
            threat_score=75.0 if is_malicious else 0.0,
            sources=["VirusTotal (Mock)"]
        )

    def _mock_hash_result(self, file_hash: str) -> ThreatIntelResult:
        """Mock文件哈希查询"""
        is_malicious = file_hash.startswith("abc")
        return ThreatIntelResult(
            ioc_value=file_hash,
            ioc_type=IOCType.FILE_HASH,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=ThreatLevel.CRITICAL if is_malicious else ThreatLevel.CLEAN,
            threat_score=95.0 if is_malicious else 0.0,
            threat_types=["Trojan", "Backdoor"] if is_malicious else [],
            sources=["VirusTotal (Mock)"]
        )


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB威胁情报提供商"""

    def __init__(self, config: ThreatIntelConfig):
        super().__init__(config)
        self.api_url = config.api_url or "https://api.abuseipdb.com/api/v2"
        self.api_key = config.api_key

    async def query_ip(self, ip: str) -> ThreatIntelResult:
        """查询IP"""
        if self.config.use_mock:
            return self._mock_ip_result(ip)

        try:
            url = f"{self.api_url}/check"
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {"ipAddress": ip, "maxAgeInDays": "90"}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(ip, data)
                    else:
                        error = f"API错误: {response.status}"
                        return self._create_error_result(ip, IOCType.IP, error)

        except Exception as e:
            return self._create_error_result(ip, IOCType.IP, str(e))

    async def query_domain(self, domain: str) -> ThreatIntelResult:
        """AbuseIPDB不支持域名查询"""
        return self._create_error_result(domain, IOCType.DOMAIN, "不支持域名查询")

    async def query_url(self, url: str) -> ThreatIntelResult:
        """AbuseIPDB不支持URL查询"""
        return self._create_error_result(url, IOCType.URL, "不支持URL查询")

    async def query_file_hash(self, file_hash: str) -> ThreatIntelResult:
        """AbuseIPDB不支持文件哈希查询"""
        return self._create_error_result(file_hash, IOCType.FILE_HASH, "不支持文件哈希查询")

    def _parse_response(self, ip: str, data: Dict) -> ThreatIntelResult:
        """解析响应"""
        ip_data = data.get("data", {})
        abuse_score = ip_data.get("abuseConfidenceScore", 0)
        is_malicious = abuse_score > 50

        return ThreatIntelResult(
            ioc_value=ip,
            ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=self._calculate_threat_level(abuse_score),
            threat_score=float(abuse_score),
            details={
                "total_reports": ip_data.get("totalReports", 0),
                "num_distinct_users": ip_data.get("numDistinctUsers", 0),
                "country_code": ip_data.get("countryCode", ""),
                "usage_type": ip_data.get("usageType", ""),
                "isp": ip_data.get("isp", "")
            },
            sources=["AbuseIPDB"]
        )

    def _calculate_threat_level(self, score: float) -> ThreatLevel:
        """计算威胁级别"""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.CLEAN

    def _mock_ip_result(self, ip: str) -> ThreatIntelResult:
        """Mock IP查询"""
        is_malicious = ip.startswith("10.0.0.")
        return ThreatIntelResult(
            ioc_value=ip,
            ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=is_malicious,
            threat_level=ThreatLevel.HIGH if is_malicious else ThreatLevel.CLEAN,
            threat_score=75.0 if is_malicious else 0.0,
            sources=["AbuseIPDB (Mock)"]
        )


# 其他提供商的简化实现
class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault OTX提供商"""

    def __init__(self, config: ThreatIntelConfig):
        super().__init__(config)
        self.api_url = config.api_url or "https://otx.alienvault.com/api/v1"
        self.api_key = config.api_key

    async def query_ip(self, ip: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_ip(ip)
        try:
            url = f"{self.api_url}/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": self.api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_ip(ip, data)
                    return self._create_error_result(ip, IOCType.IP, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(ip, IOCType.IP, str(e))

    async def query_domain(self, domain: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_domain(domain)
        try:
            url = f"{self.api_url}/indicators/domain/{domain}/general"
            headers = {"X-OTX-API-KEY": self.api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_domain(domain, data)
                    return self._create_error_result(domain, IOCType.DOMAIN, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(domain, IOCType.DOMAIN, str(e))

    async def query_url(self, url_str: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_clean(url_str, IOCType.URL)
        return self._create_error_result(url_str, IOCType.URL, "OTX不直接支持URL查询")

    async def query_file_hash(self, file_hash: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_hash(file_hash)
        try:
            url = f"{self.api_url}/indicators/file/{file_hash}/general"
            headers = {"X-OTX-API-KEY": self.api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        pulses = data.get("pulse_info", {}).get("count", 0)
                        score = min(pulses * 15, 100)
                        return ThreatIntelResult(
                            ioc_value=file_hash, ioc_type=IOCType.FILE_HASH,
                            provider=self.provider_name,
                            is_malicious=pulses > 0,
                            threat_level=self._score_to_level(score),
                            threat_score=score,
                            threat_types=["malware"] if pulses > 0 else [],
                            details={"pulse_count": pulses},
                            sources=["AlienVault OTX"],
                        )
                    return self._create_error_result(file_hash, IOCType.FILE_HASH, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(file_hash, IOCType.FILE_HASH, str(e))

    def _parse_ip(self, ip: str, data: Dict) -> ThreatIntelResult:
        pulses = data.get("pulse_info", {}).get("count", 0)
        reputation = data.get("reputation", 0)
        score = min(pulses * 10 + abs(reputation) * 5, 100)
        return ThreatIntelResult(
            ioc_value=ip, ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=pulses > 0,
            threat_level=self._score_to_level(score),
            threat_score=score,
            threat_types=self._extract_tags(data),
            details={"pulse_count": pulses, "reputation": reputation,
                     "country": data.get("country_name", "")},
            sources=["AlienVault OTX"],
        )

    def _parse_domain(self, domain: str, data: Dict) -> ThreatIntelResult:
        pulses = data.get("pulse_info", {}).get("count", 0)
        score = min(pulses * 12, 100)
        return ThreatIntelResult(
            ioc_value=domain, ioc_type=IOCType.DOMAIN,
            provider=self.provider_name,
            is_malicious=pulses > 0,
            threat_level=self._score_to_level(score),
            threat_score=score,
            threat_types=self._extract_tags(data),
            details={"pulse_count": pulses},
            sources=["AlienVault OTX"],
        )

    @staticmethod
    def _extract_tags(data: Dict) -> List[str]:
        tags = set()
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.update(pulse.get("tags", []))
        return list(tags)[:10]

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        if score >= 80: return ThreatLevel.CRITICAL
        if score >= 60: return ThreatLevel.HIGH
        if score >= 30: return ThreatLevel.MEDIUM
        if score > 0: return ThreatLevel.LOW
        return ThreatLevel.CLEAN

    def _mock_ip(self, ip: str) -> ThreatIntelResult:
        is_suspicious = ip.startswith("10.0.") or ip.endswith(".1")
        score = 45.0 if is_suspicious else 0.0
        return ThreatIntelResult(
            ioc_value=ip, ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=is_suspicious,
            threat_level=ThreatLevel.MEDIUM if is_suspicious else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["scanning"] if is_suspicious else [],
            details={"pulse_count": 3 if is_suspicious else 0, "country": "CN"},
            sources=["AlienVault OTX (Mock)"],
        )

    def _mock_domain(self, domain: str) -> ThreatIntelResult:
        is_suspicious = any(kw in domain for kw in ("malware", "phish", "evil", "bad"))
        score = 70.0 if is_suspicious else 0.0
        return ThreatIntelResult(
            ioc_value=domain, ioc_type=IOCType.DOMAIN,
            provider=self.provider_name,
            is_malicious=is_suspicious,
            threat_level=ThreatLevel.HIGH if is_suspicious else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["phishing"] if is_suspicious else [],
            details={"pulse_count": 5 if is_suspicious else 0},
            sources=["AlienVault OTX (Mock)"],
        )

    def _mock_hash(self, file_hash: str) -> ThreatIntelResult:
        is_suspicious = file_hash.startswith("bad") or file_hash.startswith("mal")
        score = 80.0 if is_suspicious else 0.0
        return ThreatIntelResult(
            ioc_value=file_hash, ioc_type=IOCType.FILE_HASH,
            provider=self.provider_name,
            is_malicious=is_suspicious,
            threat_level=ThreatLevel.CRITICAL if is_suspicious else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["malware"] if is_suspicious else [],
            details={"pulse_count": 8 if is_suspicious else 0},
            sources=["AlienVault OTX (Mock)"],
        )

    def _mock_clean(self, ioc_value: str, ioc_type: IOCType) -> ThreatIntelResult:
        return ThreatIntelResult(
            ioc_value=ioc_value, ioc_type=ioc_type,
            provider=self.provider_name,
            is_malicious=False, threat_level=ThreatLevel.CLEAN,
            threat_score=0.0, sources=["AlienVault OTX (Mock)"],
        )


class ShodanProvider(ThreatIntelProvider):
    """Shodan提供商"""

    def __init__(self, config: ThreatIntelConfig):
        super().__init__(config)
        self.api_url = config.api_url or "https://api.shodan.io"
        self.api_key = config.api_key

    async def query_ip(self, ip: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_ip(ip)
        try:
            url = f"{self.api_url}/shodan/host/{ip}?key={self.api_key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_ip(ip, data)
                    return self._create_error_result(ip, IOCType.IP, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(ip, IOCType.IP, str(e))

    async def query_domain(self, domain: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_domain(domain)
        try:
            url = f"{self.api_url}/dns/resolve?hostnames={domain}&key={self.api_key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        resolved_ip = data.get(domain)
                        if resolved_ip:
                            return await self.query_ip(resolved_ip)
                    return self._create_clean_result(domain, IOCType.DOMAIN)
        except Exception as e:
            return self._create_error_result(domain, IOCType.DOMAIN, str(e))

    async def query_url(self, url: str) -> ThreatIntelResult:
        return self._create_error_result(url, IOCType.URL, "Shodan不支持URL查询")

    async def query_file_hash(self, file_hash: str) -> ThreatIntelResult:
        return self._create_error_result(file_hash, IOCType.FILE_HASH, "Shodan不支持文件哈希查询")

    def _parse_ip(self, ip: str, data: Dict) -> ThreatIntelResult:
        vulns = data.get("vulns", [])
        ports = data.get("ports", [])
        tags = data.get("tags", [])
        score = min(len(vulns) * 15 + len(ports) * 2, 100)
        return ThreatIntelResult(
            ioc_value=ip, ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=len(vulns) > 0,
            threat_level=self._score_to_level(score),
            threat_score=score,
            threat_types=tags[:5],
            details={"open_ports": ports[:20], "vulns": vulns[:10],
                     "org": data.get("org", ""), "os": data.get("os", ""),
                     "country": data.get("country_code", "")},
            sources=["Shodan"],
        )

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        if score >= 80: return ThreatLevel.CRITICAL
        if score >= 60: return ThreatLevel.HIGH
        if score >= 30: return ThreatLevel.MEDIUM
        if score > 0: return ThreatLevel.LOW
        return ThreatLevel.CLEAN

    def _mock_ip(self, ip: str) -> ThreatIntelResult:
        has_vulns = ip.endswith(".100") or ip.endswith(".200")
        score = 55.0 if has_vulns else 10.0
        return ThreatIntelResult(
            ioc_value=ip, ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=has_vulns,
            threat_level=ThreatLevel.MEDIUM if has_vulns else ThreatLevel.LOW,
            threat_score=score,
            threat_types=["vulnerable"] if has_vulns else [],
            details={"open_ports": [22, 80, 443], "vulns": ["CVE-2024-0001"] if has_vulns else [],
                     "org": "Mock ISP", "country": "US"},
            sources=["Shodan (Mock)"],
        )

    def _mock_domain(self, domain: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            ioc_value=domain, ioc_type=IOCType.DOMAIN,
            provider=self.provider_name,
            is_malicious=False, threat_level=ThreatLevel.CLEAN,
            threat_score=0.0,
            details={"resolved_ip": "93.184.216.34"},
            sources=["Shodan (Mock)"],
        )

    def _create_clean_result(self, ioc_value: str, ioc_type: IOCType) -> ThreatIntelResult:
        return ThreatIntelResult(
            ioc_value=ioc_value, ioc_type=ioc_type,
            provider=self.provider_name,
            is_malicious=False, threat_level=ThreatLevel.CLEAN,
            threat_score=0.0, sources=["Shodan"],
        )


class GreyNoiseProvider(ThreatIntelProvider):
    """GreyNoise提供商"""

    def __init__(self, config: ThreatIntelConfig):
        super().__init__(config)
        self.api_url = config.api_url or "https://api.greynoise.io/v3"
        self.api_key = config.api_key

    async def query_ip(self, ip: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_ip(ip)
        try:
            url = f"{self.api_url}/community/{ip}"
            headers = {"key": self.api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_ip(ip, data)
                    return self._create_error_result(ip, IOCType.IP, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(ip, IOCType.IP, str(e))

    async def query_domain(self, domain: str) -> ThreatIntelResult:
        return self._create_error_result(domain, IOCType.DOMAIN, "GreyNoise不支持域名查询")

    async def query_url(self, url: str) -> ThreatIntelResult:
        return self._create_error_result(url, IOCType.URL, "GreyNoise不支持URL查询")

    async def query_file_hash(self, file_hash: str) -> ThreatIntelResult:
        return self._create_error_result(file_hash, IOCType.FILE_HASH, "GreyNoise不支持文件哈希查询")

    def _parse_ip(self, ip: str, data: Dict) -> ThreatIntelResult:
        classification = data.get("classification", "unknown")
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        name = data.get("name", "unknown")

        if classification == "malicious":
            score, level = 75.0, ThreatLevel.HIGH
        elif classification == "benign" or riot:
            score, level = 0.0, ThreatLevel.CLEAN
        elif noise:
            score, level = 30.0, ThreatLevel.MEDIUM
        else:
            score, level = 10.0, ThreatLevel.LOW

        return ThreatIntelResult(
            ioc_value=ip, ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=classification == "malicious",
            threat_level=level, threat_score=score,
            threat_types=[classification] if classification != "unknown" else [],
            details={"classification": classification, "noise": noise,
                     "riot": riot, "name": name},
            sources=["GreyNoise"],
        )

    def _mock_ip(self, ip: str) -> ThreatIntelResult:
        is_noisy = ip.startswith("10.") or ip.endswith(".50")
        score = 30.0 if is_noisy else 0.0
        return ThreatIntelResult(
            ioc_value=ip, ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=False,
            threat_level=ThreatLevel.MEDIUM if is_noisy else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["scanner"] if is_noisy else [],
            details={"classification": "benign", "noise": is_noisy, "riot": False},
            sources=["GreyNoise (Mock)"],
        )


class URLhausProvider(ThreatIntelProvider):
    """URLhaus提供商 - abuse.ch URL威胁情报"""

    def __init__(self, config: ThreatIntelConfig):
        super().__init__(config)
        self.api_url = config.api_url or "https://urlhaus-api.abuse.ch/v1"

    async def query_ip(self, ip: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_ip(ip)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/host/",
                    data={"host": ip},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_host(ip, IOCType.IP, data)
                    return self._create_error_result(ip, IOCType.IP, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(ip, IOCType.IP, str(e))

    async def query_domain(self, domain: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_domain(domain)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/host/",
                    data={"host": domain},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_host(domain, IOCType.DOMAIN, data)
                    return self._create_error_result(domain, IOCType.DOMAIN, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(domain, IOCType.DOMAIN, str(e))

    async def query_url(self, url_str: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_url(url_str)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/url/",
                    data={"url": url_str},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_url(url_str, data)
                    return self._create_error_result(url_str, IOCType.URL, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(url_str, IOCType.URL, str(e))

    async def query_file_hash(self, file_hash: str) -> ThreatIntelResult:
        if self.config.use_mock:
            return self._mock_hash(file_hash)
        try:
            hash_type = "md5_hash" if len(file_hash) == 32 else "sha256_hash"
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/payload/",
                    data={hash_type: file_hash},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_payload(file_hash, data)
                    return self._create_error_result(file_hash, IOCType.FILE_HASH, f"HTTP {resp.status}")
        except Exception as e:
            return self._create_error_result(file_hash, IOCType.FILE_HASH, str(e))

    def _parse_host(self, host: str, ioc_type: IOCType, data: Dict) -> ThreatIntelResult:
        status = data.get("query_status", "no_results")
        url_count = data.get("urls_online", 0) or 0
        score = min(url_count * 20, 100)
        return ThreatIntelResult(
            ioc_value=host, ioc_type=ioc_type,
            provider=self.provider_name,
            is_malicious=url_count > 0,
            threat_level=self._score_to_level(score),
            threat_score=score,
            threat_types=["malware_hosting"] if url_count > 0 else [],
            details={"urls_online": url_count, "status": status},
            sources=["URLhaus"],
        )

    def _parse_url(self, url_str: str, data: Dict) -> ThreatIntelResult:
        status = data.get("query_status", "no_results")
        threat = data.get("threat", "")
        is_mal = status == "listed"
        score = 85.0 if is_mal else 0.0
        return ThreatIntelResult(
            ioc_value=url_str, ioc_type=IOCType.URL,
            provider=self.provider_name,
            is_malicious=is_mal,
            threat_level=ThreatLevel.HIGH if is_mal else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=[threat] if threat else [],
            details={"status": status, "threat": threat},
            sources=["URLhaus"],
        )

    def _parse_payload(self, file_hash: str, data: Dict) -> ThreatIntelResult:
        status = data.get("query_status", "no_results")
        is_mal = status == "ok"
        score = 90.0 if is_mal else 0.0
        sig = data.get("signature", "")
        return ThreatIntelResult(
            ioc_value=file_hash, ioc_type=IOCType.FILE_HASH,
            provider=self.provider_name,
            is_malicious=is_mal,
            threat_level=ThreatLevel.CRITICAL if is_mal else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=[sig] if sig else [],
            details={"status": status, "signature": sig},
            sources=["URLhaus"],
        )

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        if score >= 80: return ThreatLevel.CRITICAL
        if score >= 60: return ThreatLevel.HIGH
        if score >= 30: return ThreatLevel.MEDIUM
        if score > 0: return ThreatLevel.LOW
        return ThreatLevel.CLEAN

    def _mock_ip(self, ip: str) -> ThreatIntelResult:
        is_bad = ip.endswith(".66") or ip.endswith(".99")
        score = 60.0 if is_bad else 0.0
        return ThreatIntelResult(
            ioc_value=ip, ioc_type=IOCType.IP,
            provider=self.provider_name,
            is_malicious=is_bad,
            threat_level=ThreatLevel.HIGH if is_bad else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["malware_hosting"] if is_bad else [],
            details={"urls_online": 3 if is_bad else 0},
            sources=["URLhaus (Mock)"],
        )

    def _mock_domain(self, domain: str) -> ThreatIntelResult:
        is_bad = any(kw in domain for kw in ("malware", "evil", "bad"))
        score = 80.0 if is_bad else 0.0
        return ThreatIntelResult(
            ioc_value=domain, ioc_type=IOCType.DOMAIN,
            provider=self.provider_name,
            is_malicious=is_bad,
            threat_level=ThreatLevel.CRITICAL if is_bad else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["malware_distribution"] if is_bad else [],
            details={"urls_online": 5 if is_bad else 0},
            sources=["URLhaus (Mock)"],
        )

    def _mock_url(self, url_str: str) -> ThreatIntelResult:
        is_bad = any(kw in url_str for kw in ("malware", "evil", "payload", "exploit"))
        score = 85.0 if is_bad else 0.0
        return ThreatIntelResult(
            ioc_value=url_str, ioc_type=IOCType.URL,
            provider=self.provider_name,
            is_malicious=is_bad,
            threat_level=ThreatLevel.HIGH if is_bad else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["malware_download"] if is_bad else [],
            details={"status": "listed" if is_bad else "no_results"},
            sources=["URLhaus (Mock)"],
        )

    def _mock_hash(self, file_hash: str) -> ThreatIntelResult:
        is_bad = file_hash.startswith("bad") or file_hash.startswith("mal")
        score = 90.0 if is_bad else 0.0
        return ThreatIntelResult(
            ioc_value=file_hash, ioc_type=IOCType.FILE_HASH,
            provider=self.provider_name,
            is_malicious=is_bad,
            threat_level=ThreatLevel.CRITICAL if is_bad else ThreatLevel.CLEAN,
            threat_score=score,
            threat_types=["trojan"] if is_bad else [],
            details={"status": "ok" if is_bad else "no_results"},
            sources=["URLhaus (Mock)"],
        )


__all__ = [
    'VirusTotalProvider',
    'AbuseIPDBProvider',
    'AlienVaultOTXProvider',
    'ShodanProvider',
    'GreyNoiseProvider',
    'URLhausProvider',
]