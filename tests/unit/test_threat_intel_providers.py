"""
威胁情报提供商单元测试

测试所有提供商的mock模式查询
"""
import pytest
import asyncio
from src.threat_intel.base import ThreatIntelConfig, IOCType, ThreatLevel
from src.threat_intel.providers import (
    AlienVaultOTXProvider,
    ShodanProvider,
    GreyNoiseProvider,
    URLhausProvider,
)


def _mock_config(name: str) -> ThreatIntelConfig:
    return ThreatIntelConfig(provider_name=name, use_mock=True)


class TestAlienVaultOTXProvider:
    def test_query_ip_clean(self):
        p = AlienVaultOTXProvider(_mock_config("otx"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("8.8.8.8"))
        assert result.ioc_value == "8.8.8.8"
        assert result.provider == "otx"

    def test_query_ip_suspicious(self):
        p = AlienVaultOTXProvider(_mock_config("otx"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("10.0.1.1"))
        assert result.is_malicious is True
        assert result.threat_score > 0

    def test_query_domain_clean(self):
        p = AlienVaultOTXProvider(_mock_config("otx"))
        result = asyncio.get_event_loop().run_until_complete(p.query_domain("google.com"))
        assert result.is_malicious is False

    def test_query_domain_suspicious(self):
        p = AlienVaultOTXProvider(_mock_config("otx"))
        result = asyncio.get_event_loop().run_until_complete(p.query_domain("malware.example.com"))
        assert result.is_malicious is True
        assert result.threat_score > 0

    def test_query_file_hash_clean(self):
        p = AlienVaultOTXProvider(_mock_config("otx"))
        result = asyncio.get_event_loop().run_until_complete(p.query_file_hash("abc123"))
        assert result.is_malicious is False

    def test_query_file_hash_suspicious(self):
        p = AlienVaultOTXProvider(_mock_config("otx"))
        result = asyncio.get_event_loop().run_until_complete(p.query_file_hash("bad_hash_123"))
        assert result.is_malicious is True

    def test_query_url(self):
        p = AlienVaultOTXProvider(_mock_config("otx"))
        result = asyncio.get_event_loop().run_until_complete(p.query_url("https://example.com"))
        assert result.ioc_type == IOCType.URL


class TestShodanProvider:
    def test_query_ip_clean(self):
        p = ShodanProvider(_mock_config("shodan"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("8.8.8.8"))
        assert result.ioc_value == "8.8.8.8"
        assert result.provider == "shodan"

    def test_query_ip_with_vulns(self):
        p = ShodanProvider(_mock_config("shodan"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("10.0.0.100"))
        assert result.is_malicious is True
        assert "open_ports" in result.details

    def test_query_domain(self):
        p = ShodanProvider(_mock_config("shodan"))
        result = asyncio.get_event_loop().run_until_complete(p.query_domain("example.com"))
        assert result.ioc_type == IOCType.DOMAIN

    def test_query_url_unsupported(self):
        p = ShodanProvider(_mock_config("shodan"))
        result = asyncio.get_event_loop().run_until_complete(p.query_url("https://x.com"))
        assert result.error is not None


class TestGreyNoiseProvider:
    def test_query_ip_clean(self):
        p = GreyNoiseProvider(_mock_config("greynoise"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("8.8.8.8"))
        assert result.provider == "greynoise"
        assert result.is_malicious is False

    def test_query_ip_noisy(self):
        p = GreyNoiseProvider(_mock_config("greynoise"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("10.0.0.50"))
        assert result.threat_score > 0
        assert "classification" in result.details

    def test_query_domain_unsupported(self):
        p = GreyNoiseProvider(_mock_config("greynoise"))
        result = asyncio.get_event_loop().run_until_complete(p.query_domain("example.com"))
        assert result.error is not None

    def test_query_file_hash_unsupported(self):
        p = GreyNoiseProvider(_mock_config("greynoise"))
        result = asyncio.get_event_loop().run_until_complete(p.query_file_hash("abc"))
        assert result.error is not None


class TestURLhausProvider:
    def test_query_ip_clean(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("8.8.8.8"))
        assert result.provider == "urlhaus"
        assert result.is_malicious is False

    def test_query_ip_malicious(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_ip("10.0.0.66"))
        assert result.is_malicious is True
        assert result.threat_score > 0

    def test_query_domain_clean(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_domain("google.com"))
        assert result.is_malicious is False

    def test_query_domain_malicious(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_domain("malware.bad.com"))
        assert result.is_malicious is True

    def test_query_url_clean(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_url("https://safe.com"))
        assert result.is_malicious is False

    def test_query_url_malicious(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_url("https://evil.com/payload"))
        assert result.is_malicious is True

    def test_query_hash_clean(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_file_hash("clean123"))
        assert result.is_malicious is False

    def test_query_hash_malicious(self):
        p = URLhausProvider(_mock_config("urlhaus"))
        result = asyncio.get_event_loop().run_until_complete(p.query_file_hash("bad_trojan"))
        assert result.is_malicious is True
