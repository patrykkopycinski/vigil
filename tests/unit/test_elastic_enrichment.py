"""Unit tests for ElasticEnrichmentService — enrichment, risk, TI, and Claude analysis."""

from unittest.mock import Mock, patch, MagicMock

import pytest

from services.elastic_enrichment_service import ElasticEnrichmentService


class TestExtractIndicators:

    def _make_service(self):
        es = Mock()
        claude = Mock()
        return ElasticEnrichmentService(elastic_service=es, claude_service=claude)

    def test_extracts_ips_from_entities(self):
        svc = self._make_service()
        case = {"title": "Test Case"}
        findings = [
            {"entities": {"ip_addresses": ["8.8.8.8", "1.1.1.1"], "usernames": [], "hostnames": [], "domains": [], "file_hashes": []}}
        ]
        indicators = svc.extract_indicators(case, findings)
        assert "8.8.8.8" in indicators["ips"]
        assert "1.1.1.1" in indicators["ips"]

    def test_filters_private_ips(self):
        svc = self._make_service()
        case = {"description": "Source 192.168.1.1 and 8.8.8.8"}
        findings = []
        indicators = svc.extract_indicators(case, findings)
        assert "192.168.1.1" not in indicators["ips"]
        assert "8.8.8.8" in indicators["ips"]

    def test_filters_common_domains(self):
        svc = self._make_service()
        case = {"description": "Connected to server.local and evil.com"}
        findings = []
        indicators = svc.extract_indicators(case, findings)
        assert "server.local" not in indicators["domains"]

    def test_extracts_hashes_from_findings(self):
        svc = self._make_service()
        case = {}
        findings = [
            {"entities": {"file_hashes": ["a" * 64], "ip_addresses": [], "usernames": [], "hostnames": [], "domains": []}}
        ]
        indicators = svc.extract_indicators(case, findings)
        assert "a" * 64 in indicators["hashes"]

    def test_extracts_usernames_from_entity_context(self):
        svc = self._make_service()
        case = {}
        findings = [
            {
                "entities": {"ip_addresses": [], "usernames": [], "hostnames": [], "domains": [], "file_hashes": []},
                "entity_context": {"user": "admin", "src_ip": "8.8.8.8"},
            }
        ]
        indicators = svc.extract_indicators(case, findings)
        assert "admin" in indicators["usernames"]
        assert "8.8.8.8" in indicators["ips"]

    def test_deduplicates(self):
        svc = self._make_service()
        case = {"title": "IP 8.8.8.8 twice: 8.8.8.8"}
        findings = [
            {"entities": {"ip_addresses": ["8.8.8.8"], "usernames": [], "hostnames": [], "domains": [], "file_hashes": []}}
        ]
        indicators = svc.extract_indicators(case, findings)
        assert indicators["ips"].count("8.8.8.8") == 1


class TestQueryElasticForIndicators:

    def test_queries_all_indicator_types(self):
        es = Mock()
        es.search_by_ip.return_value = [{"event": "network"}]
        es.search_by_domain.return_value = []
        es.search_by_hash.return_value = []
        es.search_by_username.return_value = [{"event": "login"}]
        es.search_by_hostname.return_value = []

        svc = ElasticEnrichmentService(elastic_service=es, claude_service=Mock())
        indicators = {"ips": ["8.8.8.8"], "domains": ["evil.com"], "hashes": [], "usernames": ["jdoe"], "hostnames": []}

        result = svc.query_elastic_for_indicators(indicators, hours=24)
        assert result["summary"]["total_events"] == 2
        es.search_by_ip.assert_called_once_with("8.8.8.8", hours=24)
        es.search_by_username.assert_called_once_with("jdoe", hours=24)

    def test_limits_per_type_to_10(self):
        es = Mock()
        es.search_by_ip.return_value = []
        svc = ElasticEnrichmentService(elastic_service=es, claude_service=Mock())
        indicators = {"ips": [f"1.2.3.{i}" for i in range(20)], "domains": [], "hashes": [], "usernames": [], "hostnames": []}

        svc.query_elastic_for_indicators(indicators, hours=24)
        assert es.search_by_ip.call_count == 10

    def test_handles_query_errors_gracefully(self):
        es = Mock()
        es.search_by_ip.side_effect = RuntimeError("connection lost")
        svc = ElasticEnrichmentService(elastic_service=es, claude_service=Mock())
        indicators = {"ips": ["8.8.8.8"], "domains": [], "hashes": [], "usernames": [], "hostnames": []}

        result = svc.query_elastic_for_indicators(indicators)
        assert result["summary"]["total_events"] == 0


class TestGetRiskScores:

    def test_fetches_user_and_host_scores(self):
        es = Mock()
        es.get_risk_score.side_effect = [
            {"risk_score": 80, "risk_level": "High"},
            {"risk_score": 45, "risk_level": "Moderate"},
        ]
        svc = ElasticEnrichmentService(elastic_service=es, claude_service=Mock())
        indicators = {"usernames": ["admin"], "hostnames": ["srv-01"]}

        scores = svc.get_risk_scores(indicators)
        assert "user:admin" in scores
        assert "host:srv-01" in scores
        assert scores["user:admin"]["risk_score"] == 80

    def test_skips_null_scores(self):
        es = Mock()
        es.get_risk_score.return_value = {"risk_score": None, "risk_level": "Unknown"}
        svc = ElasticEnrichmentService(elastic_service=es, claude_service=Mock())
        indicators = {"usernames": ["nobody"], "hostnames": []}

        scores = svc.get_risk_scores(indicators)
        assert len(scores) == 0


class TestGetThreatIntelligence:

    def test_queries_ti_indices(self):
        es = Mock()
        es.run_esql.side_effect = [
            [{"threat.indicator.ip": "8.8.8.8", "threat.feed.name": "abuse.ch"}],
            [],
        ]
        svc = ElasticEnrichmentService(elastic_service=es, claude_service=Mock())
        indicators = {"ips": ["8.8.8.8"], "domains": ["safe.com"], "hashes": []}

        matches = svc.get_threat_intelligence(indicators)
        assert "ip:8.8.8.8" in matches
        assert len(matches["ip:8.8.8.8"]) == 1

    def test_handles_missing_ti_indices(self):
        es = Mock()
        es.run_esql.side_effect = RuntimeError("index_not_found")
        svc = ElasticEnrichmentService(elastic_service=es, claude_service=Mock())
        indicators = {"ips": ["1.2.3.4"], "domains": [], "hashes": []}

        matches = svc.get_threat_intelligence(indicators)
        assert matches == {}


class TestAnalyzeWithClaude:

    def test_calls_claude_with_prompt(self):
        es = Mock()
        claude = Mock()
        claude.has_api_key.return_value = True
        claude.chat.return_value = "Analysis: Suspicious C2 activity detected."

        svc = ElasticEnrichmentService(elastic_service=es, claude_service=claude)
        result = svc.analyze_with_claude(
            case={"case_id": "c1", "title": "Test"},
            findings=[{"finding_id": "f1", "severity": "high", "data_source": "elastic", "timestamp": "2025-01-01"}],
            enrichment_data={"summary": {"total_events": 5}},
            risk_scores={"user:admin": {"risk_score": 80, "risk_level": "High"}},
            ti_matches={"ip:8.8.8.8": [{"feed": "abuse.ch"}]},
        )

        assert "Suspicious C2" in result
        claude.chat.assert_called_once()
        prompt = claude.chat.call_args[0][0]
        assert "Entity Analytics" in prompt or "Risk Scores" in prompt

    def test_skips_when_no_api_key(self):
        es = Mock()
        claude = Mock()
        claude.has_api_key.return_value = False
        svc = ElasticEnrichmentService(elastic_service=es, claude_service=claude)

        result = svc.analyze_with_claude({}, [], {})
        assert "not available" in result
        claude.chat.assert_not_called()


class TestPrivateHelpers:

    def test_is_private_ip(self):
        assert ElasticEnrichmentService._is_private_ip("10.0.0.1") is True
        assert ElasticEnrichmentService._is_private_ip("172.16.0.1") is True
        assert ElasticEnrichmentService._is_private_ip("192.168.1.1") is True
        assert ElasticEnrichmentService._is_private_ip("127.0.0.1") is True
        assert ElasticEnrichmentService._is_private_ip("8.8.8.8") is False
        assert ElasticEnrichmentService._is_private_ip("203.0.113.1") is False

    def test_is_common_domain(self):
        assert ElasticEnrichmentService._is_common_domain("server.local") is True
        assert ElasticEnrichmentService._is_common_domain("host.internal") is True
        assert ElasticEnrichmentService._is_common_domain("evil.com") is False
