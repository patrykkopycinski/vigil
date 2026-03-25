"""Unit tests for ElasticIngestion — alert ingestion and ECS-to-finding mapping."""

from unittest.mock import patch, Mock, MagicMock
from datetime import datetime, timezone

import pytest

from services.elastic_ingestion import ElasticIngestion, _nested


# ── _nested helper ────────────────────────────────────────────────────────────

class TestNestedHelper:

    def test_simple_key(self):
        assert _nested({"a": 1}, "a") == 1

    def test_deep_key(self):
        d = {"kibana": {"alert": {"rule": {"name": "MyRule"}}}}
        assert _nested(d, "kibana.alert.rule.name") == "MyRule"

    def test_missing_key(self):
        assert _nested({"a": 1}, "b", "default") == "default"

    def test_missing_intermediate(self):
        assert _nested({"a": {"b": 1}}, "a.c.d") is None

    def test_non_dict_intermediate(self):
        assert _nested({"a": "string"}, "a.b") is None


# ── ElasticIngestion init ────────────────────────────────────────────────────

class TestElasticIngestionInit:

    @patch("services.elastic_ingestion.get_integration_config", return_value={})
    def test_init_sets_siem_name(self, _mock_config):
        ing = ElasticIngestion()
        assert ing.siem_name == "Elastic"
        assert ing.elastic_service is None

    @patch("services.elastic_ingestion.get_integration_config", return_value={"elasticsearch_url": "http://es:9200"})
    def test_get_elastic_service_creates_from_config(self, _mock_config):
        ing = ElasticIngestion()
        svc = ing._get_elastic_service()
        assert svc is not None
        assert svc.url == "http://es:9200"

    @patch("services.elastic_ingestion.get_integration_config", return_value={})
    def test_get_elastic_service_no_url(self, _mock_config):
        ing = ElasticIngestion()
        svc = ing._get_elastic_service()
        assert svc is None

    @patch("services.elastic_ingestion.get_integration_config", return_value={"cloud_id": "deploy:abc"})
    def test_get_elastic_service_cloud_id(self, _mock_config):
        ing = ElasticIngestion()
        svc = ing._get_elastic_service()
        assert svc is not None
        assert svc.cloud_id == "deploy:abc"


# ── transform_alert_to_finding ───────────────────────────────────────────────

class TestTransformAlertToFinding:

    @patch("services.elastic_ingestion.get_integration_config", return_value={})
    def _make_ingestion(self, _mock):
        return ElasticIngestion()

    def _sample_alert(self, **overrides):
        base = {
            "@timestamp": "2025-03-25T10:00:00Z",
            "kibana": {
                "alert": {
                    "uuid": "alert-uuid-001",
                    "rule": {
                        "name": "Suspicious DNS Request",
                        "description": "Detects DNS queries to known C2 domains",
                        "uuid": "rule-uuid-001",
                        "index": [".alerts-security.alerts-default"],
                    },
                    "severity": "high",
                    "workflow_status": "open",
                    "risk_score": 73,
                },
            },
            "source": {"ip": "10.1.2.3"},
            "destination": {"ip": "203.0.113.50"},
            "user": {"name": "jdoe"},
            "host": {"name": "workstation-42"},
            "dns": {"question": {"name": "evil.example.com"}},
            "file": {"hash": {"sha256": "abc123def456", "md5": "abcdef"}},
            "threat": [
                {
                    "tactic": {"id": "TA0011", "name": "Command and Control"},
                    "technique": [{"id": "T1071", "name": "Application Layer Protocol"}],
                }
            ],
        }
        base.update(overrides)
        return base

    def test_basic_transform(self):
        ing = self._make_ingestion()
        alert = self._sample_alert()
        finding = ing.transform_alert_to_finding(alert)

        assert finding is not None
        assert finding["finding_id"] == "elastic-alert-uuid-001"
        assert finding["title"] == "Suspicious DNS Request"
        assert finding["data_source"] == "elastic"
        assert finding["timestamp"] == "2025-03-25T10:00:00Z"

    def test_severity_mapping(self):
        ing = self._make_ingestion()
        for sev in ("critical", "high", "medium", "low"):
            alert = self._sample_alert()
            alert["kibana"]["alert"]["severity"] = sev
            finding = ing.transform_alert_to_finding(alert)
            assert finding["severity"] in ("critical", "high", "medium", "low")

    def test_entity_extraction(self):
        ing = self._make_ingestion()
        alert = self._sample_alert()
        finding = ing.transform_alert_to_finding(alert)

        entities = finding["entities"]
        assert "10.1.2.3" in entities["ip_addresses"]
        assert "203.0.113.50" in entities["ip_addresses"]
        assert "jdoe" in entities["usernames"]
        assert "workstation-42" in entities["hostnames"]
        assert "evil.example.com" in entities["domains"]
        assert "abc123def456" in entities["file_hashes"]

    def test_mitre_attack_extraction(self):
        ing = self._make_ingestion()
        alert = self._sample_alert()
        finding = ing.transform_alert_to_finding(alert)

        mitre = finding["mitre_attack"]
        assert "TA0011" in mitre["tactics"]
        assert "T1071" in mitre["techniques"]

    def test_metadata_preserved(self):
        ing = self._make_ingestion()
        alert = self._sample_alert()
        finding = ing.transform_alert_to_finding(alert)

        meta = finding["metadata"]
        assert meta["alert_uuid"] == "alert-uuid-001"
        assert meta["rule_id"] == "rule-uuid-001"
        assert meta["workflow_status"] == "open"
        assert meta["risk_score"] == 73

    def test_raw_data_included(self):
        ing = self._make_ingestion()
        alert = self._sample_alert()
        finding = ing.transform_alert_to_finding(alert)
        assert finding["raw_data"] is alert

    def test_missing_uuid_generates_id(self):
        ing = self._make_ingestion()
        alert = self._sample_alert()
        alert["kibana"]["alert"]["uuid"] = ""
        finding = ing.transform_alert_to_finding(alert)
        assert finding["finding_id"].startswith("elastic-")
        assert len(finding["finding_id"]) > len("elastic-")

    def test_missing_entities_empty_lists(self):
        ing = self._make_ingestion()
        alert = {
            "@timestamp": "2025-01-01T00:00:00Z",
            "kibana": {"alert": {"uuid": "x", "rule": {"name": "Test"}, "severity": "low"}},
        }
        finding = ing.transform_alert_to_finding(alert)
        assert finding["entities"]["ip_addresses"] == []
        assert finding["entities"]["usernames"] == []
        assert finding["entities"]["hostnames"] == []

    def test_entity_context_populated(self):
        """entity_context must be set for daemon processor compatibility."""
        ing = self._make_ingestion()
        alert = self._sample_alert()
        finding = ing.transform_alert_to_finding(alert)

        ec = finding["entity_context"]
        assert "10.1.2.3" in ec["src_ips"]
        assert "203.0.113.50" in ec["dest_ips"]
        assert "workstation-42" in ec["hostnames"]
        assert "jdoe" in ec["usernames"]
        assert "abc123def456" in ec["file_hashes"]

    def test_mitre_predictions_populated(self):
        """mitre_predictions dict must be set for daemon triage prompt."""
        ing = self._make_ingestion()
        alert = self._sample_alert()
        finding = ing.transform_alert_to_finding(alert)

        mp = finding["mitre_predictions"]
        assert "T1071" in mp
        assert mp["T1071"] == "Application Layer Protocol"

    def test_entity_context_empty_when_no_entities(self):
        ing = self._make_ingestion()
        alert = {
            "@timestamp": "2025-01-01T00:00:00Z",
            "kibana": {"alert": {"uuid": "x", "rule": {"name": "Test"}, "severity": "low"}},
        }
        finding = ing.transform_alert_to_finding(alert)
        ec = finding["entity_context"]
        assert ec["src_ips"] == []
        assert ec["dest_ips"] == []
        assert ec["hostnames"] == []
        assert ec["usernames"] == []

    def test_malformed_alert_returns_none(self):
        ing = self._make_ingestion()
        finding = ing.transform_alert_to_finding(None)
        assert finding is None


# ── fetch_alerts ─────────────────────────────────────────────────────────────

class TestFetchAlerts:

    @pytest.mark.asyncio
    @patch("services.elastic_ingestion.get_integration_config", return_value={"elasticsearch_url": "http://es:9200"})
    async def test_fetch_alerts_calls_search(self, _mock_config):
        ing = ElasticIngestion()
        mock_es = Mock()
        mock_es.search_alerts.return_value = [{"kibana": {"alert": {"uuid": "a1"}}}]
        ing.elastic_service = mock_es

        alerts = await ing.fetch_alerts()
        assert len(alerts) == 1
        mock_es.search_alerts.assert_called_once()

    @pytest.mark.asyncio
    @patch("services.elastic_ingestion.get_integration_config", return_value={})
    async def test_fetch_alerts_no_service(self, _mock_config):
        ing = ElasticIngestion()
        alerts = await ing.fetch_alerts()
        assert alerts == []
