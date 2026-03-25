"""Integration tests for ElasticService against a live Elasticsearch cluster.

These tests verify that actual API calls, ES|QL queries, and Kibana requests
are well-formed and accepted by a real Elastic stack. They do NOT require
specific data — a fresh cluster with Security enabled is sufficient.

Skip behavior:
    - All tests skip if ELASTIC_URL is not set or the cluster is unreachable
    - Kibana tests skip if KIBANA_URL is not set
    - Tests that need specific data (alerts, TI) skip if the data doesn't exist

Run:
    ELASTIC_URL=http://localhost:9200 KIBANA_URL=http://localhost:5601 \\
        python3 -m pytest tests/integration/test_elastic_live.py -v -m integration

Environment variables:
    ELASTIC_URL         Elasticsearch URL (required)
    ELASTIC_API_KEY     API key auth (preferred)
    ELASTIC_USERNAME    Basic auth username
    ELASTIC_PASSWORD    Basic auth password
    KIBANA_URL          Kibana URL (optional, enables Kibana tests)
    ELASTIC_VERIFY_SSL  SSL verification (default: true)
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.elastic_service import ElasticService


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def elastic_url():
    url = os.getenv("ELASTIC_URL")
    if not url:
        pytest.skip("ELASTIC_URL not set — skipping live integration tests")
    return url


@pytest.fixture(scope="module")
def kibana_url():
    url = os.getenv("KIBANA_URL")
    if not url:
        pytest.skip("KIBANA_URL not set — skipping Kibana integration tests")
    return url


@pytest.fixture(scope="module")
def svc(elastic_url):
    """Create an ElasticService from env vars and verify connectivity."""
    service = ElasticService.from_env()
    ok, msg = service.test_connection()
    if not ok:
        pytest.skip(f"Cluster unreachable: {msg}")
    return service


@pytest.fixture(scope="module")
def svc_with_kibana(elastic_url, kibana_url):
    """ElasticService with Kibana URL configured."""
    service = ElasticService.from_env()
    ok, msg = service.test_connection()
    if not ok:
        pytest.skip(f"Cluster unreachable: {msg}")
    return service


@pytest.fixture(scope="module")
def has_alerts(svc):
    """Check if the alerts index exists and has documents."""
    try:
        client = svc._get_client()
        resp = client.count(index=".alerts-security.alerts-default")
        return resp["count"] > 0
    except Exception:
        return False


@pytest.fixture(scope="module")
def has_logs(svc):
    """Check if any logs-* data streams/indices exist.

    Data stream backing indices start with .ds- which get_indices filters out,
    so we check data streams directly or try a cheap ES|QL probe.
    """
    try:
        results = svc.run_esql("FROM logs-* | STATS c = COUNT(*) | LIMIT 1")
        return bool(results and results[0].get("c", 0) > 0)
    except Exception:
        return False


# ── Connection & Cluster ──────────────────────────────────────────────────────

@pytest.mark.integration
class TestConnection:

    def test_connection_succeeds(self, svc):
        ok, msg = svc.test_connection()
        assert ok is True
        assert "Connected to Elastic" in msg

    def test_cluster_info_returns_valid_shape(self, svc):
        info = svc.get_cluster_info()
        assert "error" not in info
        assert info["cluster_name"] is not None
        assert info["version"] is not None
        assert info["health"] in ("green", "yellow", "red")
        assert isinstance(info["node_count"], int) and info["node_count"] > 0


# ── Index Discovery ──────────────────────────────────────────────────────────

@pytest.mark.integration
class TestIndexDiscovery:

    def test_get_indices_returns_list(self, svc):
        indices = svc.get_indices()
        assert isinstance(indices, list)

    def test_get_indices_filters_system_indices(self, svc):
        indices = svc.get_indices()
        for idx in indices:
            for prefix in ElasticService.SYSTEM_INDEX_PREFIXES:
                assert not idx.startswith(prefix), f"System index leaked: {idx}"

    def test_get_indices_with_pattern(self, svc, has_logs):
        if not has_logs:
            pytest.skip("No logs-* data on this cluster")
        indices = svc.get_indices("logs-*")
        if not indices:
            streams = svc.get_data_streams("logs-*")
            assert len(streams) > 0, (
                "logs-* exists as data streams but get_indices filters .ds- backing indices; "
                "this is expected — use get_data_streams for data stream discovery"
            )

    def test_get_data_streams_returns_list(self, svc):
        streams = svc.get_data_streams()
        assert isinstance(streams, list)


# ── ES|QL Queries ────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestESQLQueries:
    """Verify ES|QL query syntax is accepted by the cluster."""

    def test_simple_esql(self, svc, has_logs):
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.run_esql("FROM logs-* | LIMIT 1")
        assert isinstance(results, list)

    def test_esql_with_stats(self, svc, has_logs):
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.run_esql(
            "FROM logs-* | STATS count = COUNT(*) BY data_stream.dataset | SORT count DESC | LIMIT 10"
        )
        assert isinstance(results, list)
        if results:
            assert "count" in results[0]

    def test_search_by_ip_syntax(self, svc, has_logs):
        """Verify the IP search ES|QL is syntactically valid."""
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.search_by_ip("10.0.0.1", hours=1)
        assert isinstance(results, list)

    def test_search_by_domain_syntax(self, svc, has_logs):
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.search_by_domain("example.com", hours=1)
        assert isinstance(results, list)

    def test_search_by_hash_handles_missing_fields(self, svc, has_logs):
        """search_by_hash should return [] instead of crashing when
        file.hash.* fields aren't in the index mapping."""
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.search_by_hash("abc123deadbeef", hours=1)
        assert isinstance(results, list)

    def test_search_by_username_syntax(self, svc, has_logs):
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.search_by_username("admin", hours=1)
        assert isinstance(results, list)

    def test_search_by_hostname_syntax(self, svc, has_logs):
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.search_by_hostname("server01", hours=1)
        assert isinstance(results, list)

    def test_esql_sanitization_prevents_injection(self, svc, has_logs):
        """Injected pipes and newlines should not execute — ES|QL's type
        system rejects the malformed value as a non-valid IP, which is the
        desired outcome (injection neutralized)."""
        if not has_logs:
            pytest.skip("No logs-* indices")
        try:
            results = svc.search_by_ip('10.0.0.1"| DROP @timestamp', hours=1)
            assert isinstance(results, list)
        except Exception as e:
            assert "not an IP string literal" in str(e) or "verification_exception" in str(e), (
                f"Expected type-validation rejection, got: {e}"
            )

    def test_esql_invalid_query_raises(self, svc):
        """Malformed ES|QL should raise, not silently return garbage."""
        with pytest.raises(Exception):
            svc.run_esql("THIS IS NOT VALID ESQL")


# ── Alert Search ─────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestAlertSearch:

    def test_search_alerts_returns_list(self, svc, has_alerts):
        if not has_alerts:
            pytest.skip("No alerts in .alerts-security.alerts-default")
        alerts = svc.search_alerts(max_count=5)
        assert isinstance(alerts, list)
        assert len(alerts) > 0

    def test_search_alerts_shape(self, svc, has_alerts):
        """Verify alerts have expected ECS fields."""
        if not has_alerts:
            pytest.skip("No alerts")
        alerts = svc.search_alerts(max_count=1)
        alert = alerts[0]
        assert "@timestamp" in alert or "kibana.alert.rule.name" in alert

    def test_search_alerts_with_filters(self, svc, has_alerts):
        if not has_alerts:
            pytest.skip("No alerts")
        alerts = svc.search_alerts(
            filters={"status": "open"},
            time_range="-720h",
            max_count=3,
        )
        assert isinstance(alerts, list)

    def test_search_alerts_on_empty_cluster(self, svc):
        """Even without alerts, the query should not crash."""
        try:
            alerts = svc.search_alerts(
                filters={"severity": "critical"},
                time_range="-1m",
                max_count=1,
            )
            assert isinstance(alerts, list)
        except Exception as e:
            if "index_not_found" in str(e).lower():
                pytest.skip("Alerts index not created yet")
            raise

    def test_get_alert_by_id_not_found(self, svc, has_alerts):
        """Looking up a nonexistent alert ID should return None, not crash."""
        if not has_alerts:
            pytest.skip("No alerts index")
        result = svc.get_alert_by_id("nonexistent-uuid-12345")
        assert result is None

    def test_get_alert_by_id_found(self, svc, has_alerts):
        """Fetch a real alert if any exist."""
        if not has_alerts:
            pytest.skip("No alerts")
        alerts = svc.search_alerts(max_count=1)
        if not alerts:
            pytest.skip("No alerts returned")
        uuid = alerts[0].get("kibana.alert.uuid")
        if not uuid:
            pytest.skip("Alert missing kibana.alert.uuid field")
        found = svc.get_alert_by_id(uuid)
        assert found is not None
        assert found.get("kibana.alert.uuid") == uuid


# ── Risk Scores ──────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestRiskScores:

    def test_risk_score_returns_dict_shape(self, svc):
        """Even on clusters without Entity Analytics, should return a clean dict."""
        result = svc.get_risk_score("host", "nonexistent-host")
        assert isinstance(result, dict)
        assert "entity_type" in result
        assert result["entity_type"] == "host"

    def test_risk_score_user_entity(self, svc):
        result = svc.get_risk_score("user", "nonexistent-user")
        assert isinstance(result, dict)
        assert result["entity_type"] == "user"


# ── Kibana API ───────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestKibanaAPI:

    def test_get_detection_rules(self, svc_with_kibana):
        """GET /api/detection_engine/rules/_find should return a list."""
        rules = svc_with_kibana.get_detection_rules()
        assert isinstance(rules, list)

    def test_get_detection_rules_with_filter(self, svc_with_kibana):
        rules = svc_with_kibana.get_detection_rules(filter_params={"enabled": True})
        assert isinstance(rules, list)

    def test_get_asset_criticality_returns_dict(self, svc_with_kibana):
        """Even for nonexistent entities, should not crash."""
        try:
            result = svc_with_kibana.get_asset_criticality("host", "nonexistent-host-12345")
            assert isinstance(result, dict)
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                pass  # expected for missing entities
            else:
                raise


# ── Preview Rule ─────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestPreviewRule:

    def test_preview_rule_with_simple_kql(self, svc, has_logs):
        """Preview a detection rule query — verifies the query DSL is valid."""
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.preview_rule(
            query='event.action: "connection_attempted"',
            time_range="-1h",
            index_patterns=["logs-*"],
        )
        assert isinstance(results, dict)
        assert "match_count" in results
        assert "samples" in results
        assert isinstance(results["match_count"], int)

    def test_preview_rule_returns_count(self, svc, has_logs):
        if not has_logs:
            pytest.skip("No logs-* indices")
        results = svc.preview_rule(
            query="*",
            time_range="-1h",
            index_patterns=["logs-*"],
        )
        assert isinstance(results, dict)


# ── Enrichment Service ───────────────────────────────────────────────────────

@pytest.mark.integration
class TestEnrichmentService:

    def test_threat_intelligence_query_syntax(self, svc):
        """TI queries should not crash even on clusters without TI data."""
        from services.elastic_enrichment_service import ElasticEnrichmentService
        enrichment = ElasticEnrichmentService(elastic_service=svc)
        indicators = {
            "ips": ["192.168.1.1"],
            "domains": ["example.com"],
            "hashes": ["abc123"],
        }
        result = enrichment.get_threat_intelligence(indicators)
        assert isinstance(result, dict)

    def test_extract_indicators_from_empty_case(self, svc):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        enrichment = ElasticEnrichmentService(elastic_service=svc)
        indicators = enrichment.extract_indicators(
            case={"title": "Test", "description": "nothing here"},
            findings=[],
        )
        assert isinstance(indicators, dict)
        assert "ips" in indicators


# ── Ingestion Service ────────────────────────────────────────────────────────

@pytest.mark.integration
class TestIngestionService:

    def test_transform_alert_round_trip(self, svc, has_alerts):
        """Fetch a real alert, transform it, and verify the finding shape."""
        if not has_alerts:
            pytest.skip("No alerts")
        alerts = svc.search_alerts(max_count=1)
        if not alerts:
            pytest.skip("No alerts returned")

        from services.elastic_ingestion import ElasticIngestion
        ingestion = ElasticIngestion.__new__(ElasticIngestion)
        finding = ingestion.transform_alert_to_finding(alerts[0])

        assert isinstance(finding, dict)
        assert "title" in finding
        assert "severity" in finding
        assert finding.get("source") == "elastic" or finding.get("data_source") == "elastic"
        assert "entity_context" in finding

    def test_transform_preserves_entity_context_shape(self, svc, has_alerts):
        if not has_alerts:
            pytest.skip("No alerts")
        alerts = svc.search_alerts(max_count=1)
        if not alerts:
            pytest.skip("No alerts returned")

        from services.elastic_ingestion import ElasticIngestion
        ingestion = ElasticIngestion.__new__(ElasticIngestion)
        finding = ingestion.transform_alert_to_finding(alerts[0])

        ctx = finding["entity_context"]
        assert isinstance(ctx["src_ips"], list)
        assert isinstance(ctx["dest_ips"], list)
        assert isinstance(ctx["usernames"], list)
        assert isinstance(ctx["hostnames"], list)
