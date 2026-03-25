"""Unit tests for ElasticService — core Elasticsearch client wrapper."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from services.elastic_service import ElasticService


class TestElasticServiceInit:

    def test_init_defaults(self):
        svc = ElasticService(url="http://localhost:9200")
        assert svc.url == "http://localhost:9200"
        assert svc.verify_ssl is True
        assert svc._client is None

    def test_init_with_cloud_id(self):
        svc = ElasticService(cloud_id="my-deploy:abc123")
        assert svc.cloud_id == "my-deploy:abc123"
        assert svc.url is None

    def test_init_kibana_url_trailing_slash(self):
        svc = ElasticService(url="http://localhost:9200", kibana_url="http://kibana:5601/")
        assert svc.kibana_url == "http://kibana:5601"

    def test_from_env(self):
        env = {
            "ELASTIC_URL": "http://es:9200",
            "ELASTIC_API_KEY": "key123",
            "ELASTIC_CLOUD_ID": "",
            "ELASTIC_USERNAME": "user",
            "ELASTIC_PASSWORD": "pass",
            "ELASTIC_VERIFY_SSL": "false",
            "KIBANA_URL": "http://kibana:5601",
        }
        with patch.dict("os.environ", env, clear=False):
            svc = ElasticService.from_env()
        assert svc.url == "http://es:9200"
        assert svc.api_key == "key123"
        assert svc.verify_ssl is False
        assert svc.kibana_url == "http://kibana:5601"

    def test_from_config(self):
        config = {
            "elasticsearch_url": "http://es:9200",
            "api_key": "key",
            "verify_ssl": False,
        }
        svc = ElasticService.from_config(config)
        assert svc.url == "http://es:9200"
        assert svc.api_key == "key"
        assert svc.verify_ssl is False


class TestGetClient:

    def test_raises_when_no_url_or_cloud_id(self):
        svc = ElasticService()
        with patch("elasticsearch.Elasticsearch"):
            with pytest.raises(ValueError, match="Either ELASTIC_URL"):
                svc._get_client()

    def test_creates_client_with_url(self):
        with patch("elasticsearch.Elasticsearch") as mock_es_cls:
            mock_es_cls.return_value = Mock()
            svc = ElasticService(url="http://es:9200", api_key="k")
            client = svc._get_client()
            assert client is not None
            mock_es_cls.assert_called_once()

    def test_caches_client(self):
        with patch("elasticsearch.Elasticsearch") as mock_es_cls:
            mock_es_cls.return_value = Mock()
            svc = ElasticService(url="http://es:9200")
            c1 = svc._get_client()
            c2 = svc._get_client()
            assert c1 is c2
            assert mock_es_cls.call_count == 1


class TestTestConnection:

    def test_success(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        mock_client.info.return_value = {
            "version": {"number": "8.15.0"},
            "name": "node-1",
            "cluster_name": "test-cluster",
        }
        mock_client.cluster.health.return_value = {"status": "green"}
        svc._client = mock_client

        ok, msg = svc.test_connection()
        assert ok is True
        assert "8.15.0" in msg
        assert "test-cluster" in msg
        assert "green" in msg

    def test_failure(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        mock_client.info.side_effect = ConnectionError("refused")
        svc._client = mock_client

        ok, msg = svc.test_connection()
        assert ok is False
        assert "Connection error" in msg


class TestRunEsql:

    def test_returns_list_of_dicts(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        mock_client.esql.query.return_value = {
            "columns": [{"name": "ip"}, {"name": "count"}],
            "values": [["1.2.3.4", 10], ["5.6.7.8", 3]],
        }
        svc._client = mock_client

        results = svc.run_esql("FROM logs-* | STATS count=COUNT(*) BY source.ip")
        assert len(results) == 2
        assert results[0] == {"ip": "1.2.3.4", "count": 10}

    def test_propagates_exception(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        mock_client.esql.query.side_effect = RuntimeError("parse error")
        svc._client = mock_client

        with pytest.raises(RuntimeError, match="parse error"):
            svc.run_esql("bad query")


class TestSearchAlerts:

    def _make_svc(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        svc._client = mock_client
        return svc, mock_client

    def test_basic_alert_search(self):
        svc, mock_client = self._make_svc()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"kibana.alert.rule.name": "Test Rule", "@timestamp": "2025-01-01T00:00:00Z"}},
                ]
            }
        }

        alerts = svc.search_alerts()
        assert len(alerts) == 1
        assert alerts[0]["kibana.alert.rule.name"] == "Test Rule"
        mock_client.search.assert_called_once()

    def test_filtered_search(self):
        svc, mock_client = self._make_svc()
        mock_client.search.return_value = {"hits": {"hits": []}}

        svc.search_alerts(filters={"severity": "critical", "status": "open"})
        call_body = mock_client.search.call_args[1]["body"]
        must_clauses = call_body["query"]["bool"]["must"]
        assert len(must_clauses) == 3  # timestamp + severity + status

    def test_raises_on_error(self):
        svc, mock_client = self._make_svc()
        mock_client.search.side_effect = Exception("network error")

        with pytest.raises(Exception, match="network error"):
            svc.search_alerts()


class TestEntitySearch:

    def test_search_by_ip(self):
        svc = ElasticService(url="http://es:9200")
        with patch.object(svc, "run_esql", return_value=[{"source.ip": "1.2.3.4"}]) as mock:
            results = svc.search_by_ip("1.2.3.4", hours=48)
            assert len(results) == 1
            assert "1.2.3.4" in mock.call_args[0][0]

    def test_search_by_domain(self):
        svc = ElasticService(url="http://es:9200")
        with patch.object(svc, "run_esql", return_value=[]) as mock:
            svc.search_by_domain("evil.com")
            assert "evil.com" in mock.call_args[0][0]

    def test_search_by_hash(self):
        svc = ElasticService(url="http://es:9200")
        with patch.object(svc, "run_esql", return_value=[]) as mock:
            svc.search_by_hash("abc123")
            assert "abc123" in mock.call_args[0][0]

    def test_search_by_username(self):
        svc = ElasticService(url="http://es:9200")
        with patch.object(svc, "run_esql", return_value=[]) as mock:
            svc.search_by_username("jdoe")
            assert "jdoe" in mock.call_args[0][0]

    def test_search_by_hostname(self):
        svc = ElasticService(url="http://es:9200")
        with patch.object(svc, "run_esql", return_value=[]) as mock:
            svc.search_by_hostname("web-01")
            assert "web-01" in mock.call_args[0][0]


class TestGetIndices:

    def test_filters_system_indices(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        mock_client.cat.indices.return_value = [
            {"index": "logs-endpoint"},
            {"index": ".kibana_8.15.0"},
            {"index": ".internal-something"},
            {"index": "metrics-system"},
        ]
        svc._client = mock_client

        indices = svc.get_indices()
        assert "logs-endpoint" in indices
        assert "metrics-system" in indices
        assert ".kibana_8.15.0" not in indices
        assert ".internal-something" not in indices


class TestGetRiskScore:

    def test_user_risk(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [{"_source": {"risk_score": 75.5, "risk_level": "High"}}]
            }
        }
        svc._client = mock_client

        result = svc.get_risk_score("user", "jdoe")
        assert result["risk_score"] == 75.5
        assert result["risk_level"] == "High"
        assert result["entity_type"] == "user"
        assert result["entity_value"] == "jdoe"

    def test_no_risk_score(self):
        svc = ElasticService(url="http://es:9200")
        mock_client = Mock()
        mock_client.search.return_value = {"hits": {"hits": []}}
        svc._client = mock_client

        result = svc.get_risk_score("host", "srv-01")
        assert result["risk_score"] is None
        assert result["risk_level"] == "Unknown"


class TestKibanaApi:

    def test_kibana_url_not_configured(self):
        svc = ElasticService(url="http://es:9200", kibana_url="")
        result = svc._kibana_request("GET", "/api/status")
        assert result is None

    def test_create_case(self):
        with patch("requests.request") as mock_request:
            mock_resp = Mock()
            mock_resp.json.return_value = {"id": "case-123", "title": "Test", "version": "v1"}
            mock_resp.raise_for_status = Mock()
            mock_request.return_value = mock_resp

            svc = ElasticService(url="http://es:9200", api_key="key", kibana_url="http://kibana:5601")
            result = svc.create_case("Test Case", "Description")
            assert result["id"] == "case-123"
            assert "kibana_url" in result

    def test_update_alert_status_no_kibana(self):
        svc = ElasticService(url="http://es:9200")
        result = svc.update_alert_status(["id1"], "closed")
        assert "error" in result
