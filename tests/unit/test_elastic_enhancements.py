"""Tests for Elastic integration enhancements — response actions, detection mgmt,
osquery, asset criticality, NL→ES|QL, and correlation improvements."""

from unittest.mock import patch, Mock, MagicMock
import json
import pytest

from services.elastic_service import ElasticService


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_service(**kwargs):
    defaults = {"url": "http://es:9200", "kibana_url": "http://kibana:5601", "api_key": "test-key"}
    defaults.update(kwargs)
    return ElasticService(**defaults)


# ── Response Actions ─────────────────────────────────────────────────────────

class TestUnisolateEndpoint:

    @patch("requests.request")
    def test_unisolate_by_agent_id(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {"action": "unisolate"})
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.unisolate_endpoint("agent-123")
        assert result.get("action") == "unisolate"

    @patch("requests.request")
    def test_unisolate_fallback_to_hostname(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {"action": "unisolate"}, raise_for_status=Mock())
        svc = _make_service()
        svc._kibana_request = Mock(side_effect=[None, {"action": "unisolate"}])
        with patch.object(svc, "_resolve_agent_id", return_value="resolved-agent"):
            result = svc.unisolate_endpoint("my-host")
            assert result.get("action") == "unisolate"
            assert "error" not in result


class TestKillProcess:

    @patch("requests.request")
    def test_kill_by_pid(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {"action_id": "kill-1"})
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.kill_process("agent-1", pid=1234)
        assert "error" not in result

    def test_no_pid_or_entity(self):
        svc = _make_service()
        result = svc.kill_process("agent-1")
        assert result["error"] == "Either pid or entity_id must be provided"

    @patch("requests.request")
    def test_kill_by_entity_id(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {"action_id": "kill-2"})
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.kill_process("agent-1", entity_id="proc-entity-abc")
        assert "error" not in result


class TestGetFile:

    @patch("requests.request")
    def test_get_file_success(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {"action_id": "getfile-1"})
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.get_file("agent-1", "/tmp/malware.exe")
        assert "error" not in result


class TestGetActionStatus:

    @patch("requests.request")
    def test_action_status(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"data": {"status": "successful", "isCompleted": True, "startedAt": "t1", "completedAt": "t2"}},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.get_action_status("action-123")
        assert result["is_completed"] is True
        assert result["action_id"] == "action-123"


# ── Osquery ──────────────────────────────────────────────────────────────────

class TestOsquery:

    @patch("requests.request")
    def test_run_osquery(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"data": {"id": "oq-action-1"}},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.run_osquery("SELECT * FROM processes", ["agent-1"])
        assert result["action_id"] == "oq-action-1"
        assert result["status"] == "submitted"

    @patch("requests.request")
    def test_get_osquery_results(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"data": {"status": "complete", "total": 5, "items": [{"pid": 1}]}},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.get_osquery_results("oq-action-1")
        assert result["total"] == 5
        assert len(result["results"]) == 1

    def test_run_osquery_no_kibana(self):
        svc = _make_service(kibana_url="")
        result = svc.run_osquery("SELECT 1", ["agent-1"])
        assert "error" in result


# ── Asset Criticality ────────────────────────────────────────────────────────

class TestAssetCriticality:

    @patch("requests.request")
    def test_get_asset_criticality(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"criticality_level": "high_impact"},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.get_asset_criticality("host", "critical-server")
        assert result["criticality_level"] == "high_impact"
        assert result["assigned"] is True

    @patch("requests.request")
    def test_unknown_asset(self, mock_req):
        mock_req.return_value = Mock(status_code=404, raise_for_status=Mock(side_effect=Exception("404")))
        svc = _make_service()
        result = svc.get_asset_criticality("user", "nobody")
        assert result["criticality_level"] == "unknown"
        assert result["assigned"] is False


# ── Detection Rule Management ────────────────────────────────────────────────

class TestDetectionRuleManagement:

    @patch("requests.request")
    def test_create_query_rule(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "rule-1", "name": "Test Rule", "enabled": True},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.create_detection_rule("query", "Test Rule", "Desc", "process.name: cmd.exe")
        assert result["id"] == "rule-1"

    @patch("requests.request")
    def test_create_esql_rule(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "rule-2", "name": "ESQL Rule", "enabled": True},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.create_detection_rule("esql", "ESQL Rule", "Desc", "FROM logs-* | WHERE x > 1")
        assert result["id"] == "rule-2"

    @patch("requests.request")
    def test_update_rule(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "rule-1", "name": "Updated", "updated": True},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.update_detection_rule("rule-1", {"severity": "critical"})
        assert result["updated"] is True

    @patch("requests.request")
    def test_enable_rule(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"success": True},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.enable_detection_rule(["rule-1", "rule-2"], enabled=False)
        assert result["action"] == "disable"
        assert result["success"] is True

    @patch("requests.request")
    def test_delete_rule(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {})
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.delete_detection_rule("rule-1")
        assert result["deleted"] is True

    @patch("requests.request")
    def test_create_exception_list(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "exc-1", "list_id": "vigil-abc", "name": "FP List"},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.create_exception_list("FP List", "False positives")
        assert result["list_id"].startswith("vigil-")

    @patch("requests.request")
    def test_add_exception_item(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "item-1"},
        )
        mock_req.return_value.raise_for_status = Mock()
        svc = _make_service()
        result = svc.add_exception_item("vigil-abc", "Backup process", [{"field": "process.name", "value": "backup.exe"}])
        assert result["id"] == "item-1"


class TestPreviewRule:

    @patch("elasticsearch.Elasticsearch")
    def test_preview_rule(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {"total": {"value": 42}, "hits": [{"_source": {"event": "test"}}]}
        }
        mock_es_cls.return_value = mock_client
        svc = _make_service()
        result = svc.preview_rule("process.name: cmd.exe")
        assert result["match_count"] == 42
        assert len(result["samples"]) == 1


# ── Correlation with Elastic Results ─────────────────────────────────────────

class TestCorrelationElastic:

    def _make_response_service(self):
        from services.autonomous_response_service import AutonomousResponseService
        svc = AutonomousResponseService()
        return svc

    def test_elastic_results_add_evidence(self):
        svc = self._make_response_service()
        result = svc.correlate_alerts(
            elastic_results={
                "alerts": [{"severity": "high", "rule_name": "Malware"}],
                "events": list(range(60)),
                "risk_scores": {},
            }
        )
        assert any("Elastic" in e for e in result["evidence"])
        assert result["confidence"] > 0

    def test_high_severity_elastic_alert_adds_confidence(self):
        svc = self._make_response_service()
        result = svc.correlate_alerts(
            elastic_results={
                "alerts": [{"severity": "critical", "rule_name": "Ransomware"}],
                "events": [],
                "risk_scores": {},
            }
        )
        assert result["confidence"] >= 0.15

    def test_high_risk_score_adds_confidence(self):
        svc = self._make_response_service()
        result = svc.correlate_alerts(
            elastic_results={
                "alerts": [],
                "events": [],
                "risk_scores": {"user:admin": {"risk_score": 85, "risk_level": "High"}},
            }
        )
        assert result["confidence"] >= 0.10

    def test_elastic_volume_bonus(self):
        svc = self._make_response_service()
        result = svc.correlate_alerts(
            elastic_results={
                "alerts": [],
                "events": list(range(100)),
                "risk_scores": {},
            }
        )
        assert result["confidence"] >= 0.10

    def test_no_elastic_results(self):
        svc = self._make_response_service()
        result = svc.correlate_alerts()
        assert result["confidence"] == 0


# ── Integration Bridge Fix ──────────────────────────────────────────────────

class TestIntegrationBridgeFix:

    def test_elastic_maps_to_correct_server(self):
        from services.integration_bridge_service import IntegrationBridgeService
        bridge = IntegrationBridgeService()
        assert bridge.INTEGRATION_TO_SERVER_MAP["elastic-siem"] == "elastic-security"


# ── Prometheus Metrics ──────────────────────────────────────────────────────

class TestPrometheusMetrics:

    def test_metrics_output_includes_elastic(self):
        """Verify the metrics handler would include elastic counters."""
        from daemon.metrics import MetricsServer, MetricsConfig
        config = MetricsConfig()
        server = MetricsServer(config)

        mock_poller = Mock()
        mock_poller.stats = {
            "splunk_polls": 10,
            "crowdstrike_polls": 5,
            "elastic_polls": 7,
            "splunk_findings": 100,
            "crowdstrike_findings": 50,
            "elastic_findings": 70,
            "webhook_findings": 20,
            "errors": 0,
        }
        server.poller = mock_poller
        server.processor = None
        server.responder = None
        server.scheduler = None
        server.orchestrator = None

        metrics = server._collect_metrics()
        assert metrics["poller"]["elastic_polls"] == 7
        assert metrics["poller"]["elastic_findings"] == 70


# ── NL→ES|QL Tool ──────────────────────────────────────────────────────────

class TestNlToEsql:

    def _run_tool(self, question, hours=24, limit=100):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from tools.elastic_security import nl_to_esql
        raw = nl_to_esql(question, hours=hours, limit=limit)
        return json.loads(raw)

    def test_ip_lookup(self):
        result = self._run_tool("show events from IP 10.0.0.5")
        assert "10.0.0.5" in result["esql"]
        assert result["template"] == "ip_lookup"

    def test_failed_logins(self):
        result = self._run_tool("failed logins in the last hour")
        assert "authentication" in result["esql"]
        assert result["template"] == "failed_logins"

    def test_process_exec(self):
        result = self._run_tool("processes executed on host SERVER01")
        assert "process" in result["esql"].lower()

    def test_dns_queries(self):
        result = self._run_tool("dns queries in last 24 hours")
        assert "dns" in result["esql"]

    def test_fallback_for_unknown(self):
        result = self._run_tool("something completely unrelated foobar")
        assert result["template"] == "fallback"
        assert "FROM logs-*" in result["esql"]

    def test_alert_summary(self):
        result = self._run_tool("alert summary for today")
        assert ".alerts-security" in result["esql"]

    def test_network_connections(self):
        result = self._run_tool("network connections in last 12 hours")
        assert "network" in result["esql"]


# ── run_esql FROM guard ─────────────────────────────────────────────────────

class TestRunEsqlFromGuard:

    def test_rejects_query_without_from(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from tools.elastic_security import run_esql
        with patch("tools.elastic_security._require_service") as mock_svc:
            mock_svc.return_value = (Mock(), None)
            raw = run_esql("DELETE FROM logs-*")
            result = json.loads(raw)
            assert "error" in result
            assert "FROM" in result["error"]

    def test_accepts_valid_from_query(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from tools.elastic_security import run_esql
        with patch("tools.elastic_security._require_service") as mock_svc:
            svc = Mock()
            svc.run_esql.return_value = [{"count": 1}]
            mock_svc.return_value = (svc, None)
            raw = run_esql("FROM logs-* | LIMIT 10")
            result = json.loads(raw)
            assert result["count"] == 1


# ── data_source threading through isolation paths ───────────────────────────

class TestDataSourceThreading:

    def _make_response_service_with_approval(self):
        from services.autonomous_response_service import AutonomousResponseService
        from unittest.mock import MagicMock

        svc = AutonomousResponseService()
        mock_approval = MagicMock()
        svc.approval_service = mock_approval
        return svc, mock_approval

    def test_create_isolation_stores_data_source_in_params(self):
        svc, mock_approval = self._make_response_service_with_approval()

        mock_action = Mock()
        mock_action.status = "pending"
        mock_action.action_id = "act-1"
        mock_approval.create_action.return_value = mock_action

        result = svc.create_isolation_action(
            ip_address="10.0.0.1",
            hostname="server01",
            confidence=0.80,
            reason="test",
            evidence=["ev-1"],
            correlation_data={"indicators": [], "reasoning": []},
            data_source="elastic",
        )
        call_args = mock_approval.create_action.call_args
        assert call_args[1]["parameters"]["data_source"] == "elastic"

    @patch("services.elastic_service.ElasticService.from_env")
    def test_auto_approved_isolation_uses_elastic_api(self, mock_from_env):
        svc, mock_approval = self._make_response_service_with_approval()

        mock_action = Mock()
        mock_action.status = "approved"
        mock_action.action_id = "act-2"
        mock_approval.create_action.return_value = mock_action

        mock_es = Mock()
        mock_es.isolate_endpoint.return_value = {"success": True}
        mock_from_env.return_value = mock_es

        result = svc.create_isolation_action(
            ip_address="10.0.0.1",
            hostname="server01",
            confidence=0.95,
            reason="test",
            evidence=["ev-1"],
            correlation_data={"indicators": [], "reasoning": []},
            data_source="elastic",
        )
        mock_es.isolate_endpoint.assert_called_once()

    def test_investigate_and_respond_passes_elastic_results(self):
        from services.autonomous_response_service import AutonomousResponseService

        svc = AutonomousResponseService()
        mock_finding = {
            "data_source": "elastic",
            "entity_context": {"src_ips": ["10.0.0.1"], "hostnames": ["srv01"]},
            "severity": "high",
            "metadata": {"risk_scores": {"host:srv01": {"risk_score": 90}}},
        }

        with patch("services.database_data_service.DatabaseDataService.get_finding", return_value=mock_finding):
            with patch.object(svc, "correlate_alerts", wraps=svc.correlate_alerts) as spy:
                svc.investigate_and_respond("f-123", auto_execute=False)
                call_kwargs = spy.call_args[1]
                assert call_kwargs["elastic_results"] is not None
                assert call_kwargs["elastic_results"]["risk_scores"] == mock_finding["metadata"]["risk_scores"]


# ── Agent Builder Service Methods ────────────────────────────────────────────

class TestAgentBuilderTools:

    @patch("requests.request")
    def test_list_tools_returns_list(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: [
                {"id": "t1", "name": "My ES|QL Tool", "description": "desc", "type": "esql", "is_custom": True},
                {"id": "t2", "name": "Builtin", "description": "built", "type": "index_search", "source": "builtin"},
            ],
            raise_for_status=Mock(),
        )
        svc = _make_service()
        tools = svc.list_agent_builder_tools()
        assert len(tools) == 2
        assert tools[0]["id"] == "t1"
        assert tools[0]["type"] == "esql"

    @patch("requests.request")
    def test_list_tools_handles_empty(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200, json=lambda: [], raise_for_status=Mock(),
        )
        svc = _make_service()
        tools = svc.list_agent_builder_tools()
        assert tools == []

    @patch("requests.request")
    def test_list_tools_handles_none(self, mock_req):
        mock_req.return_value = Mock(
            status_code=500,
            raise_for_status=Mock(side_effect=Exception("500")),
        )
        svc = _make_service()
        tools = svc.list_agent_builder_tools()
        assert tools == []

    @patch("requests.request")
    def test_create_tool_success(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "new-tool", "name": "My Tool", "type": "esql"},
            raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc.create_agent_builder_tool(
            tool_type="esql",
            name="My Tool",
            description="Hunts lateral movement",
            configuration={"query": "FROM logs-* | WHERE ..."},
        )
        assert result["created"] is True
        assert result["id"] == "new-tool"

    @patch("requests.request")
    def test_create_tool_failure(self, mock_req):
        mock_req.return_value = Mock(
            status_code=400,
            raise_for_status=Mock(side_effect=Exception("400")),
        )
        svc = _make_service()
        result = svc.create_agent_builder_tool("esql", "Bad", "desc", {})
        assert "error" in result

    @patch("requests.request")
    def test_delete_tool_success(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200, json=lambda: {}, raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc.delete_agent_builder_tool("tool-123")
        assert result["deleted"] is True
        assert result["tool_id"] == "tool-123"

    @patch("requests.request")
    def test_test_tool_success(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"output": "Found 5 events", "tool_id": "t1"},
            raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc.test_agent_builder_tool("t1", "find lateral movement from 10.0.0.1")
        assert result["output"] == "Found 5 events"

    @patch("requests.request")
    def test_test_tool_failure(self, mock_req):
        mock_req.return_value = Mock(
            status_code=500,
            raise_for_status=Mock(side_effect=Exception("500")),
        )
        svc = _make_service()
        result = svc.test_agent_builder_tool("t1", "query")
        assert "error" in result


class TestAgentBuilderAgents:

    @patch("requests.request")
    def test_list_agents_returns_list(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: [
                {"id": "a1", "name": "Triage Agent", "description": "Auto-triage", "tool_ids": ["t1", "t2"], "is_custom": True},
            ],
            raise_for_status=Mock(),
        )
        svc = _make_service()
        agents = svc.list_agent_builder_agents()
        assert len(agents) == 1
        assert agents[0]["name"] == "Triage Agent"
        assert agents[0]["tool_ids"] == ["t1", "t2"]

    @patch("requests.request")
    def test_create_agent_success(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "new-agent", "name": "SOC Agent"},
            raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc.create_agent_builder_agent(
            name="SOC Agent",
            instructions="Triage security alerts",
            tool_ids=["t1", "t2"],
            description="Automated triage",
        )
        assert result["created"] is True
        assert result["id"] == "new-agent"

    @patch("requests.request")
    def test_create_agent_failure(self, mock_req):
        mock_req.return_value = Mock(
            status_code=400,
            raise_for_status=Mock(side_effect=Exception("400")),
        )
        svc = _make_service()
        result = svc.create_agent_builder_agent("Bad", "instructions", ["t1"])
        assert "error" in result

    @patch("requests.request")
    def test_delete_agent_success(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200, json=lambda: {}, raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc.delete_agent_builder_agent("agent-456")
        assert result["deleted"] is True
        assert result["agent_id"] == "agent-456"


class TestAgentBuilderMCPConfig:

    def test_returns_config_with_api_key(self):
        svc = _make_service()
        config = svc.get_agent_builder_mcp_config()
        assert config["url"] == "http://kibana:5601/api/agent_builder/mcp"
        assert config["transport"] == "sse"
        assert "Authorization" in config["headers"]
        assert config["headers"]["Authorization"] == "ApiKey test-key"

    def test_returns_config_with_basic_auth(self):
        svc = _make_service(api_key=None, username="admin", password="pass")
        config = svc.get_agent_builder_mcp_config()
        assert config["url"] == "http://kibana:5601/api/agent_builder/mcp"
        assert config["auth"]["type"] == "basic"
        assert config["auth"]["username"] == "admin"

    def test_returns_error_without_kibana_url(self):
        svc = _make_service(kibana_url=None)
        config = svc.get_agent_builder_mcp_config()
        assert "error" in config


# ── Agent Builder MCP Tools ──────────────────────────────────────────────────

class TestAgentBuilderMCPTools:
    """Tests for the MCP tool wrappers in tools/elastic_security.py."""

    @patch("tools.elastic_security._get_service")
    def test_list_custom_tools(self, mock_get_svc):
        from tools.elastic_security import list_custom_tools
        mock_svc = Mock()
        mock_svc.list_agent_builder_tools.return_value = [
            {"id": "t1", "name": "Tool1", "description": "", "type": "esql", "is_custom": True},
        ]
        mock_get_svc.return_value = mock_svc
        result = json.loads(list_custom_tools())
        assert result["count"] == 1
        assert result["tools"][0]["id"] == "t1"

    @patch("tools.elastic_security._get_service")
    def test_create_custom_tool_valid(self, mock_get_svc):
        from tools.elastic_security import create_custom_tool
        mock_svc = Mock()
        mock_svc.create_agent_builder_tool.return_value = {"id": "new", "name": "T", "type": "esql", "created": True}
        mock_get_svc.return_value = mock_svc
        result = json.loads(create_custom_tool("T", "desc", "esql", '{"query": "FROM logs-*"}'))
        assert result["created"] is True

    @patch("tools.elastic_security._get_service")
    def test_create_custom_tool_invalid_type(self, mock_get_svc):
        from tools.elastic_security import create_custom_tool
        mock_svc = Mock()
        mock_get_svc.return_value = mock_svc
        result = json.loads(create_custom_tool("T", "desc", "bad_type", "{}"))
        assert "error" in result

    @patch("tools.elastic_security._get_service")
    def test_create_custom_tool_invalid_json(self, mock_get_svc):
        from tools.elastic_security import create_custom_tool
        mock_svc = Mock()
        mock_get_svc.return_value = mock_svc
        result = json.loads(create_custom_tool("T", "desc", "esql", "not-json"))
        assert "error" in result

    @patch("tools.elastic_security._get_service")
    def test_delete_custom_tool(self, mock_get_svc):
        from tools.elastic_security import delete_custom_tool
        mock_svc = Mock()
        mock_svc.delete_agent_builder_tool.return_value = {"deleted": True, "tool_id": "t1"}
        mock_get_svc.return_value = mock_svc
        result = json.loads(delete_custom_tool("t1"))
        assert result["deleted"] is True

    @patch("tools.elastic_security._get_service")
    def test_test_custom_tool(self, mock_get_svc):
        from tools.elastic_security import test_custom_tool
        mock_svc = Mock()
        mock_svc.test_agent_builder_tool.return_value = {"output": "3 events"}
        mock_get_svc.return_value = mock_svc
        result = json.loads(test_custom_tool("t1", "find lateral movement"))
        assert result["output"] == "3 events"

    @patch("tools.elastic_security._get_service")
    def test_list_custom_agents(self, mock_get_svc):
        from tools.elastic_security import list_custom_agents
        mock_svc = Mock()
        mock_svc.list_agent_builder_agents.return_value = [
            {"id": "a1", "name": "Agent1", "description": "", "tool_ids": ["t1"], "is_custom": True},
        ]
        mock_get_svc.return_value = mock_svc
        result = json.loads(list_custom_agents())
        assert result["count"] == 1

    @patch("tools.elastic_security._get_service")
    def test_create_custom_agent_valid(self, mock_get_svc):
        from tools.elastic_security import create_custom_agent
        mock_svc = Mock()
        mock_svc.create_agent_builder_agent.return_value = {"id": "a1", "name": "A", "tool_ids": ["t1"], "created": True}
        mock_get_svc.return_value = mock_svc
        result = json.loads(create_custom_agent("A", "instructions", "t1,t2"))
        assert result["created"] is True

    @patch("tools.elastic_security._get_service")
    def test_create_custom_agent_no_tools(self, mock_get_svc):
        from tools.elastic_security import create_custom_agent
        mock_svc = Mock()
        mock_get_svc.return_value = mock_svc
        result = json.loads(create_custom_agent("A", "instructions", ""))
        assert "error" in result

    @patch("tools.elastic_security._get_service")
    def test_delete_custom_agent(self, mock_get_svc):
        from tools.elastic_security import delete_custom_agent
        mock_svc = Mock()
        mock_svc.delete_agent_builder_agent.return_value = {"deleted": True, "agent_id": "a1"}
        mock_get_svc.return_value = mock_svc
        result = json.loads(delete_custom_agent("a1"))
        assert result["deleted"] is True

    @patch("tools.elastic_security._get_service")
    def test_get_agent_builder_config(self, mock_get_svc):
        from tools.elastic_security import get_agent_builder_config
        mock_svc = Mock()
        mock_svc.get_agent_builder_mcp_config.return_value = {
            "url": "http://kibana:5601/api/agent_builder/mcp",
            "transport": "sse",
            "headers": {"Authorization": "ApiKey abc"},
        }
        mock_get_svc.return_value = mock_svc
        result = json.loads(get_agent_builder_config())
        assert "agent_builder/mcp" in result["url"]


# ══════════════════════════════════════════════════════════════════════════════
# ElasticService Core Methods
# ══════════════════════════════════════════════════════════════════════════════

class TestElasticServiceFactory:

    def test_from_env(self):
        env = {
            "ELASTIC_URL": "http://es:9200",
            "ELASTIC_API_KEY": "key-123",
            "ELASTIC_CLOUD_ID": "cloud-abc",
            "ELASTIC_USERNAME": "user",
            "ELASTIC_PASSWORD": "pass",
            "ELASTIC_VERIFY_SSL": "false",
            "KIBANA_URL": "http://kibana:5601",
        }
        with patch.dict("os.environ", env, clear=False):
            svc = ElasticService.from_env()
        assert svc.url == "http://es:9200"
        assert svc.api_key == "key-123"
        assert svc.cloud_id == "cloud-abc"
        assert svc.verify_ssl is False
        assert svc.kibana_url == "http://kibana:5601"

    def test_from_config(self):
        config = {
            "elasticsearch_url": "http://es:9200",
            "api_key": "key-1",
            "kibana_url": "http://kibana:5601/",
        }
        svc = ElasticService.from_config(config)
        assert svc.url == "http://es:9200"
        assert svc.api_key == "key-1"
        assert svc.kibana_url == "http://kibana:5601"

    def test_from_config_url_field(self):
        svc = ElasticService.from_config({"url": "http://alt:9200"})
        assert svc.url == "http://alt:9200"


class TestElasticServiceConnection:

    @patch("elasticsearch.Elasticsearch")
    def test_test_connection_success(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.info.return_value = {
            "name": "node-1",
            "cluster_name": "test-cluster",
            "version": {"number": "8.15.0"},
        }
        mock_client.cluster.health.return_value = {"status": "green"}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        ok, msg = svc.test_connection()
        assert ok is True
        assert "8.15.0" in msg
        assert "test-cluster" in msg

    @patch("elasticsearch.Elasticsearch")
    def test_test_connection_failure(self, mock_es_cls):
        mock_es_cls.side_effect = Exception("Connection refused")
        svc = _make_service()
        ok, msg = svc.test_connection()
        assert ok is False
        assert "Connection" in msg

    def test_get_client_requires_url_or_cloud_id(self):
        svc = ElasticService(api_key="k")
        with pytest.raises(ValueError, match="ELASTIC_URL or ELASTIC_CLOUD_ID"):
            svc._get_client()


class TestElasticServiceEsql:

    @patch("elasticsearch.Elasticsearch")
    def test_run_esql_success(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.return_value = {
            "columns": [{"name": "host"}, {"name": "count"}],
            "values": [["srv01", 10], ["srv02", 5]],
        }
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        results = svc.run_esql("FROM logs-* | STATS count=COUNT(*) BY host.name")
        assert len(results) == 2
        assert results[0] == {"host": "srv01", "count": 10}

    @patch("elasticsearch.Elasticsearch")
    def test_run_esql_with_limit(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.return_value = {
            "columns": [{"name": "x"}],
            "values": [[1], [2], [3]],
        }
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        results = svc.run_esql("FROM logs-*", limit=2)
        assert len(results) == 2

    @patch("elasticsearch.Elasticsearch")
    def test_run_esql_error_raises(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.side_effect = Exception("parse error")
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        with pytest.raises(Exception, match="parse error"):
            svc.run_esql("bad query")


class TestElasticServiceAlerts:

    @patch("elasticsearch.Elasticsearch")
    def test_search_alerts_with_filters(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {"hits": [
                {"_source": {"@timestamp": "2025-01-01", "kibana.alert.severity": "high"}},
            ]},
        }
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        alerts = svc.search_alerts(
            filters={"severity": "high", "status": "open", "source_ip": "10.0.0.1"},
            time_range="-1h",
            max_count=10,
        )
        assert len(alerts) == 1

        call_body = mock_client.search.call_args[1]["body"]
        must_clauses = call_body["query"]["bool"]["must"]
        field_matches = [list(c.keys())[0] for c in must_clauses]
        assert "range" in field_matches
        assert "term" in field_matches

    @patch("elasticsearch.Elasticsearch")
    def test_search_alerts_empty(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": []}}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        assert svc.search_alerts() == []

    @patch("elasticsearch.Elasticsearch")
    def test_search_alerts_error_returns_empty(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("index not found")
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        assert svc.search_alerts() == []

    @patch("elasticsearch.Elasticsearch")
    def test_get_alert_by_id_found(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {"hits": [{"_source": {"kibana.alert.uuid": "abc-123"}}]},
        }
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        alert = svc.get_alert_by_id("abc-123")
        assert alert is not None
        assert alert["kibana.alert.uuid"] == "abc-123"

    @patch("elasticsearch.Elasticsearch")
    def test_get_alert_by_id_not_found(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": []}}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        assert svc.get_alert_by_id("nonexistent") is None


class TestElasticServiceEntitySearch:

    @patch("elasticsearch.Elasticsearch")
    def test_search_by_ip(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.return_value = {"columns": [{"name": "src"}], "values": [["10.0.0.1"]]}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        results = svc.search_by_ip("10.0.0.1", hours=12)
        assert len(results) == 1

    @patch("elasticsearch.Elasticsearch")
    def test_search_by_username(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.return_value = {"columns": [{"name": "user"}], "values": [["admin"]]}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        results = svc.search_by_username("admin")
        assert len(results) == 1

    @patch("elasticsearch.Elasticsearch")
    def test_search_by_hostname(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.return_value = {"columns": [{"name": "host"}], "values": [["srv01"]]}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        assert len(svc.search_by_hostname("srv01")) == 1

    @patch("elasticsearch.Elasticsearch")
    def test_search_by_domain(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.return_value = {"columns": [{"name": "dns"}], "values": [["evil.com"]]}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        assert len(svc.search_by_domain("evil.com")) == 1

    @patch("elasticsearch.Elasticsearch")
    def test_search_by_hash(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.esql.query.return_value = {"columns": [{"name": "hash"}], "values": [["abc123"]]}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        assert len(svc.search_by_hash("abc123")) == 1


class TestElasticServiceIndices:

    @patch("elasticsearch.Elasticsearch")
    def test_get_indices_filters_system(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.cat.indices.return_value = [
            {"index": "logs-endpoint-1"},
            {"index": ".kibana_8.15.0"},
            {"index": "metrics-apm"},
            {"index": ".internal-something"},
        ]
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        indices = svc.get_indices()
        assert "logs-endpoint-1" in indices
        assert "metrics-apm" in indices
        assert ".kibana_8.15.0" not in indices
        assert ".internal-something" not in indices

    @patch("elasticsearch.Elasticsearch")
    def test_get_data_streams(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.indices.get_data_stream.return_value = {
            "data_streams": [{"name": "logs-elastic_agent-default"}, {"name": "logs-endpoint.events.process-default"}],
        }
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        streams = svc.get_data_streams()
        assert len(streams) == 2

    @patch("elasticsearch.Elasticsearch")
    def test_get_cluster_info(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.info.return_value = {"cluster_name": "prod", "version": {"number": "8.15.0"}}
        mock_client.cluster.health.return_value = {"status": "green", "number_of_nodes": 3}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        info = svc.get_cluster_info()
        assert info["cluster_name"] == "prod"
        assert info["health"] == "green"
        assert info["node_count"] == 3


class TestElasticServiceCaseAndAlertUpdate:

    @patch("requests.request")
    def test_update_alert_status(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {"updated": 2}, raise_for_status=Mock())
        svc = _make_service()
        result = svc.update_alert_status(["a1", "a2"], "closed")
        assert result["updated"] == 2

    @patch("requests.request")
    def test_create_case_success(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "case-1", "title": "Test Case", "version": "v1"},
            raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc.create_case("Test Case", "description", severity="high", tags=["vigil"])
        assert result["id"] == "case-1"
        assert "kibana_url" in result
        assert "case-1" in result["kibana_url"]

    @patch("requests.request")
    def test_create_case_failure(self, mock_req):
        mock_req.return_value = Mock(status_code=500, raise_for_status=Mock(side_effect=Exception("500")))
        svc = _make_service()
        result = svc.create_case("Fail", "desc")
        assert "error" in result


class TestElasticServiceIsolation:

    @patch("requests.request")
    def test_isolate_endpoint_success(self, mock_req):
        mock_req.return_value = Mock(status_code=200, json=lambda: {"action": "isolate"}, raise_for_status=Mock())
        svc = _make_service()
        result = svc.isolate_endpoint("agent-1")
        assert result["action"] == "isolate"

    @patch("requests.request")
    def test_isolate_endpoint_fallback_to_hostname(self, mock_req):
        responses = [
            Mock(status_code=404, raise_for_status=Mock(side_effect=Exception("404"))),
            Mock(status_code=200, json=lambda: {"action": "isolate"}, raise_for_status=Mock()),
        ]
        mock_req.side_effect = responses
        svc = _make_service()
        with patch.object(svc, "_resolve_agent_id", return_value="resolved-id"):
            result = svc.isolate_endpoint("my-host")
            assert "error" not in result or result.get("action") == "isolate"

    @patch("elasticsearch.Elasticsearch")
    def test_resolve_agent_id(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {"hits": [{"_source": {"agent": {"id": "fleet-agent-1"}}}]},
        }
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        agent_id = svc._resolve_agent_id("server01")
        assert agent_id == "fleet-agent-1"

    @patch("elasticsearch.Elasticsearch")
    def test_resolve_agent_id_not_found(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": []}}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        assert svc._resolve_agent_id("unknown-host") is None


class TestElasticServiceRiskScore:

    @patch("elasticsearch.Elasticsearch")
    def test_get_risk_score_found(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {"hits": [{"_source": {"risk_score": 82, "risk_level": "High"}}]},
        }
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        result = svc.get_risk_score("user", "admin")
        assert result["risk_score"] == 82
        assert result["risk_level"] == "High"

    @patch("elasticsearch.Elasticsearch")
    def test_get_risk_score_not_found(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": []}}
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        result = svc.get_risk_score("host", "unknown")
        assert result["risk_score"] is None
        assert result["risk_level"] == "Unknown"

    @patch("elasticsearch.Elasticsearch")
    def test_get_risk_score_entity_analytics_disabled(self, mock_es_cls):
        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("index_not_found")
        mock_es_cls.return_value = mock_client

        svc = _make_service()
        result = svc.get_risk_score("user", "test")
        assert result["risk_score"] is None
        assert "error" in result


class TestElasticServiceDetectionRules:

    @patch("requests.request")
    def test_get_detection_rules(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200,
            json=lambda: {"data": [
                {"id": "r1", "name": "Rule 1", "severity": "high", "enabled": True, "type": "query",
                 "description": "desc", "tags": ["test"], "threat": []},
            ]},
            raise_for_status=Mock(),
        )
        svc = _make_service()
        rules = svc.get_detection_rules()
        assert len(rules) == 1
        assert rules[0]["id"] == "r1"

    @patch("requests.request")
    def test_get_detection_rules_empty(self, mock_req):
        mock_req.return_value = Mock(status_code=404, raise_for_status=Mock(side_effect=Exception("404")))
        svc = _make_service()
        assert svc.get_detection_rules() == []


# ══════════════════════════════════════════════════════════════════════════════
# Kibana Link Service
# ══════════════════════════════════════════════════════════════════════════════

class TestKibanaLinkService:

    def test_generate_alert_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("alert", {"id": "abc-123"})
        assert url == "http://kibana:5601/app/security/alerts?query=kibana.alert.uuid:abc-123"

    def test_generate_rule_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("rule", {"id": "rule-1"})
        assert url == "http://kibana:5601/app/security/rules/id/rule-1"

    def test_generate_case_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("case", {"id": "case-99"})
        assert url == "http://kibana:5601/app/security/cases/case-99"

    def test_generate_timeline_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("timeline", {"id": "tl-1"})
        assert "timelines" in url and "tl-1" in url

    def test_generate_entity_analytics_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("entity_analytics")
        assert url == "http://kibana:5601/app/security/entity_analytics"

    def test_generate_user_risk_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("user_risk", {"user": "admin"})
        assert "users" in url and "admin" in url

    def test_generate_host_risk_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("host_risk", {"host": "srv01"})
        assert "hosts" in url and "srv01" in url

    def test_generate_detection_rules_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("detection_rules")
        assert url == "http://kibana:5601/app/security/rules"

    def test_generate_mitre_coverage_link(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            url = generate_kibana_link("mitre_coverage")
        assert url == "http://kibana:5601/app/security/rules/coverage"

    def test_returns_none_without_kibana_url(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": ""}, clear=False):
            assert generate_kibana_link("alert", {"id": "x"}) is None

    def test_returns_none_for_unknown_page(self):
        from services.kibana_link_service import generate_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            assert generate_kibana_link("nonexistent") is None

    def test_format_kibana_link_markdown(self):
        from services.kibana_link_service import format_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}, clear=False):
            md = format_kibana_link("alert", {"id": "abc"}, label="Open Alert")
        assert md.startswith("[Open Alert](")
        assert "abc" in md

    def test_format_kibana_link_empty_when_no_url(self):
        from services.kibana_link_service import format_kibana_link
        with patch.dict("os.environ", {"KIBANA_URL": ""}, clear=False):
            assert format_kibana_link("alert", {"id": "x"}) == ""

    def test_strips_trailing_slash(self):
        from services.kibana_link_service import get_kibana_url
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601/"}, clear=False):
            assert get_kibana_url() == "http://kibana:5601"


# ══════════════════════════════════════════════════════════════════════════════
# Elastic Ingestion — transform_alert_to_finding
# ══════════════════════════════════════════════════════════════════════════════

class TestElasticIngestion:

    def _make_ingestion(self):
        from services.elastic_ingestion import ElasticIngestion
        with patch("services.elastic_ingestion.get_integration_config", return_value={}):
            svc = ElasticIngestion()
        return svc

    def _sample_alert(self, **overrides):
        alert = {
            "@timestamp": "2025-03-25T12:00:00Z",
            "kibana": {"alert": {
                "uuid": "alert-uuid-001",
                "severity": "high",
                "workflow_status": "open",
                "risk_score": 73,
                "rule": {
                    "uuid": "rule-uuid-001",
                    "name": "Suspicious PowerShell Execution",
                    "description": "Detects encoded PowerShell commands",
                    "index": ["logs-*"],
                },
            }},
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "192.168.1.100"},
            "user": {"name": "jdoe"},
            "host": {"name": "WIN-DESKTOP01"},
            "dns": {"question": {"name": "evil.example.com"}},
            "file": {"hash": {"sha256": "a" * 64, "md5": "b" * 32}},
            "threat": [
                {
                    "tactic": {"id": "TA0002", "name": "Execution"},
                    "technique": [
                        {"id": "T1059", "name": "Command and Scripting Interpreter"},
                        {"id": "T1059.001", "name": "PowerShell"},
                    ],
                }
            ],
        }
        alert.update(overrides)
        return alert

    def test_transform_basic_alert(self):
        svc = self._make_ingestion()
        finding = svc.transform_alert_to_finding(self._sample_alert())

        assert finding is not None
        assert finding["finding_id"] == "elastic-alert-uuid-001"
        assert finding["title"] == "Suspicious PowerShell Execution"
        assert finding["severity"] == "high"
        assert finding["data_source"] == "elastic"

    def test_transform_extracts_entities(self):
        svc = self._make_ingestion()
        finding = svc.transform_alert_to_finding(self._sample_alert())

        entities = finding["entities"]
        assert "10.0.0.5" in entities["ip_addresses"]
        assert "192.168.1.100" in entities["ip_addresses"]
        assert "jdoe" in entities["usernames"]
        assert "WIN-DESKTOP01" in entities["hostnames"]
        assert "evil.example.com" in entities["domains"]
        assert "a" * 64 in entities["file_hashes"]
        assert "b" * 32 in entities["file_hashes"]

    def test_transform_extracts_entity_context(self):
        svc = self._make_ingestion()
        finding = svc.transform_alert_to_finding(self._sample_alert())

        ctx = finding["entity_context"]
        assert "10.0.0.5" in ctx["src_ips"]
        assert "192.168.1.100" in ctx["dest_ips"]
        assert "WIN-DESKTOP01" in ctx["hostnames"]
        assert "jdoe" in ctx["usernames"]

    def test_transform_extracts_mitre(self):
        svc = self._make_ingestion()
        finding = svc.transform_alert_to_finding(self._sample_alert())

        mitre = finding["mitre_attack"]
        assert "TA0002" in mitre["tactics"]
        assert "T1059" in mitre["techniques"]
        assert "T1059.001" in mitre["techniques"]

    def test_transform_builds_mitre_predictions(self):
        svc = self._make_ingestion()
        finding = svc.transform_alert_to_finding(self._sample_alert())

        preds = finding["mitre_predictions"]
        assert preds["T1059"] == "Command and Scripting Interpreter"
        assert preds["T1059.001"] == "PowerShell"

    def test_transform_metadata(self):
        svc = self._make_ingestion()
        finding = svc.transform_alert_to_finding(self._sample_alert())

        meta = finding["metadata"]
        assert meta["alert_uuid"] == "alert-uuid-001"
        assert meta["rule_id"] == "rule-uuid-001"
        assert meta["rule_name"] == "Suspicious PowerShell Execution"
        assert meta["workflow_status"] == "open"
        assert meta["risk_score"] == 73

    def test_transform_missing_uuid_generates_one(self):
        svc = self._make_ingestion()
        alert = self._sample_alert()
        alert["kibana"]["alert"]["uuid"] = ""
        finding = svc.transform_alert_to_finding(alert)
        assert finding["finding_id"].startswith("elastic-")
        assert len(finding["finding_id"]) > len("elastic-")

    def test_transform_minimal_alert(self):
        svc = self._make_ingestion()
        alert = {"@timestamp": "2025-01-01T00:00:00Z"}
        finding = svc.transform_alert_to_finding(alert)
        assert finding is not None
        assert finding["title"] == "Elastic Security Alert"
        assert finding["data_source"] == "elastic"

    def test_transform_no_threat_field(self):
        svc = self._make_ingestion()
        alert = self._sample_alert()
        del alert["threat"]
        finding = svc.transform_alert_to_finding(alert)
        assert finding["mitre_attack"]["tactics"] == []
        assert finding["mitre_attack"]["techniques"] == []
        assert finding["mitre_predictions"] == {}

    @patch("services.elastic_ingestion.ElasticIngestion._get_elastic_service")
    def test_fetch_alerts_delegates_to_service(self, mock_get_es):
        import asyncio
        svc = self._make_ingestion()
        mock_es = Mock()
        mock_es.search_alerts.return_value = [{"alert": 1}]
        mock_get_es.return_value = mock_es

        alerts = asyncio.run(svc.fetch_alerts(limit=5))
        assert len(alerts) == 1
        mock_es.search_alerts.assert_called_once()

    @patch("services.elastic_ingestion.ElasticIngestion._get_elastic_service")
    def test_fetch_alerts_returns_empty_on_error(self, mock_get_es):
        import asyncio
        svc = self._make_ingestion()
        mock_get_es.return_value = None

        alerts = asyncio.run(svc.fetch_alerts())
        assert alerts == []


# ══════════════════════════════════════════════════════════════════════════════
# Elastic Enrichment Service
# ══════════════════════════════════════════════════════════════════════════════

class TestElasticEnrichmentExtractIndicators:

    def _make_enrichment_service(self):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        mock_es = Mock()
        mock_claude = Mock()
        mock_claude.has_api_key.return_value = False
        with patch("services.elastic_enrichment_service.DatabaseDataService"):
            svc = ElasticEnrichmentService(mock_es, mock_claude)
        return svc

    def test_extracts_ips_from_entities(self):
        svc = self._make_enrichment_service()
        findings = [{"entities": {"ip_addresses": ["8.8.8.8", "1.1.1.1"], "usernames": [], "hostnames": [], "domains": [], "file_hashes": []}}]
        indicators = svc.extract_indicators({}, findings)
        assert "8.8.8.8" in indicators["ips"]
        assert "1.1.1.1" in indicators["ips"]

    def test_extracts_usernames(self):
        svc = self._make_enrichment_service()
        findings = [{"entities": {"ip_addresses": [], "usernames": ["admin"], "hostnames": [], "domains": [], "file_hashes": []}}]
        indicators = svc.extract_indicators({}, findings)
        assert "admin" in indicators["usernames"]

    def test_extracts_from_entity_context(self):
        svc = self._make_enrichment_service()
        findings = [{"entity_context": {"src_ip": "8.8.8.8", "username": "root", "hostname": "srv01"}, "entities": {}}]
        indicators = svc.extract_indicators({}, findings)
        assert "8.8.8.8" in indicators["ips"]
        assert "root" in indicators["usernames"]
        assert "srv01" in indicators["hostnames"]

    def test_filters_private_ips(self):
        svc = self._make_enrichment_service()
        findings = [{"entities": {"ip_addresses": ["10.0.0.1", "8.8.8.8", "192.168.1.1"], "usernames": [], "hostnames": [], "domains": [], "file_hashes": []}}]
        indicators = svc.extract_indicators({}, findings)
        assert "10.0.0.1" not in indicators["ips"]
        assert "192.168.1.1" not in indicators["ips"]
        assert "8.8.8.8" in indicators["ips"]

    def test_filters_common_domains(self):
        svc = self._make_enrichment_service()
        findings = [{"entities": {"ip_addresses": [], "usernames": [], "hostnames": [], "domains": ["evil.com", "server.local", "dc1.corp"], "file_hashes": []}}]
        indicators = svc.extract_indicators({}, findings)
        assert "evil.com" in indicators["domains"]
        assert "server.local" not in indicators["domains"]
        assert "dc1.corp" not in indicators["domains"]


class TestElasticEnrichmentHelpers:

    def test_is_private_ip(self):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        assert ElasticEnrichmentService._is_private_ip("10.0.0.1") is True
        assert ElasticEnrichmentService._is_private_ip("172.16.0.1") is True
        assert ElasticEnrichmentService._is_private_ip("172.31.255.255") is True
        assert ElasticEnrichmentService._is_private_ip("192.168.1.1") is True
        assert ElasticEnrichmentService._is_private_ip("127.0.0.1") is True
        assert ElasticEnrichmentService._is_private_ip("8.8.8.8") is False
        assert ElasticEnrichmentService._is_private_ip("1.1.1.1") is False
        assert ElasticEnrichmentService._is_private_ip("not-an-ip") is True

    def test_is_common_domain(self):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        assert ElasticEnrichmentService._is_common_domain("server.local") is True
        assert ElasticEnrichmentService._is_common_domain("dc1.corp") is True
        assert ElasticEnrichmentService._is_common_domain("host.internal") is True
        assert ElasticEnrichmentService._is_common_domain("host.lan") is True
        assert ElasticEnrichmentService._is_common_domain("evil.com") is False
        assert ElasticEnrichmentService._is_common_domain("google.com") is False


class TestElasticEnrichmentRiskScores:

    def test_get_risk_scores_aggregates(self):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        mock_es = Mock()
        mock_es.get_risk_score.side_effect = [
            {"risk_score": 80, "risk_level": "High"},
            {"risk_score": None, "risk_level": "Unknown"},
            {"risk_score": 45, "risk_level": "Low"},
        ]
        with patch("services.elastic_enrichment_service.DatabaseDataService"):
            svc = ElasticEnrichmentService(mock_es)

        indicators = {"usernames": ["admin", "nobody"], "hostnames": ["srv01"]}
        scores = svc.get_risk_scores(indicators)

        assert "user:admin" in scores
        assert scores["user:admin"]["risk_score"] == 80
        assert "user:nobody" not in scores
        assert "host:srv01" in scores


class TestElasticEnrichmentThreatIntel:

    def test_get_threat_intelligence(self):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        mock_es = Mock()
        mock_es.run_esql.side_effect = [
            [{"threat.indicator.ip": "8.8.8.8"}],
            [],
            [{"threat.indicator.file.hash.sha256": "abc"}],
        ]
        with patch("services.elastic_enrichment_service.DatabaseDataService"):
            svc = ElasticEnrichmentService(mock_es)

        indicators = {"ips": ["8.8.8.8"], "domains": ["clean.com"], "hashes": ["abc"]}
        matches = svc.get_threat_intelligence(indicators)

        assert "ip:8.8.8.8" in matches
        assert "domain:clean.com" not in matches
        assert "hash:abc" in matches

    def test_get_threat_intelligence_handles_missing_ti_indices(self):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        mock_es = Mock()
        mock_es.run_esql.side_effect = Exception("index_not_found")
        with patch("services.elastic_enrichment_service.DatabaseDataService"):
            svc = ElasticEnrichmentService(mock_es)

        matches = svc.get_threat_intelligence({"ips": ["1.2.3.4"], "domains": [], "hashes": []})
        assert matches == {}


class TestElasticEnrichmentQueryIndicators:

    def test_query_elastic_for_indicators(self):
        from services.elastic_enrichment_service import ElasticEnrichmentService
        mock_es = Mock()
        mock_es.search_by_ip.return_value = [{"event": "1"}, {"event": "2"}]
        mock_es.search_by_username.return_value = [{"event": "3"}]
        mock_es.search_by_hostname.return_value = []
        mock_es.search_by_domain.return_value = []
        mock_es.search_by_hash.return_value = []
        with patch("services.elastic_enrichment_service.DatabaseDataService"):
            svc = ElasticEnrichmentService(mock_es)

        indicators = {"ips": ["8.8.8.8"], "usernames": ["admin"], "hostnames": [], "domains": [], "hashes": []}
        result = svc.query_elastic_for_indicators(indicators, hours=24)

        assert result["summary"]["total_events"] == 3
        assert result["summary"]["ips_queried"] == 1
        assert result["results"]["ips"]["8.8.8.8"] == [{"event": "1"}, {"event": "2"}]


# ══════════════════════════════════════════════════════════════════════════════
# MCP Tool Wrappers (original 26 tools)
# ══════════════════════════════════════════════════════════════════════════════

class TestMCPToolWrappers:
    """Tests for the original MCP tool wrappers that weren't previously covered."""

    @patch("tools.elastic_security._require_service")
    def test_search_alerts_tool(self, mock_req_svc):
        from tools.elastic_security import search_alerts
        mock_svc = Mock()
        mock_svc.search_alerts.return_value = [
            {
                "@timestamp": "2025-01-01",
                "kibana": {"alert": {"rule": {"name": "Test Rule"}, "severity": "high",
                                     "workflow_status": "open", "uuid": "uuid-1"}},
                "source": {"ip": "10.0.0.1"},
                "destination": {"ip": "10.0.0.2"},
                "user": {"name": "admin"},
                "host": {"name": "srv01"},
            }
        ]
        mock_svc.kibana_url = "http://kibana:5601"
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_alerts(severity="high", limit=10))
        assert result["count"] == 1
        assert result["alerts"][0]["rule_name"] == "Test Rule"
        assert "kibana_url" in result["alerts"][0]

    @patch("tools.elastic_security._require_service")
    def test_search_events_tool(self, mock_req_svc):
        from tools.elastic_security import search_events
        mock_svc = Mock()
        mock_svc.run_esql.return_value = [{"host": "srv01"}]
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_events("FROM logs-* | LIMIT 1"))
        assert result["count"] == 1

    @patch("tools.elastic_security._require_service")
    def test_search_events_rejects_non_from(self, mock_req_svc):
        from tools.elastic_security import search_events
        mock_svc = Mock()
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_events("DELETE FROM logs"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_search_entities_tool(self, mock_req_svc):
        from tools.elastic_security import search_entities
        mock_svc = Mock()
        mock_svc.search_by_ip.return_value = [{"event": "1"}]
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_entities("ip", "10.0.0.1"))
        assert result["count"] == 1

    @patch("tools.elastic_security._require_service")
    def test_search_entities_invalid_type(self, mock_req_svc):
        from tools.elastic_security import search_entities
        mock_svc = Mock()
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_entities("invalid", "val"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_get_alert_details_tool(self, mock_req_svc):
        from tools.elastic_security import get_alert_details
        mock_svc = Mock()
        mock_svc.get_alert_by_id.return_value = {"kibana.alert.uuid": "abc"}
        mock_svc.kibana_url = "http://kibana:5601"
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_alert_details("abc"))
        assert result["kibana.alert.uuid"] == "abc"
        assert "kibana_url" in result

    @patch("tools.elastic_security._require_service")
    def test_get_alert_details_not_found(self, mock_req_svc):
        from tools.elastic_security import get_alert_details
        mock_svc = Mock()
        mock_svc.get_alert_by_id.return_value = None
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_alert_details("missing"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_update_alert_status_tool(self, mock_req_svc):
        from tools.elastic_security import update_alert_status
        mock_svc = Mock()
        mock_svc.update_alert_status.return_value = {"updated": 2}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(update_alert_status("id1,id2", "closed"))
        assert result["updated"] == 2

    @patch("tools.elastic_security._require_service")
    def test_update_alert_status_invalid_status(self, mock_req_svc):
        from tools.elastic_security import update_alert_status
        mock_svc = Mock()
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(update_alert_status("id1", "invalid"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_get_risk_score_tool(self, mock_req_svc):
        from tools.elastic_security import get_risk_score
        mock_svc = Mock()
        mock_svc.get_risk_score.return_value = {"risk_score": 85, "risk_level": "High", "entity_type": "user", "entity_value": "admin"}
        mock_svc.kibana_url = "http://kibana:5601"
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_risk_score("user", "admin"))
        assert result["risk_score"] == 85
        assert "kibana_url" in result

    @patch("tools.elastic_security._require_service")
    def test_get_risk_score_invalid_type(self, mock_req_svc):
        from tools.elastic_security import get_risk_score
        mock_svc = Mock()
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_risk_score("invalid", "val"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_create_case_tool(self, mock_req_svc):
        from tools.elastic_security import create_case
        mock_svc = Mock()
        mock_svc.create_case.return_value = {"id": "case-1", "title": "Test"}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(create_case("Test", "desc", tags="tag1,tag2"))
        assert result["id"] == "case-1"

    @patch("tools.elastic_security._require_service")
    def test_isolate_endpoint_tool(self, mock_req_svc):
        from tools.elastic_security import isolate_endpoint
        mock_svc = Mock()
        mock_svc.isolate_endpoint.return_value = {"action": "isolate"}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(isolate_endpoint("agent-1"))
        assert result["action"] == "isolate"

    @patch("tools.elastic_security._require_service")
    def test_release_endpoint_tool(self, mock_req_svc):
        from tools.elastic_security import release_endpoint
        mock_svc = Mock()
        mock_svc.unisolate_endpoint.return_value = {"action": "unisolate"}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(release_endpoint("agent-1"))
        assert result["action"] == "unisolate"

    @patch("tools.elastic_security._require_service")
    def test_run_osquery_tool_with_pack(self, mock_req_svc):
        from tools.elastic_security import run_osquery
        mock_svc = Mock()
        mock_svc.run_osquery.return_value = {"action_id": "oq-1", "status": "submitted", "agents": ["a1"]}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(run_osquery("a1", pack="processes"))
        assert result["action_id"] == "oq-1"

    @patch("tools.elastic_security._require_service")
    def test_run_osquery_tool_invalid_pack(self, mock_req_svc):
        from tools.elastic_security import run_osquery
        mock_svc = Mock()
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(run_osquery("a1", pack="nonexistent"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_run_osquery_tool_no_query_or_pack(self, mock_req_svc):
        from tools.elastic_security import run_osquery
        mock_svc = Mock()
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(run_osquery("a1"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_get_detection_rules_tool(self, mock_req_svc):
        from tools.elastic_security import get_detection_rules
        mock_svc = Mock()
        mock_svc.get_detection_rules.return_value = [
            {"id": "r1", "name": "Rule", "threat": [{"technique": [{"id": "T1059"}]}]},
        ]
        mock_svc.kibana_url = "http://kibana:5601"
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_detection_rules(mitre_technique="T1059"))
        assert result["count"] == 1
        assert "kibana_url" in result["rules"][0]

    @patch("tools.elastic_security._require_service")
    def test_get_indices_tool(self, mock_req_svc):
        from tools.elastic_security import get_indices
        mock_svc = Mock()
        mock_svc.get_indices.return_value = ["logs-endpoint-1"]
        mock_svc.get_data_streams.return_value = ["logs-elastic_agent-default"]
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_indices())
        assert "logs-endpoint-1" in result["indices"]
        assert "logs-elastic_agent-default" in result["data_streams"]

    @patch("tools.elastic_security._require_service")
    def test_get_asset_criticality_tool(self, mock_req_svc):
        from tools.elastic_security import get_asset_criticality
        mock_svc = Mock()
        mock_svc.get_asset_criticality.return_value = {"criticality_level": "high_impact", "assigned": True, "entity_type": "host", "entity_value": "srv01"}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_asset_criticality("host", "srv01"))
        assert result["criticality_level"] == "high_impact"

    @patch("tools.elastic_security._require_service")
    def test_get_asset_criticality_invalid_type(self, mock_req_svc):
        from tools.elastic_security import get_asset_criticality
        mock_svc = Mock()
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_asset_criticality("invalid", "val"))
        assert "error" in result

    @patch("tools.elastic_security._require_service")
    def test_get_timeline_tool_create(self, mock_req_svc):
        from tools.elastic_security import get_timeline
        mock_svc = Mock()
        mock_svc._kibana_request.return_value = {
            "data": {"persistTimeline": {"timeline": {"savedObjectId": "tl-new"}}},
        }
        mock_svc.kibana_url = "http://kibana:5601"
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(get_timeline(title="My Investigation"))
        assert result["timeline_id"] == "tl-new"
        assert "kibana_url" in result

    @patch("tools.elastic_security._require_service")
    def test_preview_rule_tool(self, mock_req_svc):
        from tools.elastic_security import preview_rule
        mock_svc = Mock()
        mock_svc.preview_rule.return_value = {"match_count": 42, "samples": [], "time_range": "-24h"}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(preview_rule("process.name: cmd.exe"))
        assert result["match_count"] == 42

    @patch("tools.elastic_security._require_service")
    def test_create_exception_tool(self, mock_req_svc):
        from tools.elastic_security import create_exception
        mock_svc = Mock()
        mock_svc.create_exception_list.return_value = {"id": "exc-1", "list_id": "vigil-abc"}
        mock_svc.add_exception_item.return_value = {"id": "item-1"}
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(create_exception("FP List", "Backup", "process.name", "backup.exe"))
        assert result["list"]["list_id"] == "vigil-abc"
        assert result["item"]["id"] == "item-1"

    def test_require_service_returns_error_when_unconfigured(self):
        from tools.elastic_security import _require_service
        with patch("tools.elastic_security._get_service", side_effect=Exception("No config")):
            svc, err = _require_service()
            assert svc is None
            assert err is not None
            result = json.loads(err)
            assert "error" in result


# ══════════════════════════════════════════════════════════════════════════════
# Edge-case tests for audit findings
# ══════════════════════════════════════════════════════════════════════════════

class TestKibanaRequest204:
    """_kibana_request must handle 204 No Content without crashing."""

    @patch("requests.request")
    def test_delete_returns_empty_dict_on_204(self, mock_req):
        mock_req.return_value = Mock(
            status_code=204, content=b"", raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc._kibana_request("DELETE", "/api/detection_engine/rules?rule_id=r1")
        assert result == {}

    @patch("requests.request")
    def test_post_returns_json_on_200(self, mock_req):
        mock_req.return_value = Mock(
            status_code=200, content=b'{"id":"r1"}',
            json=lambda: {"id": "r1"}, raise_for_status=Mock(),
        )
        svc = _make_service()
        result = svc._kibana_request("POST", "/api/cases", body={"title": "x"})
        assert result == {"id": "r1"}


class TestDeleteOperationsWith204:

    @patch("requests.request")
    def test_delete_detection_rule_success_on_204(self, mock_req):
        mock_req.return_value = Mock(status_code=204, content=b"", raise_for_status=Mock())
        svc = _make_service()
        result = svc.delete_detection_rule("rule-1")
        assert result["deleted"] is True

    @patch("requests.request")
    def test_delete_agent_builder_tool_success_on_204(self, mock_req):
        mock_req.return_value = Mock(status_code=204, content=b"", raise_for_status=Mock())
        svc = _make_service()
        result = svc.delete_agent_builder_tool("tool-1")
        assert result["deleted"] is True

    @patch("requests.request")
    def test_delete_agent_builder_agent_success_on_204(self, mock_req):
        mock_req.return_value = Mock(status_code=204, content=b"", raise_for_status=Mock())
        svc = _make_service()
        result = svc.delete_agent_builder_agent("agent-1")
        assert result["deleted"] is True


class TestThreatFieldTypeSafety:

    @patch("tools.elastic_security._require_service")
    def test_search_alerts_handles_threat_as_dict(self, mock_req_svc):
        from tools.elastic_security import search_alerts
        mock_svc = Mock()
        mock_svc.search_alerts.return_value = [
            {
                "@timestamp": "2025-01-01",
                "kibana": {"alert": {"rule": {"name": "R"}, "severity": "high",
                                     "workflow_status": "open", "uuid": "u1"}},
                "threat": {"tactic": {"id": "TA0001"}},  # dict, not list
            }
        ]
        mock_svc.kibana_url = ""
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_alerts())
        assert result["count"] == 1
        assert result["alerts"][0]["mitre_techniques"] == []

    @patch("tools.elastic_security._require_service")
    def test_search_alerts_handles_empty_threat(self, mock_req_svc):
        from tools.elastic_security import search_alerts
        mock_svc = Mock()
        mock_svc.search_alerts.return_value = [
            {
                "@timestamp": "2025-01-01",
                "kibana": {"alert": {"rule": {"name": "R"}, "severity": "low",
                                     "workflow_status": "open", "uuid": "u2"}},
            }
        ]
        mock_svc.kibana_url = ""
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_alerts())
        assert result["alerts"][0]["mitre_techniques"] == []

    @patch("tools.elastic_security._require_service")
    def test_search_alerts_extracts_multiple_techniques(self, mock_req_svc):
        from tools.elastic_security import search_alerts
        mock_svc = Mock()
        mock_svc.search_alerts.return_value = [
            {
                "@timestamp": "2025-01-01",
                "kibana": {"alert": {"rule": {"name": "R"}, "severity": "high",
                                     "workflow_status": "open", "uuid": "u3"}},
                "threat": [
                    {"tactic": {"id": "TA0002"}, "technique": [{"id": "T1059"}, {"id": "T1059.001"}]},
                    {"tactic": {"id": "TA0005"}, "technique": [{"id": "T1078"}]},
                ],
            }
        ]
        mock_svc.kibana_url = ""
        mock_req_svc.return_value = (mock_svc, None)

        result = json.loads(search_alerts())
        techniques = result["alerts"][0]["mitre_techniques"]
        assert "T1059" in techniques
        assert "T1059.001" in techniques
        assert "T1078" in techniques


class TestEntityContextIPRoles:

    def _make_ingestion(self):
        from services.elastic_ingestion import ElasticIngestion
        with patch("services.elastic_ingestion.get_integration_config", return_value={}):
            return ElasticIngestion()

    def test_only_dest_ip_not_in_src_ips(self):
        svc = self._make_ingestion()
        alert = {
            "@timestamp": "2025-01-01T00:00:00Z",
            "destination": {"ip": "10.0.0.2"},
        }
        finding = svc.transform_alert_to_finding(alert)
        ctx = finding["entity_context"]
        assert ctx["src_ips"] == []
        assert ctx["dest_ips"] == ["10.0.0.2"]

    def test_both_src_and_dest_ip(self):
        svc = self._make_ingestion()
        alert = {
            "@timestamp": "2025-01-01T00:00:00Z",
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "10.0.0.2"},
        }
        finding = svc.transform_alert_to_finding(alert)
        ctx = finding["entity_context"]
        assert ctx["src_ips"] == ["10.0.0.1"]
        assert ctx["dest_ips"] == ["10.0.0.2"]
        assert "10.0.0.1" not in ctx["dest_ips"]
        assert "10.0.0.2" not in ctx["src_ips"]

    def test_only_src_ip(self):
        svc = self._make_ingestion()
        alert = {
            "@timestamp": "2025-01-01T00:00:00Z",
            "source": {"ip": "10.0.0.1"},
        }
        finding = svc.transform_alert_to_finding(alert)
        ctx = finding["entity_context"]
        assert ctx["src_ips"] == ["10.0.0.1"]
        assert ctx["dest_ips"] == []

    def test_no_ips(self):
        svc = self._make_ingestion()
        alert = {"@timestamp": "2025-01-01T00:00:00Z"}
        finding = svc.transform_alert_to_finding(alert)
        ctx = finding["entity_context"]
        assert ctx["src_ips"] == []
        assert ctx["dest_ips"] == []


class TestMCPConfigWithPassword:

    def test_basic_auth_includes_password(self):
        svc = _make_service(api_key=None, username="admin", password="secret")
        config = svc.get_agent_builder_mcp_config()
        assert config["auth"]["password"] == "secret"
        assert config["auth"]["username"] == "admin"

    def test_no_auth_when_neither_key_nor_password(self):
        svc = _make_service(api_key=None, username=None, password=None)
        config = svc.get_agent_builder_mcp_config()
        assert "headers" not in config
        assert "auth" not in config


class TestResetService:

    def test_reset_clears_singleton(self):
        from tools.elastic_security import _reset_service
        import tools.elastic_security as mod
        mod._elastic_service = Mock()
        assert mod._elastic_service is not None
        _reset_service()
        assert mod._elastic_service is None
