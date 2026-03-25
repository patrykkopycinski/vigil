"""Elasticsearch API service for Elastic Security integration."""

import logging
import os
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


class ElasticService:
    """Service for interacting with Elasticsearch and Elastic Security APIs."""

    SYSTEM_INDEX_PREFIXES = ('.internal', '.kibana', '.fleet', '.apm', '.ds-', '.security', '.async-search', '.tasks', '.transform')

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        cloud_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        kibana_url: Optional[str] = None,
    ):
        self.url = url
        self.api_key = api_key
        self.cloud_id = cloud_id
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.kibana_url = (kibana_url or '').rstrip('/')
        self._client = None

    @classmethod
    def from_env(cls) -> "ElasticService":
        """Create an ElasticService from environment variables."""
        return cls(
            url=os.getenv('ELASTIC_URL'),
            api_key=os.getenv('ELASTIC_API_KEY'),
            cloud_id=os.getenv('ELASTIC_CLOUD_ID'),
            username=os.getenv('ELASTIC_USERNAME'),
            password=os.getenv('ELASTIC_PASSWORD'),
            verify_ssl=os.getenv('ELASTIC_VERIFY_SSL', 'true').lower() == 'true',
            kibana_url=os.getenv('KIBANA_URL'),
        )

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "ElasticService":
        """Create an ElasticService from integration config dict."""
        return cls(
            url=config.get('url') or config.get('elasticsearch_url'),
            api_key=config.get('api_key'),
            cloud_id=config.get('cloud_id'),
            username=config.get('username'),
            password=config.get('password'),
            verify_ssl=config.get('verify_ssl', True),
            kibana_url=config.get('kibana_url'),
        )

    def _get_client(self):
        """Lazy-init and return the Elasticsearch client."""
        if self._client is not None:
            return self._client

        from elasticsearch import Elasticsearch

        kwargs: Dict[str, Any] = {
            'verify_certs': self.verify_ssl,
            'request_timeout': 30,
        }

        if self.api_key:
            kwargs['api_key'] = self.api_key

        if self.username and self.password:
            kwargs['basic_auth'] = (self.username, self.password)

        if self.cloud_id:
            kwargs['cloud_id'] = self.cloud_id
        elif self.url:
            kwargs['hosts'] = [self.url]
        else:
            raise ValueError("Either ELASTIC_URL or ELASTIC_CLOUD_ID must be provided")

        self._client = Elasticsearch(**kwargs)
        return self._client

    # ── Connection ────────────────────────────────────────────────────────

    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity. Returns (success, message) matching SplunkService signature."""
        try:
            client = self._get_client()
            info = client.info()
            version = info.get('version', {}).get('number', 'unknown')
            name = info.get('name', 'unknown')
            cluster = info.get('cluster_name', 'unknown')

            health = client.cluster.health()
            status = health.get('status', 'unknown')

            return True, f"Connected to Elastic {version} - Cluster: {cluster} ({status})"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    # ── ES|QL ────────────────────────────────────────────────────────────

    def run_esql(self, query: str, params: Optional[Dict] = None, limit: int = 10000) -> List[Dict]:
        """Execute an ES|QL query and return tabular results as list of dicts."""
        try:
            client = self._get_client()
            body: Dict[str, Any] = {"query": query}
            if params:
                body["params"] = params

            resp = client.esql.query(body=body)

            columns = [col["name"] for col in resp.get("columns", [])]
            rows = resp.get("values", [])
            return [dict(zip(columns, row)) for row in rows[:limit]]
        except Exception as e:
            logger.error(f"ES|QL query error: {e}")
            raise

    # ── Alert Search ──────────────────────────────────────────────────────

    def search_alerts(
        self,
        filters: Optional[Dict] = None,
        time_range: str = "-24h",
        max_count: int = 1000,
    ) -> List[Dict]:
        """Search Elastic Security alerts in .alerts-security.alerts-default.

        Raises on connection/auth errors so callers can surface them.
        """
        client = self._get_client()
        filters = filters or {}

        must = []
        must.append({"range": {"@timestamp": {"gte": f"now{time_range}"}}})

        if filters.get("severity"):
            must.append({"term": {"kibana.alert.severity": filters["severity"]}})
        if filters.get("status"):
            must.append({"term": {"kibana.alert.workflow_status": filters["status"]}})
        if filters.get("rule_name"):
            must.append({"match": {"kibana.alert.rule.name": filters["rule_name"]}})
        if filters.get("mitre_technique"):
            must.append({"term": {"threat.technique.id": filters["mitre_technique"]}})

        for entity_field, entity_key in [
            ("source.ip", "source_ip"),
            ("destination.ip", "destination_ip"),
            ("user.name", "username"),
            ("host.name", "hostname"),
        ]:
            if filters.get(entity_key):
                must.append({"term": {entity_field: filters[entity_key]}})

        body = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": "desc"}],
            "size": max_count,
        }

        resp = client.search(index=".alerts-security.alerts-default", body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def get_alert_by_id(self, alert_uuid: str) -> Optional[Dict]:
        """Fetch a single alert by kibana.alert.uuid.

        Raises on connection/auth errors so callers can surface them.
        """
        client = self._get_client()
        resp = client.search(
            index=".alerts-security.alerts-default",
            body={
                "query": {"term": {"kibana.alert.uuid": alert_uuid}},
                "size": 1,
            },
        )
        hits = resp["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    # ── Entity Search (ES|QL) ────────────────────────────────────────────

    @staticmethod
    def _sanitize_esql_value(value: str) -> str:
        """Escape a user-supplied value for safe interpolation into ES|QL strings.

        Strips characters that could break out of a quoted string or alter
        query semantics (double-quotes, backslashes, pipe operators, newlines).
        """
        return (
            value
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("|", "")
            .replace("\n", "")
            .replace("\r", "")
        )

    def _entity_esql(self, where_clause: str, hours: int) -> List[Dict]:
        """Run an entity search via ES|QL.

        Returns [] if queried fields don't exist in the index mapping
        (ES|QL raises verification_exception for unknown columns, unlike
        query DSL which silently returns no matches).
        """
        query = f"FROM logs-* | WHERE {where_clause} AND @timestamp > NOW() - {hours} hours | LIMIT 1000"
        try:
            return self.run_esql(query)
        except Exception as e:
            if "verification_exception" in str(type(e).__name__).lower() or "unknown column" in str(e).lower():
                logger.warning(f"ES|QL field not mapped, returning empty: {e}")
                return []
            raise

    def search_by_ip(self, ip_address: str, hours: int = 24) -> List[Dict]:
        safe = self._sanitize_esql_value(ip_address)
        return self._entity_esql(
            f'source.ip == "{safe}" OR destination.ip == "{safe}"', hours
        )

    def search_by_domain(self, domain: str, hours: int = 24) -> List[Dict]:
        safe = self._sanitize_esql_value(domain)
        return self._entity_esql(f'dns.question.name == "{safe}"', hours)

    def search_by_hash(self, file_hash: str, hours: int = 24) -> List[Dict]:
        safe = self._sanitize_esql_value(file_hash)
        return self._entity_esql(
            f'file.hash.sha256 == "{safe}" OR file.hash.md5 == "{safe}"', hours
        )

    def search_by_username(self, username: str, hours: int = 24) -> List[Dict]:
        safe = self._sanitize_esql_value(username)
        return self._entity_esql(f'user.name == "{safe}"', hours)

    def search_by_hostname(self, hostname: str, hours: int = 24) -> List[Dict]:
        safe = self._sanitize_esql_value(hostname)
        return self._entity_esql(f'host.name == "{safe}"', hours)

    # ── Index Discovery ──────────────────────────────────────────────────

    def get_indices(self, pattern: str = "*") -> List[str]:
        """List available indices, filtering out system indices."""
        try:
            client = self._get_client()
            resp = client.cat.indices(index=pattern, format="json", h="index")
            return sorted(
                idx["index"]
                for idx in resp
                if not any(idx["index"].startswith(p) for p in self.SYSTEM_INDEX_PREFIXES)
            )
        except Exception as e:
            logger.error(f"Index listing error: {e}")
            return []

    def get_data_streams(self, pattern: str = "*") -> List[str]:
        """List data streams."""
        try:
            client = self._get_client()
            resp = client.indices.get_data_stream(name=pattern)
            return sorted(ds["name"] for ds in resp.get("data_streams", []))
        except Exception as e:
            logger.error(f"Data stream listing error: {e}")
            return []

    # ── Cluster Info ─────────────────────────────────────────────────────

    def get_cluster_info(self) -> Dict:
        """Return cluster name, version, health status, and node count."""
        try:
            client = self._get_client()
            info = client.info()
            health = client.cluster.health()
            return {
                "cluster_name": info.get("cluster_name"),
                "version": info.get("version", {}).get("number"),
                "health": health.get("status"),
                "node_count": health.get("number_of_nodes"),
            }
        except Exception as e:
            logger.error(f"Cluster info error: {e}")
            return {"error": str(e)}

    # ── Entity Analytics (Elastic-only) ──────────────────────────────────

    def get_risk_score(self, entity_type: str, entity_value: str) -> Dict:
        """Query Entity Analytics risk engine for a user or host risk score."""
        try:
            client = self._get_client()
            index = f"ml_host_risk_score_latest_default" if entity_type == "host" else "ml_user_risk_score_latest_default"
            field = "host.name" if entity_type == "host" else "user.name"

            resp = client.search(
                index=index,
                body={
                    "query": {"term": {field: entity_value}},
                    "size": 1,
                },
            )
            hits = resp["hits"]["hits"]
            if not hits:
                return {"entity_type": entity_type, "entity_value": entity_value, "risk_score": None, "risk_level": "Unknown"}

            source = hits[0]["_source"]
            score = source.get("risk_score", source.get(f"{entity_type}.risk.calculated_score_norm"))
            level = source.get("risk_level", source.get(f"{entity_type}.risk.calculated_level", "Unknown"))
            return {
                "entity_type": entity_type,
                "entity_value": entity_value,
                "risk_score": score,
                "risk_level": level,
                "raw": source,
            }
        except Exception as e:
            logger.warning(f"Risk score lookup error (Entity Analytics may not be enabled): {e}")
            return {"entity_type": entity_type, "entity_value": entity_value, "risk_score": None, "risk_level": "Unknown", "error": str(e)}

    # ── Kibana API helpers (require KIBANA_URL) ──────────────────────────

    def _kibana_request(self, method: str, path: str, body: Optional[Dict] = None) -> Optional[Dict]:
        """Make a request to Kibana API. Requires KIBANA_URL."""
        if not self.kibana_url:
            logger.warning("KIBANA_URL not configured")
            return None

        import requests

        url = f"{self.kibana_url}{path}"
        headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}

        auth = None
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.username and self.password:
            from requests.auth import HTTPBasicAuth
            auth = HTTPBasicAuth(self.username, self.password)

        try:
            resp = requests.request(
                method, url, json=body, headers=headers,
                auth=auth, verify=self.verify_ssl, timeout=30,
            )
            resp.raise_for_status()
            if resp.status_code == 204 or not resp.content:
                return {}
            return resp.json()
        except Exception as e:
            logger.error(f"Kibana API error ({method} {path}): {e}")
            return None

    def get_detection_rules(self, filter_params: Optional[Dict] = None) -> List[Dict]:
        """List detection rules via Kibana Detection Engine API."""
        filter_params = filter_params or {}
        params_parts = []
        if filter_params.get("enabled") is not None:
            params_parts.append(f"filter=alert.attributes.enabled:{str(filter_params['enabled']).lower()}")

        page = 1
        per_page = 100
        query = f"?page={page}&per_page={per_page}"
        if params_parts:
            query += "&" + "&".join(params_parts)

        result = self._kibana_request("GET", f"/api/detection_engine/rules/_find{query}")
        if not result:
            return []

        rules = []
        for rule in result.get("data", []):
            rules.append({
                "id": rule.get("id"),
                "name": rule.get("name"),
                "description": rule.get("description", ""),
                "severity": rule.get("severity"),
                "enabled": rule.get("enabled"),
                "type": rule.get("type"),
                "tags": rule.get("tags", []),
                "threat": rule.get("threat", []),
            })
        return rules

    def update_alert_status(self, alert_ids: List[str], status: str) -> Dict:
        """Update alert workflow status (open, acknowledged, closed)."""
        result = self._kibana_request(
            "POST",
            "/api/detection_engine/signals/status",
            body={
                "signal_ids": alert_ids,
                "status": status,
            },
        )
        return result or {"error": "Failed to update alert status"}

    def create_case(self, title: str, description: str, severity: str = "medium", tags: Optional[List[str]] = None) -> Dict:
        """Create a case in Kibana Cases."""
        body = {
            "title": title,
            "description": description,
            "tags": tags or [],
            "severity": severity,
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
            "settings": {"syncAlerts": True},
            "owner": "securitySolution",
        }
        result = self._kibana_request("POST", "/api/cases", body=body)
        if not result:
            return {"error": "Failed to create case"}

        case_id = result.get("id", "")
        resp = {"id": case_id, "title": result.get("title"), "version": result.get("version")}
        if self.kibana_url:
            resp["kibana_url"] = f"{self.kibana_url}/app/security/cases/{case_id}"
        return resp

    def isolate_endpoint(self, agent_id_or_hostname: str) -> Dict:
        """Trigger endpoint isolation via Elastic Defend / Fleet API."""
        body = {
            "endpoint_ids": [agent_id_or_hostname],
            "comment": "Isolated by Vigil AI SOC",
        }
        result = self._kibana_request("POST", "/api/endpoint/action/isolate", body=body)
        if not result:
            agent_by_host = self._resolve_agent_id(agent_id_or_hostname)
            if agent_by_host:
                body["endpoint_ids"] = [agent_by_host]
                result = self._kibana_request("POST", "/api/endpoint/action/isolate", body=body)

        return result or {"error": "Failed to isolate endpoint"}

    def unisolate_endpoint(self, agent_id_or_hostname: str) -> Dict:
        """Release (unisolate) a previously isolated endpoint via Elastic Defend."""
        body = {
            "endpoint_ids": [agent_id_or_hostname],
            "comment": "Released by Vigil AI SOC",
        }
        result = self._kibana_request("POST", "/api/endpoint/action/unisolate", body=body)
        if not result:
            agent_by_host = self._resolve_agent_id(agent_id_or_hostname)
            if agent_by_host:
                body["endpoint_ids"] = [agent_by_host]
                result = self._kibana_request("POST", "/api/endpoint/action/unisolate", body=body)
        return result or {"error": "Failed to unisolate endpoint"}

    def kill_process(self, agent_id: str, pid: Optional[int] = None, entity_id: Optional[str] = None) -> Dict:
        """Kill a process on an endpoint via Elastic Defend."""
        if not pid and not entity_id:
            return {"error": "Either pid or entity_id must be provided"}

        params: Dict[str, Any] = {}
        if pid is not None:
            params["pid"] = pid
        if entity_id:
            params["entity_id"] = entity_id

        body: Dict[str, Any] = {
            "endpoint_ids": [agent_id],
            "parameters": params,
            "comment": "Process killed by Vigil AI SOC",
        }
        result = self._kibana_request("POST", "/api/endpoint/action/kill_process", body=body)
        return result or {"error": "Failed to kill process"}

    def get_file(self, agent_id: str, path: str) -> Dict:
        """Retrieve a file from an endpoint for forensic analysis via Elastic Defend."""
        body: Dict[str, Any] = {
            "endpoint_ids": [agent_id],
            "parameters": {"path": path},
            "comment": "File retrieved by Vigil AI SOC",
        }
        result = self._kibana_request("POST", "/api/endpoint/action/get_file", body=body)
        return result or {"error": "Failed to retrieve file"}

    def get_action_status(self, action_id: str) -> Dict:
        """Check status of a pending response action."""
        result = self._kibana_request("GET", f"/api/endpoint/action/{action_id}")
        if not result:
            return {"error": f"Failed to get action status for {action_id}"}
        data = result.get("data", result)
        return {
            "action_id": action_id,
            "status": data.get("status", data.get("command", "unknown")),
            "is_completed": data.get("isCompleted", False),
            "started_at": data.get("startedAt"),
            "completed_at": data.get("completedAt"),
            "outputs": data.get("outputs", {}),
        }

    # ── Osquery (Elastic Agent) ──────────────────────────────────────────

    def run_osquery(self, query: str, agent_ids: List[str]) -> Dict:
        """Submit a live Osquery query to Elastic Agents via Kibana."""
        body = {
            "query": query,
            "agent_ids": agent_ids,
        }
        result = self._kibana_request("POST", "/api/osquery/live_queries", body=body)
        if not result:
            return {"error": "Failed to submit Osquery — is Osquery Manager enabled?"}
        action_id = result.get("data", {}).get("id", result.get("id"))
        return {"action_id": action_id, "status": "submitted", "agents": agent_ids}

    def get_osquery_results(self, action_id: str) -> Dict:
        """Retrieve results from a live Osquery action."""
        result = self._kibana_request("GET", f"/api/osquery/live_queries/{action_id}/results")
        if not result:
            return {"error": f"Failed to get Osquery results for {action_id}"}
        data = result.get("data", result)
        return {
            "action_id": action_id,
            "status": data.get("status", "unknown"),
            "total": data.get("total", 0),
            "results": data.get("items", data.get("results", [])),
        }

    # ── Asset Criticality ────────────────────────────────────────────────

    def get_asset_criticality(self, entity_type: str, entity_value: str) -> Dict:
        """Query asset criticality for a host or user."""
        id_field = f"{entity_type}.name"
        result = self._kibana_request(
            "GET",
            f"/internal/asset_criticality?id_field={id_field}&id_value={entity_value}",
        )
        if not result:
            return {
                "entity_type": entity_type,
                "entity_value": entity_value,
                "criticality_level": "unknown",
                "assigned": False,
            }
        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "criticality_level": result.get("criticality_level", "unknown"),
            "assigned": True,
        }

    # ── Detection Rule Management ────────────────────────────────────────

    def create_detection_rule(self, rule_type: str, name: str, description: str,
                              query: str, index_patterns: Optional[List[str]] = None,
                              severity: str = "medium", risk_score: int = 50,
                              tags: Optional[List[str]] = None,
                              threat: Optional[List[Dict]] = None) -> Dict:
        """Create a detection rule via Kibana Detection Engine API."""
        body: Dict[str, Any] = {
            "type": rule_type,
            "name": name,
            "description": description,
            "severity": severity,
            "risk_score": risk_score,
            "tags": tags or [],
            "enabled": True,
        }
        if rule_type == "esql":
            body["language"] = "esql"
            body["query"] = query
        else:
            body["query"] = query
            body["language"] = "kuery"
            body["index"] = index_patterns or ["logs-*"]
        if threat:
            body["threat"] = threat

        result = self._kibana_request("POST", "/api/detection_engine/rules", body=body)
        if not result:
            return {"error": "Failed to create detection rule"}
        return {"id": result.get("id"), "name": result.get("name"), "enabled": result.get("enabled")}

    def update_detection_rule(self, rule_id: str, updates: Dict[str, Any]) -> Dict:
        """Update an existing detection rule."""
        updates["id"] = rule_id
        result = self._kibana_request("PUT", "/api/detection_engine/rules", body=updates)
        if not result:
            return {"error": f"Failed to update rule {rule_id}"}
        return {"id": result.get("id"), "name": result.get("name"), "updated": True}

    def enable_detection_rule(self, rule_ids: List[str], enabled: bool = True) -> Dict:
        """Enable or disable detection rules via bulk action."""
        action = "enable" if enabled else "disable"
        body = {"ids": rule_ids, "action": action}
        result = self._kibana_request("POST", "/api/detection_engine/rules/_bulk_action", body=body)
        if not result:
            return {"error": f"Failed to {action} rules"}
        return {"action": action, "rule_count": len(rule_ids), "success": True}

    def delete_detection_rule(self, rule_id: str) -> Dict:
        """Delete a detection rule."""
        result = self._kibana_request("DELETE", f"/api/detection_engine/rules?rule_id={rule_id}")
        if result is None:
            return {"error": f"Failed to delete rule {rule_id}"}
        return {"deleted": True, "rule_id": rule_id}

    def create_exception_list(self, name: str, description: str, list_type: str = "detection") -> Dict:
        """Create an exception list."""
        import uuid as _uuid
        body = {
            "name": name,
            "description": description,
            "type": list_type,
            "list_id": f"vigil-{_uuid.uuid4().hex[:8]}",
            "namespace_type": "single",
        }
        result = self._kibana_request("POST", "/api/exception_lists", body=body)
        if not result:
            return {"error": "Failed to create exception list"}
        return {"id": result.get("id"), "list_id": result.get("list_id"), "name": name}

    def add_exception_item(self, list_id: str, name: str,
                            entries: List[Dict[str, str]]) -> Dict:
        """Add an item to an exception list. Each entry: {field, operator, value}."""
        formatted = []
        for e in entries:
            formatted.append({
                "field": e["field"],
                "operator": e.get("operator", "included"),
                "type": "match",
                "value": e["value"],
            })

        body = {
            "list_id": list_id,
            "name": name,
            "description": f"Added by Vigil AI SOC",
            "type": "simple",
            "namespace_type": "single",
            "entries": formatted,
        }
        result = self._kibana_request("POST", "/api/exception_lists/items", body=body)
        if not result:
            return {"error": "Failed to add exception item"}
        return {"id": result.get("id"), "list_id": list_id, "name": name}

    def preview_rule(self, query: str, index_patterns: Optional[List[str]] = None,
                      time_range: str = "-24h") -> Dict:
        """Dry-run a detection rule query against recent data."""
        try:
            client = self._get_client()
            indices = index_patterns or ["logs-*"]
            body = {
                "query": {"query_string": {"query": query}},
                "sort": [{"@timestamp": "desc"}],
                "size": 10,
                "track_total_hits": True,
            }
            body["query"] = {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                        {"range": {"@timestamp": {"gte": f"now{time_range}"}}},
                    ]
                }
            }
            resp = client.search(index=",".join(indices), body=body)
            total = resp["hits"]["total"]
            count = total["value"] if isinstance(total, dict) else total
            samples = [hit["_source"] for hit in resp["hits"]["hits"]]
            return {"match_count": count, "samples": samples, "time_range": time_range}
        except Exception as e:
            logger.error(f"Rule preview error: {e}")
            return {"error": str(e)}

    def _resolve_agent_id(self, hostname: str) -> Optional[str]:
        """Try to resolve a hostname to an Elastic Agent ID via Fleet."""
        try:
            client = self._get_client()
            resp = client.search(
                index=".fleet-agents",
                body={"query": {"term": {"local_metadata.host.hostname": hostname}}, "size": 1},
            )
            hits = resp["hits"]["hits"]
            return hits[0]["_source"].get("agent", {}).get("id") if hits else None
        except Exception:
            return None

    # ── Agent Builder (Kibana) ──────────────────────────────────────────

    def list_agent_builder_tools(self) -> List[Dict]:
        """List all Agent Builder tools (builtin + custom) from Kibana."""
        result = self._kibana_request("GET", "/api/agent_builder/tools")
        if not result:
            return []
        tools = result if isinstance(result, list) else result.get("data", result.get("tools", []))
        return [
            {
                "id": t.get("id") or t.get("tool_id"),
                "name": t.get("name"),
                "description": t.get("description", ""),
                "type": t.get("type", "unknown"),
                "is_custom": t.get("is_custom", t.get("source") == "custom"),
            }
            for t in tools
        ]

    def create_agent_builder_tool(
        self,
        tool_type: str,
        name: str,
        description: str,
        configuration: Dict[str, Any],
    ) -> Dict:
        """Create a custom Agent Builder tool in Kibana.

        tool_type: 'esql', 'index_search', 'workflow', or 'mcp'
        configuration: type-specific config (e.g. {"query": "..."} for esql)
        """
        body: Dict[str, Any] = {
            "type": tool_type,
            "name": name,
            "description": description,
            "configuration": configuration,
        }
        result = self._kibana_request("POST", "/api/agent_builder/tools", body=body)
        if not result:
            return {"error": f"Failed to create Agent Builder tool '{name}'"}
        return {
            "id": result.get("id") or result.get("tool_id"),
            "name": result.get("name", name),
            "type": tool_type,
            "created": True,
        }

    def delete_agent_builder_tool(self, tool_id: str) -> Dict:
        """Delete a custom Agent Builder tool by ID."""
        result = self._kibana_request("DELETE", f"/api/agent_builder/tools/{tool_id}")
        if result is None:
            return {"error": f"Failed to delete Agent Builder tool {tool_id}"}
        return {"deleted": True, "tool_id": tool_id}

    def test_agent_builder_tool(
        self,
        tool_id: str,
        query: str,
        connector_id: Optional[str] = None,
    ) -> Dict:
        """Test an Agent Builder tool by sending a query through converse."""
        body: Dict[str, Any] = {"query": query, "tool_id": tool_id}
        if connector_id:
            body["connector_id"] = connector_id
        result = self._kibana_request("POST", "/api/agent_builder/tools/_test", body=body)
        if not result:
            return {"error": f"Failed to test tool {tool_id}"}
        return result

    def list_agent_builder_agents(self) -> List[Dict]:
        """List all Agent Builder agents (default + custom) from Kibana."""
        result = self._kibana_request("GET", "/api/agent_builder/agents")
        if not result:
            return []
        agents = result if isinstance(result, list) else result.get("data", result.get("agents", []))
        return [
            {
                "id": a.get("id") or a.get("agent_id"),
                "name": a.get("name"),
                "description": a.get("description", ""),
                "tool_ids": a.get("tool_ids", []),
                "is_custom": a.get("is_custom", a.get("source") == "custom"),
            }
            for a in agents
        ]

    def create_agent_builder_agent(
        self,
        name: str,
        instructions: str,
        tool_ids: List[str],
        description: str = "",
    ) -> Dict:
        """Create a custom Agent Builder agent with specific tool access."""
        body: Dict[str, Any] = {
            "name": name,
            "description": description,
            "instructions": instructions,
            "tool_ids": tool_ids,
        }
        result = self._kibana_request("POST", "/api/agent_builder/agents", body=body)
        if not result:
            return {"error": f"Failed to create Agent Builder agent '{name}'"}
        return {
            "id": result.get("id") or result.get("agent_id"),
            "name": result.get("name", name),
            "tool_ids": tool_ids,
            "created": True,
        }

    def delete_agent_builder_agent(self, agent_id: str) -> Dict:
        """Delete a custom Agent Builder agent by ID."""
        result = self._kibana_request("DELETE", f"/api/agent_builder/agents/{agent_id}")
        if result is None:
            return {"error": f"Failed to delete Agent Builder agent {agent_id}"}
        return {"deleted": True, "agent_id": agent_id}

    def get_agent_builder_mcp_config(self) -> Dict:
        """Return MCP client config for connecting to Kibana's Agent Builder endpoint."""
        if not self.kibana_url:
            return {"error": "KIBANA_URL not configured"}

        config: Dict[str, Any] = {
            "url": f"{self.kibana_url}/api/agent_builder/mcp",
            "transport": "sse",
        }
        if self.api_key:
            config["headers"] = {"Authorization": f"ApiKey {self.api_key}"}
        elif self.username and self.password:
            config["auth"] = {"type": "basic", "username": self.username, "password": self.password}

        return config
