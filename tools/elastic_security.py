"""Elastic Security MCP Server — agent-facing tools for Elastic Security."""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools import create_server, json_response, error_response, get_config
from utils import nested_get

logger = logging.getLogger(__name__)

mcp = create_server("elastic-security")

_elastic_service = None


def _reset_service():
    """Reset the cached service instance (for testing and config reloads)."""
    global _elastic_service
    _elastic_service = None


def _get_service():
    """Lazy-init ElasticService from config or env vars."""
    global _elastic_service
    if _elastic_service is not None:
        return _elastic_service

    from services.elastic_service import ElasticService

    config = get_config("elastic-siem")
    if config:
        _elastic_service = ElasticService.from_config(config)
    else:
        _elastic_service = ElasticService.from_env()
    return _elastic_service


def _require_service():
    """Return (service, None) or (None, error_string)."""
    try:
        svc = _get_service()
        svc._get_client()
        return svc, None
    except Exception as e:
        return None, error_response(
            "Elastic Security not configured — configure in Settings > Integrations",
            detail=str(e),
        )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_mitre_techniques(alert: dict) -> list:
    """Safely extract MITRE technique IDs from an alert's threat field."""
    threat = alert.get("threat")
    if not isinstance(threat, list) or not threat:
        return []
    techniques = []
    for entry in threat:
        if not isinstance(entry, dict):
            continue
        for tech in entry.get("technique", []):
            if isinstance(tech, dict) and tech.get("id"):
                techniques.append(tech["id"])
    return techniques


# ── Search Tools ─────────────────────────────────────────────────────────────

@mcp.tool()
def search_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    time_range: str = "-24h",
    limit: int = 50,
) -> str:
    """Search Elastic Security alerts.

    Args:
        severity: Filter by severity (critical, high, medium, low)
        status: Filter by workflow status (open, acknowledged, closed)
        rule_name: Filter by detection rule name
        source_ip: Filter by source IP address
        destination_ip: Filter by destination IP address
        username: Filter by username
        hostname: Filter by host name
        mitre_technique: Filter by MITRE ATT&CK technique ID (e.g. T1059)
        time_range: Time range in Elastic datemath (default: -24h)
        limit: Maximum results (default: 50)
    """
    svc, err = _require_service()
    if err:
        return err

    filters = {}
    if severity:
        filters["severity"] = severity
    if status:
        filters["status"] = status
    if rule_name:
        filters["rule_name"] = rule_name
    if source_ip:
        filters["source_ip"] = source_ip
    if destination_ip:
        filters["destination_ip"] = destination_ip
    if username:
        filters["username"] = username
    if hostname:
        filters["hostname"] = hostname
    if mitre_technique:
        filters["mitre_technique"] = mitre_technique

    try:
        alerts = svc.search_alerts(filters=filters, time_range=time_range, max_count=limit)
    except Exception as e:
        return error_response(f"Alert search failed: {str(e)}")

    results = []
    for alert in alerts:
        entry = {
            "rule_name": _nested_get(alert, "kibana.alert.rule.name"),
            "severity": _nested_get(alert, "kibana.alert.severity"),
            "status": _nested_get(alert, "kibana.alert.workflow_status"),
            "timestamp": alert.get("@timestamp"),
            "uuid": _nested_get(alert, "kibana.alert.uuid"),
            "source_ip": _nested_get(alert, "source.ip"),
            "destination_ip": _nested_get(alert, "destination.ip"),
            "user": _nested_get(alert, "user.name"),
            "host": _nested_get(alert, "host.name"),
            "mitre_techniques": _extract_mitre_techniques(alert),
        }
        if svc.kibana_url:
            uuid = entry["uuid"]
            entry["kibana_url"] = f"{svc.kibana_url}/app/security/alerts?query=kibana.alert.uuid:{uuid}"
        results.append(entry)

    return json_response({"count": len(results), "alerts": results})


@mcp.tool()
def search_events(query: str, limit: int = 100) -> str:
    """Execute an ES|QL query for investigation. Query must start with FROM.

    Example queries:
    - FROM logs-* | WHERE source.ip == "10.0.0.1" | STATS count=COUNT(*) BY destination.port | SORT count DESC | LIMIT 10
    - FROM logs-* | WHERE event.action == "logon-failed" AND @timestamp > NOW() - 1 hour | STATS attempts=COUNT(*) BY source.ip, user.name | WHERE attempts > 5

    Args:
        query: ES|QL query (must start with FROM)
        limit: Maximum results (default: 100)
    """
    svc, err = _require_service()
    if err:
        return err

    stripped = query.strip()
    if not stripped.upper().startswith("FROM"):
        return error_response("Query must start with FROM to prevent injection")

    try:
        results = svc.run_esql(stripped, limit=limit)
        return json_response({"count": len(results), "results": results})
    except Exception as e:
        return error_response(f"ES|QL query failed: {str(e)}")


@mcp.tool()
def search_entities(entity_type: str, entity_value: str, hours: int = 24) -> str:
    """Search for events related to an entity.

    Args:
        entity_type: One of: ip, user, host, domain, hash
        entity_value: The entity value to search for
        hours: Lookback hours (default: 24)
    """
    svc, err = _require_service()
    if err:
        return err

    method_map = {
        "ip": svc.search_by_ip,
        "user": svc.search_by_username,
        "host": svc.search_by_hostname,
        "domain": svc.search_by_domain,
        "hash": svc.search_by_hash,
    }

    fn = method_map.get(entity_type)
    if not fn:
        return error_response(f"Invalid entity_type: {entity_type}. Use: ip, user, host, domain, hash")

    try:
        results = fn(entity_value, hours=hours)
        return json_response({"entity_type": entity_type, "entity_value": entity_value, "count": len(results), "events": results[:200]})
    except Exception as e:
        return error_response(f"Entity search failed: {str(e)}")


@mcp.tool()
def run_esql(query: str) -> str:
    """Execute a raw ES|QL query. For advanced agent use.

    Common patterns:
    - Alert summary: FROM .alerts-security.alerts-default | STATS count=COUNT(*) BY kibana.alert.severity | SORT count DESC
    - Network connections: FROM logs-* | WHERE source.ip == "10.0.0.1" | STATS bytes=SUM(network.bytes) BY destination.ip, destination.port | SORT bytes DESC | LIMIT 20
    - Process execution: FROM logs-endpoint.events.process-* | WHERE host.name == "WIN-SRV01" | STATS count=COUNT(*) BY process.name | SORT count DESC | LIMIT 20
    - Failed logins: FROM logs-* | WHERE event.action == "logon-failed" AND @timestamp > NOW() - 1 hour | STATS attempts=COUNT(*) BY source.ip, user.name | WHERE attempts > 5

    Args:
        query: Full ES|QL query string (must start with FROM)
    """
    svc, err = _require_service()
    if err:
        return err

    stripped = query.strip()
    if not stripped.upper().startswith("FROM"):
        return error_response("Query must start with FROM to prevent injection")

    try:
        results = svc.run_esql(stripped)
        return json_response({"count": len(results), "results": results})
    except Exception as e:
        return error_response(f"ES|QL error: {str(e)}")


# ── Alert Management Tools ───────────────────────────────────────────────────

@mcp.tool()
def get_alert_details(alert_id: str) -> str:
    """Get full details for an alert by its UUID.

    Args:
        alert_id: The kibana.alert.uuid of the alert
    """
    svc, err = _require_service()
    if err:
        return err

    try:
        alert = svc.get_alert_by_id(alert_id)
    except Exception as e:
        return error_response(f"Alert lookup failed: {str(e)}")
    if not alert:
        return error_response(f"Alert not found: {alert_id}")

    result = dict(alert)
    if svc.kibana_url:
        result["kibana_url"] = f"{svc.kibana_url}/app/security/alerts?query=kibana.alert.uuid:{alert_id}"
    return json_response(result)


@mcp.tool()
def update_alert_status(alert_ids: str, status: str) -> str:
    """Update workflow status for one or more alerts.

    Args:
        alert_ids: Comma-separated alert UUIDs
        status: New status — open, acknowledged, or closed
    """
    svc, err = _require_service()
    if err:
        return err

    if status not in ("open", "acknowledged", "closed"):
        return error_response("Status must be one of: open, acknowledged, closed")

    ids = [aid.strip() for aid in alert_ids.split(",") if aid.strip()]
    if not ids:
        return error_response("No alert IDs provided")

    result = svc.update_alert_status(ids, status)
    return json_response(result)


# ── Entity Analytics (Elastic-only) ──────────────────────────────────────────

@mcp.tool()
def get_risk_score(entity_type: str, entity_value: str) -> str:
    """Get Entity Analytics risk score for a user or host.

    Args:
        entity_type: user or host
        entity_value: The username or hostname
    """
    svc, err = _require_service()
    if err:
        return err

    if entity_type not in ("user", "host"):
        return error_response("entity_type must be 'user' or 'host'")

    result = svc.get_risk_score(entity_type, entity_value)
    if svc.kibana_url:
        page = "users" if entity_type == "user" else "hosts"
        field = "user.name" if entity_type == "user" else "host.name"
        result["kibana_url"] = f'{svc.kibana_url}/app/security/entity_analytics/{page}?query={field}:"{entity_value}"'
    return json_response(result)


# ── Case Management (Elastic-only) ──────────────────────────────────────────

@mcp.tool()
def create_case(title: str, description: str, severity: str = "medium", tags: str = "") -> str:
    """Create a case in Kibana Cases.

    Args:
        title: Case title
        description: Case description
        severity: low, medium, high, or critical (default: medium)
        tags: Comma-separated tags
    """
    svc, err = _require_service()
    if err:
        return err

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    result = svc.create_case(title, description, severity=severity, tags=tag_list)
    return json_response(result)


# ── Response Actions (Elastic-only) ──────────────────────────────────────────

@mcp.tool()
def isolate_endpoint(agent_id_or_hostname: str) -> str:
    """Isolate an endpoint via Elastic Defend. Requires approval.

    Args:
        agent_id_or_hostname: Elastic Agent ID or hostname to isolate
    """
    svc, err = _require_service()
    if err:
        return err

    result = svc.isolate_endpoint(agent_id_or_hostname)
    return json_response(result)


# ── Extended Response Actions (Elastic-only) ─────────────────────────────────

@mcp.tool()
def release_endpoint(agent_id_or_hostname: str) -> str:
    """Release (unisolate) a previously isolated endpoint.

    Args:
        agent_id_or_hostname: Elastic Agent ID or hostname to release
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.unisolate_endpoint(agent_id_or_hostname)
    return json_response(result)


@mcp.tool()
def kill_process(agent_id: str, pid: Optional[int] = None, entity_id: Optional[str] = None) -> str:
    """Kill a process on an endpoint via Elastic Defend.

    Args:
        agent_id: Elastic Agent ID of the target endpoint
        pid: Process ID to kill (provide pid or entity_id)
        entity_id: Process entity_id to kill (alternative to pid)
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.kill_process(agent_id, pid=pid, entity_id=entity_id)
    return json_response(result)


@mcp.tool()
def get_file(agent_id: str, path: str) -> str:
    """Retrieve a file from an endpoint for forensic analysis.

    Args:
        agent_id: Elastic Agent ID of the target endpoint
        path: Full file path to retrieve
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.get_file(agent_id, path)
    return json_response(result)


@mcp.tool()
def get_action_status(action_id: str) -> str:
    """Check status of a pending response action (isolate, kill, get_file).

    Args:
        action_id: The action ID returned by a response action
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.get_action_status(action_id)
    return json_response(result)


# ── Osquery Live Queries (Elastic-only) ──────────────────────────────────────

OSQUERY_PACKS = {
    "processes": "SELECT pid, name, path, cmdline, uid, parent FROM processes ORDER BY start_time DESC LIMIT 200",
    "connections": "SELECT s.pid, p.name, s.remote_address, s.remote_port, s.local_address, s.local_port, s.protocol, s.state FROM process_open_sockets s JOIN processes p ON s.pid = p.pid WHERE s.remote_address != '' AND s.remote_address != '::' AND s.remote_address != '0.0.0.0' LIMIT 200",
    "users": "SELECT uid, username, type, host FROM logged_in_users WHERE type = 'user' ORDER BY time DESC LIMIT 50",
    "persistence": "SELECT name, path, args, source FROM startup_items UNION SELECT name, path, status, source FROM launchd UNION SELECT name, path, data, source FROM registry WHERE path LIKE '%%\\Run%%' LIMIT 200",
    "file_info": "SELECT path, filename, size, mtime, atime, uid, gid, mode, sha256 FROM file WHERE path = ?",
}


@mcp.tool()
def run_osquery(agent_id: str, query: Optional[str] = None, pack: Optional[str] = None) -> str:
    """Run a live Osquery query on an endpoint via Elastic Agent.

    Args:
        agent_id: Elastic Agent ID of the target endpoint
        query: Raw SQL query (provide query or pack)
        pack: Pre-built pack name: processes, connections, users, persistence, file_info
    """
    svc, err = _require_service()
    if err:
        return err

    if pack:
        if pack not in OSQUERY_PACKS:
            return error_response(f"Unknown pack: {pack}. Available: {', '.join(OSQUERY_PACKS.keys())}")
        actual_query = OSQUERY_PACKS[pack]
    elif query:
        actual_query = query
    else:
        return error_response("Provide either 'query' or 'pack'")

    result = svc.run_osquery(actual_query, [agent_id])
    return json_response(result)


@mcp.tool()
def get_osquery_results(action_id: str) -> str:
    """Get results from a live Osquery action.

    Args:
        action_id: The action ID from run_osquery
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.get_osquery_results(action_id)
    return json_response(result)


# ── Detection Rule Management (Elastic-only) ────────────────────────────────

@mcp.tool()
def create_detection_rule(
    name: str, description: str, query: str,
    rule_type: str = "query",
    index_patterns: str = "logs-*",
    severity: str = "medium",
    risk_score: int = 50,
    tags: str = "",
) -> str:
    """Create a detection rule in Elastic Security.

    Args:
        name: Rule name
        description: Rule description
        query: KQL or ES|QL query for the rule
        rule_type: query (KQL) or esql (default: query)
        index_patterns: Comma-separated index patterns (default: logs-*)
        severity: low, medium, high, or critical
        risk_score: 0-100 risk score
        tags: Comma-separated tags
    """
    svc, err = _require_service()
    if err:
        return err

    idx = [p.strip() for p in index_patterns.split(",") if p.strip()]
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    result = svc.create_detection_rule(
        rule_type=rule_type, name=name, description=description,
        query=query, index_patterns=idx, severity=severity,
        risk_score=risk_score, tags=tag_list,
    )
    return json_response(result)


@mcp.tool()
def update_detection_rule(rule_id: str, severity: Optional[str] = None,
                           enabled: Optional[bool] = None,
                           description: Optional[str] = None) -> str:
    """Update an existing detection rule.

    Args:
        rule_id: Rule ID to update
        severity: New severity (low, medium, high, critical)
        enabled: Enable or disable the rule
        description: New description
    """
    svc, err = _require_service()
    if err:
        return err

    updates = {}
    if severity:
        updates["severity"] = severity
    if enabled is not None:
        updates["enabled"] = enabled
    if description:
        updates["description"] = description
    if not updates:
        return error_response("No updates provided")

    result = svc.update_detection_rule(rule_id, updates)
    return json_response(result)


@mcp.tool()
def toggle_detection_rules(rule_ids: str, enabled: bool = True) -> str:
    """Enable or disable one or more detection rules.

    Args:
        rule_ids: Comma-separated rule IDs
        enabled: True to enable, False to disable
    """
    svc, err = _require_service()
    if err:
        return err

    ids = [r.strip() for r in rule_ids.split(",") if r.strip()]
    if not ids:
        return error_response("No rule IDs provided")
    result = svc.enable_detection_rule(ids, enabled=enabled)
    return json_response(result)


@mcp.tool()
def delete_detection_rule(rule_id: str) -> str:
    """Delete a detection rule.

    Args:
        rule_id: Rule ID to delete
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.delete_detection_rule(rule_id)
    return json_response(result)


@mcp.tool()
def create_exception(list_name: str, item_name: str, field: str, value: str,
                      operator: str = "included") -> str:
    """Create an exception list and add an exception item to suppress false positives.

    Args:
        list_name: Exception list name
        item_name: Exception item name
        field: Field to match (e.g. process.name, source.ip)
        value: Value to match
        operator: included (match) or excluded (not match)
    """
    svc, err = _require_service()
    if err:
        return err

    exc_list = svc.create_exception_list(list_name, f"Exception list for {list_name}")
    if exc_list.get("error"):
        return json_response(exc_list)

    item = svc.add_exception_item(
        exc_list["list_id"], item_name,
        [{"field": field, "operator": operator, "value": value}],
    )
    return json_response({"list": exc_list, "item": item})


@mcp.tool()
def preview_rule(query: str, index_patterns: str = "logs-*", time_range: str = "-24h") -> str:
    """Dry-run a detection rule query to see how many documents match.

    Args:
        query: KQL query to preview
        index_patterns: Comma-separated index patterns
        time_range: Lookback (default: -24h)
    """
    svc, err = _require_service()
    if err:
        return err
    idx = [p.strip() for p in index_patterns.split(",") if p.strip()]
    result = svc.preview_rule(query, index_patterns=idx, time_range=time_range)
    return json_response(result)


# ── Asset Criticality (Elastic-only) ────────────────────────────────────────

@mcp.tool()
def get_asset_criticality(entity_type: str, entity_value: str) -> str:
    """Get asset criticality level for a host or user.

    Args:
        entity_type: user or host
        entity_value: The username or hostname
    """
    svc, err = _require_service()
    if err:
        return err
    if entity_type not in ("user", "host"):
        return error_response("entity_type must be 'user' or 'host'")
    result = svc.get_asset_criticality(entity_type, entity_value)
    return json_response(result)


# ── NL→ES|QL Generation ─────────────────────────────────────────────────────

ESQL_TEMPLATES = [
    {"name": "ip_lookup", "pattern": r"(?:events?|activity|traffic)\s+(?:from|for|with)\s+(?:ip\s+)?(\d+\.\d+\.\d+\.\d+)",
     "template": 'FROM logs-* | WHERE (source.ip == "{0}" OR destination.ip == "{0}") AND @timestamp > NOW() - {hours} hours | LIMIT {limit}'},
    {"name": "user_activity", "pattern": r"(?:activity|events?|actions?)\s+(?:for|by|from)\s+user\s+(\S+)",
     "template": 'FROM logs-* | WHERE user.name == "{0}" AND @timestamp > NOW() - {hours} hours | LIMIT {limit}'},
    {"name": "host_activity", "pattern": r"(?:activity|events?|processes?|what)\s+(?:on|from|for|did)\s+(?:host\s+)?(\S+)",
     "template": 'FROM logs-* | WHERE host.name == "{0}" AND @timestamp > NOW() - {hours} hours | LIMIT {limit}'},
    {"name": "failed_logins", "pattern": r"failed\s+(?:logins?|auth|authentication)",
     "template": 'FROM logs-* | WHERE event.category == "authentication" AND event.outcome == "failure" AND @timestamp > NOW() - {hours} hours | STATS attempts=COUNT(*) BY source.ip, user.name | WHERE attempts > 3 | SORT attempts DESC | LIMIT {limit}'},
    {"name": "process_exec", "pattern": r"process(?:es)?\s+(?:on|from|run|executed)",
     "template": 'FROM logs-endpoint.events.process-* | WHERE @timestamp > NOW() - {hours} hours | STATS count=COUNT(*) BY process.name, host.name | SORT count DESC | LIMIT {limit}'},
    {"name": "dns_queries", "pattern": r"dns\s+(?:queries|lookups|requests|resolution)",
     "template": 'FROM logs-* | WHERE event.category == "dns" AND @timestamp > NOW() - {hours} hours | STATS count=COUNT(*) BY dns.question.name | SORT count DESC | LIMIT {limit}'},
    {"name": "file_operations", "pattern": r"file\s+(?:operations?|changes?|modifications?|access)",
     "template": 'FROM logs-* | WHERE event.category == "file" AND @timestamp > NOW() - {hours} hours | STATS count=COUNT(*) BY file.path, event.action, host.name | SORT count DESC | LIMIT {limit}'},
    {"name": "network_connections", "pattern": r"network\s+(?:connections?|traffic|flows?)",
     "template": 'FROM logs-* | WHERE event.category == "network" AND @timestamp > NOW() - {hours} hours | STATS bytes=SUM(network.bytes), count=COUNT(*) BY destination.ip, destination.port | SORT bytes DESC | LIMIT {limit}'},
    {"name": "alert_summary", "pattern": r"alert\s+(?:summary|overview|stats|count)",
     "template": 'FROM .alerts-security.alerts-default | WHERE @timestamp > NOW() - {hours} hours | STATS count=COUNT(*) BY kibana.alert.severity, kibana.alert.rule.name | SORT count DESC | LIMIT {limit}'},
    {"name": "threat_indicators", "pattern": r"threat\s+(?:indicator|intel|ioc|intelligence)",
     "template": 'FROM logs-ti_*-* | WHERE @timestamp > NOW() - {hours} hours | STATS count=COUNT(*) BY threat.indicator.type | SORT count DESC | LIMIT {limit}'},
]


@mcp.tool()
def nl_to_esql(question: str, hours: int = 24, limit: int = 100) -> str:
    """Convert a natural language question to an ES|QL query.

    Args:
        question: Natural language security question (e.g. "show events from IP 10.0.0.5")
        hours: Lookback window in hours (default: 24)
        limit: Max results (default: 100)
    """
    import re
    q_lower = question.lower()

    for tmpl in ESQL_TEMPLATES:
        match = re.search(tmpl["pattern"], q_lower)
        if match:
            groups = match.groups()
            generated = tmpl["template"].format(*groups, hours=hours, limit=limit) if groups else tmpl["template"].format(hours=hours, limit=limit)
            if not generated.strip().upper().startswith("FROM"):
                return error_response("Generated query failed validation — no FROM clause")
            return json_response({
                "template": tmpl["name"],
                "esql": generated,
                "note": "Generated from template. Review before executing.",
            })

    fallback = f'FROM logs-* | WHERE @timestamp > NOW() - {hours} hours | LIMIT {limit}'
    return json_response({
        "template": "fallback",
        "esql": fallback,
        "note": f"No specific template matched '{question}'. Returning broad query — refine manually.",
    })


# ── Investigation Tools (Elastic-only) ───────────────────────────────────────

@mcp.tool()
def get_timeline(timeline_id: Optional[str] = None, title: str = "Vigil Investigation") -> str:
    """Get or create an investigation timeline.

    Args:
        timeline_id: Existing timeline ID (creates new if omitted)
        title: Title for new timeline
    """
    svc, err = _require_service()
    if err:
        return err

    if timeline_id:
        result = svc._kibana_request("GET", f"/api/timeline?id={timeline_id}")
    else:
        result = svc._kibana_request(
            "POST",
            "/api/timeline",
            body={
                "timeline": {"title": title, "timelineType": "default"},
                "timelineId": None,
                "version": None,
            },
        )

    if not result:
        return error_response("Timeline operation failed — KIBANA_URL may not be configured")

    tid = result.get("data", {}).get("persistTimeline", {}).get("timeline", {}).get("savedObjectId", timeline_id)
    resp = {"timeline_id": tid, "title": title}
    if svc.kibana_url and tid:
        resp["kibana_url"] = f"{svc.kibana_url}/app/security/timelines?timeline=(id:'{tid}',isOpen:!t)"
    return json_response(resp)


@mcp.tool()
def get_detection_rules(enabled: Optional[bool] = None, mitre_technique: Optional[str] = None) -> str:
    """List detection rules from Elastic Security.

    Args:
        enabled: Filter by enabled status (true/false, omit for all)
        mitre_technique: Filter rules by MITRE ATT&CK technique ID (e.g. T1059)
    """
    svc, err = _require_service()
    if err:
        return err

    filter_params = {}
    if enabled is not None:
        filter_params["enabled"] = enabled

    rules = svc.get_detection_rules(filter_params)

    if mitre_technique:
        filtered = []
        for rule in rules:
            for threat in rule.get("threat", []):
                for tech in threat.get("technique", []):
                    if tech.get("id", "").startswith(mitre_technique):
                        filtered.append(rule)
                        break
        rules = filtered

    if svc.kibana_url:
        for rule in rules:
            rule["kibana_url"] = f"{svc.kibana_url}/app/security/rules/id/{rule.get('id')}"
    return json_response({"count": len(rules), "rules": rules})


@mcp.tool()
def get_indices() -> str:
    """List available security-relevant indices and data streams."""
    svc, err = _require_service()
    if err:
        return err

    indices = svc.get_indices()
    data_streams = svc.get_data_streams()
    return json_response({"indices": indices, "data_streams": data_streams})


# ── Agent Builder (Elastic-only) ─────────────────────────────────────────────

@mcp.tool()
def list_custom_tools() -> str:
    """List all Agent Builder tools (builtin + custom) registered in Kibana.

    Returns tool names, types (esql, index_search, workflow, mcp), and whether they are custom.
    """
    svc, err = _require_service()
    if err:
        return err
    tools = svc.list_agent_builder_tools()
    return json_response({"count": len(tools), "tools": tools})


@mcp.tool()
def create_custom_tool(
    name: str,
    description: str,
    tool_type: str = "esql",
    configuration: str = "{}",
) -> str:
    """Create a custom Agent Builder tool in Kibana.

    Args:
        name: Tool display name
        description: What the tool does
        tool_type: esql, index_search, workflow, or mcp
        configuration: JSON string with type-specific config (e.g. {"query": "FROM logs-* | ..."} for esql)
    """
    svc, err = _require_service()
    if err:
        return err

    if tool_type not in ("esql", "index_search", "workflow", "mcp"):
        return error_response("tool_type must be one of: esql, index_search, workflow, mcp")

    try:
        config = json.loads(configuration)
    except json.JSONDecodeError as e:
        return error_response(f"Invalid JSON in configuration: {e}")

    result = svc.create_agent_builder_tool(tool_type, name, description, config)
    return json_response(result)


@mcp.tool()
def delete_custom_tool(tool_id: str) -> str:
    """Delete a custom Agent Builder tool.

    Args:
        tool_id: ID of the custom tool to delete
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.delete_agent_builder_tool(tool_id)
    return json_response(result)


@mcp.tool()
def test_custom_tool(tool_id: str, query: str, connector_id: str = "") -> str:
    """Test an Agent Builder tool by running a query through it.

    Args:
        tool_id: ID of the tool to test
        query: Natural language or structured query to send to the tool
        connector_id: Optional LLM connector ID for converse mode
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.test_agent_builder_tool(tool_id, query, connector_id=connector_id or None)
    return json_response(result)


@mcp.tool()
def list_custom_agents() -> str:
    """List all Agent Builder agents (default + custom) in Kibana.

    Returns agent names, descriptions, and their allowed tool IDs.
    """
    svc, err = _require_service()
    if err:
        return err
    agents = svc.list_agent_builder_agents()
    return json_response({"count": len(agents), "agents": agents})


@mcp.tool()
def create_custom_agent(name: str, instructions: str, tool_ids: str, description: str = "") -> str:
    """Create a custom Agent Builder agent with a specific set of allowed tools.

    Args:
        name: Agent display name
        instructions: System prompt / instructions for the agent
        tool_ids: Comma-separated tool IDs the agent can use
        description: Short description of the agent's purpose
    """
    svc, err = _require_service()
    if err:
        return err

    ids = [t.strip() for t in tool_ids.split(",") if t.strip()]
    if not ids:
        return error_response("No tool_ids provided")

    result = svc.create_agent_builder_agent(name, instructions, ids, description=description)
    return json_response(result)


@mcp.tool()
def delete_custom_agent(agent_id: str) -> str:
    """Delete a custom Agent Builder agent.

    Args:
        agent_id: ID of the custom agent to delete
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.delete_agent_builder_agent(agent_id)
    return json_response(result)


@mcp.tool()
def get_agent_builder_config() -> str:
    """Get MCP client configuration for Kibana's Agent Builder endpoint.

    Returns the URL and auth hints needed to connect an MCP client directly
    to Kibana's Agent Builder MCP server.
    """
    svc, err = _require_service()
    if err:
        return err
    result = svc.get_agent_builder_mcp_config()
    return json_response(result)


# ── Helper ───────────────────────────────────────────────────────────────────

_nested_get = nested_get


if __name__ == "__main__":
    mcp.run()
