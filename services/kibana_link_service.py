"""Kibana deep link generator for Elastic Security app pages."""

import os
from typing import Optional, Dict
from urllib.parse import quote


def get_kibana_url() -> Optional[str]:
    """Return the configured KIBANA_URL, stripped of trailing slash."""
    url = os.getenv('KIBANA_URL', '').rstrip('/')
    return url or None


def generate_kibana_link(page: str, params: Optional[Dict] = None) -> Optional[str]:
    """Generate a Kibana Security app deep link.

    Args:
        page: One of alert, rule, case, timeline, entity_analytics,
              user_risk, host_risk, detection_rules, mitre_coverage, alerts
        params: Page-specific parameters (id, query, etc.)

    Returns:
        Full Kibana URL or None if KIBANA_URL is not configured.
    """
    base = get_kibana_url()
    if not base:
        return None

    params = params or {}
    link_map = {
        "alert": lambda p: f"/app/security/alerts?query=kibana.alert.uuid:{p.get('id', '')}",
        "rule": lambda p: f"/app/security/rules/id/{p.get('id', '')}",
        "case": lambda p: f"/app/security/cases/{p.get('id', '')}",
        "timeline": lambda p: f"/app/security/timelines?timeline=(id:'{p.get('id', '')}',isOpen:!t)",
        "entity_analytics": lambda _: "/app/security/entity_analytics",
        "user_risk": lambda p: f'/app/security/entity_analytics/users?query=user.name:"{quote(p.get("user", ""))}"',
        "host_risk": lambda p: f'/app/security/entity_analytics/hosts?query=host.name:"{quote(p.get("host", ""))}"',
        "detection_rules": lambda _: "/app/security/rules",
        "mitre_coverage": lambda _: "/app/security/rules/coverage",
        "alerts": lambda _: "/app/security/alerts",
    }

    builder = link_map.get(page)
    if not builder:
        return None

    return f"{base}{builder(params)}"


def format_kibana_link(page: str, params: Optional[Dict] = None, label: Optional[str] = None) -> str:
    """Return a Markdown-formatted Kibana link, or empty string if unavailable."""
    url = generate_kibana_link(page, params)
    if not url:
        return ""

    label = label or f"View in Kibana"
    return f"[{label}]({url})"
