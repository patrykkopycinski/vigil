"""
Elastic Ingestion Service — Ingest alerts from Elastic Security.

Fetches security alerts from .alerts-security.alerts-default and converts
them to Vigil findings using ECS field mapping.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from utils import nested_get

from services.siem_ingestion_service import SIEMIngestionService
from services.elastic_service import ElasticService
from core.config import get_integration_config

logger = logging.getLogger(__name__)


class ElasticIngestion(SIEMIngestionService):
    """Elastic Security alert ingestion service."""

    def __init__(self):
        super().__init__()
        self.siem_name = "Elastic"
        self.config = get_integration_config('elastic-siem')
        self.elastic_service: Optional[ElasticService] = None
        self._last_poll_time: Optional[datetime] = None

    def _get_elastic_service(self) -> Optional[ElasticService]:
        if self.elastic_service:
            return self.elastic_service

        try:
            url = self.config.get('url') or self.config.get('elasticsearch_url')
            api_key = self.config.get('api_key')
            cloud_id = self.config.get('cloud_id')
            username = self.config.get('username')
            password = self.config.get('password')

            if not (url or cloud_id):
                logger.error("Elastic configuration incomplete — need url or cloud_id")
                return None

            self.elastic_service = ElasticService(
                url=url,
                api_key=api_key,
                cloud_id=cloud_id,
                username=username,
                password=password,
                verify_ssl=self.config.get('verify_ssl', True),
                kibana_url=self.config.get('kibana_url'),
            )
            return self.elastic_service
        except Exception as e:
            logger.error(f"Error creating Elastic service: {e}")
            return None

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        try:
            es = self._get_elastic_service()
            if not es:
                return []

            if not start_time:
                start_time = self._last_poll_time or (datetime.now(timezone.utc) - timedelta(hours=24))
            if not end_time:
                end_time = datetime.now(timezone.utc)

            hours_ago = max(int((datetime.now(timezone.utc) - start_time).total_seconds() / 3600), 1)
            time_range = f"-{hours_ago}h"

            alerts = es.search_alerts(
                filters={"status": "open"},
                time_range=time_range,
                max_count=limit,
            )

            self._last_poll_time = datetime.now(timezone.utc)
            logger.info(f"Fetched {len(alerts)} alerts from Elastic Security")
            return alerts
        except Exception as e:
            logger.error(f"Error fetching Elastic alerts: {e}")
            return []

    def transform_alert_to_finding(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            alert_uuid = _nested(alert, "kibana.alert.uuid", "")
            if not alert_uuid:
                import uuid as _uuid
                alert_uuid = _uuid.uuid4().hex[:12]
            finding_id = f"elastic-{alert_uuid}"

            title = _nested(alert, "kibana.alert.rule.name") or "Elastic Security Alert"
            description = _nested(alert, "kibana.alert.rule.description") or ""

            severity_raw = _nested(alert, "kibana.alert.severity") or "medium"
            severity = self.normalize_severity(severity_raw)

            entities = {
                "ip_addresses": [],
                "domains": [],
                "usernames": [],
                "hostnames": [],
                "file_hashes": [],
            }

            for field in ("source.ip", "destination.ip"):
                val = _nested(alert, field)
                if val and val not in entities["ip_addresses"]:
                    entities["ip_addresses"].append(val)

            for field in ("user.name", "source.user.name"):
                val = _nested(alert, field)
                if val and val not in entities["usernames"]:
                    entities["usernames"].append(val)

            hostname = _nested(alert, "host.name")
            if hostname:
                entities["hostnames"].append(hostname)

            dns_name = _nested(alert, "dns.question.name")
            if dns_name:
                entities["domains"].append(dns_name)

            for hash_field in ("file.hash.sha256", "file.hash.md5"):
                val = _nested(alert, hash_field)
                if val:
                    entities["file_hashes"].append(val)

            # MITRE ATT&CK
            tactics = []
            techniques = []
            for threat_entry in alert.get("threat", []):
                tactic = threat_entry.get("tactic", {})
                if tactic.get("id"):
                    tactics.append(tactic["id"])
                if tactic.get("name") and tactic["name"] not in tactics:
                    tactics.append(tactic["name"])
                for tech in threat_entry.get("technique", []):
                    if tech.get("id"):
                        techniques.append(tech["id"])

            # Build mitre_predictions dict (technique_id -> technique_name)
            # for daemon processor compatibility
            mitre_predictions = {}
            for threat_entry in alert.get("threat", []):
                for tech in threat_entry.get("technique", []):
                    tid = tech.get("id")
                    tname = tech.get("name", tid)
                    if tid:
                        mitre_predictions[tid] = tname

            # Build entity_context for daemon triage/enrichment compatibility
            src_ip = _nested(alert, "source.ip")
            dst_ip = _nested(alert, "destination.ip")
            src_ips = [src_ip] if src_ip else []
            dest_ips = [dst_ip] if dst_ip else []

            entity_context = {
                "src_ips": src_ips,
                "dest_ips": dest_ips,
                "hostnames": entities.get("hostnames") or [],
                "usernames": entities.get("usernames") or [],
                "file_hashes": entities.get("file_hashes") or [],
            }

            finding = {
                "finding_id": finding_id,
                "title": title,
                "description": description,
                "severity": severity,
                "data_source": "elastic",
                "timestamp": alert.get("@timestamp", datetime.now(timezone.utc).isoformat()),
                "raw_data": alert,
                "metadata": {
                    "alert_uuid": alert_uuid,
                    "rule_id": _nested(alert, "kibana.alert.rule.uuid"),
                    "rule_name": _nested(alert, "kibana.alert.rule.name"),
                    "index": _nested(alert, "kibana.alert.rule.index"),
                    "workflow_status": _nested(alert, "kibana.alert.workflow_status"),
                    "risk_score": _nested(alert, "kibana.alert.risk_score"),
                },
                "entities": entities,
                "entity_context": entity_context,
                "mitre_attack": {
                    "tactics": tactics,
                    "techniques": techniques,
                },
                "mitre_predictions": mitre_predictions,
            }
            return finding
        except Exception as e:
            logger.error(f"Error transforming Elastic alert: {e}")
            return None


_nested = nested_get
