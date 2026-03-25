"""Elastic enrichment service with Claude AI analysis."""

import logging
import re
import json
from typing import Optional, Dict, List, Any
from datetime import datetime

from services.elastic_service import ElasticService
from services.claude_service import ClaudeService
from services.database_data_service import DatabaseDataService

logger = logging.getLogger(__name__)


class ElasticEnrichmentService:
    """Enrich cases and findings with Elasticsearch data, Entity Analytics risk scores,
    threat intelligence, and Claude AI analysis."""

    def __init__(self, elastic_service: ElasticService, claude_service=None):
        self.elastic_service = elastic_service
        self.claude_service = claude_service or ClaudeService(use_mcp_tools=False)
        self.data_service = DatabaseDataService()

    # ── IOC Extraction (reuses SplunkEnrichmentService pattern) ──────────

    def extract_indicators(self, case: Dict, findings: List[Dict]) -> Dict[str, List[str]]:
        indicators = {
            'ips': set(),
            'domains': set(),
            'hashes': set(),
            'usernames': set(),
            'hostnames': set(),
            'emails': set(),
        }

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        case_text = json.dumps(case)
        indicators['ips'].update(re.findall(ip_pattern, case_text))
        indicators['domains'].update(re.findall(domain_pattern, case_text))
        indicators['hashes'].update(re.findall(hash_pattern, case_text))
        indicators['emails'].update(re.findall(email_pattern, case_text))

        for finding in findings:
            finding_text = json.dumps(finding)
            indicators['ips'].update(re.findall(ip_pattern, finding_text))
            indicators['domains'].update(re.findall(domain_pattern, finding_text))
            indicators['hashes'].update(re.findall(hash_pattern, finding_text))
            indicators['emails'].update(re.findall(email_pattern, finding_text))

            entities = finding.get('entities', {})
            indicators['ips'].update(entities.get('ip_addresses', []))
            indicators['usernames'].update(entities.get('usernames', []))
            indicators['hostnames'].update(entities.get('hostnames', []))
            indicators['domains'].update(entities.get('domains', []))
            indicators['hashes'].update(entities.get('file_hashes', []))

            entity_context = finding.get('entity_context', {})
            for k in ('src_ip', 'dest_ip'):
                if entity_context.get(k):
                    indicators['ips'].add(entity_context[k])
            for k in ('user', 'username'):
                if entity_context.get(k):
                    indicators['usernames'].add(entity_context[k])
            for k in ('host', 'hostname', 'src_host', 'dest_host'):
                if entity_context.get(k):
                    indicators['hostnames'].add(entity_context[k])

        indicators['ips'] = sorted(ip for ip in indicators['ips'] if not self._is_private_ip(ip))
        indicators['domains'] = sorted(d for d in indicators['domains'] if not self._is_common_domain(d))
        indicators['hashes'] = sorted(indicators['hashes'])
        indicators['usernames'] = sorted(indicators['usernames'])
        indicators['hostnames'] = sorted(indicators['hostnames'])
        indicators['emails'] = sorted(indicators['emails'])

        return indicators

    # ── IOC Query Enrichment via ES|QL ───────────────────────────────────

    def query_elastic_for_indicators(self, indicators: Dict[str, List[str]], hours: int = 168) -> Dict[str, Any]:
        enrichment_data: Dict[str, Any] = {
            'query_time': datetime.now().isoformat(),
            'lookback_hours': hours,
            'results': {},
            'summary': {},
        }
        total_events = 0

        search_map = {
            'ips': self.elastic_service.search_by_ip,
            'domains': self.elastic_service.search_by_domain,
            'hashes': self.elastic_service.search_by_hash,
            'usernames': self.elastic_service.search_by_username,
            'hostnames': self.elastic_service.search_by_hostname,
        }

        for indicator_type, search_fn in search_map.items():
            values = indicators.get(indicator_type, [])[:10]
            if not values:
                continue
            enrichment_data['results'][indicator_type] = {}
            for value in values:
                logger.info(f"Querying Elastic for {indicator_type}: {value}")
                try:
                    results = search_fn(value, hours=hours)
                    if results:
                        enrichment_data['results'][indicator_type][value] = results[:100]
                        total_events += len(results[:100])
                except Exception as e:
                    logger.warning(f"Query failed for {indicator_type} {value}: {e}")

        enrichment_data['summary'] = {
            'total_events': total_events,
            'ips_queried': len(indicators.get('ips', [])),
            'domains_queried': len(indicators.get('domains', [])),
            'hashes_queried': len(indicators.get('hashes', [])),
            'usernames_queried': len(indicators.get('usernames', [])),
            'hostnames_queried': len(indicators.get('hostnames', [])),
        }
        return enrichment_data

    # ── Entity Analytics Risk Scores (Elastic-only) ─────────────────────

    def get_risk_scores(self, indicators: Dict[str, List[str]]) -> Dict[str, Any]:
        risk_scores = {}
        for username in indicators.get('usernames', [])[:10]:
            score = self.elastic_service.get_risk_score('user', username)
            if score.get('risk_score') is not None:
                risk_scores[f"user:{username}"] = score

        for hostname in indicators.get('hostnames', [])[:10]:
            score = self.elastic_service.get_risk_score('host', hostname)
            if score.get('risk_score') is not None:
                risk_scores[f"host:{hostname}"] = score

        return risk_scores

    # ── Threat Intelligence Enrichment (Elastic-only) ───────────────────

    def get_threat_intelligence(self, indicators: Dict[str, List[str]]) -> Dict[str, Any]:
        ti_matches: Dict[str, Any] = {}
        try:
            for ip in indicators.get('ips', [])[:10]:
                results = self.elastic_service.run_esql(
                    f'FROM logs-ti_*-* | WHERE threat.indicator.ip == "{ip}" | LIMIT 10'
                )
                if results:
                    ti_matches[f"ip:{ip}"] = results

            for domain in indicators.get('domains', [])[:10]:
                results = self.elastic_service.run_esql(
                    f'FROM logs-ti_*-* | WHERE threat.indicator.url.domain == "{domain}" | LIMIT 10'
                )
                if results:
                    ti_matches[f"domain:{domain}"] = results

            for file_hash in indicators.get('hashes', [])[:10]:
                results = self.elastic_service.run_esql(
                    f'FROM logs-ti_*-* | WHERE threat.indicator.file.hash.sha256 == "{file_hash}" OR threat.indicator.file.hash.md5 == "{file_hash}" | LIMIT 10'
                )
                if results:
                    ti_matches[f"hash:{file_hash}"] = results
        except Exception as e:
            logger.warning(f"Threat intelligence enrichment failed (TI indices may not exist): {e}")

        return ti_matches

    # ── Claude AI Analysis ──────────────────────────────────────────────

    def analyze_with_claude(
        self,
        case: Dict,
        findings: List[Dict],
        enrichment_data: Dict[str, Any],
        risk_scores: Optional[Dict] = None,
        ti_matches: Optional[Dict] = None,
    ) -> str:
        if not self.claude_service.has_api_key():
            logger.warning("Claude API key not available, skipping AI analysis")
            return "AI analysis not available (API key not configured)"

        system_prompt = """You are a security analyst enriching cases with Elasticsearch data.
You have access to case data, findings, Elastic enrichment data, Entity Analytics risk scores,
and threat intelligence matches.

Analyze all data and provide:
1. Key findings from the Elasticsearch data
2. Correlations between findings and enrichment events
3. Entity risk assessment (using Entity Analytics scores)
4. Threat intelligence context (known malicious indicators)
5. Timeline of activities
6. Risk assessment and recommended next steps

Provide a clear, structured analysis that a SOC analyst can act upon."""

        case_summary = f"""
**Case ID**: {case.get('case_id', 'Unknown')}
**Title**: {case.get('title', 'Untitled')}
**Priority**: {case.get('priority', 'unknown')}
**Status**: {case.get('status', 'unknown')}
**Description**: {case.get('description', 'No description')}
**Number of Findings**: {len(findings)}
"""

        findings_summary = "\n\n**Findings Summary**:\n"
        for i, finding in enumerate(findings[:5], 1):
            findings_summary += f"\n{i}. **{finding.get('finding_id', 'Unknown')}**\n"
            findings_summary += f"   - Severity: {finding.get('severity', 'unknown')}\n"
            findings_summary += f"   - Data Source: {finding.get('data_source', 'unknown')}\n"
            findings_summary += f"   - Timestamp: {finding.get('timestamp', 'unknown')}\n"

        summary = enrichment_data.get('summary', {})
        enrichment_summary = f"""
**Elastic Enrichment Summary**:
- Total Events Retrieved: {summary.get('total_events', 0)}
- IPs Queried: {summary.get('ips_queried', 0)}
- Domains Queried: {summary.get('domains_queried', 0)}
- Hashes Queried: {summary.get('hashes_queried', 0)}
- Usernames Queried: {summary.get('usernames_queried', 0)}
- Hostnames Queried: {summary.get('hostnames_queried', 0)}
- Lookback Period: {enrichment_data.get('lookback_hours', 0)} hours
"""

        risk_summary = ""
        if risk_scores:
            risk_summary = "\n**Entity Analytics Risk Scores**:\n"
            for entity, data in risk_scores.items():
                risk_summary += f"- {entity}: Score={data.get('risk_score')}, Level={data.get('risk_level')}\n"

        ti_summary = ""
        if ti_matches:
            ti_summary = f"\n**Threat Intelligence Matches**: {len(ti_matches)} indicator(s) found in TI feeds\n"
            for indicator, matches in list(ti_matches.items())[:5]:
                ti_summary += f"- {indicator}: {len(matches)} match(es)\n"

        user_prompt = f"""Analyze the following security case with Elasticsearch enrichment data:

{case_summary}
{findings_summary}
{enrichment_summary}
{risk_summary}
{ti_summary}

Provide a comprehensive analysis focusing on key findings, correlations, risk assessment, and next steps."""

        try:
            logger.info("Requesting Claude analysis of enriched case data")
            analysis = self.claude_service.chat(user_prompt, system_prompt=system_prompt)
            return analysis or "Analysis failed — no response from Claude"
        except Exception as e:
            logger.error(f"Error getting Claude analysis: {e}")
            return f"Error during AI analysis: {str(e)}"

    # ── Case Enrichment Orchestrator ────────────────────────────────────

    def enrich_case(self, case_id: str, lookback_hours: int = 168) -> Dict[str, Any]:
        logger.info(f"Starting Elastic enrichment for case {case_id}")

        case = self.data_service.get_case(case_id)
        if not case:
            return {'success': False, 'error': f'Case {case_id} not found'}

        finding_ids = case.get('finding_ids', [])
        findings = []
        for fid in finding_ids:
            finding = self.data_service.get_finding(fid)
            if finding:
                findings.append(finding)

        logger.info("Extracting indicators from case and findings")
        indicators = self.extract_indicators(case, findings)

        logger.info("Querying Elasticsearch for indicators")
        enrichment_data = self.query_elastic_for_indicators(indicators, hours=lookback_hours)

        logger.info("Fetching Entity Analytics risk scores")
        risk_scores = self.get_risk_scores(indicators)

        logger.info("Checking threat intelligence indices")
        ti_matches = self.get_threat_intelligence(indicators)

        logger.info("Analyzing with Claude AI")
        analysis = self.analyze_with_claude(case, findings, enrichment_data, risk_scores, ti_matches)

        enrichment_result = {
            'success': True,
            'case_id': case_id,
            'enrichment_timestamp': datetime.now().isoformat(),
            'indicators': {k: v for k, v in indicators.items() if v},
            'elastic_data': enrichment_data,
            'risk_scores': risk_scores,
            'threat_intelligence': ti_matches,
            'claude_analysis': analysis,
        }

        notes_entry = f"""
=== Elastic Enrichment (from {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ===

**Indicators Analyzed**:
- IPs: {len(indicators.get('ips', []))}
- Domains: {len(indicators.get('domains', []))}
- Hashes: {len(indicators.get('hashes', []))}
- Usernames: {len(indicators.get('usernames', []))}
- Hostnames: {len(indicators.get('hostnames', []))}

**Elastic Events Retrieved**: {enrichment_data['summary'].get('total_events', 0)}
**Entity Risk Scores**: {len(risk_scores)} entities scored
**TI Matches**: {len(ti_matches)} indicator(s) found

**AI Analysis**:
{analysis}

---
"""
        self.data_service.update_case(case_id, notes=notes_entry)
        logger.info(f"Enrichment completed for case {case_id}")
        return enrichment_result

    # ── Private helpers ─────────────────────────────────────────────────

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return True
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except Exception:
            return True

    @staticmethod
    def _is_common_domain(domain: str) -> bool:
        common_tlds = ['localhost', 'local', 'internal', 'corp', 'lan']
        domain_lower = domain.lower()
        return any(domain_lower.endswith(f'.{tld}') for tld in common_tlds)
