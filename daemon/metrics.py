"""Metrics server for Prometheus-compatible health monitoring."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from collections import defaultdict

from aiohttp import web

from daemon.config import MetricsConfig

logger = logging.getLogger(__name__)


class DaemonMetrics:
    """Simple metrics tracking class for daemon operations."""
    
    def __init__(self):
        """Initialize metrics tracking."""
        self._poll_counts: Dict[str, int] = defaultdict(int)
        self._poll_durations: Dict[str, list] = defaultdict(list)
        self._events_counts: Dict[str, int] = defaultdict(int)
        self._processing_count: int = 0
        self._processing_durations: list = []
        self._start_time = datetime.utcnow()
    
    def record_poll(self, source: str, duration: float, events_count: int):
        """
        Record a poll operation.
        
        Args:
            source: Source system (e.g., "splunk", "crowdstrike")
            duration: Duration in seconds
            events_count: Number of events retrieved
        """
        self._poll_counts[source] += 1
        self._poll_durations[source].append(duration)
        self._events_counts[source] += events_count
        logger.debug(f"Recorded poll for {source}: {events_count} events in {duration:.2f}s")
    
    def get_poll_count(self, source: str) -> int:
        """
        Get total poll count for a source.
        
        Args:
            source: Source system name
            
        Returns:
            Total number of polls for this source
        """
        return self._poll_counts.get(source, 0)
    
    def record_processing(self, findings_count: int, duration: float):
        """
        Record findings processing operation.
        
        Args:
            findings_count: Number of findings processed
            duration: Duration in seconds
        """
        self._processing_count += findings_count
        self._processing_durations.append(duration)
        logger.debug(f"Recorded processing: {findings_count} findings in {duration:.2f}s")
    
    def get_total_processed(self) -> int:
        """
        Get total number of findings processed.
        
        Returns:
            Total findings processed
        """
        return self._processing_count
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of all metrics.
        
        Returns:
            Dictionary containing metrics summary
        """
        uptime = (datetime.utcnow() - self._start_time).total_seconds()
        
        # Calculate total polls across all sources
        total_polls = sum(self._poll_counts.values())
        
        # Calculate averages
        poll_stats = {}
        for source, durations in self._poll_durations.items():
            avg_duration = sum(durations) / len(durations) if durations else 0
            poll_stats[source] = {
                "count": self._poll_counts[source],
                "events": self._events_counts[source],
                "avg_duration": avg_duration
            }
        
        processing_avg = (
            sum(self._processing_durations) / len(self._processing_durations)
            if self._processing_durations else 0
        )
        
        return {
            "uptime_seconds": uptime,
            "total_polls": total_polls,
            "total_processed": self._processing_count,
            "polls": poll_stats,
            "processing": {
                "total_processed": self._processing_count,
                "avg_duration": processing_avg,
                "batch_count": len(self._processing_durations)
            }
        }
    
    def reset(self):
        """Reset all metrics."""
        self._poll_counts.clear()
        self._poll_durations.clear()
        self._events_counts.clear()
        self._processing_count = 0
        self._processing_durations.clear()
        self._start_time = datetime.utcnow()
        logger.info("Metrics reset")


class MetricsServer:
    """Exposes daemon metrics via HTTP for monitoring."""
    
    def __init__(self, config: MetricsConfig):
        self.config = config
        self._start_time = datetime.utcnow()
        
        # Component references (set externally)
        self.poller = None
        self.processor = None
        self.responder = None
        self.scheduler = None
        self.orchestrator = None
    
    async def run(self, shutdown_event: asyncio.Event):
        """Run the metrics HTTP server."""
        app = web.Application()
        app.router.add_get(self.config.path, self._handle_metrics)
        app.router.add_get('/health', self._handle_health)
        app.router.add_get('/status', self._handle_status)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.config.port)
        
        logger.info(f"Metrics server starting on port {self.config.port}")
        await site.start()
        
        await shutdown_event.wait()
        
        await runner.cleanup()
        logger.info("Metrics server stopped")
    
    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """Handle Prometheus metrics request."""
        metrics = self._collect_metrics()
        
        # Format as Prometheus text format
        lines = []
        
        # Uptime
        uptime = (datetime.utcnow() - self._start_time).total_seconds()
        lines.append(f"# HELP soc_daemon_uptime_seconds Daemon uptime in seconds")
        lines.append(f"# TYPE soc_daemon_uptime_seconds gauge")
        lines.append(f"soc_daemon_uptime_seconds {uptime}")
        
        # Poller metrics
        if metrics.get("poller"):
            poller = metrics["poller"]
            lines.append(f"# HELP soc_daemon_poller_polls_total Total number of polls")
            lines.append(f"# TYPE soc_daemon_poller_polls_total counter")
            lines.append(f'soc_daemon_poller_polls_total{{source="splunk"}} {poller.get("splunk_polls", 0)}')
            lines.append(f'soc_daemon_poller_polls_total{{source="crowdstrike"}} {poller.get("crowdstrike_polls", 0)}')
            lines.append(f'soc_daemon_poller_polls_total{{source="elastic"}} {poller.get("elastic_polls", 0)}')
            
            lines.append(f"# HELP soc_daemon_poller_findings_total Total findings polled")
            lines.append(f"# TYPE soc_daemon_poller_findings_total counter")
            lines.append(f'soc_daemon_poller_findings_total{{source="splunk"}} {poller.get("splunk_findings", 0)}')
            lines.append(f'soc_daemon_poller_findings_total{{source="crowdstrike"}} {poller.get("crowdstrike_findings", 0)}')
            lines.append(f'soc_daemon_poller_findings_total{{source="elastic"}} {poller.get("elastic_findings", 0)}')
            lines.append(f'soc_daemon_poller_findings_total{{source="webhook"}} {poller.get("webhook_findings", 0)}')
        
        # Processor metrics
        if metrics.get("processor"):
            proc = metrics["processor"]
            lines.append(f"# HELP soc_daemon_processor_processed_total Total findings processed")
            lines.append(f"# TYPE soc_daemon_processor_processed_total counter")
            lines.append(f"soc_daemon_processor_processed_total {proc.get('processed', 0)}")
            
            lines.append(f"# HELP soc_daemon_processor_triaged_total Total findings AI triaged")
            lines.append(f"# TYPE soc_daemon_processor_triaged_total counter")
            lines.append(f"soc_daemon_processor_triaged_total {proc.get('triaged', 0)}")
            
            lines.append(f"# HELP soc_daemon_processor_enriched_total Total findings enriched")
            lines.append(f"# TYPE soc_daemon_processor_enriched_total counter")
            lines.append(f"soc_daemon_processor_enriched_total {proc.get('enriched', 0)}")
        
        # Responder metrics
        if metrics.get("responder"):
            resp = metrics["responder"]
            lines.append(f"# HELP soc_daemon_responder_evaluated_total Total response candidates evaluated")
            lines.append(f"# TYPE soc_daemon_responder_evaluated_total counter")
            lines.append(f"soc_daemon_responder_evaluated_total {resp.get('evaluated', 0)}")
            
            lines.append(f"# HELP soc_daemon_responder_auto_executed_total Total auto-executed actions")
            lines.append(f"# TYPE soc_daemon_responder_auto_executed_total counter")
            lines.append(f"soc_daemon_responder_auto_executed_total {resp.get('auto_executed', 0)}")
            
            lines.append(f"# HELP soc_daemon_responder_escalated_total Total escalations sent")
            lines.append(f"# TYPE soc_daemon_responder_escalated_total counter")
            lines.append(f"soc_daemon_responder_escalated_total {resp.get('escalated', 0)}")
        
        # Scheduler metrics
        if metrics.get("scheduler"):
            sched = metrics["scheduler"]
            lines.append(f"# HELP soc_daemon_scheduler_tasks_total Total scheduled tasks run")
            lines.append(f"# TYPE soc_daemon_scheduler_tasks_total counter")
            lines.append(f"soc_daemon_scheduler_tasks_total {sched.get('tasks_run', 0)}")
        
        # Orchestrator metrics
        if metrics.get("orchestrator"):
            orch = metrics["orchestrator"]
            lines.append(f"# HELP soc_daemon_orchestrator_investigations_created_total Total investigations created")
            lines.append(f"# TYPE soc_daemon_orchestrator_investigations_created_total counter")
            lines.append(f"soc_daemon_orchestrator_investigations_created_total {orch.get('investigations_created', 0)}")
            
            lines.append(f"# HELP soc_daemon_orchestrator_investigations_completed_total Total investigations completed")
            lines.append(f"# TYPE soc_daemon_orchestrator_investigations_completed_total counter")
            lines.append(f"soc_daemon_orchestrator_investigations_completed_total {orch.get('investigations_completed', 0)}")
            
            lines.append(f"# HELP soc_daemon_orchestrator_active_agents Current running agents")
            lines.append(f"# TYPE soc_daemon_orchestrator_active_agents gauge")
            lines.append(f"soc_daemon_orchestrator_active_agents {orch.get('active_agents', 0)}")
            
            lines.append(f"# HELP soc_daemon_orchestrator_cost_usd_total Total cost in USD")
            lines.append(f"# TYPE soc_daemon_orchestrator_cost_usd_total counter")
            lines.append(f"soc_daemon_orchestrator_cost_usd_total {orch.get('total_cost_usd', 0)}")
            
            lines.append(f"# HELP soc_daemon_orchestrator_stuck_agents_total Stuck agents detected and killed")
            lines.append(f"# TYPE soc_daemon_orchestrator_stuck_agents_total counter")
            lines.append(f"soc_daemon_orchestrator_stuck_agents_total {orch.get('stuck_agents_killed', 0)}")
        
        # Error metrics
        total_errors = sum([
            metrics.get("poller", {}).get("errors", 0),
            metrics.get("processor", {}).get("errors", 0),
            metrics.get("responder", {}).get("errors", 0),
            metrics.get("scheduler", {}).get("errors", 0)
        ])
        lines.append(f"# HELP soc_daemon_errors_total Total errors across all components")
        lines.append(f"# TYPE soc_daemon_errors_total counter")
        lines.append(f"soc_daemon_errors_total {total_errors}")
        
        return web.Response(
            text="\n".join(lines) + "\n",
            content_type="text/plain; version=0.0.4"
        )
    
    async def _handle_health(self, request: web.Request) -> web.Response:
        """Handle health check request."""
        health = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds()
        }
        
        # Check component health
        components = {}
        
        if self.poller:
            components["poller"] = "running"
        else:
            components["poller"] = "not_initialized"
        
        if self.processor:
            components["processor"] = "running"
        else:
            components["processor"] = "not_initialized"
        
        if self.responder:
            components["responder"] = "running"
        else:
            components["responder"] = "not_initialized"
        
        if self.scheduler:
            components["scheduler"] = "running"
        else:
            components["scheduler"] = "not_initialized"
        
        if self.orchestrator:
            components["orchestrator"] = "running" if self.orchestrator.enabled else "disabled"
        else:
            components["orchestrator"] = "not_initialized"
        
        health["components"] = components
        
        # Determine overall status
        if all(v == "running" for v in components.values()):
            health["status"] = "healthy"
        elif any(v == "running" for v in components.values()):
            health["status"] = "degraded"
        else:
            health["status"] = "unhealthy"
        
        status_code = 200 if health["status"] != "unhealthy" else 503
        return web.json_response(health, status=status_code)
    
    async def _handle_status(self, request: web.Request) -> web.Response:
        """Handle detailed status request."""
        metrics = self._collect_metrics()
        
        status = {
            "daemon": {
                "start_time": self._start_time.isoformat(),
                "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds()
            },
            "poller": metrics.get("poller", {}),
            "processor": metrics.get("processor", {}),
            "responder": metrics.get("responder", {}),
            "scheduler": metrics.get("scheduler", {}),
            "orchestrator": metrics.get("orchestrator", {}),
        }
        
        return web.json_response(status)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect metrics from all components."""
        metrics = {}
        
        if self.poller:
            metrics["poller"] = self.poller.stats.copy()
        
        if self.processor:
            metrics["processor"] = self.processor.stats.copy()
        
        if self.responder:
            metrics["responder"] = self.responder.stats.copy()
        
        if self.scheduler:
            metrics["scheduler"] = self.scheduler.stats.copy()
        
        if self.orchestrator:
            orch_stats = self.orchestrator.stats.copy()
            orch_stats["active_agents"] = self.orchestrator.agent_runner.active_count
            orch_stats["enabled"] = self.orchestrator.enabled
            metrics["orchestrator"] = orch_stats
        
        return metrics
