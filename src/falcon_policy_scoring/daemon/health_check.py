"""Health check endpoint for Kubernetes probes."""
import json
import logging
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Dict, Optional, Any
from enum import Enum
from falcon_policy_scoring.utils.datetime_utils import get_utc_iso_timestamp


logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck:
    """HTTP health check endpoint for container orchestration."""

    def __init__(self, port: int = 8088):
        """Initialize health check server.

        Args:
            port: Port to listen on
        """
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[Thread] = None

        # Health state
        self._status = HealthStatus.HEALTHY
        self._last_successful_run: Optional[datetime] = None
        self._last_failed_run: Optional[datetime] = None
        self._next_scheduled_run: Optional[datetime] = None
        self._consecutive_failures = 0
        self._error_message: Optional[str] = None
        self._metrics: Dict[str, Any] = {}
        self._started_at = datetime.now()

    def start(self) -> None:
        """Start the health check HTTP server in background thread."""
        if self.server_thread and self.server_thread.is_alive():
            logger.warning("Health check server already running")
            return

        handler = self._create_handler()
        self.server = HTTPServer(('0.0.0.0', self.port), handler)
        self.server_thread = Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

        logger.info(f"Health check server started on port {self.port}")

    def stop(self) -> None:
        """Stop the health check HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Health check server stopped")

    def _create_handler(self):
        """Create HTTP request handler with access to health state."""
        health_check = self

        class HealthCheckHandler(BaseHTTPRequestHandler):
            """HTTP request handler for health checks."""

            def log_message(self, format, *args):
                """Override to use our logger."""
                logger.info(f"Health check request: {format % args}")

            def do_GET(self):
                """Handle GET requests."""
                try:
                    if self.path == '/health' or self.path == '/healthz':
                        self._handle_health()
                    elif self.path == '/ready' or self.path == '/readiness':
                        self._handle_readiness()
                    elif self.path == '/metrics':
                        self._handle_metrics()
                    else:
                        self.send_error(404, "Not Found")
                except Exception as e:
                    logger.error(f"Error handling health check request: {e}", exc_info=True)
                    try:
                        self.send_error(500, f"Internal Server Error: {str(e)}")
                    except:
                        pass

            def _handle_health(self):
                """Liveness probe - is the service running?"""
                try:
                    logger.info("Handling health check request")
                    # Always return 200 if we can respond
                    response = {
                        'status': 'alive',
                        'timestamp': get_utc_iso_timestamp(),
                        'uptime_seconds': (datetime.now() - health_check._started_at).total_seconds()
                    }
                    logger.info(f"Sending response: {response}")
                    self._send_json_response(200, response)
                    logger.info("Response sent successfully")
                except Exception as e:
                    logger.error(f"Error in _handle_health: {e}", exc_info=True)
                    raise

            def _handle_readiness(self):
                """Readiness probe - is the service ready to accept work?"""
                status = health_check.get_status()

                # Return 200 if healthy or degraded, 503 if unhealthy
                status_code = 200 if status['status'] != HealthStatus.UNHEALTHY.value else 503
                self._send_json_response(status_code, status)

            def _handle_metrics(self):
                """Metrics endpoint - return current metrics."""
                metrics = health_check.get_metrics()
                self._send_json_response(200, metrics)

            def _send_json_response(self, status_code: int, data: dict):
                """Send JSON response."""
                self.send_response(status_code)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data, default=str).encode())

        return HealthCheckHandler

    def update_successful_run(self, next_run: Optional[datetime] = None) -> None:
        """Update health state after successful run.

        Args:
            next_run: Next scheduled run time
        """
        self._last_successful_run = datetime.now()
        self._consecutive_failures = 0
        self._error_message = None
        self._next_scheduled_run = next_run

        # Return to healthy if we were degraded
        if self._status != HealthStatus.HEALTHY:
            logger.info("Health status restored to HEALTHY")
            self._status = HealthStatus.HEALTHY

    def update_failed_run(self, error_message: str, next_run: Optional[datetime] = None) -> None:
        """Update health state after failed run.

        Args:
            error_message: Error description
            next_run: Next scheduled run time
        """
        self._last_failed_run = datetime.now()
        self._consecutive_failures += 1
        self._error_message = error_message
        self._next_scheduled_run = next_run

        # Update health status based on failure count
        if self._consecutive_failures >= 5:
            new_status = HealthStatus.UNHEALTHY
        elif self._consecutive_failures >= 2:
            new_status = HealthStatus.DEGRADED
        else:
            new_status = HealthStatus.DEGRADED

        if new_status != self._status:
            logger.warning(f"Health status changed: {self._status.value} -> {new_status.value}")
            self._status = new_status

    def update_metrics(self, metrics: Dict[str, Any]) -> None:
        """Update metrics data.

        Args:
            metrics: Current metrics
        """
        self._metrics = metrics

    def update_next_run(self, next_run: Optional[datetime] = None) -> None:
        """Update next scheduled run time.

        Args:
            next_run: Next scheduled run time
        """
        self._next_scheduled_run = next_run

    def get_status(self) -> Dict[str, Any]:
        """Get current health status.

        Returns:
            Health status dictionary
        """
        return {
            'status': self._status.value,
            'timestamp': get_utc_iso_timestamp(),
            'uptime_seconds': (datetime.now() - self._started_at).total_seconds(),
            'last_successful_run': self._last_successful_run.isoformat() if self._last_successful_run else None,
            'last_failed_run': self._last_failed_run.isoformat() if self._last_failed_run else None,
            'next_scheduled_run': self._next_scheduled_run.isoformat() if self._next_scheduled_run else None,
            'consecutive_failures': self._consecutive_failures,
            'error_message': self._error_message
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics.

        Returns:
            Metrics dictionary
        """
        return {
            'timestamp': get_utc_iso_timestamp(),
            'uptime_seconds': (datetime.now() - self._started_at).total_seconds(),
            **self._metrics
        }
