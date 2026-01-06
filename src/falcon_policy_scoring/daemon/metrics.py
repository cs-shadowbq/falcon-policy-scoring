"""Metrics tracking for daemon operations."""
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional
from threading import Lock


logger = logging.getLogger(__name__)


@dataclass
class RunMetrics:
    """Metrics for a single run."""
    start_time: datetime
    end_time: Optional[datetime] = None
    hosts_processed: int = 0
    policies_fetched: int = 0
    policies_graded: int = 0
    policies_passed: int = 0
    policies_failed: int = 0
    api_calls: int = 0
    api_errors: int = 0
    duration_seconds: float = 0.0
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class DaemonMetrics:
    """Aggregate metrics for daemon operations."""
    started_at: datetime = field(default_factory=datetime.now)
    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0
    total_hosts_processed: int = 0
    total_policies_graded: int = 0
    total_policies_passed: int = 0
    total_policies_failed: int = 0
    total_api_calls: int = 0
    total_api_errors: int = 0
    total_duration_seconds: float = 0.0
    last_run: Optional[RunMetrics] = None

    def __post_init__(self):
        """Initialize thread lock."""
        self._lock = Lock()

    def start_run(self) -> RunMetrics:
        """Start tracking a new run.

        Returns:
            RunMetrics object to track this run
        """
        return RunMetrics(start_time=datetime.now())

    def complete_run(self, run: RunMetrics, success: bool = True,
                     error_message: Optional[str] = None) -> None:
        """Complete a run and update aggregate metrics.

        Args:
            run: RunMetrics object for this run
            success: Whether the run succeeded
            error_message: Error message if failed
        """
        run.end_time = datetime.now()
        run.duration_seconds = (run.end_time - run.start_time).total_seconds()
        run.success = success
        run.error_message = error_message

        with self._lock:
            self.total_runs += 1
            if success:
                self.successful_runs += 1
            else:
                self.failed_runs += 1

            self.total_hosts_processed += run.hosts_processed
            self.total_policies_graded += run.policies_graded
            self.total_policies_passed += run.policies_passed
            self.total_policies_failed += run.policies_failed
            self.total_api_calls += run.api_calls
            self.total_api_errors += run.api_errors
            self.total_duration_seconds += run.duration_seconds
            self.last_run = run

        logger.info(
            f"Run completed in {run.duration_seconds:.1f}s: "
            f"hosts={run.hosts_processed}, policies={run.policies_graded}, "
            f"api_calls={run.api_calls}, success={success}"
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary.

        Returns:
            Dictionary of metrics
        """
        with self._lock:
            uptime = (datetime.now() - self.started_at).total_seconds()

            summary = {
                'uptime_seconds': uptime,
                'uptime_hours': uptime / 3600,
                'total_runs': self.total_runs,
                'successful_runs': self.successful_runs,
                'failed_runs': self.failed_runs,
                'success_rate': self.successful_runs / self.total_runs if self.total_runs > 0 else 0.0,
                'total_hosts_processed': self.total_hosts_processed,
                'total_policies_graded': self.total_policies_graded,
                'total_policies_passed': self.total_policies_passed,
                'total_policies_failed': self.total_policies_failed,
                'policy_pass_rate': (
                    self.total_policies_passed / self.total_policies_graded
                    if self.total_policies_graded > 0 else 0.0
                ),
                'total_api_calls': self.total_api_calls,
                'total_api_errors': self.total_api_errors,
                'api_error_rate': (
                    self.total_api_errors / self.total_api_calls
                    if self.total_api_calls > 0 else 0.0
                ),
                'total_duration_seconds': self.total_duration_seconds,
                'avg_run_duration_seconds': (
                    self.total_duration_seconds / self.total_runs
                    if self.total_runs > 0 else 0.0
                ),
            }

            if self.last_run:
                summary['last_run'] = {
                    'start_time': self.last_run.start_time.isoformat(),
                    'end_time': self.last_run.end_time.isoformat() if self.last_run.end_time else None,
                    'duration_seconds': self.last_run.duration_seconds,
                    'hosts_processed': self.last_run.hosts_processed,
                    'policies_graded': self.last_run.policies_graded,
                    'policies_passed': self.last_run.policies_passed,
                    'policies_failed': self.last_run.policies_failed,
                    'api_calls': self.last_run.api_calls,
                    'api_errors': self.last_run.api_errors,
                    'success': self.last_run.success,
                    'error_message': self.last_run.error_message
                }

            return summary

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self.started_at = datetime.now()
            self.total_runs = 0
            self.successful_runs = 0
            self.failed_runs = 0
            self.total_hosts_processed = 0
            self.total_policies_graded = 0
            self.total_policies_passed = 0
            self.total_policies_failed = 0
            self.total_api_calls = 0
            self.total_api_errors = 0
            self.total_duration_seconds = 0.0
            self.last_run = None

        logger.info("Metrics reset")
