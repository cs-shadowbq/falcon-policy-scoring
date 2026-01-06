"""Main daemon runner for continuous policy auditing."""
import logging
import os
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from falconpy import APIHarnessV2

from falcon_policy_scoring.utils.config import read_config_from_yaml
from falcon_policy_scoring.utils.logger import setup_logging
from falcon_policy_scoring.factories.database_factory import DatabaseFactory
from falcon_policy_scoring.falconapi.cid import get_cid
from falcon_policy_scoring.falconapi.hosts import Hosts
from falcon_policy_scoring.utils.policy_registry import get_policy_registry
from falcon_policy_scoring.utils.policy_registry import get_policy_registry
from falcon_policy_scoring.utils.host_data import collect_host_data, calculate_host_stats
from falcon_policy_scoring.utils.policy_helpers import (
    fetch_all_graded_policies,
    get_policy_status
)
from falcon_policy_scoring.utils.constants import POLICY_TYPE_REGISTRY
from falcon_policy_scoring.utils.exceptions import (
    ConfigurationError,
    ApiConnectionError,
    GradingError,
    ReportGenerationError,
    SchedulerError,
)

from .scheduler import Scheduler
from .rate_limiter import RateLimiter, RateLimitConfig
from .json_writer import JsonWriter
from .health_check import HealthCheck
from .metrics import DaemonMetrics, RunMetrics


logger = logging.getLogger(__name__)


class DaemonRunner:
    """Main daemon orchestrator for continuous policy auditing."""

    def __init__(self, config_path: str, output_dir: str, immediate: bool = False):
        """Initialize daemon runner.

        Args:
            config_path: Path to configuration file
            output_dir: Directory for JSON output files
            immediate: If True, run fetch and grade immediately on startup
        """
        self.config_path = config_path
        self.output_dir = output_dir
        self.immediate = immediate
        self.running = False

        # Core components
        self.config = None
        self.adapter = None
        self.falcon = None
        self.cid = None

        # Daemon components
        self.scheduler = Scheduler()
        self.rate_limiter: Optional[RateLimiter] = None
        self.json_writer: Optional[JsonWriter] = None
        self.health_check: Optional[HealthCheck] = None
        self.metrics = DaemonMetrics()

        # Signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGHUP, self._handle_sighup)

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals gracefully."""
        signal_name = 'SIGTERM' if signum == signal.SIGTERM else 'SIGINT'
        # Print to console immediately so user sees feedback
        print("\n\033[93mReceived interrupt signal, shutting down gracefully...\033[0m")
        logger.info(f"Received {signal_name}, initiating graceful shutdown...")
        self.stop()
        # For SIGINT (Ctrl+C), raise KeyboardInterrupt to exit cleanly
        if signum == signal.SIGINT:
            raise KeyboardInterrupt()

    def _handle_sighup(self, signum, frame):
        """Handle SIGHUP signal to reload configuration."""
        print("\n\033[96mReceived SIGHUP, reloading configuration...\033[0m")
        logger.info("Received SIGHUP, reloading configuration...")
        try:
            self._reload_config()
            print("\033[92mConfiguration reloaded successfully\033[0m")
            logger.info("Configuration reloaded successfully")
        except ConfigurationError as e:
            print(f"\033[91mConfiguration error: {e}\033[0m")
            logger.error(f"Configuration error: {e}", exc_info=True)
        except Exception as e:
            print(f"\033[91mFailed to reload configuration: {e}\033[0m")
            logger.error(f"Failed to reload configuration: {e}", exc_info=True)

    def initialize(self) -> None:
        """Initialize all daemon components."""
        logger.info(f"Initializing daemon with config: {self.config_path}")

        # Load environment variables from .env file if present
        load_dotenv()

        # Load configuration
        self.config = read_config_from_yaml(self.config_path)

        # Initialize database
        db_type = self.config.get('db', {}).get('type', 'sqlite')
        self.adapter = DatabaseFactory.create_adapter(db_type)
        self.adapter.connect(self.config[db_type])
        logger.info(f"Database initialized: {db_type}")

        # Initialize Falcon API client
        falcon_config = self.config.get('falcon_credentials', {})

        # Get environment variable prefix
        prefix = falcon_config.get('prefix', '')

        # Load credentials with priority: ENV var > config file
        client_id = os.environ.get(prefix + 'CLIENT_ID') or falcon_config.get('client_id')
        client_secret = os.environ.get(prefix + 'CLIENT_SECRET') or falcon_config.get('client_secret')
        base_url = os.environ.get(prefix + 'BASE_URL') or falcon_config.get('base_url')

        if not client_id or not client_secret or not base_url:
            raise ConfigurationError(
                f"Missing Falcon API credentials. Set {prefix}CLIENT_ID, {prefix}CLIENT_SECRET, "
                f"{prefix}BASE_URL env vars or configure in YAML"
            )

        self.falcon = APIHarnessV2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )
        self.cid = get_cid(self.falcon)
        logger.info(f"Falcon API initialized for CID: {self.cid}")

        # Initialize rate limiter
        daemon_config = self.config.get('daemon', {})
        rate_limit_config = RateLimitConfig(
            requests_per_second=daemon_config.get('rate_limit', {}).get('requests_per_second', 10.0),
            requests_per_minute=daemon_config.get('rate_limit', {}).get('requests_per_minute', 500),
            burst_size=daemon_config.get('rate_limit', {}).get('burst_size', 20),
            retry_attempts=daemon_config.get('rate_limit', {}).get('retry_attempts', 5)
        )
        self.rate_limiter = RateLimiter(rate_limit_config)
        logger.info("Rate limiter initialized")

        # Initialize JSON writer
        compress = daemon_config.get('output', {}).get('compress', False)
        self.json_writer = JsonWriter(self.output_dir, compress=compress)
        logger.info(f"JSON writer initialized: {self.output_dir}")

        # Initialize health check (if enabled)
        health_check_config = daemon_config.get('health_check', {})
        health_enabled = health_check_config.get('enabled', True)
        if health_enabled:
            health_port = health_check_config.get('port', 8088)
            self.health_check = HealthCheck(port=health_port)
            self.health_check.start()
            logger.info(f"Health check started on port {health_port}")
        else:
            self.health_check = None
            logger.info("Health check disabled by configuration")

        # Setup scheduled tasks
        self._setup_scheduled_tasks()

        # Update health check with initial next run time
        if self.health_check:
            fetch_task = self.scheduler.tasks.get('fetch_and_grade')
            if fetch_task:
                self.health_check.update_next_run(fetch_task.next_run)

        logger.info("Daemon initialization complete")

    def _reload_config(self) -> None:
        """Reload configuration from file and update daemon components."""
        logger.info(f"Reloading configuration from: {self.config_path}")

        # Load new configuration
        new_config = read_config_from_yaml(self.config_path)
        old_config = self.config
        self.config = new_config

        # Update rate limiter if settings changed
        daemon_config = new_config.get('daemon', {})
        old_rate_limit = old_config.get('daemon', {}).get('rate_limit', {})
        new_rate_limit = daemon_config.get('rate_limit', {})

        if old_rate_limit != new_rate_limit:
            logger.info("Rate limit settings changed, updating rate limiter...")
            rate_limit_config = RateLimitConfig(
                requests_per_second=new_rate_limit.get('requests_per_second', 10.0),
                requests_per_minute=new_rate_limit.get('requests_per_minute', 500),
                burst_size=new_rate_limit.get('burst_size', 20),
                retry_attempts=new_rate_limit.get('retry_attempts', 5)
            )
            self.rate_limiter = RateLimiter(rate_limit_config)
            logger.info("Rate limiter updated")

        # Update JSON writer compression if setting changed
        old_compress = old_config.get('daemon', {}).get('output', {}).get('compress', False)
        new_compress = daemon_config.get('output', {}).get('compress', False)

        if old_compress != new_compress:
            logger.info(f"Output compression changed: {old_compress} -> {new_compress}")
            self.json_writer = JsonWriter(self.output_dir, compress=new_compress)
            logger.info("JSON writer updated")

        # Rebuild scheduled tasks if schedules changed
        old_schedules = old_config.get('daemon', {}).get('schedules', {})
        new_schedules = daemon_config.get('schedules', {})

        if old_schedules != new_schedules:
            logger.info("Schedules changed, rebuilding scheduled tasks...")
            self.scheduler.tasks.clear()
            self._setup_scheduled_tasks()
            logger.info("Scheduled tasks rebuilt")

        # Update health check port if changed (requires restart of health check)
        old_health_config = old_config.get('daemon', {}).get('health_check', {})
        new_health_config = daemon_config.get('health_check', {})

        if old_health_config != new_health_config:
            logger.info("Health check settings changed, restarting health check...")

            # Stop old health check
            if self.health_check:
                self.health_check.stop()
                self.health_check = None

            # Start new health check if enabled
            if new_health_config.get('enabled', True):
                health_port = new_health_config.get('port', 8088)
                self.health_check = HealthCheck(port=health_port)
                self.health_check.start()
                logger.info(f"Health check restarted on port {health_port}")
            else:
                logger.info("Health check disabled")

        logger.info("Configuration reload complete")

    def _setup_scheduled_tasks(self) -> None:
        """Setup scheduled tasks from configuration."""
        daemon_config = self.config.get('daemon', {})
        schedules = daemon_config.get('schedules', {})

        # Fetch hosts and policies schedule
        fetch_schedule = schedules.get('fetch_and_grade', '0 */2 * * *')  # Default: every 2 hours
        self.scheduler.add_task(
            name='fetch_and_grade',
            schedule=fetch_schedule,
            handler=self._run_fetch_and_grade
        )

        # Cleanup old files schedule
        cleanup_schedule = schedules.get('cleanup', '0 2 * * *')  # Default: daily at 2am
        self.scheduler.add_task(
            name='cleanup',
            schedule=cleanup_schedule,
            handler=self._run_cleanup
        )

        # Write metrics schedule
        metrics_schedule = schedules.get('metrics', '*/30 * * * *')  # Default: every 30 minutes
        self.scheduler.add_task(
            name='metrics',
            schedule=metrics_schedule,
            handler=self._write_metrics
        )

        logger.info(f"Scheduled tasks: fetch_and_grade={fetch_schedule}, cleanup={cleanup_schedule}, metrics={metrics_schedule}")

    def _run_fetch_and_grade(self) -> None:
        """Fetch hosts and policies, grade them, and write reports."""
        run = self.metrics.start_run()

        try:
            logger.info("Starting fetch and grade run")

            # Fetch hosts
            logger.info("Fetching hosts...")
            product_types = self.config.get('daemon', {}).get('product_types', [])
            hosts_api = Hosts(self.cid, self.falcon, product_types=product_types)

            # Use rate limiter for API calls
            hosts_list = self.rate_limiter.execute_with_retry(hosts_api.get_devices)
            run.api_calls += 1
            self.adapter.put_hosts(hosts_list)

            total_hosts = len(hosts_list.get('hosts', []))
            run.hosts_processed = total_hosts
            logger.info(f"Fetched {total_hosts} hosts")

            # Fetch and grade policies
            policy_results = {}
            policy_types = self.config.get('daemon', {}).get('policy_types', [
                'prevention', 'sensor-update', 'content-update',
                'firewall', 'device-control', 'it-automation'
            ])

            for policy_type in policy_types:
                logger.info(f"Grading {policy_type} policies...")

                try:
                    result = self._grade_policy_type(policy_type, run)
                    policy_results[policy_type] = result

                    run.policies_graded += result.get('policies_count', 0)
                    run.policies_passed += result.get('passed_policies', 0)
                    run.policies_failed += result.get('failed_policies', 0)

                except GradingError as e:
                    logger.error(f"Grading error for {policy_type} policies: {e}")
                    run.api_errors += 1
                except Exception as e:
                    logger.error(f"Failed to grade {policy_type} policies: {e}")
                    run.api_errors += 1

            # Generate and write reports
            self._write_policy_report(policy_results, run)
            self._write_host_report(total_hosts, run)
            self._write_host_details_report()

            # Update health check
            next_run = self.scheduler.get_task_status('fetch_and_grade').get('next_run')
            if next_run:
                next_run_dt = datetime.fromisoformat(next_run)
                if self.health_check:
                    self.health_check.update_successful_run(next_run_dt)

            self.metrics.complete_run(run, success=True)
            logger.info("Fetch and grade run completed successfully")

        except Exception as e:
            logger.error(f"Fetch and grade run failed: {e}", exc_info=True)
            self.metrics.complete_run(run, success=False, error_message=str(e))

            # Update health check
            next_run = self.scheduler.get_task_status('fetch_and_grade').get('next_run')
            if next_run:
                next_run_dt = datetime.fromisoformat(next_run)
                if self.health_check:
                    self.health_check.update_failed_run(str(e), next_run_dt)

    def _grade_policy_type(self, policy_type: str, run: RunMetrics) -> dict:
        """Grade a specific policy type.

        Args:
            policy_type: Type of policy to grade
            run: Current run metrics

        Returns:
            Grading results
        """
        registry = get_policy_registry()
        policy_info = registry.get_by_cli_name(policy_type)

        if not policy_info or not policy_info.grader_func:
            logger.warning(f"Unknown policy type: {policy_type}")
            return {}

        # Execute with rate limiting
        result = self.rate_limiter.execute_with_retry(
            policy_info.grader_func, self.falcon, self.adapter, self.cid
        )

        run.api_calls += 1
        return result

    def _write_policy_report(self, policy_results: dict, run: RunMetrics) -> None:
        """Write policy audit report."""
        summary = {
            'total_policies': run.policies_graded,
            'passed_policies': run.policies_passed,
            'failed_policies': run.policies_failed,
            'pass_rate': run.policies_passed / run.policies_graded if run.policies_graded > 0 else 0.0
        }

        self.json_writer.write_policy_audit(self.cid, policy_results, summary, self.config)

    def _write_host_report(self, total_hosts: int, run: RunMetrics) -> None:
        """Write host summary report."""
        # Get hosts from database
        hosts_record = self.adapter.get_hosts(self.cid)
        hosts = hosts_record.get('hosts', [])

        # Fetch all graded policies to calculate host compliance
        policy_records = fetch_all_graded_policies(self.adapter, self.cid, POLICY_TYPE_REGISTRY)

        # Calculate actual compliance from host data
        host_data = collect_host_data(self.adapter, self.cid, policy_records, get_policy_status, self.config)
        stats = calculate_host_stats(host_data)

        summary = {
            'total_hosts': stats['total'],
            'hosts_all_passed': stats['all_passed'],
            'hosts_any_failed': stats['any_failed']
        }

        self.json_writer.write_host_summary(self.cid, hosts, summary, self.config)

    def _write_host_details_report(self) -> None:
        """Write comprehensive host details report matching policy_audit_output.schema.json."""
        try:
            logger.info("Writing host details report...")
            self.json_writer.write_host_details(self.adapter, self.cid, self.config)
            logger.info("Host details report written successfully")
        except ReportGenerationError as e:
            logger.error(f"Report generation error: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Failed to write host details report: {e}", exc_info=True)

    def _run_cleanup(self) -> None:
        """Clean up old report files."""
        logger.info("Running cleanup task")

        try:
            daemon_config = self.config.get('daemon', {})
            max_age_days = daemon_config.get('output', {}).get('max_age_days', 30)
            max_files = daemon_config.get('output', {}).get('max_files_per_type', 100)

            deleted = self.json_writer.cleanup_old_files(max_age_days, max_files)
            logger.info(f"Cleanup complete: deleted {deleted} files")

        except Exception as e:
            logger.error(f"Cleanup failed: {e}", exc_info=True)

    def _write_metrics(self) -> None:
        """Write current metrics to file."""
        try:
            metrics_summary = self.metrics.get_summary()

            # Add rate limiter metrics
            if self.rate_limiter:
                metrics_summary['rate_limiter'] = self.rate_limiter.get_metrics()

            if self.health_check:
                self.health_check.update_metrics(metrics_summary)
            self.json_writer.write_metrics(metrics_summary, self.cid, self.config)

            logger.debug("Metrics written")

        except Exception as e:
            logger.error(f"Failed to write metrics: {e}", exc_info=True)

    def run(self) -> None:
        """Run the daemon indefinitely."""
        self.running = True
        logger.info("Daemon started")

        try:
            # Run immediate fetch if requested
            if self.immediate:
                logger.info("Executing immediate fetch and grade run...")
                try:
                    self._run_fetch_and_grade()
                    logger.info("Immediate run completed successfully")
                except Exception as e:
                    logger.error(f"Immediate run failed: {e}", exc_info=True)

            # Run scheduler (blocks until stopped)
            check_interval = self.config.get('daemon', {}).get('check_interval', 60)
            self.scheduler.run_forever(check_interval=check_interval)

        except Exception as e:
            logger.error(f"Daemon error: {e}", exc_info=True)
            raise

        finally:
            self.cleanup()

    def stop(self) -> None:
        """Stop the daemon gracefully."""
        print("Stopping daemon gracefully...")
        logger.info("Stopping daemon...")
        self.running = False
        self.scheduler.stop()

    def cleanup(self) -> None:
        """Cleanup resources."""
        print("Cleaning up resources...")
        logger.info("Cleaning up resources...")

        try:
            if self.health_check:
                self.health_check.stop()

            if self.adapter:
                self.adapter.close()

            print("Cleanup complete")
            logger.info("Cleanup complete")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)


def main(config_path: str, output_dir: str) -> int:
    """Main entry point for daemon mode.

    Args:
        config_path: Path to configuration file
        output_dir: Directory for JSON output

    Returns:
        Exit code
    """
    try:
        daemon = DaemonRunner(config_path, output_dir)
        daemon.initialize()
        daemon.run()
        return 0

    except KeyboardInterrupt:
        logger.info("Daemon interrupted by user")
        return 130

    except Exception as e:
        logger.error(f"Daemon failed: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main('config/config.yaml', './output'))
