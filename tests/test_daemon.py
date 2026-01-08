"""Tests for daemon mode components.

Tests the scheduler, rate limiter, health checks, and metrics tracking
for daemon mode operations.
"""
import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock
from freezegun import freeze_time
import threading

from falcon_policy_scoring.daemon.scheduler import Scheduler, CronParser, ScheduledTask
from falcon_policy_scoring.daemon.rate_limiter import RateLimiter, RateLimitConfig
from falcon_policy_scoring.daemon.health_check import HealthCheck, HealthStatus
from falcon_policy_scoring.daemon.metrics import DaemonMetrics, RunMetrics


class TestCronParser:
    """Tests for cron expression parsing."""

    def test_parse_asterisk(self):
        """Test parsing asterisk (any value)."""
        result = CronParser.parse_field("*", 0, 59)
        assert len(result) == 60
        assert result[0] == 0
        assert result[59] == 59

    def test_parse_specific_value(self):
        """Test parsing specific numeric value."""
        result = CronParser.parse_field("5", 0, 59)
        assert result == [5]

    def test_parse_range(self):
        """Test parsing range (N-M)."""
        result = CronParser.parse_field("10-15", 0, 59)
        assert result == [10, 11, 12, 13, 14, 15]

    def test_parse_list(self):
        """Test parsing comma-separated list."""
        result = CronParser.parse_field("1,5,10", 0, 59)
        assert result == [1, 5, 10]

    def test_parse_step_from_asterisk(self):
        """Test parsing step from asterisk (*/N)."""
        result = CronParser.parse_field("*/15", 0, 59)
        assert len(result) == 4
        assert result == [0, 15, 30, 45]

    def test_parse_step_from_value(self):
        """Test parsing step from specific value (N/S)."""
        result = CronParser.parse_field("5/10", 0, 59)
        assert result == [5, 15, 25, 35, 45, 55]

    def test_parse_full_cron_expression(self):
        """Test parsing complete cron expression."""
        cron_parts = CronParser.parse_cron("*/5 * * * *")

        assert len(cron_parts['minute']) == 12  # 0, 5, 10, ..., 55
        assert len(cron_parts['hour']) == 24
        assert len(cron_parts['day']) == 31


class TestScheduler:
    """Tests for task scheduler."""

    def test_create_scheduler(self):
        """Test scheduler initialization."""
        scheduler = Scheduler()
        assert scheduler.tasks == {}
        assert not scheduler.running

    def test_add_task(self):
        """Test adding a scheduled task."""
        scheduler = Scheduler()
        handler = Mock()

        scheduler.add_task("test_task", "* * * * *", handler)

        assert len(scheduler.tasks) == 1
        assert "test_task" in scheduler.tasks
        assert scheduler.tasks["test_task"].name == "test_task"
        assert scheduler.tasks["test_task"].schedule == "* * * * *"
        assert scheduler.tasks["test_task"].enabled

    def test_remove_task(self):
        """Test removing a task."""
        scheduler = Scheduler()
        handler = Mock()

        scheduler.add_task("task1", "* * * * *", handler)
        scheduler.add_task("task2", "*/5 * * * *", handler)

        assert len(scheduler.tasks) == 2
        scheduler.remove_task("task1")

        assert len(scheduler.tasks) == 1
        assert "task1" not in scheduler.tasks
        assert "task2" in scheduler.tasks

    def test_disable_enable_task(self):
        """Test disabling and enabling tasks."""
        scheduler = Scheduler()
        handler = Mock()

        scheduler.add_task("test_task", "* * * * *", handler)
        assert scheduler.tasks["test_task"].enabled

        scheduler.disable_task("test_task")
        assert not scheduler.tasks["test_task"].enabled

        scheduler.enable_task("test_task")
        assert scheduler.tasks["test_task"].enabled

    @freeze_time("2024-01-01 12:04:00")
    def test_task_should_run_at_scheduled_time(self):
        """Test that tasks run at their scheduled time."""
        scheduler = Scheduler()
        handler = Mock()

        # Add task at 12:04, next run will be 12:05
        scheduler.add_task("test_task", "5 * * * *", handler)

        # Move to 12:05:00
        with freeze_time("2024-01-01 12:05:00"):
            results = scheduler.check_and_run_tasks()

        assert len(results) == 1
        assert results[0][0] == "test_task"
        assert results[0][1] is True  # success
        assert handler.called

    @freeze_time("2024-01-01 11:59:00")
    def test_task_execution(self):
        """Test that tasks are executed with correct arguments."""
        scheduler = Scheduler()
        results = []

        def capture_handler(arg1, arg2, kwarg1=None):
            results.append((arg1, arg2, kwarg1))

        # Add task at 11:59, next run will be 12:00
        scheduler.add_task(
            "test_task",
            "0 * * * *",  # At minute 0 every hour
            capture_handler,
            args=("value1", "value2"),
            kwargs={"kwarg1": "kwarg_value"}
        )

        # Execute task at the scheduled time (12:00)
        with freeze_time("2024-01-01 12:00:00"):
            task_results = scheduler.check_and_run_tasks()

        assert len(task_results) == 1
        assert task_results[0][0] == "test_task"
        assert task_results[0][1] is True  # success
        assert len(results) == 1
        assert results[0] == ("value1", "value2", "kwarg_value")

    @freeze_time("2024-01-01 11:59:00")
    def test_task_execution_error_handling(self):
        """Test task error handling."""
        scheduler = Scheduler()
        handler = Mock(side_effect=Exception("Task failed"))

        # Add task at 11:59, next run will be 12:00
        scheduler.add_task("failing_task", "0 * * * *", handler)

        # Move to 12:00 and run
        with freeze_time("2024-01-01 12:00:00"):
            results = scheduler.check_and_run_tasks()

        assert len(results) == 1
        assert results[0][0] == "failing_task"
        assert results[0][1] is False  # failed
        assert "Task failed" in results[0][2]

        handler.assert_called_once()


class TestRateLimiter:
    """Tests for API rate limiting."""

    def test_create_rate_limiter(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter()
        assert limiter.config.requests_per_second == 10.0
        assert limiter.config.requests_per_minute == 500
        assert limiter.total_requests == 0

    def test_acquire_within_limits(self):
        """Test acquiring tokens within rate limits."""
        config = RateLimitConfig(requests_per_second=10, burst_size=5)
        limiter = RateLimiter(config)

        # Should succeed within burst
        for _ in range(5):
            assert limiter.acquire()

        assert limiter.total_requests == 5

    def test_acquire_exceeds_burst(self):
        """Test rate limiting when burst exceeded."""
        config = RateLimitConfig(requests_per_second=100, burst_size=2)
        limiter = RateLimiter(config)

        # First 2 should succeed instantly
        assert limiter.acquire(timeout=0.1)
        assert limiter.acquire(timeout=0.1)

        # Third should need to wait (may timeout)
        start = time.time()
        result = limiter.acquire(timeout=0.1)
        elapsed = time.time() - start

        # Either succeeded after brief wait or timed out
        assert elapsed >= 0.01 or not result

    def test_token_bucket_refill(self):
        """Test that tokens refill over time."""
        config = RateLimitConfig(requests_per_second=10, burst_size=5)
        limiter = RateLimiter(config)

        # Use all tokens
        for _ in range(5):
            limiter.acquire()

        # Wait for refill (0.5 seconds = 5 tokens at 10/sec)
        time.sleep(0.5)

        # Should be able to acquire again
        assert limiter.acquire(timeout=0.1)

    @freeze_time("2024-01-01 12:00:00")
    def test_handle_429_backoff(self):
        """Test exponential backoff after 429 errors."""
        limiter = RateLimiter()

        # Trigger 429
        limiter.handle_429()

        assert limiter._consecutive_429s == 1
        assert limiter._backoff_until is not None
        assert limiter._backoff_until > time.time()

        # Should wait before allowing next request
        assert limiter.acquire(timeout=0.01) is False

    def test_exponential_backoff_increases(self):
        """Test that backoff time increases exponentially."""
        limiter = RateLimiter()

        limiter.handle_429()
        first_backoff = limiter._backoff_until - time.time()

        limiter.handle_429()
        second_backoff = limiter._backoff_until - time.time()

        # Second backoff should be longer
        assert second_backoff > first_backoff

    def test_reset_backoff_on_success(self):
        """Test that backoff resets after successful request."""
        limiter = RateLimiter()

        limiter.handle_429()
        assert limiter._consecutive_429s == 1

        limiter.reset_backoff()
        assert limiter._consecutive_429s == 0
        assert limiter._backoff_until is None

    def test_execute_with_retry(self):
        """Test execute_with_retry method."""
        config = RateLimitConfig(requests_per_second=100)
        limiter = RateLimiter(config)

        call_count = 0

        def test_func():
            nonlocal call_count
            call_count += 1
            return "result"

        result = limiter.execute_with_retry(test_func)
        assert result == "result"
        assert call_count == 1
        assert limiter.total_requests >= 1

    def test_max_backoff_limit(self):
        """Test that backoff is capped at maximum."""
        config = RateLimitConfig(backoff_max=10.0)
        limiter = RateLimiter(config)

        # Trigger many 429s
        for _ in range(10):
            limiter.handle_429()

        backoff_time = limiter._backoff_until - time.time()
        assert backoff_time <= config.backoff_max + 1.0  # Allow small margin


class TestHealthCheck:
    """Tests for health check endpoint."""

    def test_create_health_check(self):
        """Test health check initialization."""
        health = HealthCheck(port=8088)
        assert health.port == 8088
        assert health._status == HealthStatus.HEALTHY
        assert health._consecutive_failures == 0

    def test_update_success(self):
        """Test updating health after successful run."""
        health = HealthCheck()
        next_run = datetime(2024, 1, 1, 13, 0, 0)

        health.update_successful_run(next_run=next_run)

        assert health._last_successful_run is not None
        assert health._consecutive_failures == 0
        assert health._status == HealthStatus.HEALTHY
        assert health._next_scheduled_run == next_run

    def test_update_failure(self):
        """Test updating health after failed run."""
        health = HealthCheck()

        health.update_failed_run(
            error_message="Test error",
            next_run=datetime(2024, 1, 1, 13, 0, 0)
        )

        assert health._last_failed_run is not None
        assert health._consecutive_failures == 1
        assert health._status == HealthStatus.DEGRADED
        assert health._error_message == "Test error"

    def test_multiple_failures_unhealthy(self):
        """Test that multiple failures mark service as unhealthy."""
        health = HealthCheck()

        # Fail 5 times
        for i in range(5):
            health.update_failed_run(f"Error {i}")

        assert health._consecutive_failures == 5
        assert health._status == HealthStatus.UNHEALTHY

    def test_recovery_after_success(self):
        """Test that service recovers after successful run."""
        health = HealthCheck()

        # Fail multiple times
        for i in range(3):
            health.update_failed_run(f"Error {i}")

        assert health._status == HealthStatus.DEGRADED

        # Successful run should restore health
        health.update_successful_run()

        assert health._consecutive_failures == 0
        assert health._status == HealthStatus.HEALTHY

    def test_get_health_status(self):
        """Test getting health status."""
        health = HealthCheck()

        status = health.get_status()

        assert status['status'] == HealthStatus.HEALTHY.value
        assert 'timestamp' in status
        assert 'uptime_seconds' in status
        assert status['consecutive_failures'] == 0

    def test_readiness_probe(self):
        """Test readiness probe logic via get_status."""
        health = HealthCheck()

        # Healthy service is ready
        status = health.get_status()
        assert status['status'] == HealthStatus.HEALTHY.value

        # Degraded service after failure
        health.update_failed_run("Error")
        status = health.get_status()
        assert status['status'] == HealthStatus.DEGRADED.value

        # Unhealthy service after 5 failures
        for i in range(4):
            health.update_failed_run(f"Error {i}")
        status = health.get_status()
        assert status['status'] == HealthStatus.UNHEALTHY.value

    def test_liveness_probe(self):
        """Test that get_status returns data even after failures."""
        health = HealthCheck()

        # Should always return status while running
        status = health.get_status()
        assert 'status' in status
        assert 'timestamp' in status

        # Even after failures
        for i in range(10):
            health.update_failed_run(f"Error {i}")
        status = health.get_status()
        assert status['status'] == HealthStatus.UNHEALTHY.value
        assert status['consecutive_failures'] == 10

    def test_update_metrics(self):
        """Test updating metrics data."""
        health = HealthCheck()
        metrics = {'total_runs': 5, 'api_calls': 100}

        health.update_metrics(metrics)

        result = health.get_metrics()
        assert result['total_runs'] == 5
        assert result['api_calls'] == 100

    def test_set_next_run(self):
        """Test setting next scheduled run time."""
        health = HealthCheck()
        next_run = datetime(2024, 1, 1, 14, 0, 0)

        health.update_next_run(next_run)

        status = health.get_status()
        assert status['next_scheduled_run'] == next_run.isoformat()


class TestDaemonMetrics:
    """Tests for daemon metrics tracking."""

    def test_create_metrics(self):
        """Test metrics initialization."""
        metrics = DaemonMetrics()
        assert metrics.total_runs == 0
        assert metrics.successful_runs == 0
        assert metrics.failed_runs == 0

    def test_start_run(self):
        """Test starting a new run."""
        metrics = DaemonMetrics()
        run = metrics.start_run()

        assert isinstance(run, RunMetrics)
        assert run.start_time is not None
        assert run.end_time is None

    def test_complete_successful_run(self):
        """Test completing a successful run."""
        metrics = DaemonMetrics()
        run = metrics.start_run()
        run.hosts_processed = 10
        run.policies_graded = 50
        run.api_calls = 25

        metrics.complete_run(run, success=True)

        assert metrics.total_runs == 1
        assert metrics.successful_runs == 1
        assert metrics.failed_runs == 0
        assert metrics.total_hosts_processed == 10
        assert metrics.total_policies_graded == 50
        assert metrics.total_api_calls == 25

    def test_complete_failed_run(self):
        """Test completing a failed run."""
        metrics = DaemonMetrics()
        run = metrics.start_run()
        run.hosts_processed = 5
        run.policies_graded = 20
        run.api_calls = 10

        metrics.complete_run(run, success=False, error_message="Test error")

        assert metrics.total_runs == 1
        assert metrics.failed_runs == 1
        assert metrics.successful_runs == 0
        assert metrics.last_run.success is False
        assert metrics.last_run.error_message == "Test error"

    def test_run_duration_calculation(self):
        """Test that run duration is calculated correctly."""
        metrics = DaemonMetrics()
        run = metrics.start_run()

        time.sleep(0.1)
        metrics.complete_run(run)

        assert run.duration_seconds >= 0.1
        assert metrics.total_duration_seconds >= 0.1

    def test_get_summary(self):
        """Test getting metrics summary."""
        metrics = DaemonMetrics()
        run = metrics.start_run()
        run.hosts_processed = 10
        metrics.complete_run(run)

        summary = metrics.get_summary()

        assert 'total_runs' in summary
        assert 'successful_runs' in summary
        assert 'total_hosts_processed' in summary
        assert summary['total_runs'] == 1
        assert summary['successful_runs'] == 1
        assert summary['total_hosts_processed'] == 10
        assert 'last_run' in summary

    def test_concurrent_run_tracking(self):
        """Test that metrics handle concurrent updates."""
        metrics = DaemonMetrics()
        results = []

        def run_task():
            run = metrics.start_run()
            run.hosts_processed = 1
            time.sleep(0.01)
            metrics.complete_run(run)
            results.append(True)

        # Run 5 tasks concurrently
        threads = [threading.Thread(target=run_task) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5
        assert metrics.total_runs == 5
        assert metrics.total_hosts_processed == 5


class TestDaemonIntegration:
    """Integration tests for daemon components working together."""

    @freeze_time("2024-01-01 11:59:00")
    def test_scheduler_with_rate_limiter(self):
        """Test scheduler with rate limiter."""
        scheduler = Scheduler()
        limiter = RateLimiter(RateLimitConfig(requests_per_second=100))

        call_count = 0

        def rate_limited_handler():
            nonlocal call_count
            limiter.acquire()
            call_count += 1

        # Add at 11:59, next run will be 12:00
        scheduler.add_task("test_task", "0 * * * *", rate_limited_handler)

        with freeze_time("2024-01-01 12:00:00"):
            results = scheduler.check_and_run_tasks()

        assert len(results) == 1
        assert results[0][1] is True  # success
        assert call_count == 1
        assert limiter.total_requests >= 1

    @freeze_time("2024-01-01 11:59:00")
    def test_scheduler_updates_health_check(self):
        """Test that scheduler updates health check."""
        scheduler = Scheduler()
        health = HealthCheck()

        def task_handler():
            health.update_successful_run()

        # Add at 11:59, next run will be 12:00
        scheduler.add_task("health_task", "0 * * * *", task_handler)

        with freeze_time("2024-01-01 12:00:00"):
            results = scheduler.check_and_run_tasks()

        assert len(results) == 1
        assert results[0][1] is True  # success
        assert health._last_successful_run is not None
        assert health._status == HealthStatus.HEALTHY

    @freeze_time("2024-01-01 11:59:00")
    def test_failed_task_updates_health(self):
        """Test that failed tasks update health check."""
        scheduler = Scheduler()
        health = HealthCheck()

        def failing_handler():
            health.update_failed_run("Task failed")
            raise ValueError("Task failed")

        # Add at 11:59, next run will be 12:00
        scheduler.add_task("failing_task", "0 * * * *", failing_handler)

        with freeze_time("2024-01-01 12:00:00"):
            results = scheduler.check_and_run_tasks()

        assert len(results) == 1
        assert results[0][1] is False  # failed
        assert health._last_failed_run is not None
        assert health._status == HealthStatus.DEGRADED

    @freeze_time("2024-01-01 11:59:00")
    def test_metrics_track_scheduler_runs(self):
        """Test that metrics track scheduler runs."""
        scheduler = Scheduler()
        metrics = DaemonMetrics()

        def task_handler():
            run = metrics.start_run()
            run.hosts_processed = 5
            metrics.complete_run(run)

        # Add at 11:59, next run will be 12:00
        scheduler.add_task("metrics_task", "0 * * * *", task_handler)

        with freeze_time("2024-01-01 12:00:00"):
            results = scheduler.check_and_run_tasks()

        assert len(results) == 1
        assert results[0][1] is True  # success
        assert metrics.total_runs == 1
        assert metrics.successful_runs == 1
        assert metrics.total_hosts_processed == 5
