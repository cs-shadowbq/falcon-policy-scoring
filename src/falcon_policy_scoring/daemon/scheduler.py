"""Cron-like scheduler for daemon mode."""
import logging
import time
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from falcon_policy_scoring.utils.exceptions import SchedulerError


logger = logging.getLogger(__name__)


@dataclass
class ScheduledTask:
    """Represents a scheduled task with cron-like timing."""
    name: str
    schedule: str  # Cron expression: "minute hour day month dayofweek"
    handler: Callable
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    enabled: bool = True
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)


class CronParser:
    """Parse and evaluate cron expressions."""

    @staticmethod
    def parse_field(field: str, min_val: int, max_val: int) -> List[int]:
        """Parse a single cron field.

        Supports:
        - * (any value)
        - */N (every N units)
        - N (specific value)
        - N-M (range)
        - N,M,O (list)
        """
        if field == '*':
            return list(range(min_val, max_val + 1))

        if '/' in field:
            parts = field.split('/')
            step = int(parts[1])
            if parts[0] == '*':
                return list(range(min_val, max_val + 1, step))
            else:
                start = int(parts[0])
                return list(range(start, max_val + 1, step))

        if ',' in field:
            return [int(x) for x in field.split(',')]

        if '-' in field:
            start, end = field.split('-')
            return list(range(int(start), int(end) + 1))

        return [int(field)]

    @classmethod
    def parse_cron(cls, cron_expr: str) -> Dict[str, List[int]]:
        """Parse a cron expression into component parts.

        Format: "minute hour day month dayofweek"
        Example: "*/5 * * * *" = every 5 minutes
        Example: "0 2 * * *" = daily at 2am
        Example: "0 */6 * * *" = every 6 hours
        """
        parts = cron_expr.split()
        if len(parts) != 5:
            raise SchedulerError(f"Invalid cron expression: {cron_expr}. Expected 5 fields.")

        return {
            'minute': cls.parse_field(parts[0], 0, 59),
            'hour': cls.parse_field(parts[1], 0, 23),
            'day': cls.parse_field(parts[2], 1, 31),
            'month': cls.parse_field(parts[3], 1, 12),
            'dayofweek': cls.parse_field(parts[4], 0, 6)  # 0=Sunday
        }

    @staticmethod
    def matches(dt: datetime, cron_parts: Dict[str, List[int]]) -> bool:
        """Check if a datetime matches the cron schedule."""
        return (
            dt.minute in cron_parts['minute'] and
            dt.hour in cron_parts['hour'] and
            dt.day in cron_parts['day'] and
            dt.month in cron_parts['month'] and
            dt.weekday() in [(d + 6) % 7 for d in cron_parts['dayofweek']]  # Convert Sunday=0 to Monday=0
        )

    @classmethod
    def get_next_run(cls, cron_expr: str, from_time: Optional[datetime] = None) -> datetime:
        """Calculate the next run time for a cron expression."""
        if from_time is None:
            from_time = datetime.now()

        # Start from the next minute
        next_time = from_time.replace(second=0, microsecond=0) + timedelta(minutes=1)
        cron_parts = cls.parse_cron(cron_expr)

        # Check up to 4 years in the future (avoid infinite loop)
        max_iterations = 525600 * 4  # minutes in 4 years
        for _ in range(max_iterations):
            if cls.matches(next_time, cron_parts):
                return next_time
            next_time += timedelta(minutes=1)

        raise SchedulerError(f"Could not find next run time for cron expression: {cron_expr}")


class Scheduler:
    """Schedule and execute tasks based on cron expressions."""

    def __init__(self):
        """Initialize the scheduler."""
        self.tasks: Dict[str, ScheduledTask] = {}
        self.running = False
        self._parser = CronParser()

    def add_task(self, name: str, schedule: str, handler: Callable,
                 args: tuple = (), kwargs: dict = None) -> None:
        """Add a scheduled task.

        Args:
            name: Unique task identifier
            schedule: Cron expression (e.g., "*/5 * * * *")
            handler: Function to call when task runs
            args: Positional arguments for handler
            kwargs: Keyword arguments for handler
        """
        if name in self.tasks:
            logger.warning("Task '%s' already exists. Replacing.", name)

        task = ScheduledTask(
            name=name,
            schedule=schedule,
            handler=handler,
            args=args,
            kwargs=kwargs or {}
        )

        # Calculate initial next_run time
        task.next_run = self._parser.get_next_run(schedule)
        self.tasks[name] = task

        logger.info("Scheduled task '%s' with schedule '%s'. Next run: %s", name, schedule, task.next_run)

    def remove_task(self, name: str) -> None:
        """Remove a scheduled task."""
        if name in self.tasks:
            del self.tasks[name]
            logger.info("Removed task '%s'", name)

    def enable_task(self, name: str) -> None:
        """Enable a task."""
        if name in self.tasks:
            self.tasks[name].enabled = True
            logger.info("Enabled task '%s'", name)

    def disable_task(self, name: str) -> None:
        """Disable a task without removing it."""
        if name in self.tasks:
            self.tasks[name].enabled = False
            logger.info("Disabled task '%s'", name)

    def get_task_status(self, name: str) -> Optional[Dict]:
        """Get status information for a task."""
        task = self.tasks.get(name)
        if not task:
            return None

        return {
            'name': task.name,
            'schedule': task.schedule,
            'enabled': task.enabled,
            'last_run': task.last_run.isoformat() if task.last_run else None,
            'next_run': task.next_run.isoformat() if task.next_run else None
        }

    def get_all_tasks_status(self) -> List[Dict]:
        """Get status for all tasks."""
        return [self.get_task_status(name) for name in self.tasks.keys()]

    def check_and_run_tasks(self) -> List[Tuple[str, bool, Optional[str]]]:
        """Check all tasks and run those that are due.

        Returns:
            List of tuples: (task_name, success, error_message)
        """
        now = datetime.now().replace(second=0, microsecond=0)
        results = []

        for name, task in self.tasks.items():
            if not task.enabled:
                continue

            if task.next_run and now >= task.next_run:
                logger.info("Running task '%s'", name)
                success = True
                error_msg = None

                try:
                    task.handler(*task.args, **task.kwargs)
                    task.last_run = now
                except Exception as e:
                    logger.error("Task '%s' failed: %s", name, e, exc_info=True)
                    success = False
                    error_msg = str(e)

                # Calculate next run time
                try:
                    task.next_run = self._parser.get_next_run(task.schedule, now)
                    logger.info("Task '%s' next run: %s", name, task.next_run)
                except Exception as e:
                    logger.error("Failed to calculate next run for task '%s': %s", name, e)
                    task.enabled = False

                results.append((name, success, error_msg))

        return results

    def run_forever(self, check_interval: int = 60) -> None:
        """Run the scheduler indefinitely.

        Args:
            check_interval: Seconds between checks (default: 60)
        """
        self.running = True
        logger.info("Scheduler started. Check interval: %ss", check_interval)

        while self.running:
            try:
                self.check_and_run_tasks()

                # Sleep in small increments to allow quick shutdown
                # Break the check_interval into 1-second chunks
                for _ in range(check_interval):
                    if not self.running:
                        break
                    time.sleep(1)

            except KeyboardInterrupt:
                logger.info("Scheduler interrupted by user")
                break
            except Exception as e:
                logger.error("Scheduler error: %s", e, exc_info=True)
                # Also use incremental sleep for error recovery
                for _ in range(check_interval):
                    if not self.running:
                        break
                    time.sleep(1)

    def stop(self) -> None:
        """Stop the scheduler."""
        logger.info("Stopping scheduler")
        self.running = False
