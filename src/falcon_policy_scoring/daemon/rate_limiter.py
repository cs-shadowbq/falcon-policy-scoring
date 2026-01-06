"""Rate limiter for CrowdStrike API calls with exponential backoff."""
import logging
import time
from typing import Optional, Callable, Any
from dataclasses import dataclass
from threading import Lock
from collections import deque
from datetime import datetime, timedelta
from falcon_policy_scoring.utils.exceptions import RateLimitError


logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    requests_per_second: float = 10.0  # CrowdStrike default: ~10 requests/sec
    requests_per_minute: int = 500  # Conservative limit
    burst_size: int = 20  # Allow short bursts
    backoff_base: float = 2.0  # Exponential backoff multiplier
    backoff_max: float = 300.0  # Max backoff time (5 minutes)
    retry_attempts: int = 5  # Max retry attempts


class RateLimiter:
    """Token bucket rate limiter with exponential backoff."""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """Initialize rate limiter.

        Args:
            config: Rate limit configuration
        """
        self.config = config or RateLimitConfig()
        self._lock = Lock()

        # Token bucket for requests per second
        self._tokens = self.config.burst_size
        self._last_update = time.time()

        # Sliding window for requests per minute
        self._request_times: deque = deque(maxlen=self.config.requests_per_minute)

        # Backoff tracking
        self._consecutive_429s = 0
        self._backoff_until: Optional[float] = None

        # Metrics
        self.total_requests = 0
        self.throttled_requests = 0
        self.failed_requests = 0
        self.total_wait_time = 0.0

    def _refill_tokens(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_update

        # Add tokens based on configured rate
        tokens_to_add = elapsed * self.config.requests_per_second
        self._tokens = min(self.config.burst_size, self._tokens + tokens_to_add)
        self._last_update = now

    def _check_minute_limit(self) -> bool:
        """Check if we're within the per-minute limit."""
        now = time.time()
        cutoff = now - 60.0

        # Remove old entries
        while self._request_times and self._request_times[0] < cutoff:
            self._request_times.popleft()

        return len(self._request_times) < self.config.requests_per_minute

    def _wait_for_capacity(self) -> float:
        """Calculate wait time needed for capacity."""
        wait_time = 0.0

        # Check if we're in backoff period
        if self._backoff_until:
            backoff_wait = self._backoff_until - time.time()
            if backoff_wait > 0:
                wait_time = max(wait_time, backoff_wait)
            else:
                # Backoff period ended
                self._backoff_until = None
                self._consecutive_429s = 0

        # Check token bucket
        with self._lock:
            self._refill_tokens()

            if self._tokens < 1.0:
                # Calculate wait time for next token
                tokens_needed = 1.0 - self._tokens
                token_wait = tokens_needed / self.config.requests_per_second
                wait_time = max(wait_time, token_wait)

            # Check minute limit
            if not self._check_minute_limit():
                # Wait until oldest request falls outside the window
                if self._request_times:
                    oldest = self._request_times[0]
                    minute_wait = 60.0 - (time.time() - oldest)
                    wait_time = max(wait_time, minute_wait)

        return wait_time

    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire permission to make a request.

        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)

        Returns:
            True if permission granted, False if timeout
        """
        start_time = time.time()

        while True:
            wait_time = self._wait_for_capacity()

            if wait_time <= 0:
                # We have capacity
                with self._lock:
                    self._refill_tokens()
                    self._tokens -= 1.0
                    self._request_times.append(time.time())
                    self.total_requests += 1
                return True

            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed + wait_time > timeout:
                    return False

            # Wait for capacity
            logger.debug(f"Rate limiter waiting {wait_time:.2f}s for capacity")
            self.total_wait_time += wait_time
            self.throttled_requests += 1
            time.sleep(wait_time)

    def handle_429(self) -> None:
        """Handle a 429 (Too Many Requests) response with exponential backoff."""
        with self._lock:
            self._consecutive_429s += 1

            # Calculate backoff time: base^attempts (capped at max)
            backoff_time = min(
                self.config.backoff_base ** self._consecutive_429s,
                self.config.backoff_max
            )

            self._backoff_until = time.time() + backoff_time

            logger.warning(
                f"Rate limit exceeded (429). Backing off for {backoff_time:.1f}s "
                f"(attempt {self._consecutive_429s})"
            )

    def reset_backoff(self) -> None:
        """Reset backoff counter after successful request."""
        with self._lock:
            if self._consecutive_429s > 0:
                logger.info(f"Resetting backoff after {self._consecutive_429s} 429 responses")
                self._consecutive_429s = 0
                self._backoff_until = None

    def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute a function with rate limiting and retry logic.

        Args:
            func: Function to execute
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func

        Returns:
            Result from func

        Raises:
            Exception: If all retry attempts fail
        """
        last_exception = None

        for attempt in range(1, self.config.retry_attempts + 1):
            # Acquire rate limit token
            if not self.acquire(timeout=300.0):  # 5 minute timeout
                raise RateLimitError("Rate limiter timeout waiting for capacity")

            try:
                result = func(*args, **kwargs)
                self.reset_backoff()
                return result

            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()

                # Check for rate limit errors
                if '429' in error_msg or 'rate limit' in error_msg or 'too many requests' in error_msg:
                    self.handle_429()
                    logger.warning(f"Attempt {attempt}/{self.config.retry_attempts} failed with rate limit")
                    continue

                # Check for other retryable errors
                if '503' in error_msg or '502' in error_msg or 'timeout' in error_msg:
                    wait_time = min(self.config.backoff_base ** attempt, 60.0)
                    logger.warning(f"Attempt {attempt}/{self.config.retry_attempts} failed: {e}. Retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue

                # Non-retryable error
                self.failed_requests += 1
                raise

        # All retries exhausted
        self.failed_requests += 1
        logger.error(f"All {self.config.retry_attempts} retry attempts exhausted")
        raise last_exception

    def get_metrics(self) -> dict:
        """Get rate limiter metrics."""
        with self._lock:
            current_rpm = len([t for t in self._request_times if time.time() - t < 60.0])

            return {
                'total_requests': self.total_requests,
                'throttled_requests': self.throttled_requests,
                'failed_requests': self.failed_requests,
                'total_wait_time': self.total_wait_time,
                'current_rpm': current_rpm,
                'current_tokens': self._tokens,
                'consecutive_429s': self._consecutive_429s,
                'in_backoff': self._backoff_until is not None,
                'backoff_remaining': max(0, self._backoff_until - time.time()) if self._backoff_until else 0
            }
