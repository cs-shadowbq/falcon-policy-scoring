"""Custom exceptions for falcon_policy_scoring.

Business logic exceptions shared between CLI and daemon modules.
These exceptions provide semantic error handling for common failure scenarios.
"""


class PolicyScoringError(Exception):
    """Base exception for all falcon_policy_scoring errors.

    All custom exceptions in the project should inherit from this base class.
    """
    pass


class ConfigurationError(PolicyScoringError):
    """Configuration file or settings error.

    Raised when:
    - Configuration file is missing or invalid
    - Required configuration parameters are missing
    - Configuration values are out of acceptable range
    - YAML parsing fails
    """
    pass


class ApiConnectionError(PolicyScoringError):
    """Error connecting to CrowdStrike API.

    Raised when:
    - Cannot establish connection to Falcon API
    - Authentication fails (invalid credentials)
    - Network timeout occurs
    - API endpoint is unreachable
    """
    pass


class ApiError(PolicyScoringError):
    """Error from CrowdStrike API response.

    Raised when:
    - API returns error status code
    - API response is malformed
    - Rate limit exceeded
    - Invalid API request parameters
    """
    pass


class DatabaseError(PolicyScoringError):
    """Database operation error.

    Raised when:
    - Cannot connect to database
    - Database file is corrupted
    - Database query fails
    - Transaction fails
    - Database is locked
    """
    pass


class DataNotFoundError(PolicyScoringError):
    """Requested data not found.

    Raised when:
    - Host not found in database
    - Policy not found in database
    - Cache is empty
    - Required data is missing from API response
    """
    pass


class GradingError(PolicyScoringError):
    """Error during policy grading operation.

    Raised when:
    - Grading rules file is missing or invalid
    - Grading logic encounters unexpected data format
    - Cannot calculate policy score
    - Grading criteria cannot be evaluated
    """
    pass


class ReportGenerationError(PolicyScoringError):
    """Error generating output reports.

    Raised when:
    - Cannot write report file
    - Report data is incomplete
    - JSON serialization fails
    - Output directory is not writable
    """
    pass


class SchedulerError(PolicyScoringError):
    """Error in task scheduling.

    Raised when:
    - Invalid cron expression
    - Cannot calculate next run time
    - Task execution fails
    - Scheduler state is inconsistent
    """
    pass


class RateLimitError(PolicyScoringError):
    """Rate limit exceeded.

    Raised when:
    - API rate limit exceeded
    - Rate limiter timeout
    - Cannot acquire rate limiter capacity
    """
    pass


class ValidationError(PolicyScoringError):
    """Data validation error.

    Raised when:
    - Input data fails validation
    - Data format is incorrect
    - Required fields are missing
    - Data type mismatch
    """
    pass


# Backwards compatibility aliases (to be deprecated)
CliError = PolicyScoringError  # Deprecated: Use PolicyScoringError instead


__all__ = [
    'PolicyScoringError',
    'ConfigurationError',
    'ApiConnectionError',
    'ApiError',
    'DatabaseError',
    'DataNotFoundError',
    'GradingError',
    'ReportGenerationError',
    'SchedulerError',
    'RateLimitError',
    'ValidationError',
    # Deprecated
    'CliError',
]
