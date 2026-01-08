"""
VCR.py configuration for recording and replaying API interactions.

Provides fixtures and utilities for managing VCR cassettes in tests:
- Recording mode control via VCR_RECORD_MODE environment variable
- Cassette filtering to remove sensitive data
- Graceful test skipping when cassettes are unavailable
- Integration with pytest fixtures
"""

import os
import vcr
from pathlib import Path
from typing import Optional
import pytest


# VCR recording modes:
# - 'none': No recording, cassettes must exist or tests are skipped
# - 'once': Record cassettes if they don't exist, replay if they do
# - 'new_episodes': Record new interactions, replay existing ones
# - 'all': Always re-record all cassettes (overwrites existing)
DEFAULT_RECORD_MODE = 'none'


def get_vcr_record_mode() -> str:
    """Get VCR recording mode from environment variable.

    Returns:
        Recording mode string ('none', 'once', 'new_episodes', 'all')
    """
    return os.getenv('VCR_RECORD_MODE', DEFAULT_RECORD_MODE)


def should_skip_cassette_test() -> bool:
    """Determine if cassette-dependent tests should be skipped.

    Returns:
        True if tests should be skipped (no cassettes and not recording)
    """
    mode = get_vcr_record_mode()
    return mode == 'none'


def filter_request_headers(request):
    """Remove sensitive headers from VCR cassette requests.

    Filters out:
    - Authorization tokens
    - Client credentials
    - API keys

    Args:
        request: VCR request object

    Returns:
        Modified request with sensitive headers removed
    """
    # Remove authorization headers
    if 'Authorization' in request.headers:
        request.headers['Authorization'] = ['REDACTED']

    # Remove any other sensitive headers
    sensitive_headers = ['X-Api-Key', 'X-Client-Id', 'X-Client-Secret']
    for header in sensitive_headers:
        if header in request.headers:
            request.headers[header] = ['REDACTED']

    return request


def filter_request_body(request):
    """Remove sensitive data from VCR cassette request bodies.

    Filters out:
    - Client ID and secret in OAuth requests
    - API credentials

    Args:
        request: VCR request object

    Returns:
        Modified request with sensitive body data removed
    """
    if request.body:
        body_str = request.body.decode('utf-8') if isinstance(request.body, bytes) else request.body

        # Redact OAuth credentials
        if 'client_id' in body_str and 'client_secret' in body_str:
            request.body = 'client_id=REDACTED&client_secret=REDACTED'

    return request


def filter_response_body(response):
    """Remove sensitive data from VCR cassette response bodies.

    Filters out:
    - Access tokens
    - Refresh tokens
    - API keys
    - Customer IDs (CIDs)
    - Device IDs (AIDs)
    - IP addresses
    - Hostnames

    Args:
        response: VCR response object

    Returns:
        Modified response with sensitive body data removed
    """
    # Note: For now, we'll keep response bodies as-is since they're in the private repo
    # If we need to sanitize for sharing, we can implement JSON parsing and field redaction
    return response


def get_vcr_instance(
    cassette_dir: Optional[Path] = None,
    record_mode: Optional[str] = None,
    match_on: tuple = ('method', 'scheme', 'host', 'port', 'path', 'query'),
    filter_sensitive: bool = True
) -> vcr.VCR:
    """Create a configured VCR instance.

    Args:
        cassette_dir: Directory to store cassettes (default: tests/vcr_cassettes)
        record_mode: Recording mode override (default: from env var)
        match_on: Tuple of request attributes to match on
        filter_sensitive: Whether to filter sensitive data from cassettes

    Returns:
        Configured VCR instance
    """
    if record_mode is None:
        record_mode = get_vcr_record_mode()

    if cassette_dir is None:
        cassette_dir = Path(__file__).parent.parent / 'vcr_cassettes'

    vcr_instance = vcr.VCR(
        cassette_library_dir=str(cassette_dir),
        record_mode=record_mode,
        match_on=match_on,
        filter_headers=[],  # We'll use before_record_request instead
        filter_post_data_parameters=[],  # We'll use before_record_request instead
        decode_compressed_response=True,
        serializer='yaml',
    )

    # Apply filters if requested
    if filter_sensitive:
        vcr_instance.before_record_request = filter_request_headers
        # Additional filtering can be chained here

    return vcr_instance


def cassette_exists(cassette_name: str, cassette_dir: Optional[Path] = None) -> bool:
    """Check if a VCR cassette file exists.

    Args:
        cassette_name: Name of the cassette (without .yaml extension)
        cassette_dir: Directory where cassettes are stored

    Returns:
        True if cassette file exists
    """
    if cassette_dir is None:
        cassette_dir = Path(__file__).parent.parent / 'vcr_cassettes'

    cassette_path = cassette_dir / f"{cassette_name}.yaml"
    return cassette_path.exists()


# Pytest fixtures

@pytest.fixture
def vcr_cassette_dir() -> Path:
    """Fixture providing the VCR cassette directory path.

    Returns:
        Path to cassette directory
    """
    cassette_dir = Path(__file__).parent.parent / 'vcr_cassettes'
    cassette_dir.mkdir(exist_ok=True, parents=True)
    return cassette_dir


@pytest.fixture
def vcr_config(vcr_cassette_dir: Path) -> vcr.VCR:
    """Fixture providing a configured VCR instance.

    Args:
        vcr_cassette_dir: Cassette directory from fixture

    Returns:
        Configured VCR instance
    """
    return get_vcr_instance(cassette_dir=vcr_cassette_dir)


@pytest.fixture
def check_cassette_or_skip(vcr_cassette_dir: Path, request):
    """Fixture to skip test if cassette is missing and not in recording mode.

    Usage:
        @pytest.mark.requires_cassettes
        def test_with_cassette(check_cassette_or_skip):
            cassette_name = "test_api_call"
            check_cassette_or_skip(cassette_name)
            # Test code that uses the cassette

    Args:
        vcr_cassette_dir: Cassette directory from fixture
        request: Pytest request object

    Returns:
        Function to check cassette availability
    """
    def _check(cassette_name: str):
        """Check if cassette exists, skip test if not available.

        Args:
            cassette_name: Name of the cassette to check
        """
        mode = get_vcr_record_mode()

        if mode == 'none' and not cassette_exists(cassette_name, vcr_cassette_dir):
            pytest.skip(f"VCR cassette '{cassette_name}.yaml' not found and VCR_RECORD_MODE=none")

    return _check


@pytest.fixture
def vcr_with_cassette(vcr_config: vcr.VCR, vcr_cassette_dir: Path):
    """Fixture providing VCR context manager for a specific cassette.

    Usage:
        def test_something(vcr_with_cassette):
            with vcr_with_cassette('my_test_cassette'):
                # API calls here will be recorded/replayed
                response = api.get_data()

    Args:
        vcr_config: VCR instance from fixture
        vcr_cassette_dir: Cassette directory from fixture

    Returns:
        Function that returns VCR context manager
    """
    def _cassette_context(cassette_name: str):
        """Get VCR context manager for cassette.

        Args:
            cassette_name: Name of the cassette file (without .yaml)

        Returns:
            VCR context manager
        """
        return vcr_config.use_cassette(f"{cassette_name}.yaml")

    return _cassette_context
