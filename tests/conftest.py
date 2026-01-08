"""
Shared pytest fixtures and configuration for all tests.

This module provides fixtures for:
- Temporary configuration files
- Database instances (SQLite and TinyDB)
- Mock FalconPy APIHarnessV2 responses
- VCR cassette management
- Time-travel utilities (freezegun)
- Temporary directories and cleanup
"""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Generator
import pytest
import yaml


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory that is cleaned up after the test."""
    temp_path = Path(tempfile.mkdtemp(prefix="falcon_test_"))
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_config_dir(temp_dir: Path) -> Path:
    """Create a temporary config directory."""
    config_dir = temp_dir / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


@pytest.fixture
def temp_data_dir(temp_dir: Path) -> Path:
    """Create a temporary data directory for databases."""
    data_dir = temp_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


@pytest.fixture
def temp_output_dir(temp_dir: Path) -> Path:
    """Create a temporary output directory for results."""
    output_dir = temp_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


@pytest.fixture
def minimal_config_data() -> Dict[str, Any]:
    """Minimal configuration data for testing.

    Uses short TTLs and basic settings without complex features.
    """
    return {
        "db": {
            "type": "sqlite"
        },
        "sqlite": {
            "path": "./data/test_db.sqlite"
        },
        "tiny_db": {
            "path": "./data/test_db.json"
        },
        "ttl": {
            "default": 60,
            "hosts": 30,
            "host_records": 60,
            "policies": {
                "prevention_policy": 60,
                "firewall_policy": 60,
                "sensor_update_policy": 60,
                "device_control_policy": 60,
                "content_update_policy": 60,
                "it_automation_policy": 60
            }
        },
        "falcon_credentials": {
            "prefix": "FALCON_",
            "metadata": {
                "include_client_source": False,
                "include_client_hash": False,
                "include_client_id": False
            }
        },
        "host_fetching": {
            "batch_size": 100,
            "progress_threshold": 500,
            "include_zta": False
        }
    }


@pytest.fixture
def balanced_config_data() -> Dict[str, Any]:
    """Balanced configuration data with moderate settings.

    Default production-like configuration for general testing.
    """
    return {
        "db": {
            "type": "sqlite"
        },
        "sqlite": {
            "path": "./data/test_db.sqlite"
        },
        "tiny_db": {
            "path": "./data/test_db.json"
        },
        "ttl": {
            "default": 600,
            "hosts": 300,
            "host_records": 600,
            "policies": {
                "prevention_policy": 600,
                "firewall_policy": 600,
                "firewall_policy_containers": 3600,
                "sensor_update_policy": 600,
                "device_control_policy": 600,
                "content_update_policy": 600,
                "it_automation_policy": 600
            }
        },
        "falcon_credentials": {
            "prefix": "FALCON_",
            "metadata": {
                "include_client_source": False,
                "include_client_hash": False,
                "include_client_id": False
            }
        },
        "host_fetching": {
            "batch_size": 100,
            "progress_threshold": 500,
            "include_zta": False
        }
    }


@pytest.fixture
def maximal_config_data() -> Dict[str, Any]:
    """Maximal configuration data with all features enabled.

    Long TTLs, ZTA, host groups, containers - for comprehensive testing.
    """
    return {
        "db": {
            "type": "sqlite"
        },
        "sqlite": {
            "path": "./data/test_db.sqlite"
        },
        "tiny_db": {
            "path": "./data/test_db.json"
        },
        "ttl": {
            "default": 3600,
            "hosts": 1800,
            "host_records": 3600,
            "policies": {
                "prevention_policy": 3600,
                "firewall_policy": 3600,
                "firewall_policy_containers": 7200,
                "sensor_update_policy": 3600,
                "device_control_policy": 3600,
                "content_update_policy": 3600,
                "it_automation_policy": 3600
            }
        },
        "falcon_credentials": {
            "prefix": "FALCON_",
            "metadata": {
                "include_client_source": True,
                "include_client_hash": True,
                "include_client_id": True
            }
        },
        "host_fetching": {
            "batch_size": 200,
            "progress_threshold": 1000,
            "include_zta": True,
            "product_types": ["Workstation", "Server"],
            "host_groups": ["Production", "Development"]
        }
    }


@pytest.fixture
def daemon_config_data() -> Dict[str, Any]:
    """Daemon-focused configuration for testing daemon functionality.

    Includes aggressive schedules, rate limiting, health checks.
    """
    return {
        "db": {
            "type": "sqlite"
        },
        "sqlite": {
            "path": "./data/test_db.sqlite"
        },
        "tiny_db": {
            "path": "./data/test_db.json"
        },
        "ttl": {
            "default": 600,
            "hosts": 300,
            "host_records": 600,
            "policies": {
                "prevention_policy": 600,
                "firewall_policy": 600,
                "sensor_update_policy": 600,
                "device_control_policy": 600,
                "content_update_policy": 600,
                "it_automation_policy": 600
            }
        },
        "falcon_credentials": {
            "prefix": "FALCON_",
            "metadata": {
                "include_client_source": False,
                "include_client_hash": False,
                "include_client_id": False
            }
        },
        "host_fetching": {
            "batch_size": 100,
            "progress_threshold": 500,
            "include_zta": False
        },
        "daemon": {
            "schedules": {
                "fetch_and_grade": "*/15 * * * *",
                "cleanup": "0 2 * * *",
                "metrics": "*/5 * * * *"
            },
            "check_interval": 60,
            "policy_types": [
                "prevention",
                "sensor-update",
                "firewall",
                "device-control",
                "content-update",
                "it-automation"
            ],
            "product_types": [],
            "rate_limit": {
                "requests_per_second": 10.0,
                "requests_per_minute": 500,
                "burst_size": 20,
                "retry_attempts": 5
            },
            "output": {
                "compress": False,
                "max_age_days": 30,
                "max_files_per_type": 100
            },
            "health_check": {
                "enabled": True,
                "port": 8088
            }
        }
    }


def write_config_file(config_dir: Path, config_data: Dict[str, Any], filename: str = "config.yaml") -> Path:
    """Helper function to write configuration data to a YAML file.

    Args:
        config_dir: Directory to write the config file
        config_data: Configuration dictionary
        filename: Name of the config file (default: config.yaml)

    Returns:
        Path to the written config file
    """
    config_path = config_dir / filename
    with open(config_path, 'w') as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
    return config_path


@pytest.fixture
def minimal_config_file(temp_config_dir: Path, minimal_config_data: Dict[str, Any]) -> Path:
    """Create a minimal config file in a temporary directory."""
    return write_config_file(temp_config_dir, minimal_config_data)


@pytest.fixture
def balanced_config_file(temp_config_dir: Path, balanced_config_data: Dict[str, Any]) -> Path:
    """Create a balanced config file in a temporary directory."""
    return write_config_file(temp_config_dir, balanced_config_data)


@pytest.fixture
def maximal_config_file(temp_config_dir: Path, maximal_config_data: Dict[str, Any]) -> Path:
    """Create a maximal config file in a temporary directory."""
    return write_config_file(temp_config_dir, maximal_config_data)


@pytest.fixture
def daemon_config_file(temp_config_dir: Path, daemon_config_data: Dict[str, Any]) -> Path:
    """Create a daemon config file in a temporary directory."""
    return write_config_file(temp_config_dir, daemon_config_data)


@pytest.fixture
def sqlite_db_path(temp_data_dir: Path) -> Path:
    """Return path for SQLite database file."""
    return temp_data_dir / "test_db.sqlite"


@pytest.fixture
def tinydb_path(temp_data_dir: Path) -> Path:
    """Return path for TinyDB JSON file."""
    return temp_data_dir / "test_db.json"


@pytest.fixture
def mock_env_credentials(monkeypatch) -> Dict[str, str]:
    """Set up mock environment variables for Falcon API credentials.

    Returns:
        Dictionary of credential values set
    """
    credentials = {
        "FALCON_CLIENT_ID": "test_client_id_12345",
        "FALCON_CLIENT_SECRET": "test_client_secret_67890",
        "FALCON_BASE_URL": "https://api.test.crowdstrike.com"
    }

    for key, value in credentials.items():
        monkeypatch.setenv(key, value)

    return credentials


@pytest.fixture(scope="session")
def vcr_cassette_dir() -> Path:
    """Return the directory where VCR cassettes are stored (E2E tests).

    Session-scoped to match pytest-vcr's requirements.
    """
    cassette_dir = Path(__file__).parent / "fixtures" / "vcr_cassettes_e2e"
    cassette_dir.mkdir(exist_ok=True, parents=True)
    return cassette_dir


@pytest.fixture(scope="module")
def vcr_config():
    """Configure VCR for E2E tests.

    This configures pytest-vcr plugin globally for E2E tests.
    Cassettes are stored in tests/fixtures/vcr_cassettes_e2e/
    """
    return {
        "cassette_library_dir": str(Path(__file__).parent / "fixtures" / "vcr_cassettes_e2e"),
        "record_mode": "once",  # Record if cassette doesn't exist, else replay
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
        "filter_headers": [
            ("authorization", "REDACTED"),
            ("Authorization", "REDACTED"),
        ],
        "filter_post_data_parameters": [
            ("client_id", "REDACTED"),
            ("client_secret", "REDACTED"),
        ],
        "decode_compressed_response": True,
    }


def get_cassette_metadata_path(cassette_name: str, cassette_dir: Path) -> Path:
    """Get the path to the metadata file for a cassette.

    Args:
        cassette_name: Name of the test (e.g., 'TestHostsAPIE2E.test_fetch_workstation_device_ids')
        cassette_dir: Directory containing cassettes

    Returns:
        Path to metadata YAML file (e.g., 'TestHostsAPIE2E.test_fetch_workstation_device_ids.meta.yaml')
    """
    return cassette_dir / f"{cassette_name}.meta.yaml"


def save_cassette_metadata(cassette_name: str, cassette_dir: Path, metadata: Dict[str, Any]):
    """Save metadata about a VCR cassette recording.

    Stores environment context (CID, BASE_URL, timestamp) alongside the cassette
    for accurate replay configuration.

    Args:
        cassette_name: Name of the test
        cassette_dir: Directory containing cassettes
        metadata: Dictionary with 'cid', 'base_url', 'recorded_at', etc.
    """
    from datetime import datetime

    meta_path = get_cassette_metadata_path(cassette_name, cassette_dir)

    # Add timestamp if not present
    if 'recorded_at' not in metadata:
        metadata['recorded_at'] = datetime.utcnow().isoformat() + 'Z'

    with open(meta_path, 'w') as f:
        yaml.dump(metadata, f, default_flow_style=False, sort_keys=False)


def load_cassette_metadata(cassette_name: str, cassette_dir: Path) -> Dict[str, Any]:
    """Load metadata about a VCR cassette.

    Args:
        cassette_name: Name of the test
        cassette_dir: Directory containing cassettes

    Returns:
        Metadata dictionary with 'cid', 'base_url', 'recorded_at', etc.
        Returns empty dict if metadata file doesn't exist.
    """
    meta_path = get_cassette_metadata_path(cassette_name, cassette_dir)

    if not meta_path.exists():
        return {}

    with open(meta_path, 'r') as f:
        return yaml.safe_load(f) or {}


@pytest.fixture
def skip_if_no_cassette():
    """Skip test if VCR cassette is not available and not in recording mode.

    This fixture integrates with vcr_config.py to provide consistent
    cassette availability checking across all tests.

    Usage:
        @pytest.mark.requires_cassettes
        def test_something(skip_if_no_cassette, vcr_cassette_dir):
            cassette_path = vcr_cassette_dir / "test_cassette.yaml"
            if not cassette_path.exists():
                skip_if_no_cassette("test_cassette")
            # Test code that needs cassettes
    """
    from tests.fixtures.vcr_config import get_vcr_record_mode

    def _skip(cassette_name: str):
        """Skip test if cassette unavailable.

        Args:
            cassette_name: Name of the cassette required
        """
        recording_mode = get_vcr_record_mode()
        if recording_mode == "none":
            pytest.skip(f"VCR cassette '{cassette_name}' required but VCR_RECORD_MODE=none")

    return _skip
