"""
Tests for configuration loading and validation.

Tests various config scenarios: minimal, maximal, invalid configs,
malformed YAML, missing required fields, and default value handling.
"""
import pytest
import os
from pathlib import Path
import yaml
from falcon_policy_scoring.utils.config import read_config_from_yaml, _load_config_defaults


# Get test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "configs"


class TestConfigLoading:
    """Test basic config file loading."""

    def test_load_minimal_config(self):
        """Test loading minimal valid configuration."""
        config_path = FIXTURES_DIR / "minimal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        # Check required fields
        assert config['db']['type'] == 'sqlite'
        assert config['sqlite']['path'] == './test_data/minimal.sqlite'

        # Check defaults were applied
        assert 'host_fetching' in config
        assert config['host_fetching']['batch_size'] == 100  # Default
        assert config['host_fetching']['progress_threshold'] == 500  # Default

    def test_load_maximal_config(self):
        """Test loading configuration with all options specified."""
        config_path = FIXTURES_DIR / "maximal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        # Check db settings
        assert config['db']['type'] == 'sqlite'
        assert config['sqlite']['path'] == './test_data/maximal.sqlite'

        # Check TTL settings
        assert config['ttl']['default'] == 1200
        assert config['ttl']['hosts'] == 450
        assert config['ttl']['policies']['prevention_policy'] == 900

        # Check falcon credentials
        assert config['falcon_credentials']['client_id'] == 'test_client_id_maximal'
        assert config['falcon_credentials']['base_url'] == 'US1'
        assert config['falcon_credentials']['prefix'] == 'FALCON_'
        assert config['falcon_credentials']['metadata']['include_client_source'] is True

        # Check host fetching
        assert config['host_fetching']['batch_size'] == 50
        assert config['host_fetching']['progress_threshold'] == 250
        assert config['host_fetching']['include_zta'] is True

        # Check logging
        assert config['logging']['level'] == 'DEBUG'
        assert config['logging']['file'] == 'logs/maximal_app.log'

        # Check daemon settings
        assert config['daemon']['check_interval'] == 30
        assert 'prevention' in config['daemon']['policy_types']
        assert config['daemon']['rate_limit']['requests_per_second'] == 15.0
        assert config['daemon']['output']['compress'] is True
        assert config['daemon']['health_check']['port'] == 9090

    def test_load_tinydb_config(self):
        """Test loading configuration with TinyDB adapter."""
        config_path = FIXTURES_DIR / "tinydb_config.yaml"
        config = read_config_from_yaml(str(config_path))

        assert config['db']['type'] == 'tiny_db'
        assert config['tiny_db']['path'] == './test_data/tinydb_test.json'
        assert config['host_fetching']['batch_size'] == 75
        assert config['logging']['level'] == 'WARNING'

    def test_load_custom_ttl_config(self):
        """Test loading configuration with custom TTL values."""
        config_path = FIXTURES_DIR / "custom_ttl_config.yaml"
        config = read_config_from_yaml(str(config_path))

        assert config['ttl']['default'] == 1800
        assert config['ttl']['hosts'] == 900
        assert config['ttl']['policies']['prevention_policy'] == 3600
        assert config['ttl']['policies']['firewall_policy'] == 3600
        assert config['host_fetching']['batch_size'] == 200
        assert config['host_fetching']['progress_threshold'] == 1000

    def test_load_empty_config(self):
        """Test loading empty config applies all defaults."""
        config_path = FIXTURES_DIR / "empty_config.yaml"
        config = read_config_from_yaml(str(config_path))

        # All defaults should be applied
        assert config['db']['type'] == 'sqlite'  # Default
        assert config['sqlite']['path'] == 'data/db.sqlite'  # Default
        assert config['host_fetching']['batch_size'] == 100  # Default
        assert config['host_fetching']['progress_threshold'] == 500  # Default
        assert config['logging']['level'] == 'INFO'  # Default
        assert config['ttl']['default'] == 600  # Default
        assert config['ttl']['hosts'] == 300  # Default

    def test_load_nonexistent_file(self):
        """Test loading non-existent config file returns defaults."""
        config_path = FIXTURES_DIR / "nonexistent_config.yaml"
        config = read_config_from_yaml(str(config_path))

        # Should return all defaults without error
        assert config['db']['type'] == 'sqlite'
        assert config['host_fetching']['batch_size'] == 100


class TestConfigDefaults:
    """Test default value application."""

    def test_defaults_applied_to_empty_dict(self):
        """Test that defaults are applied to empty config."""
        config = {}
        config = _load_config_defaults(config)

        # Database defaults
        assert config['db']['type'] == 'sqlite'
        assert config['sqlite']['path'] == 'data/db.sqlite'
        assert config['tiny_db']['path'] == 'data/db.json'

        # Host fetching defaults
        assert config['host_fetching']['batch_size'] == 100
        assert config['host_fetching']['progress_threshold'] == 500

        # Logging defaults
        assert config['logging']['file'] == 'logs/app.log'
        assert config['logging']['api'] == 'logs/api.log'
        assert config['logging']['level'] == 'INFO'

        # TTL defaults
        assert config['ttl']['default'] == 600
        assert config['ttl']['hosts'] == 300
        assert config['ttl']['host_records'] == 600
        assert config['ttl']['policies']['prevention_policy'] == 600

    def test_defaults_preserve_existing_values(self):
        """Test that existing values are not overwritten by defaults."""
        config = {
            'db': {'type': 'tiny_db'},
            'host_fetching': {'batch_size': 50},
            'logging': {'level': 'DEBUG'}
        }
        config = _load_config_defaults(config)

        # Existing values should be preserved
        assert config['db']['type'] == 'tiny_db'
        assert config['host_fetching']['batch_size'] == 50
        assert config['logging']['level'] == 'DEBUG'

        # But missing values should get defaults
        assert config['host_fetching']['progress_threshold'] == 500
        assert config['logging']['file'] == 'logs/app.log'

    def test_defaults_with_partial_config(self):
        """Test defaults applied to partially specified config."""
        config = {
            'db': {'type': 'sqlite'},
            'ttl': {
                'hosts': 450  # Only hosts specified
            }
        }
        config = _load_config_defaults(config)

        # Specified value preserved
        assert config['ttl']['hosts'] == 450

        # Other TTL defaults applied
        assert config['ttl']['default'] == 600
        assert config['ttl']['host_records'] == 600
        assert 'prevention_policy' in config['ttl']['policies']

    def test_defaults_handle_none_config(self):
        """Test that None config is converted to defaults."""
        config = None
        config = _load_config_defaults(config)

        assert isinstance(config, dict)
        assert config['db']['type'] == 'sqlite'
        assert config['host_fetching']['batch_size'] == 100


class TestConfigStructure:
    """Test configuration structure validation."""

    def test_minimal_config_has_required_keys(self):
        """Test that minimal config has all required top-level keys after defaults."""
        config_path = FIXTURES_DIR / "minimal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        # Required top-level keys
        required_keys = ['db', 'sqlite', 'tiny_db', 'falcon_credentials',
                         'host_fetching', 'logging', 'ttl']
        for key in required_keys:
            assert key in config, f"Missing required key: {key}"

    def test_db_config_structure(self):
        """Test database configuration structure."""
        config_path = FIXTURES_DIR / "minimal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        assert 'type' in config['db']
        assert config['db']['type'] in ['sqlite', 'tiny_db']

        if config['db']['type'] == 'sqlite':
            assert 'path' in config['sqlite']
        elif config['db']['type'] == 'tiny_db':
            assert 'path' in config['tiny_db']

    def test_host_fetching_structure(self):
        """Test host fetching configuration structure."""
        config_path = FIXTURES_DIR / "maximal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        hf = config['host_fetching']
        assert 'batch_size' in hf
        assert 'progress_threshold' in hf
        assert isinstance(hf['batch_size'], int)
        assert isinstance(hf['progress_threshold'], int)

    def test_logging_structure(self):
        """Test logging configuration structure."""
        config_path = FIXTURES_DIR / "maximal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        log = config['logging']
        assert 'file' in log
        assert 'api' in log
        assert 'level' in log
        assert isinstance(log['level'], str)

    def test_ttl_structure(self):
        """Test TTL configuration structure."""
        config_path = FIXTURES_DIR / "maximal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        ttl = config['ttl']
        assert 'default' in ttl
        assert 'hosts' in ttl
        assert 'host_records' in ttl
        assert 'policies' in ttl
        assert isinstance(ttl['policies'], dict)

    def test_daemon_structure(self):
        """Test daemon configuration structure."""
        config_path = FIXTURES_DIR / "maximal_config.yaml"
        config = read_config_from_yaml(str(config_path))

        daemon = config['daemon']
        assert 'schedules' in daemon
        assert 'check_interval' in daemon
        assert 'policy_types' in daemon
        assert 'rate_limit' in daemon
        assert 'output' in daemon
        assert 'health_check' in daemon

        # Check nested structures
        assert 'fetch_and_grade' in daemon['schedules']
        assert 'requests_per_second' in daemon['rate_limit']
        assert 'compress' in daemon['output']
        assert 'enabled' in daemon['health_check']


class TestInvalidConfigs:
    """Test handling of invalid configurations."""

    def test_malformed_yaml(self):
        """Test handling of malformed YAML syntax."""
        config_path = FIXTURES_DIR / "malformed_yaml.yaml"

        # Should handle gracefully and return defaults
        config = read_config_from_yaml(str(config_path))

        # When YAML parsing fails, defaults are applied
        assert config['db']['type'] == 'sqlite'  # Default
        assert config['host_fetching']['batch_size'] == 100  # Default

    def test_missing_db_section_gets_defaults(self):
        """Test that missing db section gets default values."""
        config_path = FIXTURES_DIR / "invalid_missing_db.yaml"
        config = read_config_from_yaml(str(config_path))

        # Defaults should be applied
        assert 'db' in config
        assert config['db']['type'] == 'sqlite'  # Default

    def test_invalid_db_type_preserved(self):
        """Test that invalid db type is preserved (validation at runtime)."""
        config_path = FIXTURES_DIR / "invalid_db_type.yaml"
        config = read_config_from_yaml(str(config_path))

        # Invalid value is preserved (validation happens at adapter creation)
        assert config['db']['type'] == 'invalid_db_type'


class TestConfigBatchSizeValidation:
    """Test batch size value validation (logical tests)."""

    def test_negative_batch_size_loaded(self):
        """Test that negative batch size is loaded (validated at runtime)."""
        config_path = FIXTURES_DIR / "invalid_negative_batch.yaml"
        config = read_config_from_yaml(str(config_path))

        # Negative value is loaded as-is
        assert config['host_fetching']['batch_size'] == -10

    def test_batch_size_too_large_loaded(self):
        """Test that oversized batch size is loaded (validated at runtime)."""
        config_path = FIXTURES_DIR / "invalid_batch_too_large.yaml"
        config = read_config_from_yaml(str(config_path))

        # Oversized value is loaded as-is
        assert config['host_fetching']['batch_size'] == 150

    def test_valid_batch_size_range(self):
        """Test valid batch size values."""
        for batch_size in [1, 10, 50, 100]:
            config = {'host_fetching': {'batch_size': batch_size}}
            config = _load_config_defaults(config)
            assert config['host_fetching']['batch_size'] == batch_size


class TestConfigLogLevelValidation:
    """Test log level validation (logical tests)."""

    def test_invalid_log_level_loaded(self):
        """Test that invalid log level is loaded (validated at runtime)."""
        config_path = FIXTURES_DIR / "invalid_log_level.yaml"
        config = read_config_from_yaml(str(config_path))

        # Invalid value is loaded as-is
        assert config['logging']['level'] == 'INVALID_LEVEL'

    def test_valid_log_levels(self):
        """Test that valid log levels are accepted."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

        for level in valid_levels:
            config = {'logging': {'level': level}}
            config = _load_config_defaults(config)
            assert config['logging']['level'] == level


class TestConfigTTLValues:
    """Test TTL configuration values."""

    def test_ttl_all_policies_have_defaults(self):
        """Test that all policy types have default TTL values."""
        config = _load_config_defaults({})

        expected_policies = [
            'prevention_policy',
            'devicecontrol_policy',
            'firewall_policy',
            'sensor_update_policy',
            'content_policy',
            'rtr_policy'
        ]

        for policy in expected_policies:
            assert policy in config['ttl']['policies']
            assert isinstance(config['ttl']['policies'][policy], int)
            assert config['ttl']['policies'][policy] > 0

    def test_ttl_custom_policy_values_preserved(self):
        """Test that custom TTL values for policies are preserved."""
        config = {
            'ttl': {
                'policies': {
                    'prevention_policy': 9999,
                    'firewall_policy': 8888
                }
            }
        }
        config = _load_config_defaults(config)

        assert config['ttl']['policies']['prevention_policy'] == 9999
        assert config['ttl']['policies']['firewall_policy'] == 8888
        # Others should have defaults
        assert config['ttl']['policies']['sensor_update_policy'] == 600

    def test_ttl_policies_list_converted_to_dict(self):
        """Test that policies as list is converted to dict."""
        config = {
            'ttl': {
                'policies': [
                    {'prevention_policy': 1200},
                    {'firewall_policy': 1800}
                ]
            }
        }
        config = _load_config_defaults(config)

        # Should be converted to dict
        assert isinstance(config['ttl']['policies'], dict)
        assert config['ttl']['policies']['prevention_policy'] == 1200
        assert config['ttl']['policies']['firewall_policy'] == 1800


class TestConfigCredentials:
    """Test credential configuration handling."""

    def test_credentials_defaults_empty_strings(self):
        """Test that credential defaults are empty strings."""
        config = _load_config_defaults({})

        fc = config['falcon_credentials']
        assert fc['client_id'] == ''
        assert fc['client_secret'] == ''
        assert fc['base_url'] == ''

    def test_credentials_values_preserved(self):
        """Test that provided credential values are preserved."""
        config = {
            'falcon_credentials': {
                'client_id': 'test_id',
                'client_secret': 'test_secret',
                'base_url': 'US2'
            }
        }
        config = _load_config_defaults(config)

        assert config['falcon_credentials']['client_id'] == 'test_id'
        assert config['falcon_credentials']['client_secret'] == 'test_secret'
        assert config['falcon_credentials']['base_url'] == 'US2'


class TestConfigFilePaths:
    """Test configuration file path handling."""

    def test_config_paths_relative(self):
        """Test that relative paths are preserved."""
        config = {
            'sqlite': {'path': './data/test.db'},
            'tiny_db': {'path': './data/test.json'},
            'logging': {'file': 'logs/test.log'}
        }
        config = _load_config_defaults(config)

        assert config['sqlite']['path'] == './data/test.db'
        assert config['tiny_db']['path'] == './data/test.json'
        assert config['logging']['file'] == 'logs/test.log'

    def test_config_paths_absolute(self):
        """Test that absolute paths are preserved."""
        config = {
            'sqlite': {'path': '/tmp/test.db'},
            'logging': {'file': '/var/log/test.log'}
        }
        config = _load_config_defaults(config)

        assert config['sqlite']['path'] == '/tmp/test.db'
        assert config['logging']['file'] == '/var/log/test.log'


class TestConfigEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_config_with_extra_fields(self):
        """Test that extra/unknown fields are preserved."""
        config = {
            'db': {'type': 'sqlite'},
            'custom_field': 'custom_value',
            'nested': {
                'custom': 'value'
            }
        }
        config = _load_config_defaults(config)

        # Custom fields should be preserved
        assert config['custom_field'] == 'custom_value'
        assert config['nested']['custom'] == 'value'

        # Defaults should still be applied
        assert config['host_fetching']['batch_size'] == 100

    def test_config_zero_values(self):
        """Test that zero values are accepted."""
        config = {
            'ttl': {
                'default': 0,
                'hosts': 0
            },
            'host_fetching': {
                'progress_threshold': 0
            }
        }
        config = _load_config_defaults(config)

        # Zero values should be preserved
        assert config['ttl']['default'] == 0
        assert config['ttl']['hosts'] == 0
        assert config['host_fetching']['progress_threshold'] == 0

    def test_config_very_large_values(self):
        """Test that very large values are accepted."""
        config = {
            'ttl': {
                'default': 999999
            },
            'host_fetching': {
                'progress_threshold': 1000000
            }
        }
        config = _load_config_defaults(config)

        assert config['ttl']['default'] == 999999
        assert config['host_fetching']['progress_threshold'] == 1000000

    def test_config_string_numbers_preserved(self):
        """Test that string values in number fields are preserved."""
        # YAML should parse these as strings
        with open(FIXTURES_DIR / "temp_test.yaml", 'w') as f:
            f.write('host_fetching:\n  batch_size: "100"\n')

        config = read_config_from_yaml(str(FIXTURES_DIR / "temp_test.yaml"))

        # String "100" should be preserved (validation at usage time)
        assert config['host_fetching']['batch_size'] == "100"

        # Clean up
        os.remove(FIXTURES_DIR / "temp_test.yaml")
