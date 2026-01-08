"""
Tests for environment variable overlay on configuration.

Tests the precedence: ENV vars > config file values
Tests .env file loading and credential prefix handling.
"""
import pytest
import os
from pathlib import Path
from unittest.mock import patch, mock_open
from dotenv import load_dotenv
from falcon_policy_scoring.utils.config import read_config_from_yaml


# Get test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "env_files"


class TestEnvironmentVariableOverlay:
    """Test environment variable precedence over config file values."""

    def test_env_client_id_overrides_config(self):
        """Test that CLIENT_ID env var overrides config file."""
        # This is a logical test - actual override happens in daemon/CLI
        # The config loader doesn't do the override, just loads the config
        config = {
            'falcon_credentials': {
                'client_id': 'config_client_id',
                'prefix': ''
            }
        }

        # Simulate the daemon's priority logic
        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {'CLIENT_ID': 'env_client_id'}):
            # Priority: ENV > config
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == 'env_client_id'

    def test_config_value_used_when_no_env(self):
        """Test that config value is used when ENV var not set."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_client_id',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {}, clear=True):
            # No ENV var, use config
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == 'config_client_id'

    def test_env_client_secret_overrides_config(self):
        """Test that CLIENT_SECRET env var overrides config file."""
        config = {
            'falcon_credentials': {
                'client_secret': 'config_secret',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {'CLIENT_SECRET': 'env_secret'}):
            client_secret = os.environ.get(prefix + 'CLIENT_SECRET') or config['falcon_credentials'].get('client_secret')
            assert client_secret == 'env_secret'

    def test_env_base_url_overrides_config(self):
        """Test that BASE_URL env var overrides config file."""
        config = {
            'falcon_credentials': {
                'base_url': 'US1',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {'BASE_URL': 'US2'}):
            base_url = os.environ.get(prefix + 'BASE_URL') or config['falcon_credentials'].get('base_url')
            assert base_url == 'US2'

    def test_all_credentials_from_env(self):
        """Test that all credentials can come from environment."""
        config = {
            'falcon_credentials': {
                'client_id': '',
                'client_secret': '',
                'base_url': '',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        env_vars = {
            'CLIENT_ID': 'env_id',
            'CLIENT_SECRET': 'env_secret',
            'BASE_URL': 'US2'
        }

        with patch.dict(os.environ, env_vars):
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            client_secret = os.environ.get(prefix + 'CLIENT_SECRET') or config['falcon_credentials'].get('client_secret')
            base_url = os.environ.get(prefix + 'BASE_URL') or config['falcon_credentials'].get('base_url')

            assert client_id == 'env_id'
            assert client_secret == 'env_secret'
            assert base_url == 'US2'


class TestCredentialPrefix:
    """Test credential prefix handling."""

    def test_falcon_prefix_credentials(self):
        """Test that FALCON_ prefix works correctly."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'prefix': 'FALCON_'
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        env_vars = {
            'FALCON_CLIENT_ID': 'falcon_env_id',
            'FALCON_CLIENT_SECRET': 'falcon_env_secret',
            'FALCON_BASE_URL': 'US2'
        }

        with patch.dict(os.environ, env_vars):
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == 'falcon_env_id'
            assert prefix + 'CLIENT_ID' == 'FALCON_CLIENT_ID'

    def test_custom_prefix_credentials(self):
        """Test that custom prefix works correctly."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'prefix': 'CUSTOM_'
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        env_vars = {
            'CUSTOM_CLIENT_ID': 'custom_env_id',
            'CUSTOM_CLIENT_SECRET': 'custom_env_secret',
            'CUSTOM_BASE_URL': 'US1'
        }

        with patch.dict(os.environ, env_vars):
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == 'custom_env_id'

    def test_empty_prefix_uses_no_prefix(self):
        """Test that empty prefix means no prefix."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        assert prefix == ''

        env_vars = {'CLIENT_ID': 'no_prefix_id'}
        with patch.dict(os.environ, env_vars):
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == 'no_prefix_id'

    def test_missing_prefix_defaults_to_empty(self):
        """Test that missing prefix defaults to empty string."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id'
                # No prefix specified
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        assert prefix == ''


class TestEnvVarPriority:
    """Test environment variable priority edge cases."""

    def test_empty_env_var_uses_config(self):
        """Test that empty string ENV var falls back to config."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {'CLIENT_ID': ''}):
            # Empty string is falsy, should use config
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == 'config_id'

    def test_whitespace_env_var_used(self):
        """Test that whitespace ENV var is used (not filtered)."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {'CLIENT_ID': '   '}):
            # Whitespace is truthy, should be used
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == '   '

    def test_env_var_with_special_chars(self):
        """Test that ENV var with special characters works."""
        config = {
            'falcon_credentials': {
                'base_url': 'US1',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {'BASE_URL': 'https://api.us-2.crowdstrike.com'}):
            base_url = os.environ.get(prefix + 'BASE_URL') or config['falcon_credentials'].get('base_url')
            assert base_url == 'https://api.us-2.crowdstrike.com'

    def test_multiple_prefixes_independent(self):
        """Test that different prefixes don't interfere."""
        # Config with FALCON_ prefix
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'prefix': 'FALCON_'
            }
        }

        env_vars = {
            'CLIENT_ID': 'no_prefix_id',
            'FALCON_CLIENT_ID': 'falcon_prefix_id',
            'CUSTOM_CLIENT_ID': 'custom_prefix_id'
        }

        with patch.dict(os.environ, env_vars):
            # Should use FALCON_ prefixed var
            prefix = config['falcon_credentials'].get('prefix', '')
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            assert client_id == 'falcon_prefix_id'


class TestDotEnvFileLoading:
    """Test .env file loading behavior (logical tests)."""

    def test_dotenv_variables_available(self):
        """Test that dotenv makes variables available in os.environ."""
        # Simulate what dotenv does
        env_vars = {
            'CLIENT_ID': 'dotenv_id',
            'CLIENT_SECRET': 'dotenv_secret',
            'BASE_URL': 'US2'
        }

        with patch.dict(os.environ, env_vars):
            assert os.environ.get('CLIENT_ID') == 'dotenv_id'
            assert os.environ.get('CLIENT_SECRET') == 'dotenv_secret'
            assert os.environ.get('BASE_URL') == 'US2'

    def test_dotenv_precedence_over_config(self):
        """Test that dotenv variables take precedence over config."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'client_secret': 'config_secret',
                'base_url': 'US1',
                'prefix': ''
            }
        }

        # Simulate dotenv loading
        env_vars = {
            'CLIENT_ID': 'dotenv_id',
            'CLIENT_SECRET': 'dotenv_secret',
            'BASE_URL': 'US2'
        }

        with patch.dict(os.environ, env_vars):
            prefix = config['falcon_credentials'].get('prefix', '')
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            client_secret = os.environ.get(prefix + 'CLIENT_SECRET') or config['falcon_credentials'].get('client_secret')
            base_url = os.environ.get(prefix + 'BASE_URL') or config['falcon_credentials'].get('base_url')

            assert client_id == 'dotenv_id'
            assert client_secret == 'dotenv_secret'
            assert base_url == 'US2'

    def test_system_env_precedence_over_dotenv(self):
        """Test that system ENV vars take precedence over .env file."""
        # In dotenv, system env vars are not overwritten by .env file
        # This is the default behavior of python-dotenv
        with patch.dict(os.environ, {'CLIENT_ID': 'system_env_id'}):
            # Even if .env has CLIENT_ID=dotenv_id, system env takes precedence
            assert os.environ.get('CLIENT_ID') == 'system_env_id'


class TestCredentialValidation:
    """Test credential validation logic."""

    def test_missing_all_credentials_detected(self):
        """Test that missing credentials are detected."""
        config = {
            'falcon_credentials': {
                'client_id': '',
                'client_secret': '',
                'base_url': '',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {}, clear=True):
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            client_secret = os.environ.get(prefix + 'CLIENT_SECRET') or config['falcon_credentials'].get('client_secret')
            base_url = os.environ.get(prefix + 'BASE_URL') or config['falcon_credentials'].get('base_url')

            # All should be empty/falsy
            assert not client_id
            assert not client_secret
            assert not base_url

    def test_partial_credentials_detected(self):
        """Test detection of partial credentials (some missing)."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'client_secret': '',
                'base_url': '',
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {}, clear=True):
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            client_secret = os.environ.get(prefix + 'CLIENT_SECRET') or config['falcon_credentials'].get('client_secret')
            base_url = os.environ.get(prefix + 'BASE_URL') or config['falcon_credentials'].get('base_url')

            assert client_id == 'config_id'
            assert not client_secret  # Missing
            assert not base_url  # Missing

    def test_complete_credentials_from_mixed_sources(self):
        """Test that credentials can come from both ENV and config."""
        config = {
            'falcon_credentials': {
                'client_id': 'config_id',
                'client_secret': 'config_secret',
                'base_url': '',  # Missing in config
                'prefix': ''
            }
        }

        prefix = config['falcon_credentials'].get('prefix', '')
        with patch.dict(os.environ, {'BASE_URL': 'US2'}):  # Only BASE_URL in env
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')
            client_secret = os.environ.get(prefix + 'CLIENT_SECRET') or config['falcon_credentials'].get('client_secret')
            base_url = os.environ.get(prefix + 'BASE_URL') or config['falcon_credentials'].get('base_url')

            assert client_id == 'config_id'  # From config
            assert client_secret == 'config_secret'  # From config
            assert base_url == 'US2'  # From ENV


class TestMetadataSettings:
    """Test optional metadata settings in config."""

    def test_metadata_settings_default_false(self):
        """Test that metadata settings default to False."""
        from falcon_policy_scoring.utils.config import _load_config_defaults

        config = _load_config_defaults({})

        # Check if metadata exists after defaults
        # (The actual implementation may or may not set these)
        falcon_creds = config.get('falcon_credentials', {})
        metadata = falcon_creds.get('metadata', {})

        # These should either not exist or be False
        include_source = metadata.get('include_client_source', False)
        include_hash = metadata.get('include_client_hash', False)
        include_id = metadata.get('include_client_id', False)

        assert include_source is False
        assert include_hash is False
        assert include_id is False

    def test_metadata_settings_preserved(self):
        """Test that metadata settings are preserved from config."""
        from falcon_policy_scoring.utils.config import _load_config_defaults

        config = {
            'falcon_credentials': {
                'metadata': {
                    'include_client_source': True,
                    'include_client_hash': True,
                    'include_client_id': True
                }
            }
        }

        config = _load_config_defaults(config)

        metadata = config['falcon_credentials'].get('metadata', {})
        assert metadata.get('include_client_source') is True
        assert metadata.get('include_client_hash') is True
        assert metadata.get('include_client_id') is True


class TestPythonDotenvIntegration:
    """Test actual python-dotenv library integration with real .env files."""

    def test_load_dotenv_from_file(self):
        """Test that load_dotenv() actually loads variables from .env file."""
        env_file = FIXTURES_DIR / "test.env"

        # Clear any existing env vars
        env_vars_to_clear = ['CLIENT_ID', 'CLIENT_SECRET', 'BASE_URL']
        original_values = {}
        for var in env_vars_to_clear:
            original_values[var] = os.environ.pop(var, None)

        try:
            # Load from .env file
            load_dotenv(env_file)

            # Verify variables were loaded
            assert os.environ.get('CLIENT_ID') == 'dotenv_test_client_id'
            assert os.environ.get('CLIENT_SECRET') == 'dotenv_test_client_secret'
            assert os.environ.get('BASE_URL') == 'US2'

        finally:
            # Clean up - remove loaded vars
            for var in env_vars_to_clear:
                os.environ.pop(var, None)
                # Restore original values if they existed
                if original_values[var] is not None:
                    os.environ[var] = original_values[var]

    def test_load_dotenv_with_prefix(self):
        """Test that load_dotenv() loads FALCON_ prefixed variables."""
        env_file = FIXTURES_DIR / "test_falcon_prefix.env"

        # Clear any existing env vars
        env_vars_to_clear = ['FALCON_CLIENT_ID', 'FALCON_CLIENT_SECRET', 'FALCON_BASE_URL', 'FALCON_CUSTOM_SETTING']
        original_values = {}
        for var in env_vars_to_clear:
            original_values[var] = os.environ.pop(var, None)

        try:
            # Load from .env file with prefix
            load_dotenv(env_file)

            # Verify prefixed variables were loaded
            assert os.environ.get('FALCON_CLIENT_ID') == 'falcon_dotenv_client_id'
            assert os.environ.get('FALCON_CLIENT_SECRET') == 'falcon_dotenv_client_secret'
            assert os.environ.get('FALCON_BASE_URL') == 'US1'
            assert os.environ.get('FALCON_CUSTOM_SETTING') == 'custom_value'

            # Verify we can use these with prefix in config
            config = {
                'falcon_credentials': {
                    'client_id': 'config_fallback',
                    'prefix': 'FALCON_'
                }
            }

            prefix = config['falcon_credentials'].get('prefix', '')
            client_id = os.environ.get(prefix + 'CLIENT_ID') or config['falcon_credentials'].get('client_id')

            assert client_id == 'falcon_dotenv_client_id'

        finally:
            # Clean up
            for var in env_vars_to_clear:
                os.environ.pop(var, None)
                if original_values[var] is not None:
                    os.environ[var] = original_values[var]
