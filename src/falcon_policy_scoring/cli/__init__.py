"""CLI module for policy-audit tool."""

from falcon_policy_scoring.cli.cli_setup import parse_arguments, setup_environment
from falcon_policy_scoring.cli.context import CliContext
from falcon_policy_scoring.cli.operations import handle_fetch_operations, handle_regrade_operations
from falcon_policy_scoring.cli.output_strategies import get_output_strategy
from falcon_policy_scoring.cli.schema import handle_schema_generation

__all__ = [
    'parse_arguments',
    'setup_environment',
    'CliContext',
    'handle_fetch_operations',
    'handle_regrade_operations',
    'get_output_strategy',
    'handle_schema_generation'
]
