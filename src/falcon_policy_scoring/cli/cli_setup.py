"""CLI setup and initialization functions."""
import argparse
import os
from typing import Tuple
from datetime import datetime, timedelta
from dotenv import load_dotenv
from falconpy import APIHarnessV2
from falcon_policy_scoring.utils.config import read_config_from_yaml
from falcon_policy_scoring.utils.logger import setup_logging
from falcon_policy_scoring.factories.database_factory import DatabaseFactory
from falcon_policy_scoring.falconapi.cid import get_cid
from falcon_policy_scoring.utils.exceptions import ConfigurationError, ApiConnectionError, DatabaseError
from falcon_policy_scoring.cli.context import CliContext
from rich.console import Console


def validate_last_seen(value: str) -> str:
    """Validate and convert last-seen argument to FQL filter with timestamp.

    Args:
        value: Last seen time period ('hour', '12 hours', 'day', 'week')

    Returns:
        FQL filter string for last_seen with timestamp (e.g., "last_seen:>='2025-12-31T00:00:00Z'")

    Raises:
        argparse.ArgumentTypeError: If validation fails
    """
    # Mapping from user input to timedelta
    duration_map = {
        'hour': timedelta(hours=1),
        '12 hours': timedelta(hours=12),
        'day': timedelta(days=1),
        'week': timedelta(weeks=1)
    }

    if value not in duration_map:
        raise argparse.ArgumentTypeError(
            f"Invalid last-seen value: {value}. "
            f"Valid values are: hour, 12 hours, day, week"
        )

    # Calculate timestamp: current time minus the duration
    timestamp = datetime.utcnow() - duration_map[value]

    # Format as UTC timestamp: YYYY-MM-DDTHH:MM:SSZ
    timestamp_str = timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Return FQL filter with >= comparison
    return f"last_seen:>='{timestamp_str}'"


def validate_policy_types(value: str) -> str:
    """Validate policy type argument.

    Accepts 'all' or comma-separated list of policy types.
    Cannot mix 'all' with other types.

    Args:
        value: Policy type string

    Returns:
        Validated policy type string

    Raises:
        argparse.ArgumentTypeError: If validation fails
    """
    valid_types = {'prevention', 'sensor-update', 'content-update', 'firewall', 'device-control', 'it-automation'}

    # Split by comma and strip whitespace
    types = [t.strip() for t in value.split(',')]

    # Check if 'all' is present
    if 'all' in types:
        if len(types) > 1:
            raise argparse.ArgumentTypeError(
                "'all' cannot be combined with other policy types. Use 'all' alone or specify individual types."
            )
        return value

    # Validate each type
    invalid_types = [t for t in types if t not in valid_types]
    if invalid_types:
        raise argparse.ArgumentTypeError(
            f"Invalid policy type(s): {', '.join(invalid_types)}. "
            f"Valid types are: all, {', '.join(sorted(valid_types))}"
        )

    return value


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed arguments namespace
    """

    policy_type_help_text = "Policy type(s) to process. Use 'all' or comma-separated list. Valid types are: all, content-update, device-control, firewall, it-automation, prevention, sensor-update. Example: -t 'prevention,firewall'"

    parser = argparse.ArgumentParser(
        description="CrowdStrike Falcon Policy Audit Tool - Fetch, grade, and analyze security policies",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Global arguments - Connection Configuration
    parser.add_argument(
        "-c", "--config",
        default="config/config.yaml",
        help="Path to configuration YAML file (default: config/config.yaml)"
    )
    parser.add_argument(
        "--client-id",
        help="CrowdStrike API Client ID (overrides config file)"
    )
    parser.add_argument(
        "--client-secret",
        help="CrowdStrike API Client Secret (overrides config file)"
    )
    parser.add_argument(
        "--base-url",
        help="CrowdStrike API Base URL, e.g., US1, US2, EU1, GOV1, GOV2 (overrides config file)"
    )

    # Global arguments - Output Options
    parser.add_argument(
        "--output-format",
        choices=['text', 'json'],
        default='text',
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--output-file",
        help="Write output to file instead of stdout"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    # Create subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Subcommand: fetch
    fetch_parser = subparsers.add_parser(
        'fetch',
        help='Fetch and grade policies and hosts from CrowdStrike API',
        description='Retrieve fresh data from CrowdStrike API and grade all policies and hosts'
    )
    fetch_parser.add_argument(
        '-t', '--type',
        dest='policy_type',
        type=validate_policy_types,
        default='all',
        help=policy_type_help_text
    )
    fetch_parser.add_argument(
        '--product-types',
        help='Comma-separated list of product types to include when fetching hosts '
             '(default: \'Workstation,Domain Controller,Server\'). '
             'Use \'all\' to include all product types including Mobile, Pod, Kubernetes Cluster, etc.'
    )
    fetch_parser.add_argument(
        '--host-groups',
        help='Comma-separated list of host group names to filter hosts. '
             'Only hosts that are members of these groups will be fetched. '
             'Case-insensitive. Example: --host-groups "Production Servers,Development"'
    )
    fetch_parser.add_argument(
        '--last-seen',
        type=validate_last_seen,
        help='Filter hosts by last seen time. '
             'Valid values: hour, "12 hours", day, week. '
             'Example: --last-seen day'
    )

    # Subcommand: policies
    policies_parser = subparsers.add_parser(
        'policies',
        help='Display policy-level grading tables',
        description='Show graded policy tables with optional filtering and sorting'
    )
    policies_parser.add_argument(
        '-t', '--type',
        dest='policy_type',
        type=validate_policy_types,
        default='all',
        help=policy_type_help_text
    )
    policies_parser.add_argument(
        '-p', '--platform',
        choices=['Windows', 'Mac', 'Linux'],
        help='Filter by platform'
    )
    policies_parser.add_argument(
        '-s', '--status',
        choices=['passed', 'failed'],
        help='Filter by grading status'
    )
    policies_parser.add_argument(
        '--details',
        action='store_true',
        help='Show detailed failure information for failed policies'
    )
    policies_parser.add_argument(
        '--sort',
        choices=['platform', 'name', 'score'],
        default='platform',
        help='Sort policies by: platform (default), name, or score'
    )

    # Subcommand: hosts
    hosts_parser = subparsers.add_parser(
        'hosts',
        help='Display host-level policy status summary',
        description='Show host-level policy status with optional filtering and sorting'
    )
    hosts_parser.add_argument(
        '-t', '--type',
        dest='policy_type',
        type=validate_policy_types,
        default='all',
        help=policy_type_help_text
    )
    hosts_parser.add_argument(
        '-p', '--platform',
        choices=['Windows', 'Mac', 'Linux'],
        help='Filter by platform'
    )
    hosts_parser.add_argument(
        '-s', '--status',
        dest='host_status',
        choices=['all-passed', 'any-failed'],
        help='Filter hosts by policy status'
    )
    hosts_parser.add_argument(
        '--sort',
        choices=['platform', 'hostname', 'status'],
        default='platform',
        help='Sort hosts by: platform (default), hostname, or status (failed first)'
    )

    # Subcommand: host (singular)
    host_parser = subparsers.add_parser(
        'host',
        help='Display detailed policy status for a specific host',
        description='Show detailed policy status and failure information for a single host'
    )
    host_parser.add_argument(
        'hostname',
        help='Hostname to display detailed information for'
    )
    host_parser.add_argument(
        '-t', '--type',
        dest='policy_type',
        type=validate_policy_types,
        default='all',
        help=policy_type_help_text
    )
    host_parser.add_argument(
        '--details',
        action='store_true',
        help='Show detailed failure information for failed policies'
    )

    # Subcommand: generate-schema
    schema_parser = subparsers.add_parser(
        'generate-schema',
        help='Generate JSON schema for policy-audit output',
        description='Generate JSON schema(s) for policy-audit report types. '
                    'If no report type is specified, generates all schemas to ./output/schemas/'
    )
    schema_parser.add_argument(
        'report_type',
        nargs='?',
        choices=['host-details', 'policy-audit', 'host-summary', 'metrics'],
        help='Report type to generate schema for (default: generate all)'
    )
    schema_parser.add_argument(
        '--schema-output',
        help='Path to write JSON schema file or directory (default: ./output/schemas/)'
    )

    # Subcommand: regrade
    regrade_parser = subparsers.add_parser(
        'regrade',
        help='Re-grade existing policies with updated grading criteria',
        description='Re-grade policies already in the database using current grading criteria without fetching new data'
    )
    regrade_parser.add_argument(
        '-t', '--type',
        dest='policy_type',
        type=validate_policy_types,
        default='all',
        help=policy_type_help_text
    )

    # Subcommand: daemon
    daemon_parser = subparsers.add_parser(
        'daemon',
        help='Run in daemon mode for continuous policy auditing',
        description='Run as a continuous service that periodically fetches, grades, and reports on policies'
    )
    daemon_parser.add_argument(
        '-o', '--output-dir',
        default='./output',
        help='Directory for timestamped JSON output files (default: ./output)'
    )
    daemon_parser.add_argument(
        '--health-port',
        type=int,
        help='Port for health check endpoint (overrides config, default: 8088)'
    )
    daemon_parser.add_argument(
        '--immediate',
        action='store_true',
        help='Run fetch and grade immediately on startup instead of waiting for first scheduled cycle'
    )

    return parser.parse_args()


def load_configuration(args, ctx) -> dict:
    """Load and validate configuration.

    Args:
        args: Parsed command line arguments
        ctx: CLI context

    Returns:
        Configuration dictionary

    Raises:
        ConfigurationError: If configuration is invalid
    """
    try:
        ctx.log_verbose(f"Loading configuration from {args.config}")
        config = read_config_from_yaml(args.config)
        setup_logging(config, worker_name="policy-audit")
        return config
    except FileNotFoundError as e:
        raise ConfigurationError(f"Configuration file not found: {e}")
    except Exception as e:
        raise ConfigurationError(f"Failed to load configuration: {e}")


def build_api_credentials(args, config, required: bool = True) -> dict:
    """Build API credentials from arguments and config.

    Args:
        args: Parsed command line arguments
        config: Configuration dictionary
        required: Whether credentials are required (False for cache-only operations)

    Returns:
        API credentials dictionary (may be empty if not required and not provided)

    Raises:
        ConfigurationError: If required=True and credentials are missing
    """
    # Load environment variables from .env file if present
    load_dotenv()

    apicreds = {}

    # Get environment variable prefix from config
    prefix = config.get('falcon_credentials', {}).get('prefix', '')

    # Client ID - Priority: CLI arg > ENV var > config file
    if args.client_id:
        apicreds['client_id'] = args.client_id
    else:
        # Try environment variable first
        env_client_id = os.environ.get(prefix + 'CLIENT_ID')
        if env_client_id:
            apicreds['client_id'] = env_client_id
        else:
            # Fall back to config file
            client_id = config.get('falcon_credentials', {}).get('client_id')
            if client_id:
                apicreds['client_id'] = client_id
            elif required:
                raise ConfigurationError(f"No client_id provided. Use --client-id, set {prefix}CLIENT_ID env var, or configure in YAML")

    # Client Secret - Priority: CLI arg > ENV var > config file
    if args.client_secret:
        apicreds['client_secret'] = args.client_secret
    else:
        # Try environment variable first
        env_client_secret = os.environ.get(prefix + 'CLIENT_SECRET')
        if env_client_secret:
            apicreds['client_secret'] = env_client_secret
        else:
            # Fall back to config file
            client_secret = config.get('falcon_credentials', {}).get('client_secret')
            if client_secret:
                apicreds['client_secret'] = client_secret
            elif required:
                raise ConfigurationError(f"No client_secret provided. Use --client-secret, set {prefix}CLIENT_SECRET env var, or configure in YAML")

    # Base URL - Priority: CLI arg > ENV var > config file
    if args.base_url:
        apicreds['base_url'] = args.base_url
    else:
        # Try environment variable first
        env_base_url = os.environ.get(prefix + 'BASE_URL')
        if env_base_url:
            apicreds['base_url'] = env_base_url
        else:
            # Fall back to config file
            base_url = config.get('falcon_credentials', {}).get('base_url')
            if base_url:
                apicreds['base_url'] = base_url
            elif required:
                # For API operations, default to US1 if not specified
                apicreds['base_url'] = 'US1'
            # For cache-only operations, base_url is optional and will be retrieved from cache

    return apicreds


def setup_database(config, ctx):
    """Setup database connection.

    Args:
        config: Configuration dictionary
        ctx: CLI context

    Returns:
        Database adapter instance

    Raises:
        DatabaseError: If database connection fails
    """
    try:
        ctx.log_verbose("Connecting to database...")
        db_type = config.get('db', {}).get('type', 'tiny_db')
        adapter = DatabaseFactory.create_adapter(db_type)
        adapter.connect(config[db_type])
        return adapter
    except Exception as e:
        raise DatabaseError(f"Failed to connect to database: {e}")


def setup_falcon_api(apicreds, ctx) -> Tuple[APIHarnessV2, str]:
    """Setup Falcon API connection and get CID.

    Args:
        apicreds: API credentials dictionary
        ctx: CLI context

    Returns:
        Tuple of (falcon API instance, CID)

    Raises:
        ApiConnectionError: If API connection fails
    """
    try:
        ctx.log_verbose("Connecting to CrowdStrike Falcon API...")
        falcon = APIHarnessV2(**apicreds)
        cid = get_cid(falcon)
        return falcon, cid
    except Exception as e:
        raise ApiConnectionError(f"Failed to connect to CrowdStrike API: {e}")


def get_or_fetch_cid(adapter, apicreds, fetch_required, ctx):
    """Get CID from cache or fetch from API if needed.

    Args:
        adapter: Database adapter instance
        apicreds: API credentials dictionary
        fetch_required: Boolean indicating if fetch operation is requested
        ctx: CLI context

    Returns:
        Tuple of (falcon API instance or None, CID)

    Raises:
        ApiConnectionError: If API connection fails when needed
        ConfigurationError: If CID cannot be retrieved from cache or API
    """
    base_url = apicreds.get('base_url', 'US1')

    # Try to get CID from cache first
    cached_cid = adapter.get_cid(base_url)

    if cached_cid and not fetch_required:
        # Use cached CID, no API connection needed
        ctx.log_verbose(f"Using cached CID for {base_url}")
        return None, cached_cid

    # Need to connect to API (either no cache or fetch requested)
    if fetch_required or not cached_cid:
        ctx.log_verbose("Connecting to CrowdStrike Falcon API to retrieve CID...")
        try:
            falcon = APIHarnessV2(**apicreds)
            cid = get_cid(falcon)
            # Cache the CID for future use
            adapter.put_cid(cid, base_url)
            return falcon, cid
        except Exception as e:
            raise ApiConnectionError(f"Failed to connect to CrowdStrike API: {e}")

    return None, cached_cid


def setup_environment(args) -> CliContext:
    """Setup complete environment (config, database, API).

    Args:
        args: Parsed command line arguments

    Returns:
        CliContext with all environment setup complete
    """
    # Create CLI context
    console = Console()
    ctx = CliContext(
        console=console,
        verbose=args.verbose,
        json_output_mode=(args.output_format == 'json')
    )

    # Load configuration
    config = load_configuration(args, ctx)

    # Determine if this is a cache-only command
    cache_only_commands = ['policies', 'hosts', 'host']
    is_cache_only = args.command in cache_only_commands

    # Build API credentials (not required for cache-only commands)
    apicreds = build_api_credentials(args, config, required=not is_cache_only)

    # Connect to database
    adapter = setup_database(config, ctx)

    # For cache-only commands, try to get CID from cache without API
    if is_cache_only:
        # If user provided base_url, use it to look up specific cache
        if args.base_url:
            base_url = args.base_url
            cached_cid = adapter.get_cid(base_url)
            if not cached_cid:
                raise ConfigurationError(
                    f"No cached CID found for {base_url}. Run 'policy-audit --base-url={base_url} fetch' first to populate the cache."
                )
        else:
            # No base_url provided, get the most recent cached CID
            cid_info = adapter.get_cached_cid_info()
            if not cid_info:
                raise ConfigurationError(
                    "No cached data found. Run 'policy-audit fetch' first to populate the cache."
                )
            cached_cid = cid_info['cid']
            base_url = cid_info['base_url']
            ctx.log_verbose(f"Using most recent cached CID for {base_url}")

        ctx.log_verbose(f"Using cached CID for {base_url}")
        if not ctx.json_output_mode:
            ctx.console.print(f"[bold]Using cached data (CID: {cached_cid[:8]}..., Region: {base_url})[/bold]\n")

        # Store environment info in context
        ctx.config = config
        ctx.adapter = adapter
        ctx.falcon = None
        ctx.cid = cached_cid
        ctx.base_url = base_url
        return ctx

    # For API-required commands, get CID from cache or API
    fetch_required = args.command in ['fetch', 'daemon']
    falcon, cid = get_or_fetch_cid(adapter, apicreds, fetch_required, ctx)

    # Print connection info in text mode
    if not ctx.json_output_mode:
        if falcon:
            ctx.console.print(f"[bold]Connected to CrowdStrike (CID: {cid[:8]}...)[/bold]\n")
        else:
            ctx.console.print(f"[bold]Using cached data (CID: {cid[:8]}...)[/bold]\n")

    # Store environment info in context
    ctx.config = config
    ctx.adapter = adapter
    ctx.falcon = falcon
    ctx.cid = cid
    return ctx
