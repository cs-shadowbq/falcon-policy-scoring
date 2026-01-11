#!/usr/bin/env python3
"""
CrowdStrike Falcon Policy Audit CLI Tool

Fetches, grades, and displays CrowdStrike Falcon security policies.
Supports filtering by policy type, platform, and grading status.
"""

from falcon_policy_scoring.utils.exceptions import CliError, ConfigurationError, ApiConnectionError, DatabaseError
from falcon_policy_scoring.cli.schema import handle_schema_generation
from falcon_policy_scoring.cli.output_strategies import get_output_strategy
from falcon_policy_scoring.cli.operations import handle_fetch_operations, handle_regrade_operations
from falcon_policy_scoring.cli.cli_setup import parse_arguments, setup_environment
from falcon_policy_scoring.cli.context import CliContext
from rich.console import Console
import sys
from pathlib import Path


def _handle_error(error, error_type, ctx, exit_code=1):
    """Handle error reporting for both JSON and console output modes."""
    if ctx.json_output_mode:
        print(f'{{"error": "{error_type}", "message": "{str(error)}"}}')
    else:
        ctx.console.print(f"[bold red]{error_type}:[/bold red] {error}")
        if ctx.verbose and hasattr(error, '__traceback__'):
            import traceback
            ctx.console.print(traceback.format_exc())
    sys.exit(exit_code)


def _handle_keyboard_interrupt(ctx):
    """Handle KeyboardInterrupt (Ctrl+C) gracefully."""
    if not ctx.json_output_mode:
        ctx.console.print("\n[yellow]Operation cancelled by user[/yellow]")
    sys.exit(130)


def main():
    """Main CLI entry point - orchestrates the policy audit workflow."""
    # Parse command line arguments
    args = parse_arguments()

    # Handle subcommands
    if args.command == 'generate-schema':
        handle_schema_generation(args)
        return

    if args.command == 'policies':
        # Create CLI context
        ctx = CliContext(
            console=Console(),
            verbose=args.verbose,
            json_output_mode=(args.output_format == 'json')
        )
        # Transform args to match legacy structure for output_strategies
        args.show_policies = True
        args.show_hosts = False
        args.sort_policies = args.sort
        args.fetch = False  # policies subcommand doesn't fetch
        _run_legacy_mode(args, ctx)
        return

    if args.command == 'hosts':
        # Create CLI context
        ctx = CliContext(
            console=Console(),
            verbose=args.verbose,
            json_output_mode=(args.output_format == 'json')
        )
        # Transform args to match legacy structure for output_strategies
        args.show_hosts = True
        args.show_policies = False
        args.sort_hosts = args.sort
        args.details = False  # hosts subcommand doesn't have details
        args.hostname = None  # hosts subcommand doesn't filter by hostname
        args.fetch = False  # hosts subcommand doesn't fetch
        _run_legacy_mode(args, ctx)
        return

    if args.command == 'host':
        # Create CLI context
        ctx = CliContext(
            console=Console(),
            verbose=args.verbose,
            json_output_mode=(args.output_format == 'json')
        )
        # Transform args to match legacy structure for output_strategies
        args.show_hosts = True
        args.show_policies = False
        args.sort_hosts = 'platform'
        args.host_status = None  # single host view doesn't filter by status
        args.platform = None  # single host view doesn't filter by platform
        args.fetch = False  # host subcommand doesn't fetch
        # hostname is already set as positional argument
        # details is already set in the subcommand
        _run_legacy_mode(args, ctx)
        return

    if args.command == 'fetch':
        # Create CLI context
        ctx = CliContext(
            console=Console(),
            verbose=args.verbose,
            json_output_mode=(args.output_format == 'json')
        )
        # Transform args to match legacy structure for fetch operations
        args.fetch = True
        args.show_policies = False
        args.show_hosts = False
        _run_legacy_mode(args, ctx)
        return

    if args.command == 'regrade':
        # Create CLI context
        ctx = CliContext(
            console=Console(),
            verbose=args.verbose,
            json_output_mode=(args.output_format == 'json')
        )
        # Run regrade operation
        _run_regrade_mode(args, ctx)
        return

    if args.command == 'daemon':
        # Run in daemon mode
        _run_daemon_mode(args)
        return

    # If no subcommand specified, use legacy mode (backward compatibility)
    if args.command is None:
        # Create CLI context for legacy mode
        ctx = CliContext(
            console=Console(),
            verbose=args.verbose,
            json_output_mode=(args.output_format == 'json')
        )
        _run_legacy_mode(args, ctx)
        return

    # Unknown subcommand (shouldn't happen with argparse)
    console = Console()
    console.print(f"[bold red]Error:[/bold red] Unknown command '{args.command}'")
    sys.exit(1)


def _run_daemon_mode(args):
    """Run the daemon mode for continuous policy auditing."""
    from falcon_policy_scoring.daemon.main import DaemonRunner
    from falcon_policy_scoring.utils.config import read_config_from_yaml
    from falcon_policy_scoring.utils.logger import setup_logging

    # Create minimal context for error handling
    ctx = CliContext(
        console=Console(),
        verbose=args.verbose,
        json_output_mode=False  # Daemon mode doesn't support JSON output
    )

    try:
        # Setup logging for daemon mode
        config = read_config_from_yaml(args.config)
        setup_logging(config, worker_name="daemon")

        # Override health port if specified
        if args.health_port:
            config.setdefault('daemon', {}).setdefault('health_check', {})['port'] = args.health_port

        # Default health port to 8088 if not specified
        if not config.get('daemon', {}).get('health_check', {}).get('port'):
            config.setdefault('daemon', {}).setdefault('health_check', {})['port'] = 8088

        # Ensure output directory exists
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create and run daemon
        daemon = DaemonRunner(args.config, str(output_dir), immediate=args.immediate)
        daemon.initialize()

        ctx.console.print("[bold green]Daemon started[/bold green]")
        ctx.console.print(f"Config: {args.config}")
        ctx.console.print(f"Output: {output_dir}")

        # Show health check URL only if enabled
        health_check_config = config.get('daemon', {}).get('health_check', {})
        if health_check_config.get('enabled', True):
            health_port = health_check_config.get('port', 8088)
            ctx.console.print(f"Health check: http://localhost:{health_port}/health")
        else:
            ctx.console.print("Health check: [dim]disabled[/dim]")

        ctx.console.print("\n[yellow]Press Ctrl+C to stop[/yellow]\n")

        daemon.run()
        sys.exit(0)

    except KeyboardInterrupt:
        ctx.console.print("\n[yellow]Daemon stopped by user[/yellow]")
        sys.exit(0)

    except Exception as e:  # pylint: disable=broad-exception-caught
        _handle_error(e, "Daemon Error", ctx)


def _run_regrade_mode(args, ctx):
    """Run the regrade mode to re-grade existing policies."""
    try:
        # Setup environment (config, database - no API needed)
        ctx = setup_environment(args)

        # Handle regrade operations
        handle_regrade_operations(ctx.adapter, ctx.cid, args, ctx)

    except ConfigurationError as e:
        _handle_error(e, "Configuration Error", ctx)

    except DatabaseError as e:
        _handle_error(e, "Database Error", ctx)

    except CliError as e:
        _handle_error(e, "Error", ctx)

    except KeyboardInterrupt:
        _handle_keyboard_interrupt(ctx)

    except Exception as e:  # pylint: disable=broad-exception-caught
        _handle_error(e, "Unexpected Error", ctx)


def _run_legacy_mode(args, ctx):
    """Run the legacy CLI mode (without subcommands)."""

    try:
        # Setup environment (config, database, API)
        ctx = setup_environment(args)

        # Handle fetch operations if requested
        if args.fetch:
            handle_fetch_operations(ctx.falcon, ctx.adapter, ctx.cid, args, ctx.config, ctx)

        # Get output strategy (text or JSON)
        output_strategy = get_output_strategy(args.output_format)

        # Generate and display output
        data = {
            'adapter': ctx.adapter,
            'cid': ctx.cid,
            'config': ctx.config,
            'args': args
        }
        output_strategy.output(data, ctx)

    except ConfigurationError as e:
        _handle_error(e, "Configuration Error", ctx)

    except ApiConnectionError as e:
        _handle_error(e, "API Connection Error", ctx)

    except DatabaseError as e:
        _handle_error(e, "Database Error", ctx)

    except CliError as e:
        _handle_error(e, "Error", ctx)

    except KeyboardInterrupt:
        _handle_keyboard_interrupt(ctx)

    except Exception as e:  # pylint: disable=broad-exception-caught
        _handle_error(e, "Unexpected Error", ctx)


if __name__ == "__main__":
    main()
