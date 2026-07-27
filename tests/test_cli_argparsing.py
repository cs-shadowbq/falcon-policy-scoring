"""Tests for CLI argument parsing, focused on global-option handling.

These tests lock in the fix that makes global options (``--output-format``,
``--output-file``, ``--verbose``, and the connection flags) work in ANY
position — before OR after the subcommand — via a shared parent parser with
``SUPPRESS`` defaults applied post-parse. Prior to the fix, placing a global
flag after the subcommand produced ``error: unrecognized arguments``.
"""
import argparse
import pytest

from falcon_policy_scoring.cli.cli_setup import (
    build_parser,
    _apply_global_defaults,
    GLOBAL_DEFAULTS,
)


def _parse(argv):
    """Parse argv and apply global defaults, mirroring parse_arguments()."""
    args = build_parser().parse_args(argv)
    _apply_global_defaults(args)
    return args


# Subcommands that accept the shared global options. daemon/generate-schema are
# included because the parent parser is attached to every subparser.
SUBCOMMANDS_WITH_POSITIONAL = {
    'host': ['host', 'myhost'],
}
SIMPLE_SUBCOMMANDS = ['fetch', 'policies', 'hosts', 'regrade']


class TestGlobalDefaults:
    """Post-parse defaults are applied when a flag is omitted."""

    def test_defaults_applied_when_absent(self):
        args = _parse(['policies'])
        assert args.output_format == 'text'
        assert args.output_file is None
        assert args.verbose is False
        assert args.client_id is None

    def test_all_global_dests_present_after_defaults(self):
        args = _parse(['policies'])
        for dest in GLOBAL_DEFAULTS:
            assert hasattr(args, dest), f"missing global dest: {dest}"


class TestOutputFormatPosition:
    """--output-format works before AND after each subcommand."""

    @pytest.mark.parametrize("cmd", SIMPLE_SUBCOMMANDS)
    def test_after_subcommand(self, cmd):
        args = _parse([cmd, '--output-format', 'json'])
        assert args.command == cmd
        assert args.output_format == 'json'

    @pytest.mark.parametrize("cmd", SIMPLE_SUBCOMMANDS)
    def test_before_subcommand(self, cmd):
        args = _parse(['--output-format', 'json', cmd])
        assert args.command == cmd
        assert args.output_format == 'json'

    def test_after_subcommand_with_positional(self):
        # host takes a positional hostname; flag after should still parse.
        args = _parse(['host', 'myhost', '--output-format', 'csv'])
        assert args.command == 'host'
        assert args.hostname == 'myhost'
        assert args.output_format == 'csv'

    def test_before_subcommand_with_positional(self):
        args = _parse(['--output-format', 'csv', 'host', 'myhost'])
        assert args.command == 'host'
        assert args.hostname == 'myhost'
        assert args.output_format == 'csv'


class TestNoClobber:
    """A value given before the subcommand is NOT overwritten by the
    subparser's (suppressed) default — the core regression this fix guards."""

    def test_value_before_subcommand_survives(self):
        args = _parse(['--output-format', 'json', 'hosts'])
        assert args.output_format == 'json'  # not reset to 'text'

    def test_verbose_before_subcommand_survives(self):
        args = _parse(['-v', 'policies'])
        assert args.verbose is True

    def test_verbose_after_subcommand(self):
        args = _parse(['policies', '-v'])
        assert args.verbose is True


class TestConnectionFlagsPosition:
    """Connection globals also work in either position."""

    def test_client_id_after(self):
        args = _parse(['fetch', '--client-id', 'abc'])
        assert args.client_id == 'abc'

    def test_client_id_before(self):
        args = _parse(['--client-id', 'abc', 'fetch'])
        assert args.client_id == 'abc'

    def test_base_url_after(self):
        args = _parse(['policies', '--base-url', 'EU1'])
        assert args.base_url == 'EU1'


class TestSubcommandHelpAdvertisesGlobals:
    """Each subparser's help includes the global options (discoverability)."""

    @pytest.mark.parametrize("cmd", SIMPLE_SUBCOMMANDS + ['host', 'generate-schema', 'daemon'])
    def test_output_format_in_subcommand_help(self, cmd, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([cmd, '--help'])
        out = capsys.readouterr().out
        assert '--output-format' in out
