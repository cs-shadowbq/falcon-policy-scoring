"""CLI context and configuration."""
from dataclasses import dataclass
from rich.console import Console


@dataclass
class CliContext:
    """Context object for CLI operations.

    This replaces global state variables and provides a clean way to pass
    configuration and state through the application.

    Attributes:
        console: Rich Console instance for output
        verbose: Whether verbose output is enabled
        json_output_mode: Whether JSON output mode is active
    """
    console: Console
    verbose: bool = False
    json_output_mode: bool = False

    def log_verbose(self, message: str):
        """Print verbose messages if verbose mode is enabled.

        Args:
            message: The message to print
        """
        if self.verbose and not self.json_output_mode:
            self.console.print(f"[dim]{message}[/dim]")
