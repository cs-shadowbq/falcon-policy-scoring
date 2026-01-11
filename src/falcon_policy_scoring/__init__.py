"""
Falcon Policy Scoring - CrowdStrike Falcon policy analysis and grading tool.

This package provides functionality for fetching, analyzing, and grading
CrowdStrike Falcon policies against minimum security standards.
"""

import importlib.metadata
from pathlib import Path

# Defaults
__version__ = "unknown"
__author__ = "CrowdStrike Community"
__maintainers__ = ['Scott MacGregor']
__license__ = "MIT"


def _read_pyproject_toml():
    """Read and parse pyproject.toml file."""
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # Fallback for Python 3.8-3.10
        except ModuleNotFoundError:
            return None

    pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
    if pyproject_path.exists():
        with open(pyproject_path, "rb") as f:
            return tomllib.load(f)
    return None


# Try to get version from installed package metadata
try:
    __version__ = importlib.metadata.version("falcon-policy-scoring")
except importlib.metadata.PackageNotFoundError:
    # Fallback: read from pyproject.toml
    pyproject_data = _read_pyproject_toml()
    if pyproject_data:
        __version__ = pyproject_data.get("project", {}).get("version", __version__)

# Read author, maintainers, and license from pyproject.toml
pyproject_data = _read_pyproject_toml()
if pyproject_data:
    project = pyproject_data.get("project", {})

    # Extract author from first author entry
    authors = project.get("authors", [])
    if authors:
        __author__ = authors[0].get("name", __author__)

    # Extract maintainers list
    __maintainers__ = project.get("maintainers", __maintainers__)

    # Extract license (handle both string and dict with 'file' key)
    license_info = project.get("license")
    if license_info and not isinstance(license_info, dict):
        __license__ = license_info

__all__ = ['__version__', '__author__', '__maintainers__', '__license__']
