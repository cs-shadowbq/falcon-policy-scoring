"""Metadata building utilities for reports.

This module provides shared functionality for building report metadata,
including optional client identification fields based on configuration.
"""
import socket
import getpass
import hashlib
from typing import Dict, Optional


def build_client_source_hash() -> Optional[str]:
    """Build SHA256 hash of username:hostname for client source tracking.

    Returns:
        SHA256 hash string or None if unable to retrieve username/hostname
    """
    try:
        username = getpass.getuser()
        hostname = socket.gethostname()
        client_source_str = f"{username}:{hostname}"
        return hashlib.sha256(client_source_str.encode('utf-8')).hexdigest()
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def build_client_hash(client_id: str, client_secret: str) -> Optional[str]:
    """Build SHA256 hash of client_id:client_secret for API client tracking.

    Args:
        client_id: Falcon API client ID
        client_secret: Falcon API client secret

    Returns:
        SHA256 hash string or None if credentials are empty
    """
    if not client_id or not client_secret:
        return None

    try:
        client_hash_str = f"{client_id}:{client_secret}"
        return hashlib.sha256(client_hash_str.encode('utf-8')).hexdigest()
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def build_report_metadata(config: Dict) -> Dict[str, str]:
    """Build optional report metadata fields based on configuration.

    This function extracts metadata settings from the config and builds
    optional metadata fields including client_source, client_hash, and client_id.

    Args:
        config: Configuration dictionary containing falcon_credentials and metadata settings

    Returns:
        Dictionary with optional metadata fields (only includes fields that are enabled)
    """
    metadata = {}

    falcon_creds = config.get('falcon_credentials', {})
    metadata_config = falcon_creds.get('metadata', {})

    # Add client_source (username:hostname SHA256 hash)
    if metadata_config.get('include_client_source', False):
        client_source = build_client_source_hash()
        if client_source:
            metadata['client_source'] = client_source

    # Add client_hash (client_id:client_secret SHA256 hash)
    if metadata_config.get('include_client_hash', False):
        client_id = falcon_creds.get('client_id', '')
        client_secret = falcon_creds.get('client_secret', '')
        client_hash = build_client_hash(client_id, client_secret)
        if client_hash:
            metadata['client_hash'] = client_hash

    # Add client_id directly
    if metadata_config.get('include_client_id', False):
        client_id = falcon_creds.get('client_id', '')
        if client_id:
            metadata['client_id'] = client_id

    return metadata
