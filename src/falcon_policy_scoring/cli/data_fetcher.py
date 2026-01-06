"""Data fetching operations for policy-audit CLI."""
from typing import Dict, List, Optional
from falconpy import APIHarnessV2
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from falcon_policy_scoring.utils.constants import API_COMMAND_GET_DEVICE_DETAILS, DEFAULT_BATCH_SIZE, RecordType
from falcon_policy_scoring.utils.policy_helpers import get_policy_status
from falcon_policy_scoring.utils import host_data as host_data_utils


def find_host_by_name(adapter, cid: str, hostname: str) -> Optional[Dict]:
    """Search for a host by hostname.

    Wrapper for utils function to maintain backward compatibility.
    """
    return host_data_utils.find_host_by_name(adapter, cid, hostname)


def collect_host_data(adapter, cid: str, policy_records: Dict, config: Dict = None) -> List[Dict]:
    """Collect host data with policy status.

    Wrapper for utils function to maintain backward compatibility.
    """
    return host_data_utils.collect_host_data(adapter, cid, policy_records, get_policy_status, config)


def calculate_host_stats(host_rows: List[Dict]) -> Dict:
    """Calculate statistics for hosts.

    Wrapper for utils function to maintain backward compatibility.
    """
    return host_data_utils.calculate_host_stats(host_rows)


def process_host_batch(falcon: APIHarnessV2, adapter, batch: List[str]) -> tuple:
    """Process a batch of host IDs and fetch their details.

    Wrapper for utils function to maintain backward compatibility.
    """
    return host_data_utils.process_host_batch(falcon, adapter, batch)


def fetch_hosts_with_progress(falcon: APIHarnessV2, adapter, host_ids: List[str],
                              batch_size: int, ctx) -> Dict:
    """Fetch hosts with progress bar.

    Args:
        falcon: FalconPy API client
        adapter: Database adapter
        host_ids: List of host IDs
        batch_size: Batch size for API calls
        ctx: CLI context

    Returns:
        Result dictionary with counts
    """
    total_hosts = len(host_ids)
    fetched_count = 0
    error_count = 0

    ctx.console.print(f"[bold]Fetching details for {total_hosts:,} hosts in batches of {batch_size}...[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeRemainingColumn(),
        console=ctx.console
    ) as progress:
        task = progress.add_task("[cyan]Fetching host details...", total=total_hosts)

        # Process in batches
        for i in range(0, total_hosts, batch_size):
            batch = host_ids[i:i + batch_size]
            batch_fetched, batch_errors = process_host_batch(falcon, adapter, batch)
            fetched_count += batch_fetched
            error_count += batch_errors
            progress.update(task, advance=len(batch))

    return {
        'total_hosts': total_hosts,
        'fetched': fetched_count,
        'errors': error_count
    }


def fetch_hosts_simple(falcon: APIHarnessV2, adapter, host_ids: List[str],
                       batch_size: int, ctx) -> Dict:
    """Fetch hosts without progress bar.

    Args:
        falcon: FalconPy API client
        adapter: Database adapter
        host_ids: List of host IDs
        batch_size: Batch size for API calls
        ctx: CLI context

    Returns:
        Result dictionary with counts
    """
    total_hosts = len(host_ids)
    fetched_count = 0
    error_count = 0

    ctx.log_verbose(f"Fetching details for {total_hosts} hosts...")

    # Process in batches
    for i in range(0, total_hosts, batch_size):
        batch = host_ids[i:i + batch_size]
        batch_fetched, batch_errors = process_host_batch(falcon, adapter, batch)
        fetched_count += batch_fetched
        error_count += batch_errors

    return {
        'total_hosts': total_hosts,
        'fetched': fetched_count,
        'errors': error_count
    }
