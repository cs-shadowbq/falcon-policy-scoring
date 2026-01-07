"""JSON output writer for daemon mode with timestamped files."""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import gzip
import sys
from falcon_policy_scoring.utils.datetime_utils import get_filename_timestamp, get_utc_iso_timestamp
from falcon_policy_scoring.utils.metadata_builder import build_report_metadata
from falcon_policy_scoring.utils.exceptions import ReportGenerationError
from falcon_policy_scoring.utils.json_builder import redact_sensitive_args


logger = logging.getLogger(__name__)


class JsonWriter:
    """Write JSON reports to timestamped files."""

    def __init__(self, output_dir: str, compress: bool = False):
        """Initialize JSON writer.

        Args:
            output_dir: Directory for output files
            compress: Whether to gzip compress output files
        """
        self.output_dir = Path(output_dir)
        self.compress = compress

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("JSON writer initialized. Output dir: %s", self.output_dir)

    def write_report(self, report_type: str, data: Dict[str, Any],
                     metadata: Optional[Dict[str, Any]] = None, config: Optional[Dict[str, Any]] = None) -> Path:
        """Write a JSON report to a timestamped file.

        Args:
            report_type: Type of report (e.g., 'policy-audit', 'host-summary')
            data: Report data to write
            metadata: Optional metadata to include in report (should include cid, database_type)
            config: Configuration dictionary for optional metadata fields

        Returns:
            Path to written file
        """
        from falcon_policy_scoring import __version__ as APP_VERSION

        timestamp = get_filename_timestamp()
        filename = f"{report_type}_{timestamp}.json"

        if self.compress:
            filename += ".gz"

        filepath = self.output_dir / filename

        # Build standardized metadata matching host-details format
        redacted_args = redact_sensitive_args(sys.argv)
        standard_metadata = {
            'version': APP_VERSION,
            'timestamp': get_utc_iso_timestamp(),
            'report_type': report_type,
            'command': ' '.join(redacted_args)
        }

        # Merge in any additional metadata provided
        if metadata:
            standard_metadata.update(metadata)

        # Add optional client metadata based on config settings (matching host-details format)
        if config:
            optional_metadata = build_report_metadata(config)
            standard_metadata.update(optional_metadata)

        # Build report structure with metadata at top level
        report = {
            'metadata': standard_metadata
        }
        report.update(data)

        try:
            if self.compress:
                # Write compressed JSON
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, default=str)
            else:
                # Write plain JSON
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, default=str)

            file_size = filepath.stat().st_size
            logger.info("Wrote report to %s (%s bytes)", filepath, f"{file_size:,}")
            return filepath

        except IOError as e:
            error_msg = f"Failed to write report to {filepath}: {e}"
            logger.error(error_msg)
            raise ReportGenerationError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error writing report to {filepath}: {e}"
            logger.error(error_msg)
            raise ReportGenerationError(error_msg) from e

    def write_policy_audit(self, cid: str, policies: Dict[str, Any],
                           summary: Dict[str, Any], config: Dict[str, Any]) -> Path:
        """Write a policy audit report.

        Args:
            cid: Customer ID
            policies: Policy data
            summary: Summary statistics
            config: Configuration dictionary

        Returns:
            Path to written file
        """
        data = {
            'summary': summary,
            'policies': policies
        }

        metadata = {
            'cid': cid,
            'database_type': config.get('db', {}).get('type', 'sqlite')
        }

        return self.write_report('policy-audit', data, metadata, config)

    def write_host_summary(self, cid: str, hosts: list,
                           summary: Dict[str, Any], config: Dict[str, Any]) -> Path:
        """Write a host summary report.

        Args:
            cid: Customer ID
            hosts: Host data (list of device IDs)
            summary: Summary statistics (total_hosts, hosts_all_passed, hosts_any_failed)
            config: Configuration dictionary

        Returns:
            Path to written file
        """
        data = {
            'summary': summary,
            'hosts': hosts
        }

        metadata = {
            'cid': cid,
            'database_type': config.get('db', {}).get('type', 'sqlite')
        }

        return self.write_report('host-summary', data, metadata, config)

    def write_metrics(self, metrics: Dict[str, Any], cid: str, config: Dict[str, Any]) -> Path:
        """Write daemon metrics.

        Args:
            metrics: Metrics data
            cid: Customer ID
            config: Configuration dictionary

        Returns:
            Path to written file
        """
        metadata = {
            'cid': cid,
            'database_type': config.get('db', {}).get('type', 'sqlite')
        }

        return self.write_report('metrics', metrics, metadata, config)

    def write_host_details(self, adapter, cid: str, config: Dict[str, Any]) -> Path:
        """Write comprehensive host details matching the policy_audit_output.schema.json.

        This generates the same output as './bin/policy-audit hosts --output json'
        with full policy grading and host information.

        Args:
            adapter: Database adapter
            cid: Customer ID
            config: Configuration dictionary

        Returns:
            Path to written file
        """
        from falcon_policy_scoring.utils.json_builder import build_json_output
        from argparse import Namespace

        # Create a mock args object that requests hosts and all policy types
        args = Namespace(
            show_hosts=True,
            policy_type='all',
            platform=None,
            status=None,
            hostname=None,
            host_status=None,
            output_file=None
        )

        # Build the JSON output using the CLI's json builder (matches schema)
        json_data = build_json_output(adapter, cid, config, args)

        # Write directly using the timestamped filename format
        timestamp = get_filename_timestamp()
        filename = f"host-details_{timestamp}.json"

        if self.compress:
            filename += ".gz"

        filepath = self.output_dir / filename

        try:
            if self.compress:
                # Write compressed JSON
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, default=str)
            else:
                # Write plain JSON
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, default=str)

            file_size = filepath.stat().st_size
            logger.info("Wrote host details to %s (%s bytes)", filepath, f"{file_size:,}")
            return filepath

        except Exception as e:
            logger.error("Failed to write host details to %s: %s", filepath, e)
            raise

    def cleanup_old_files(self, max_age_days: int = 30, max_files: Optional[int] = None) -> int:
        """Clean up old report files.

        Args:
            max_age_days: Delete files older than this many days
            max_files: Keep only this many most recent files per report type

        Returns:
            Number of files deleted
        """
        deleted_count = 0

        try:
            # Get all JSON files
            pattern = "*.json.gz" if self.compress else "*.json"
            all_files = sorted(self.output_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)

            # Group by report type
            files_by_type: Dict[str, list] = {}
            for filepath in all_files:
                # Extract report type from filename (type_timestamp.json)
                # Format: report-type_YYYY-MM-DD_HH-MM-SS_TZ.json
                stem = filepath.stem.replace('.json', '')
                # Split on '_' and take everything before the date (YYYY-MM-DD pattern)
                parts = stem.split('_')
                # Find the date part (matches YYYY-MM-DD pattern)
                date_index = None
                for i, part in enumerate(parts):
                    if len(part) == 10 and part[4] == '-' and part[7] == '-':
                        date_index = i
                        break
                if date_index and date_index > 0:
                    report_type = '_'.join(parts[:date_index])
                    files_by_type.setdefault(report_type, []).append(filepath)

            # Delete by age
            cutoff_time = datetime.now().timestamp() - (max_age_days * 86400)
            for filepath in all_files:
                if filepath.stat().st_mtime < cutoff_time:
                    filepath.unlink()
                    deleted_count += 1
                    logger.debug("Deleted old file: %s", filepath)

            # Delete by count (per report type)
            if max_files:
                for report_type, files in files_by_type.items():
                    if len(files) > max_files:
                        for filepath in files[max_files:]:
                            if filepath.exists():  # May have been deleted by age check
                                filepath.unlink()
                                deleted_count += 1
                                logger.debug("Deleted excess file: %s", filepath)

            if deleted_count > 0:
                logger.info("Cleaned up %s old report files", deleted_count)

        except Exception as e:
            logger.error("Error cleaning up old files: %s", e)

        return deleted_count

    def get_latest_report(self, report_type: str) -> Optional[Path]:
        """Get the most recent report of a given type.

        Args:
            report_type: Type of report to find

        Returns:
            Path to most recent report, or None if not found
        """
        pattern = f"{report_type}_*.json"
        if self.compress:
            pattern += ".gz"

        files = sorted(self.output_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        return files[0] if files else None
