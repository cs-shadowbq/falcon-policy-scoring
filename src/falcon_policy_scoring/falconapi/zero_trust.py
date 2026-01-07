"""
Zero Trust Assessment API utilities.

Handles fetching Zero Trust Assessment data for hosts.
"""

import logging
from typing import Dict, List, Optional


def fetch_zero_trust_assessments(falcon, device_ids: List[str]) -> Dict:
    """
    Fetch Zero Trust Assessment data for a list of device IDs (AIDs).

    Uses the getAssessmentV1 API endpoint which accepts device IDs (AIDs)
    and returns ZTA assessment data including:
    - aid: Agent/Device ID
    - cid: Customer ID
    - assessment: Dict with sensor_config, os, and overall scores
    - assessment_items: Dict with os_signals and sensor_signals arrays
    - modified_time: Last update timestamp
    - sensor_file_status: Deployment status

    Args:
        falcon: FalconPy APIHarnessV2 instance
        device_ids: List of device IDs (AIDs) to fetch assessments for

    Returns:
        dict: {
            'assessments': {device_id: assessment_data},
            'count': int,
            'errors': list of error dicts
        }
    """
    if not device_ids:
        logging.warning("No device IDs provided for ZTA fetch")
        return {'assessments': {}, 'count': 0, 'errors': []}

    logging.info("Fetching Zero Trust Assessments for %s devices...", len(device_ids))

    assessments = {}
    errors = []

    try:
        # Fetch in batches of 100 (API limit)
        batch_size = 100
        for i in range(0, len(device_ids), batch_size):
            batch = device_ids[i:i + batch_size]

            response = falcon.command('getAssessmentV1', ids=batch)

            if response['status_code'] == 200:
                resources = response['body'].get('resources', [])
                logging.info("Retrieved %s ZTA assessments from batch", len(resources))

                # Index by device ID (aid)
                for assessment in resources:
                    aid = assessment.get('aid')
                    if aid:
                        assessments[aid] = assessment

                # Capture any errors
                batch_errors = response['body'].get('errors', [])
                if batch_errors:
                    errors.extend(batch_errors)
                    logging.warning("Batch had %s errors", len(batch_errors))
            else:
                error_msg = f"Failed to fetch ZTA batch: status {response['status_code']}"
                logging.error(error_msg)
                errors.append({
                    'code': response['status_code'],
                    'message': error_msg,
                    'batch_start': i
                })

    except Exception as e:
        error_msg = f"Exception during ZTA fetch: {str(e)}"
        logging.error(error_msg)
        errors.append({
            'code': 'EXCEPTION',
            'message': error_msg
        })

    logging.info("ZTA fetch complete: %s assessments, %s errors", len(assessments), len(errors))

    return {
        'assessments': assessments,
        'count': len(assessments),
        'errors': errors
    }


def query_assessments_by_score(falcon, filter_expr: str = "score:>=0",
                               limit: int = 100, sort: str = "score|desc") -> Dict:
    """
    Query Zero Trust Assessment AIDs by score criteria.

    Uses getAssessmentsByScoreV1 to find devices matching score criteria.
    This is useful for finding devices with low ZTA scores.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        filter_expr: FQL filter expression (e.g., "score:<50")
        limit: Maximum results to return
        sort: Sort specification ("score|asc" or "score|desc")

    Returns:
        dict: {
            'results': [{'aid': str, 'score': int}, ...],
            'count': int,
            'total': int from pagination metadata
        }
    """
    logging.info("Querying ZTA scores with filter: %s", filter_expr)

    try:
        response = falcon.command('getAssessmentsByScoreV1',
                                  filter=filter_expr,
                                  limit=limit,
                                  sort=sort)

        if response['status_code'] == 200:
            resources = response['body'].get('resources', [])
            meta = response['body'].get('meta', {})
            pagination = meta.get('pagination', {})
            total = pagination.get('total', len(resources))

            logging.info("Query returned %s results (total: %s)", len(resources), total)

            return {
                'results': resources,
                'count': len(resources),
                'total': total
            }
        else:
            error_msg = f"ZTA query failed: status {response['status_code']}"
            logging.error(error_msg)
            return {
                'results': [],
                'count': 0,
                'total': 0,
                'error': error_msg
            }

    except Exception as e:
        error_msg = f"Exception during ZTA query: {str(e)}"
        logging.error(error_msg)
        return {
            'results': [],
            'count': 0,
            'total': 0,
            'error': error_msg
        }


def get_audit_report(falcon) -> Optional[Dict]:
    """
    Fetch the Zero Trust Assessment audit report for the CID.

    Returns aggregate ZTA information including average scores by platform.

    Args:
        falcon: FalconPy APIHarnessV2 instance

    Returns:
        dict: Audit report data or None if fetch fails
    """
    logging.info("Fetching ZTA audit report...")

    try:
        response = falcon.command('getAuditV1')

        if response['status_code'] == 200:
            resources = response['body'].get('resources', [])
            if resources:
                logging.info("ZTA audit report retrieved")
                return resources[0]  # Should be single resource with CID-level data
            else:
                logging.warning("ZTA audit report returned no resources")
                return None
        else:
            logging.error("Failed to fetch ZTA audit: status %s", response['status_code'])
            return None

    except Exception as e:
        logging.error("Exception fetching ZTA audit: %s", str(e))
        return None
