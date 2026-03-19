"""Secure Configuration Assessment (SCA) API utilities.

Fetches SCA findings from the Configuration Assessment API and synthesises:
  - Virtual policy objects derived from host record SCA assignments
  - A per-host coverage index mapping device_id -> finding metadata

The SCA policy management API (/api2/policies/entities/sca/v1) is internal-only
and not accessible via OAuth2.  Instead we:

  1. Read each stored host record to discover which SCA policy_id is applied
     (from device_policies['sca']['policy_id'] and the host's platform_name).
  2. Query getCombinedAssessmentsQuery with an FQL filter built from those AIDs
     so we can tell whether each host actually has SCA findings.
     The presence of findings for a host confirms that its SCA policy is both
     enabled *and* has rule groups configured.
  3. Build virtual policy objects that represent every unique (policy_id, platform)
     pair seen across the fleet — including "default" policies that have no
     findings and therefore FAIL grading.

Required API scope: configuration-assessment:read
"""

import logging
import time
from typing import Dict, List, Optional, Tuple

# Batch size for AID filter strings — 100 AIDs per API call keeps FQL short
_AID_BATCH_SIZE = 100


def _get_host_sca_assignments(db_adapter, cid: str) -> Dict[str, Dict]:
    """Extract the SCA policy assignment for every stored host record.

    Iterates the host list stored in the database and reads each host's
    device_policies['sca'] block to obtain the applied policy_id and the
    host's platform_name.

    Args:
        db_adapter: Database adapter instance
        cid: Customer ID

    Returns:
        Dict mapping aid -> {
            'sca_policy_id': str,
            'platform_name': str,
        }
        Empty dict when no hosts or no SCA assignments found.
    """
    assignments: Dict[str, Dict] = {}

    hosts_record = db_adapter.get_hosts(cid)
    if not hosts_record:
        logging.warning("No hosts found in DB for CID %s; cannot build SCA aid filter", cid)
        return assignments

    aids = hosts_record.get('hosts', [])
    logging.info("Building SCA assignments map for %d stored hosts…", len(aids))

    for aid in aids:
        host_rec = db_adapter.get_host(aid)
        if not host_rec:
            continue
        data = host_rec.get('data', {})
        dp = data.get('device_policies', {})

        # Key is 'sca' (not 'sca_policy')
        sca_info = dp.get('sca')
        if not sca_info:
            continue

        sca_policy_id = sca_info.get('policy_id')
        if not sca_policy_id:
            continue

        platform = data.get('platform_name', 'Unknown')
        assignments[aid] = {
            'sca_policy_id': sca_policy_id,
            'platform_name': platform,
        }

    logging.info(
        "SCA assignments: %d of %d hosts have an applied SCA policy",
        len(assignments), len(aids)
    )
    return assignments


def _build_aid_filter(aids: List[str]) -> str:
    """Build an FQL filter string matching a list of AIDs.

    Args:
        aids: List of device IDs (AIDs)

    Returns:
        FQL filter string, e.g. "aid:['abc123','def456']"
    """
    quoted = ",".join(f"'{a}'" for a in aids)
    return f"aid:[{quoted}]"


def _fetch_findings_page(
    falcon, filter_str: str, limit: int
) -> Tuple[List[Dict], bool, Optional[str]]:
    """Fetch all pages of SCA findings matching an FQL filter.

    Handles cursor-based pagination internally.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        filter_str: Required FQL filter string
        limit: Max records per page (≤5000)

    Returns:
        Tuple of (all_findings, permission_error, assist_message)
    """
    from falcon_policy_scoring.falconapi.policies import check_scope_permission_error

    weblink = ('https://www.falconpy.io/Service-Collections/'
               'Configuration-Assessment.html#getcombinedassessmentsquery')
    command = 'getCombinedAssessmentsQuery'
    all_findings: List[Dict] = []
    after_token: Optional[str] = None

    while True:
        kwargs: Dict = {
            'filter': filter_str,
            'facet': ['finding.rule'],
            'limit': limit,
        }
        if after_token:
            kwargs['after'] = after_token

        logging.debug(
            "Fetching SCA findings (filter=%r, after=%s, limit=%s)…",
            filter_str[:80], after_token, limit
        )
        response = falcon.command(command, **kwargs)

        is_permission_error, assist_msg = check_scope_permission_error(
            response, command, weblink
        )
        if is_permission_error:
            logging.warning("Permission error fetching SCA findings: %s", response.get('body', {}))
            return [], True, assist_msg

        if response.get('status_code') != 200:
            logging.warning(
                "Failed to fetch SCA findings (status %s): %s",
                response.get('status_code'), response.get('body', {})
            )
            break

        body = response.get('body') or {}
        resources = body.get('resources') or []
        all_findings.extend(resources)

        meta = body.get('meta', {})
        pagination = meta.get('pagination', {})
        total = pagination.get('total', 0)
        after_token = pagination.get('after')

        logging.debug(
            "SCA findings page: %d received, %d total so far (API total: %d)",
            len(resources), len(all_findings), total
        )

        if not resources or not after_token or len(all_findings) >= total:
            break

    return all_findings, False, None


def _fetch_all_sca_findings(
    falcon,
    aids: Optional[List[str]] = None,
    limit: int = 5000,
) -> Tuple[List[Dict], bool, Optional[str]]:
    """Fetch all SCA findings, optionally scoped to specific AIDs.

    When *aids* is provided the query is batched in groups of _AID_BATCH_SIZE
    to keep FQL filter strings short.  When *aids* is None a broad date filter
    is used as a fallback to retrieve all CID-wide findings.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        aids: Optional list of device IDs to filter by
        limit: Maximum records per API page (max 5000)

    Returns:
        Tuple of (findings, permission_error, assist_message)
    """
    all_findings: List[Dict] = []

    if aids:
        for batch_start in range(0, len(aids), _AID_BATCH_SIZE):
            batch = aids[batch_start:batch_start + _AID_BATCH_SIZE]
            filter_str = _build_aid_filter(batch)
            findings_batch, permission_error, assist_msg = _fetch_findings_page(
                falcon, filter_str, limit
            )
            if permission_error:
                return [], True, assist_msg
            all_findings.extend(findings_batch)
            logging.debug(
                "Batch %d-%d: fetched %d findings (running total: %d)",
                batch_start, batch_start + len(batch), len(findings_batch), len(all_findings)
            )
    else:
        fallback_filter = "created_timestamp:>='2000-01-01T00:00:00Z'"
        logging.info("No host AIDs provided; falling back to broad SCA findings filter")
        all_findings, permission_error, assist_msg = _fetch_findings_page(
            falcon, fallback_filter, limit
        )
        if permission_error:
            return [], True, assist_msg

    logging.info("Fetched %d SCA findings total", len(all_findings))
    return all_findings, False, None


def _normalise_platform(raw: str) -> str:
    """Map raw platform_name from host records to grading config names.

    Host records use 'Windows', 'Linux', 'Mac', 'Darwin', etc.
    Grading config expects 'Windows', 'Linux', 'Mac'.
    """
    mapping = {
        'darwin': 'Mac',
        'macos': 'Mac',
        'mac': 'Mac',
        'windows': 'Windows',
        'linux': 'Linux',
    }
    return mapping.get(raw.lower(), raw)


def _build_virtual_policies(
    findings: List[Dict],
    host_sca_assignments: Optional[Dict[str, Dict]] = None,
) -> List[Dict]:
    """Build virtual policy objects representing every SCA policy seen across the fleet.

    Two sources are merged:
    1. Findings from getCombinedAssessmentsQuery  -> confirms policy is enabled
       with rule groups (has_rule_groups=True for policies that produce findings).
    2. Host record SCA assignments (device_policies['sca'])  -> reveals policies
       assigned to hosts that produced *no* findings (has_rule_groups=False).

    Args:
        findings: List of finding resources from getCombinedAssessmentsQuery
        host_sca_assignments: Optional dict from _get_host_sca_assignments()

    Returns:
        List of virtual policy dicts with keys:
            id, name, platform_name, is_enabled, has_rule_groups
    """
    seen: Dict[Tuple, Dict] = {}

    for finding in findings:
        rule = finding.get('finding', {}).get('rule', {})
        policy_id = rule.get('policy_id')
        policy_name = rule.get('policy_name', 'Unknown')
        platform_name = rule.get('platform_name', 'Unknown')

        if not policy_id:
            continue

        key = (policy_id, platform_name)
        if key not in seen:
            seen[key] = {
                'id': policy_id,
                'name': policy_name,
                'platform_name': platform_name,
                'is_enabled': True,
                'has_rule_groups': True,
            }

    # Add policies from host records that had NO findings
    if host_sca_assignments:
        # Build policy-name lookup from findings
        policy_name_map: Dict[str, str] = {}
        for finding in findings:
            rule = finding.get('finding', {}).get('rule', {})
            pid = rule.get('policy_id')
            pname = rule.get('policy_name')
            if pid and pname:
                policy_name_map[pid] = pname

        # Collect unique (policy_id, normalised_platform) pairs from host records
        host_policy_pairs: Dict[Tuple, None] = {}
        for aid_info in host_sca_assignments.values():
            policy_id = aid_info.get('sca_policy_id')
            raw_platform = aid_info.get('platform_name', 'Unknown')
            platform_name = _normalise_platform(raw_platform)
            if policy_id:
                host_policy_pairs[(policy_id, platform_name)] = None

        for (policy_id, platform_name) in host_policy_pairs:
            key = (policy_id, platform_name)
            if key not in seen:
                # No findings for this policy -> has_rule_groups=False -> will FAIL grading
                seen[key] = {
                    'id': policy_id,
                    'name': policy_name_map.get(policy_id, 'Unknown SCA Policy'),
                    'platform_name': platform_name,
                    'is_enabled': True,
                    'has_rule_groups': False,
                }

    virtual_policies = list(seen.values())
    logging.info(
        "Built %d virtual SCA policies (%d with findings, %d without)",
        len(virtual_policies),
        sum(1 for p in virtual_policies if p['has_rule_groups']),
        sum(1 for p in virtual_policies if not p['has_rule_groups']),
    )
    return virtual_policies


def _build_sca_coverage_index(findings: List[Dict]) -> Dict[str, Dict]:
    """Build a per-host SCA coverage index from findings.

    Maps each assessed host's device_id to the metadata of the SCA policy it
    was assessed under, along with a running finding count.

    Args:
        findings: List of finding resources from getCombinedAssessmentsQuery

    Returns:
        Dict mapping device_id -> {
            'policy_id': str,
            'policy_name': str,
            'has_findings': True,
            'finding_count': int
        }
    """
    index: Dict[str, Dict] = {}

    for finding in findings:
        aid = finding.get('aid')
        if not aid:
            continue

        rule = finding.get('finding', {}).get('rule', {})
        policy_id = rule.get('policy_id', '')
        policy_name = rule.get('policy_name', 'Unknown')

        if aid not in index:
            index[aid] = {
                'policy_id': policy_id,
                'policy_name': policy_name,
                'has_findings': True,
                'finding_count': 0,
            }
        index[aid]['finding_count'] += 1

    logging.info("SCA coverage index built: %d hosts have findings", len(index))
    return index


def query_combined_sca_policies(falcon, limit: int = 5000, offset: int = 0) -> Dict:
    """Shim function matching the queryCombined*Policies response shape.

    Used by the generic policy fetch engine.  Fetches all SCA findings using a
    broad date filter (no host context available here) and returns synthesised
    virtual policy objects.  The offset parameter is honoured for pagination
    parity with other policy types.

    For the full host-context-aware fetch (the main grading path), see
    fetch_sca_policies() which uses the stored host records to build a targeted
    AID filter.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        limit: Maximum records to return per request
        offset: Starting index for the virtual policy list

    Returns:
        dict: API-shaped response with 'status_code' and 'body.resources'
    """
    findings, permission_error, assist_message = _fetch_all_sca_findings(falcon, aids=None, limit=limit)

    if permission_error:
        return {
            'status_code': 403,
            'body': {},
            'permission_error': True,
            'assist_message': assist_message,
        }

    virtual_policies = _build_virtual_policies(findings)
    paginated = virtual_policies[offset:offset + limit]

    return {
        'status_code': 200,
        'body': {
            'resources': paginated,
            'meta': {
                'pagination': {
                    'total': len(virtual_policies)
                }
            }
        }
    }


def fetch_sca_policies(falcon, db_adapter, cid: str, force_refresh: bool = False) -> Dict:
    """Fetch SCA virtual policies and coverage index, then persist to DB.

    Workflow:
      1. Read all stored host records to discover which SCA policy_id is applied
         to each host (device_policies['sca']['policy_id']).
      2. Query getCombinedAssessmentsQuery with an FQL filter built from those
         AIDs so we know exactly which hosts have SCA findings.
      3. Build virtual policy objects for every unique (policy_id, platform) pair
         across the fleet - including policies whose hosts have *no* findings
         (these will FAIL grading because they have no rule groups).
      4. Build the per-host coverage index.
      5. Persist everything to the database.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        db_adapter: Database adapter instance
        cid: Customer ID
        force_refresh: If True, bypass cache and fetch fresh data

    Returns:
        dict: {
            'policies': [list of virtual policy objects],
            'total': int,
            'cid': str,
            'epoch': int
        }
        On permission error, adds 'permission_error': True and 'assist_message': str.
    """
    if not force_refresh:
        cached = db_adapter.get_policies('sca_policies', cid)
        if cached and cached.get('policies'):
            logging.info("Using cached SCA policies: %d policies", len(cached['policies']))
            return cached

    logging.info("Fetching SCA findings and building virtual policies…")

    try:
        # Step 1: Get all host SCA policy assignments from DB
        host_sca_assignments = _get_host_sca_assignments(db_adapter, cid)
        aids = list(host_sca_assignments.keys()) if host_sca_assignments else None

        if not aids:
            logging.warning(
                "No host records with SCA policy assignments found for CID %s; "
                "using broad fallback filter - run 'fetch' first to populate host records",
                cid
            )

        # Step 2: Query findings (by AID filter if available, broad fallback otherwise)
        findings, permission_error, assist_message = _fetch_all_sca_findings(
            falcon, aids=aids, limit=5000
        )

        if permission_error:
            logging.warning("Permission error detected while fetching SCA findings")
            return {
                'cid': cid,
                'epoch': int(time.time()),
                'policies': [],
                'total': 0,
                'permission_error': True,
                'assist_message': assist_message,
            }

        logging.info(
            "SCA: fetched %d findings for %d hosts", len(findings), len(aids or [])
        )

        # Step 3: Build virtual policies (from both findings AND host records)
        virtual_policies = _build_virtual_policies(findings, host_sca_assignments)

        # Step 4: Build per-host coverage index
        coverage_index = _build_sca_coverage_index(findings)

        # Step 5: Persist
        db_adapter.put_policies('sca_policies', cid, {'body': {'resources': virtual_policies}})
        db_adapter.put_policies('sca_raw_findings', cid, {'body': {'resources': findings}})
        db_adapter.put_sca_coverage(cid, coverage_index)

        logging.info(
            "SCA: stored %d virtual policies, %d hosts in coverage index",
            len(virtual_policies), len(coverage_index)
        )

        return {
            'cid': cid,
            'epoch': int(time.time()),
            'policies': virtual_policies,
            'total': len(virtual_policies),
        }

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Exception fetching SCA policies: %s", e)
        import traceback
        traceback.print_exc()
        return {
            'cid': cid,
            'epoch': int(time.time()),
            'policies': [],
            'total': 0,
        }
