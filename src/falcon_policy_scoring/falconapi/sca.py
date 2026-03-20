"""Secure Configuration Assessment (SCA) API utilities.

Fetches SCA findings from the Configuration Assessment API and synthesises:
  - Virtual policy objects derived from host record SCA assignments
  - A per-host coverage index mapping device_id -> finding metadata

The SCA policy management API (/api2/policies/entities/sca/v1) is internal-only
and not accessible via OAuth2.  Instead we:

  1. Read each stored host record to discover which SCA policy_id is applied
     (from device_policies['sca']['policy_id'] and the host's platform_name).
  2. Group those hosts by policy_id — there are far fewer unique policies (P)
     than hosts (N), typically 3–500 vs potentially 100,000+.
  3. For each unique policy, probe with a small sample of its AIDs.  If the
     probe returns no findings the policy has no rule groups (Default Policy or
     empty custom policy) and ALL its hosts are immediately marked FAILED with
     zero additional API calls.
  4. For policies whose probe returns findings, fetch the remaining AIDs in
     batches.  Only "live" hosts (M << N) incur full-fetch cost.
  5. Build virtual policy objects for every (policy_id, platform) pair —
     live policies have has_rule_groups=True, dead ones False.

Complexity: O(P + M/100) API calls vs the naive O(N/100) baseline, where
  P = unique SCA policies, M = hosts on live policies, N = total hosts.

Note on FQL fields: getCombinedAssessmentsQuery documents filter examples for
  `aid`, `created_timestamp`, and `updated_timestamp`.  Filtering by
  `finding.rule.policy_id` (a response-body path) is not guaranteed by the
  documented API contract, so we deliberately avoid it and rely only on `aid`.

Required API scope: configuration-assessment:read
"""

import logging
import time
from typing import Dict, List, Optional, Set, Tuple

# Maximum AIDs per getCombinedAssessmentsQuery call — keeps FQL strings short
_AID_BATCH_SIZE = 100

# Exactly one representative AID is needed to probe whether a policy has
# rule groups configured.  If the probe returns any findings the policy is
# live (has_rule_groups=True) and ALL hosts on it grade PASSED via the
# policy grading map — no per-host API calls are required.
_PROBE_SIZE = 1


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


def _group_aids_by_policy(
    host_sca_assignments: Dict[str, Dict]
) -> Dict[str, Dict]:
    """Invert the aid→policy map into a policy→aids map.

    Grouping by policy is the key to the O(P + M/100) optimisation: we probe
    once per unique policy (P is small) rather than once per 100 hosts.

    Args:
        host_sca_assignments: {aid: {'sca_policy_id': str, 'platform_name': str}}
            as returned by _get_host_sca_assignments().

    Returns:
        Dict mapping policy_id -> {
            'platform': str (normalised),
            'aids': [str, ...],
        }
    """
    groups: Dict[str, Dict] = {}
    for aid, info in host_sca_assignments.items():
        policy_id = info['sca_policy_id']
        platform = _normalise_platform(info.get('platform_name', 'Unknown'))
        if policy_id not in groups:
            groups[policy_id] = {'platform': platform, 'aids': []}
        groups[policy_id]['aids'].append(aid)
    logging.info(
        "Grouped %d hosts into %d unique SCA policies",
        len(host_sca_assignments), len(groups)
    )
    return groups


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


def _fetch_aids_batched(
    falcon,
    aids: List[str],
    limit: int = 5000,
) -> Tuple[List[Dict], bool, Optional[str]]:
    """Fetch findings for an explicit list of AIDs, batched at _AID_BATCH_SIZE.

    This is the inner loop used by both the probe-then-fetch strategy and the
    broad fallback path.  It does NOT probe — every AID in the list is queried.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        aids: List of device IDs to fetch findings for
        limit: Maximum records per API page (max 5000)

    Returns:
        Tuple of (findings, permission_error, assist_message)
    """
    all_findings: List[Dict] = []
    for batch_start in range(0, len(aids), _AID_BATCH_SIZE):
        batch = aids[batch_start:batch_start + _AID_BATCH_SIZE]
        findings_batch, permission_error, assist_msg = _fetch_findings_page(
            falcon, _build_aid_filter(batch), limit
        )
        if permission_error:
            return [], True, assist_msg
        all_findings.extend(findings_batch)
        logging.debug(
            "Batch %d-%d: %d findings (running total: %d)",
            batch_start, batch_start + len(batch), len(findings_batch), len(all_findings)
        )
    return all_findings, False, None


def _fetch_findings_policy_first(
    falcon,
    policy_groups: Dict[str, Dict],
    limit: int = 5000,
    verbose_print=None,
) -> Tuple[List[Dict], Set[str], bool, Optional[str]]:
    """Fetch SCA findings using a policy-first probe strategy.

    Complexity is O(P) API calls where P = number of unique SCA policies.
    For each unique policy exactly ONE AID is probed.  If the probe returns
    any findings the policy is live (has rule groups) and is added to the
    policy grading map as PASS.  If the probe returns no findings the policy
    is dead (no rule groups) and ALL its hosts grade FAIL immediately — no
    further API calls are needed for that policy.

    The coverage index is built from host records + the policy grading map
    in fetch_sca_policies(), so no remaining-AID fetching is required after
    a successful probe.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        policy_groups: {policy_id: {'platform': str, 'aids': [str, ...]}}
            as returned by _group_aids_by_policy().
        limit: Maximum records per API page (max 5000)
        verbose_print: Optional callable(str) for console-visible progress
            messages (e.g. ctx.log_verbose).  Pass None to suppress.

    Returns:
        Tuple of (probe_findings, dead_policy_ids, permission_error, assist_message)
        probe_findings: findings returned by the single probe AID for each
            live policy.  Used only for policy-name/platform extraction in
            _build_virtual_policies(); the coverage index is NOT derived from
            these findings.
        dead_policy_ids: policy IDs whose probe returned no findings.
    """
    probe_findings: List[Dict] = []
    dead_policy_ids: Set[str] = set()

    for policy_id, group_info in policy_groups.items():
        aids = group_info['aids']
        probe_aid = aids[:_PROBE_SIZE]  # exactly one AID
        platform = group_info['platform']
        n_hosts = len(aids)

        logging.info(
            "Probing policy %s… (platform=%s, %d hosts)",
            policy_id[:8], platform, n_hosts,
        )
        if verbose_print:
            verbose_print(
                f"  [SCA] Probing policy {policy_id[:8]}… (platform={platform}, {n_hosts} hosts)"
            )

        probe_result, permission_error, assist_msg = _fetch_findings_page(
            falcon, _build_aid_filter(probe_aid), limit
        )
        if permission_error:
            return [], set(), True, assist_msg

        if not probe_result:
            # No findings → policy has no rule groups; all its hosts FAIL.
            dead_policy_ids.add(policy_id)
            logging.info(
                "  → DEAD: 0 findings for probe host — marking %d hosts as FAILED",
                n_hosts,
            )
            if verbose_print:
                verbose_print(
                    f"  [SCA]   → DEAD (no rule groups) — {n_hosts} hosts will be FAILED"
                )
            continue

        # Probe returned findings → policy is live.  Collect probe data for
        # virtual-policy name extraction; skip remaining AIDs entirely.
        probe_findings.extend(probe_result)
        logging.info(
            "  → LIVE: %d findings from probe host (%d remaining hosts skipped)",
            len(probe_result), n_hosts - _PROBE_SIZE,
        )
        if verbose_print:
            verbose_print(
                f"  [SCA]   → LIVE ({len(probe_result)} findings) — {n_hosts} hosts will be PASSED"
            )

    live_count = len(policy_groups) - len(dead_policy_ids)
    logging.info(
        "Policy-first probe complete: %d live, %d dead (%d total policies)",
        live_count, len(dead_policy_ids), len(policy_groups),
    )
    if verbose_print:
        verbose_print(
            f"  [SCA] Probe complete: {live_count} live, {len(dead_policy_ids)} dead"
            f" (of {len(policy_groups)} unique policies)"
        )
    return probe_findings, dead_policy_ids, False, None


def _fetch_all_sca_findings(
    falcon,
    aids: Optional[List[str]] = None,
    limit: int = 5000,
) -> Tuple[List[Dict], bool, Optional[str]]:
    """Fetch all SCA findings using a broad filter (fallback / shim path).

    Used by query_combined_sca_policies() which has no host-record context.
    The preferred path for fetch_sca_policies() is _fetch_findings_policy_first()
    because it is O(P + M/100) rather than O(N/100).

    When *aids* is provided, all AIDs are fetched in batches with no probing.
    When *aids* is None, a broad date filter retrieves all CID-wide findings.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        aids: Optional list of device IDs to filter by
        limit: Maximum records per API page (max 5000)

    Returns:
        Tuple of (findings, permission_error, assist_message)
    """
    if aids:
        findings, permission_error, assist_msg = _fetch_aids_batched(falcon, aids, limit)
        if permission_error:
            return [], True, assist_msg
        logging.info("Fetched %d SCA findings total (aid-batched)", len(findings))
        return findings, False, None

    fallback_filter = "created_timestamp:>='2000-01-01T00:00:00Z'"
    logging.info("No host AIDs provided; using broad date filter for SCA findings")
    findings, permission_error, assist_msg = _fetch_findings_page(
        falcon, fallback_filter, limit
    )
    if permission_error:
        return [], True, assist_msg
    logging.info("Fetched %d SCA findings total (broad filter)", len(findings))
    return findings, False, None


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
    dead_policy_ids: Optional[Set[str]] = None,
) -> List[Dict]:
    """Build virtual policy objects representing every SCA policy seen across the fleet.

    Three sources are merged in priority order:
    1. Findings from getCombinedAssessmentsQuery  -> has_rule_groups=True
       (the presence of findings proves rule groups are configured).
    2. dead_policy_ids from _fetch_findings_policy_first()  -> has_rule_groups=False
       (probe returned no findings; these are confirmed null-finding policies).
    3. Host record SCA assignments not covered by either source above  ->
       has_rule_groups=False (fallback for the broad-filter / shim path where
       dead_policy_ids is not available).

    Args:
        findings: List of finding resources from getCombinedAssessmentsQuery
        host_sca_assignments: Optional {aid: {sca_policy_id, platform_name}}
            from _get_host_sca_assignments().
        dead_policy_ids: Optional set of policy IDs confirmed by probing to have
            no findings.  Provided by _fetch_findings_policy_first(); not
            available on the broad-filter / shim path.

    Returns:
        List of virtual policy dicts with keys:
            id, name, platform_name, is_enabled, has_rule_groups
    """
    seen: Dict[Tuple, Dict] = {}

    # Source 1: live policies derived from findings
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

    # Build a policy-name lookup from findings (used for dead-policy names)
    policy_name_map: Dict[str, str] = {}
    for finding in findings:
        rule = finding.get('finding', {}).get('rule', {})
        pid = rule.get('policy_id')
        pname = rule.get('policy_name')
        if pid and pname:
            policy_name_map[pid] = pname

    # Source 2: dead policies confirmed by probe (policy-first path)
    if dead_policy_ids and host_sca_assignments:
        for pid in dead_policy_ids:
            # Find the platform for this policy from host records
            for aid_info in host_sca_assignments.values():
                if aid_info.get('sca_policy_id') == pid:
                    platform_name = _normalise_platform(
                        aid_info.get('platform_name', 'Unknown')
                    )
                    key = (pid, platform_name)
                    if key not in seen:
                        seen[key] = {
                            'id': pid,
                            'name': policy_name_map.get(pid, 'Unknown SCA Policy'),
                            'platform_name': platform_name,
                            'is_enabled': True,
                            'has_rule_groups': False,
                        }
                    break  # one platform sample per dead policy is enough

    # Source 3: fallback for the broad-filter / shim path (no dead_policy_ids)
    # Covers any (policy_id, platform) pair in host records not yet in seen.
    if host_sca_assignments and not dead_policy_ids:
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


def _build_sca_coverage_index_from_map(
    host_sca_assignments: Dict[str, Dict],
    policy_grading_map: Dict[str, bool],
) -> Dict[str, Dict]:
    """Build a per-host SCA coverage index from host records and a policy grading map.

    Covers ALL hosts that have an SCA policy assignment, not just those whose
    AID appeared in the getCombinedAssessmentsQuery response.  This is the
    correct approach when using the policy-first probe strategy: one probe
    per unique policy answers the has_rule_groups question for every host
    assigned to that policy without further API calls.

    Args:
        host_sca_assignments: {aid: {'sca_policy_id': str, 'platform_name': str}}
            as returned by _get_host_sca_assignments().
        policy_grading_map: {policy_id: bool} where True = live policy
            (has rule groups → host PASSES) and False = dead policy.

    Returns:
        Dict mapping aid -> {
            'policy_id': str,
            'has_findings': bool,   # True → PASSED, False → FAILED
            'finding_count': int,   # -1 = live policy (exact count unknown)
        }
    """
    index: Dict[str, Dict] = {}
    for aid, info in host_sca_assignments.items():
        policy_id = info['sca_policy_id']
        has_findings = policy_grading_map.get(policy_id, False)
        index[aid] = {
            'policy_id': policy_id,
            'has_findings': has_findings,
            'finding_count': -1 if has_findings else 0,
        }
    logging.info(
        "SCA coverage index built from map: %d hosts (%d PASSED, %d FAILED)",
        len(index),
        sum(1 for v in index.values() if v['has_findings']),
        sum(1 for v in index.values() if not v['has_findings']),
    )
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


def fetch_sca_policies(
    falcon,
    db_adapter,
    cid: str,
    force_refresh: bool = False,
    verbose_print=None,
) -> Dict:
    """Fetch SCA virtual policies and coverage index, then persist to DB.

    Workflow:
      1. Read all stored host records to discover which SCA policy_id is applied
         to each host (device_policies['sca']['policy_id']).
      2. Group hosts by unique policy_id (P unique policies, N total hosts,
         P << N in real environments).
      3. Probe exactly ONE AID per unique policy via getCombinedAssessmentsQuery.
         If findings are returned the policy is live (has rule groups → PASS).
         If no findings, the policy is dead (no rule groups → all hosts FAIL).
      4. Build policy_grading_map {policy_id: bool} from probe results.
      5. Build virtual policy objects for every unique (policy_id, platform) pair.
      6. Build the per-host coverage index from host records + policy_grading_map
         so EVERY host gets a status without additional API calls.
      7. Persist everything to the database.

    Complexity: O(P) API calls where P = unique SCA policies.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        db_adapter: Database adapter instance
        cid: Customer ID
        force_refresh: If True, bypass cache and fetch fresh data
        verbose_print: Optional callable(str) for console-visible progress
            messages (e.g. ctx.log_verbose).  Pass None to suppress.

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
        # Step 1: Read host SCA policy assignments from DB — O(N) DB reads
        host_sca_assignments = _get_host_sca_assignments(db_adapter, cid)

        if not host_sca_assignments:
            logging.warning(
                "No host records with SCA policy assignments found for CID %s; "
                "using broad fallback filter — run 'fetch' first to populate host records",
                cid
            )
            if verbose_print:
                verbose_print("[SCA] No host SCA assignments in DB — using broad fallback filter")
            # Broad fallback: no host context available
            findings, permission_error, assist_message = _fetch_all_sca_findings(
                falcon, aids=None, limit=5000
            )
            if permission_error:
                return {
                    'cid': cid,
                    'epoch': int(time.time()),
                    'policies': [],
                    'total': 0,
                    'permission_error': True,
                    'assist_message': assist_message,
                }
            dead_policy_ids: Set[str] = set()
            policy_grading_map: Dict[str, bool] = {}
        else:
            # Step 2: Group by policy_id — O(P) probes instead of O(N/100)
            policy_groups = _group_aids_by_policy(host_sca_assignments)
            n_hosts = len(host_sca_assignments)
            n_policies = len(policy_groups)
            logging.info(
                "SCA: %d hosts across %d unique policies — probing each policy (1 AID each)…",
                n_hosts, n_policies,
            )
            if verbose_print:
                verbose_print(
                    f"[SCA] {n_hosts} hosts → {n_policies} unique policies to probe"
                    f" (1 API call per policy)"
                )

            # Step 3: One probe per policy — O(P) API calls total
            findings, dead_policy_ids, permission_error, assist_message = \
                _fetch_findings_policy_first(
                    falcon, policy_groups, limit=5000, verbose_print=verbose_print
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

            live_policy_ids = set(policy_groups) - dead_policy_ids
            logging.info(
                "SCA: %d live policies, %d dead policies (%d total)",
                len(live_policy_ids), len(dead_policy_ids), n_policies,
            )

            # Step 4: Build policy grading map {policy_id: True=PASS / False=FAIL}
            policy_grading_map = {pid: True for pid in live_policy_ids}
            policy_grading_map.update({pid: False for pid in dead_policy_ids})

        # Step 5: Build virtual policies using probe findings + dead policy set
        virtual_policies = _build_virtual_policies(
            findings, host_sca_assignments, dead_policy_ids
        )

        # Step 6: Build per-host coverage index from host records + grading map.
        # Every host with an SCA assignment gets a status — no additional API calls.
        if host_sca_assignments and policy_grading_map:
            coverage_index = _build_sca_coverage_index_from_map(
                host_sca_assignments, policy_grading_map
            )
        else:
            # Fallback path (no host records): derive index from findings only
            coverage_index = _build_sca_coverage_index(findings)

        if verbose_print:
            n_passed = sum(1 for v in coverage_index.values() if v.get('has_findings'))
            n_failed = len(coverage_index) - n_passed
            verbose_print(
                f"[SCA] Coverage index: {len(coverage_index)} hosts"
                f" ({n_passed} PASSED, {n_failed} FAILED)"
            )

        # Step 7: Persist
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
