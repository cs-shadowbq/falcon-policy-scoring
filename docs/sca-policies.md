# Understanding Secure Configuration Assessment Policy Grading

## What Secure Configuration Assessment Policies Do

Secure Configuration Assessment (SCA) policies define the hardening benchmarks that CrowdStrike evaluates against your devices. A hardening benchmark is a set of security checks — things like verifying that unnecessary services are disabled, that password complexity settings meet minimums, or that auditing is turned on for sensitive actions. These checks correspond to industry standards such as CIS Benchmarks and DISA STIGs.

Within CrowdStrike, SCA policy rule groups hold the actual benchmark checks. A policy with rule groups assigned is actively evaluating your devices against those benchmarks. A policy with no rule groups does nothing — CrowdStrike cannot perform any configuration assessment without the checks that rule groups supply.

CrowdStrike provides a built-in Default Policy for each platform (Windows, Linux, and Mac). The Default Policy ships with no rule groups. Until you create a custom policy with rule groups and assign it to your devices, no hardening checks are taking place.

## Rule Groups Are OS-Version Specific, Not Platform-Specific

A critical distinction: rule groups are scoped to a specific **OS version**, not simply to a platform. A Windows rule group written for Windows 10 workstations is not applicable to a Windows Server 2019 host. If a Windows Server 2019 device is assigned to an SCA policy that only contains Windows 10 rule groups, CrowdStrike will not run any checks against that host — there are no matching rule groups for its OS version.

This has a direct impact on grading: a host with zero applicable rule group checks will return no findings. The tool interprets zero findings as no active assessment, and the host will **FAIL** grading. The policy is technically assigned to the host, but it is not *applicable* to it.

Common scenarios where this occurs:

- A Windows Server host (2016, 2019, 2022) assigned to a policy containing only Windows 10 or Windows 11 desktop rule groups.
- A RHEL 8 server host assigned to a policy whose only rule group targets Ubuntu 22.04.
- A new OS version introduced into the fleet before the corresponding rule group is added to the assigned policy.

To resolve this, ensure that each SCA policy contains rule groups that cover every OS version of the devices assigned to it. Separate policies for workstations and servers are a common and recommended approach.

## Why Secure Configuration Assessment Policies Matter

Configuration drift is one of the most common causes of security incidents. Operating systems and applications ship with many features enabled by default for ease of use, not security. Over time, administrators make changes that weaken security posture — often to solve an immediate operational problem — and those changes persist long after the original reason for them is gone.

Hardening benchmarks like CIS and STIG provide a tested, documented standard for what a well-configured system looks like. Having SCA policies with rule groups configured means CrowdStrike continuously checks your fleet for deviation from those standards and surfaces findings that require attention.

Devices on the Default Policy, or on a custom policy with no rule groups, receive no configuration assessment at all. You have no visibility into whether those devices are hardened correctly or whether they have drifted from a secure baseline. This is the risk the tool is measuring.

## How the Tool Grades SCA Policies

Known limitation: The tool cannot query the SCA policy management API directly using standard OAuth2 credentials — that API is internal to CrowdStrike. Instead, it uses the Configuration Assessment endpoint, which exposes the actual hardening findings for each device. The presence of findings for a device confirms that its assigned SCA policy is both enabled and has rule groups producing checks.

The grading process works as follows:

1. Every stored host record is read from the local database. Each host record includes the SCA policy ID and policy assignment from the device's policy information.
2. The Configuration Assessment API is queried using a filter that targets exactly those host IDs. This returns all SCA findings for your fleet.
3. A virtual policy object is synthesised for each unique (policy ID, platform) combination seen — both from the findings themselves and from the host records. This means policies that have hosts assigned to them but produced no findings (because the policy has no rule groups) are also represented and will fail grading.
4. Each virtual policy is graded: if findings exist for that policy, the policy is marked as having rule groups (pass); if no findings exist, it is marked as having no rule groups (fail).
5. A per-host coverage index is built so that each host can be shown an individual PASSED or FAILED status.

## What Gets Checked

The grading configuration for SCA policies is intentionally simple — two requirements apply identically across Windows, Linux, and Mac:

**Is enabled — must be `true`**: The SCA policy must be enabled. A disabled policy performs no assessment regardless of whether it has rule groups. This is expected to be true in nearly all environments; a disabled policy is almost always a configuration error.

**Has rule groups — must be `true`**: The SCA policy must have at least one rule group configured. Rule groups contain the actual benchmark checks. Without them, the policy is a placeholder that performs no evaluation. This is the check that distinguishes a properly configured custom policy from the Default Policy or an empty custom policy.

A policy must pass both requirements to receive a PASSED grade. In practice, the `has_rule_groups` check is where most failures occur: devices on the Default Policy, or on a newly created custom policy that has not yet been configured with benchmark checks, fail here.

## Understanding Per-Host Status

The tool reports SCA status at the individual host level, not just at the policy level. This reflects the fact that different devices in a large environment are often assigned to different policies — some to well-configured custom policies, others still on the Default Policy.

- **PASSED** — the device's assigned SCA policy is enabled and has rule groups. Assessment findings were returned for this device, confirming that hardening checks are actively running.
- **FAILED** — the device's assigned SCA policy either has no rule groups, or all configured rule groups are for a different OS version than the device is running. In both cases no assessment findings are returned, meaning no hardening checks are active for this device.
- **NOT GRADED** — SCA data has not yet been fetched. Run `fetch -t sca` to populate results.

A large number of FAILED hosts is common in environments that have not yet built custom SCA policies. The entire fleet may still be on the Default Policy, which means zero active hardening checks across all platforms.

## Policy Precedence and SCA Assignment

SCA policies follow the same precedence rules as all other Falcon policies. Hosts are evaluated against policies assigned to their host groups in priority order, and the highest-priority matching policy wins.

This matters for SCA because a host can be **promoted out** of a well-configured policy and into one that is not applicable for its OS version. For example:

- A Windows Server 2019 host is initially in a host group assigned a policy containing a Windows Server 2019 rule group — it passes.
- An administrator creates a broad Windows policy with only Windows 10 rule groups and assigns it at a higher priority.
- The server is now governed by the higher-priority policy, which has no applicable rule groups for Server 2019. The host will show FAILED despite being in a valid-looking policy.

When investigating unexpected FAILED status on hosts that appear to be correctly assigned, always check policy precedence in the Falcon console. The effective policy for a host may not be the most recently created or most obviously named one.

## Understanding the Results

**All Linux hosts showing FAILED**: Linux hosts assigned to the Default Linux SCA Policy receive this status. This is the most common pattern in environments where CrowdStrike was deployed without customising SCA policies. The Default Policy exists to let the SCA feature be enabled gradually — it is not a secure end-state.

**Windows hosts mixed between PASSED and FAILED**: This typically means some Windows devices were migrated to a custom SCA policy during a rollout, while others remain on the Default Policy. The host-level status view shows exactly which devices have been migrated.

**Windows Server hosts showing FAILED despite a custom policy being assigned**: The most likely cause is that the assigned policy contains only workstation (Windows 10/11) rule groups. Server OS versions (2016, 2019, 2022) require their own rule groups. A policy assigned to a server host but containing no matching rule groups for that server OS version will produce zero findings — the host fails for the same reason as a host on the Default Policy. Add a Server-appropriate rule group to the policy.

**A custom policy showing FAILED**: A policy can exist and be assigned to devices without any rule groups if it was created as a placeholder. Navigating to that policy in the Falcon console and checking whether rule groups are attached will confirm this. An empty custom policy has the same security impact as the Default Policy.

**No findings returned after fetch**: If `fetch -t sca` completes but reports zero findings, this almost always means all devices in your fleet are on policies with no rule groups, or all rule groups in assigned policies target a different OS version than the hosts being evaluated. The tool will still create FAILED virtual policy entries for every (policy ID, platform) pair discovered in host records, so hosts will show FAILED rather than NOT GRADED.

## Practical Application

When SCA policies are failing, the remediation path depends on whether custom policies exist:

**No custom SCA policies exist yet**: Create a new SCA policy in the CrowdStrike Falcon console for each relevant platform. During creation, add one or more rule groups that contain benchmark checks appropriate for your environment (CIS Level 1 is a practical starting point for most organisations). Assign the new policy to a representative pilot group of devices before deploying fleet-wide.

**Custom policies exist but have no rule groups**: Open each custom SCA policy in the Falcon console and navigate to its rule groups tab. Add the benchmark rule groups that correspond to your compliance requirements. After saving, the next fetch cycle will begin returning findings for the devices covered by that policy.

**Custom policies have rule groups but server hosts are still FAILED**: The rule groups may be OS-version specific and not applicable to the server OS versions in the policy. Check the rule group contents — a policy with only Windows 10 rule groups will produce no findings for Server 2019 or Server 2022 hosts. Add the appropriate server OS rule groups (e.g. CIS Windows Server 2019 or DISA STIG for Windows Server 2022) alongside the existing workstation rule groups, or create a dedicated policy for server hosts.

**Some devices still on the Default Policy**: Identify which host groups are assigned to the Default Policy in the Falcon console. Create a new custom policy (or use an existing one with rule groups), then reassign those host groups to the custom policy. Device policy assignment changes take effect within minutes.

**Policy assigned but device still showing FAILED**: Two causes are worth checking. First, verify policy precedence — a higher-priority policy may be overriding the expected assignment (see [Policy Precedence and SCA Assignment](#policy-precedence-and-sca-assignment) above). Second, if precedence is correct, re-run `fetch -t sca` without the cache to pull fresh data. There is usually a delay of a few minutes between a policy assignment change in the console and the findings appearing in the assessment API.

As with other policy changes, test SCA hardening rule groups on a small pilot group before assigning them fleet-wide. Some benchmark checks may conflict with custom applications or localised configuration in your environment. Applying aggressive hardening to a production fleet without testing can cause application compatibility issues.
