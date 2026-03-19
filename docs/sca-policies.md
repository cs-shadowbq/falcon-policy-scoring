# Understanding Secure Configuration Assessment Policy Grading

## What Secure Configuration Assessment Policies Do

Secure Configuration Assessment (SCA) policies define the hardening benchmarks that CrowdStrike evaluates against your devices. A hardening benchmark is a set of security checks — things like verifying that unnecessary services are disabled, that password complexity settings meet minimums, or that auditing is turned on for sensitive actions. These checks correspond to industry standards such as CIS Benchmarks and DISA STIGs.

Within CrowdStrike, SCA policy rule groups hold the actual benchmark checks. A policy with rule groups assigned is actively evaluating your devices against those benchmarks. A policy with no rule groups does nothing — CrowdStrike cannot perform any configuration assessment without the checks that rule groups supply.

CrowdStrike provides a built-in Default Policy for each platform (Windows, Linux, and Mac). The Default Policy ships with no rule groups. Until you create a custom policy with rule groups and assign it to your devices, no hardening checks are taking place.

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
- **FAILED** — the device's assigned SCA policy is either disabled or has no rule groups. No assessment findings were returned, meaning no hardening checks are active for this device.
- **NOT GRADED** — SCA data has not yet been fetched. Run `fetch -t sca` to populate results.

A large number of FAILED hosts is common in environments that have not yet built custom SCA policies. The entire fleet may still be on the Default Policy, which means zero active hardening checks across all platforms.

## Understanding the Results

**All Linux hosts showing FAILED**: Linux hosts assigned to the Default Linux SCA Policy receive this status. This is the most common pattern in environments where CrowdStrike was deployed without customising SCA policies. The Default Policy exists to let the SCA feature be enabled gradually — it is not a secure end-state.

**Windows hosts mixed between PASSED and FAILED**: This typically means some Windows devices were migrated to a custom SCA policy during a rollout, while others remain on the Default Policy. The host-level status view shows exactly which devices have been migrated.

**A custom policy showing FAILED**: A policy can exist and be assigned to devices without any rule groups if it was created as a placeholder. Navigating to that policy in the Falcon console and checking whether rule groups are attached will confirm this. An empty custom policy has the same security impact as the Default Policy.

**No findings returned after fetch**: If `fetch -t sca` completes but reports zero findings, this almost always means all devices in your fleet are on policies with no rule groups. The tool will still create FAILED virtual policy entries for every (policy ID, platform) pair discovered in host records, so hosts will show FAILED rather than NOT GRADED.

## Practical Application

When SCA policies are failing, the remediation path depends on whether custom policies exist:

**No custom SCA policies exist yet**: Create a new SCA policy in the CrowdStrike Falcon console for each relevant platform. During creation, add one or more rule groups that contain benchmark checks appropriate for your environment (CIS Level 1 is a practical starting point for most organisations). Assign the new policy to a representative pilot group of devices before deploying fleet-wide.

**Custom policies exist but have no rule groups**: Open each custom SCA policy in the Falcon console and navigate to its rule groups tab. Add the benchmark rule groups that correspond to your compliance requirements. After saving, the next fetch cycle will begin returning findings for the devices covered by that policy.

**Some devices still on the Default Policy**: Identify which host groups are assigned to the Default Policy in the Falcon console. Create a new custom policy (or use an existing one with rule groups), then reassign those host groups to the custom policy. Device policy assignment changes take effect within minutes.

**Policy assigned but device still showing FAILED**: If a device appears to be assigned to a custom policy with rule groups in the Falcon console but still shows FAILED in the tool, re-run `fetch -t sca` without the cache to pull fresh data. There is usually a delay of a few minutes between a policy assignment change in the console and the findings appearing in the assessment API.

As with other policy changes, test SCA hardening rule groups on a small pilot group before assigning them fleet-wide. Some benchmark checks may conflict with custom applications or localised configuration in your environment. Applying aggressive hardening to a production fleet without testing can cause application compatibility issues.
