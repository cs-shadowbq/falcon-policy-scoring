# Understanding Zero Trust Assessment Data

## What Zero Trust Assessments Do

Zero Trust Assessments are native in CrowdStrike Falcon and provide a continuous, per-device measurement of how well each endpoint adheres to zero trust security principles. Rather than evaluating an organization-level policy configuration, ZTA produces a numeric score for every managed device based on how it is actually configured and behaving at the operating system and sensor level.

The assessment examines two independent dimensions of device posture: how the Falcon sensor itself is configured on the device, and how the underlying operating system is hardened and maintained. These two dimensions combine into an overall score. A high score indicates a device is well-configured and actively protected. A low score means the device has configuration gaps that put it at greater risk, regardless of what policies are nominally assigned to it.

ZTA data gives you a factual view of whether your policy intentions have actually been realized at the endpoint. A device can be assigned to all the right policies and still produce a low ZTA score if those policies are not fully enforced, if the sensor is degraded, or if the operating system has fallen out of compliance.

## Why Zero Trust Assessment Data Matters

Policies define what should happen. ZTA tells you what is actually happening. This distinction is operationally significant.

A prevention policy may require enhanced machine learning and real-time protection, but if the sensor is partially deployed or certain features are disabled at the agent level, the policy intent is not being fulfilled. The ZTA sensor_config score reflects the real-world enforcement state of sensor features, not just what the policy declares. A device with a low sensor_config score is not providing the level of protection its assigned policy implies.

The operating system score captures a separate set of risks. Operating systems that are unpatched, running outdated components, or configured with permissive security settings are easier for attackers to exploit even when endpoint protection is in place. The OS score surfaces these gaps so your team knows which devices have elevated risk at the platform level beyond what endpoint protection alone can address.

When you see a device with a high-confidence policy assignment but a low ZTA score, that is a signal worth investigating. It means something is wrong at the device level that the policy system alone could not detect.

## How the Tool Presents Zero Trust Assessment Data

Zero Trust Assessment is contextual data, not a graded policy. The tool collects ZTA scores for each managed device and presents them alongside policy grading results so you can correlate policy compliance with actual device posture.

Each device entry in the host output includes three ZTA values:

**sensor_config** is the score for how well the Falcon sensor is configured on the device. This score is derived from sensor signals: whether protection features are active, whether the sensor is operating at full capability, and whether the device's sensor configuration matches recommended settings. The score ranges from 0 to 100.

**os** is the score for how well the operating system is hardened and maintained. This score is derived from OS signals: patch currency, version support status, security configuration settings, and other platform-level indicators. The score ranges from 0 to 100.

**overall** is the composite score combining sensor_config and OS dimensions into a single device-level rating. This is the primary number to use when triaging or reporting on device posture. The score ranges from 0 to 100.

When ZTA data is unavailable for a device—because the assessment has not yet been fetched, the ZTA feature is not licensed, or the host has not recently connected—the tool displays N/A for that device.

## The Assessment Items

Behind each score, the assessment stores a set of individual signal evaluations. These are organized in two groups: os_signals and sensor_signals.

**os_signals** are individual checks of operating system configuration and currency. Each signal evaluates a specific aspect of OS posture and contributes to the OS score. Examples include whether the operating system version is current and supported, whether critical patches have been applied, and whether OS-level security features are enabled and configured correctly.

**sensor_signals** are individual checks of Falcon sensor configuration and feature status. Each signal evaluates whether a specific sensor capability is active and properly configured. These signals reflect whether the sensor is delivering the full protection that CrowdStrike is designed to provide.

The full assessment_items data is included in the JSON host-details output when ZTA collection is enabled. Reviewing the individual signals tells you exactly which checks are contributing to a low score, which is necessary for targeted remediation.

## Score Thresholds and Interpretation

CrowdStrike does not publish a single universal threshold that defines a passing ZTA score, as the appropriate minimum will vary by environment, industry, and risk tolerance. In practice, the following ranges are commonly used for triage:

A score of **80 or above** generally indicates a device is well-configured. Most recommended sensor features are active and the operating system is reasonably current. Devices in this range should be reviewed periodically but are unlikely to represent the highest remediation priority.

A score of **50 to 79** indicates moderate gaps. The device may be running an aging OS version, missing certain sensor features, or have configuration settings that do not align with best practices. These devices warrant investigation to understand what specific signals are failing.

A score **below 50** indicates significant posture problems. A device with a score this low has multiple configuration gaps at either the sensor or OS level, or both. These devices represent elevated risk and should be prioritized for remediation.

A score of **0** typically indicates the assessment could not be completed, the sensor is not functioning, or the device has critical configuration failures. A zero score should be treated as a failure requiring immediate attention.

These thresholds are provided as a starting point. Your organization should define its own minimum acceptable ZTA scores based on the criticality of device groups and your risk management framework.

## Platform Coverage

Zero Trust Assessments are available for Windows, Linux, and Mac devices running a supported version of the CrowdStrike Falcon sensor. The specific signals evaluated vary by platform, as operating system hardening controls and sensor capabilities differ between platforms.

On Windows, the os_signals set typically includes checks related to patch management, Secure Boot, BitLocker, and Windows Defender settings alongside Falcon-enforced controls. On Linux and Mac, the signals reflect the security controls available on those platforms.

All three scores—sensor_config, os, and overall—are reported for every platform. The numeric meaning of a score is comparable across platforms in general terms, though the specific underlying checks differ.

## What to Do About Low Scores

Remediating a low ZTA score requires identifying which specific signals are failing and addressing them at the device level.

For low **sensor_config** scores, start by reviewing the sensor signals in the assessment_items output. A degraded or partially deployed sensor, a sensor running an outdated version, or sensor features disabled at the agent level are common causes. Check the sensor_file_status field in the ZTA data to confirm the sensor deployment is healthy. In many cases, remediating a low sensor_config score involves updating the sensor or ensuring that the assigned prevention and response policies are correctly enforced.

For low **os** scores, review the os_signals and identify which OS-level checks are failing. Common remediations include applying OS patches, enabling OS security features that are currently disabled, and upgrading devices running end-of-life operating system versions. For Windows devices, ODS scheduled scan compliance is a related concern and is tracked separately by the tool.

For devices with no ZTA data at all, confirm that the ZTA feature is enabled in your CrowdStrike subscription and that ZTA collection is turned on in the tool configuration. If ZTA collection is enabled and a device is still missing data, the device may not have checked in recently or may require a sensor update before ZTA data is available.

## Relationship to Policy Grading

Zero Trust Assessment data complements policy grading but does not replace it. The two systems answer different questions.

Policy grading tells you whether your organization's security policies are configured according to minimum requirements. ZTA tells you whether the devices in your environment are actually operating at the security level those policies intend.

A device can pass all policy grading checks and still have a low ZTA score. This happens when the policy configuration is correct but the device has a local condition—an outdated OS, a sensor issue, a configuration drift—that the policy system does not directly monitor. Conversely, a device can have a high ZTA score even if it belongs to a policy group with configuration gaps, if the device happens to be well-configured locally.

The most complete picture of endpoint security posture comes from reviewing both dimensions together. Use policy grading to ensure your organizational standards are defined and applied correctly. Use ZTA scores to verify that those standards are being realized at the device level.

## Enabling ZTA Collection

ZTA collection is controlled by the `include_zta` setting in the host_fetching section of the tool configuration. When enabled, the tool fetches ZTA assessments for all managed devices and stores them alongside host records. This data is then included in the host-details JSON output and displayed in the host table view.

If the ZTA column consistently shows N/A for all devices even when ZTA collection is enabled, verify that your CrowdStrike API credentials have the ZTA scope required to call the assessment endpoints. The tool requires the Zero Trust Assessment read scope to fetch per-device assessments.

The tool also supports querying the CID-level ZTA audit report, which provides aggregate ZTA information across your entire environment. This can be useful for understanding the overall distribution of scores before drilling into individual devices.

## Practical Application

When reviewing ZTA data alongside policy results, prioritize devices where both dimensions show problems. A device that fails policy grading and has a low ZTA score has compounding risk: its policy configuration is inadequate and its local configuration does not compensate for that gap.

For large environments, use the ZTA score as a triage mechanism. Sort your device list by overall ZTA score and investigate the lowest-scoring devices first. Review the sensor_config and OS scores independently to determine whether the remediation path leads through sensor management, OS patching, or both.

If you maintain device groups by criticality or business function, assess whether your most critical devices have the highest ZTA scores. It is common to find that development or test workstations have lower scores than production systems, which may be acceptable depending on your risk posture. However, if servers or devices handling sensitive data have low scores, that requires immediate attention regardless of how the policy assignments look on paper.

Document any ZTA score thresholds you define as organizational standards. When you establish a minimum acceptable score for device groups, record that decision alongside your policy configuration decisions. This gives future administrators and auditors a clear record of your intended posture and the criteria used to evaluate compliance.
