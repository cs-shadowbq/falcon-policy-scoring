# Understanding ODS Scheduled Scan Grading

## What ODS Scheduled Scans Do

On Demand Scanning (ODS) scheduled scans run periodic full-filesystem scans on Windows devices, examining every PE executable file on the machine for threats. Unlike real-time protection, which examines files as they are accessed, scheduled scans sweep through dormant files that may have arrived through non-standard means and never triggered real-time inspection. This catches threats that slipped past defenses silently.

## Why ODS Scheduled Scans Matter

Real-time protection catches threats as they attempt to execute or are opened. However, files can reach a device through encrypted channels, offline media, or other methods that bypass inspection at the moment of arrival. Dormant malware may sit on disk waiting to be triggered. Scheduled scans close this gap by proactively checking everything on disk on a regular cadence.

A scheduled scan that runs regularly, with strong machine learning levels and quarantine enabled, provides a safety net for threats that evaded initial defenses. Disabling or weakening these scans removes this backstop.

## Windows-Only Feature

ODS scheduled scans are a Windows-exclusive feature. Mac and Linux hosts are not subject to this grading check and receive a status of **N/A**. For Windows hosts, the tool determines whether they are covered by at least one passing scheduled scan by expanding the host groups assigned to each scan. A Windows host with no scan coverage, or covered only by failing scans, receives a **FAILED** status.

## How the Tool Grades ODS Scheduled Scans

The tool fetches all scheduled scans from the CrowdStrike API, builds a coverage index mapping each Windows device to the scans targeting it, grades each scan against the requirements below, and then determines per-host status based on whether at least one passing scan covers that device.

A scan passes only if it meets every requirement. A single failing check causes the entire scan to fail compliance. Any Windows host not covered by at least one passing scan is marked **FAILED**.

## What Gets Checked

The tool evaluates eight requirements for each scheduled scan:

**Status — must be `scheduled`**: The scan must be in an active scheduled state. A scan with a status of `completed`, `pending`, or any other non-scheduled state is not providing continuous recurring coverage and fails this check.

**Schedule interval — must not exceed 7 days**: The scan must be configured to run at least once every seven days. An interval greater than seven days means devices go too long without a full scan, leaving a wide window for dormant threats to remain undetected. The tool checks the `schedule.interval` field against this maximum.

**Cloud ML detection level — minimum moderate (2)**: Cloud-based machine learning analyzes files against threat intelligence to identify malicious patterns. The detection level controls how aggressively the system flags suspicious files. A level of at least moderate (2) is required. Levels below this miss too many threats during scanning.

**Sensor ML detection level — minimum moderate (2)**: On-device machine learning analyzes file behavior without cloud connectivity, providing protection for offline devices or during cloud service interruptions. A level of at least moderate (2) is required for the same reasons as cloud detection.

**Cloud ML prevention level — minimum moderate (2)**: After cloud-based machine learning identifies a threat during a scan, this setting controls whether the system acts to stop it. At moderate (2), detected threats are quarantined or blocked. Levels below this leave the scan in a detection-only mode that logs threats without removing them.

**Sensor ML prevention level — minimum moderate (2)**: The same prevention action applied to on-device machine learning detections. A level of at least moderate (2) is required to ensure that threats found by sensor-side analysis are not simply logged and left in place.

**Cloud PUP/Adware prevention level — minimum moderate (2)**: Potentially Unwanted Programs and adware represent a lower-severity category of threat but still degrade device security and performance. The scan must be configured to prevent (not merely detect) these at a moderate level or higher.

**Quarantine — must be enabled**: When the scan finds a threat, quarantine must be turned on so that the identified file is isolated rather than left accessible. A scan with quarantine disabled identifies threats but takes no action on them, providing no actual remediation.

## Protection Level Scale

ODS scheduled scan ML levels use a numeric scale from 0 to 3:

| Level | Name | Description |
|-------|------|-------------|
| 0 | Disabled | No detection or prevention occurs for this category |
| 1 | Cautious | Minimal protection; catches only the most obvious threats |
| 2 | Moderate | Balanced protection; catches most common threats (**minimum required**) |
| 3 | Aggressive | Strong protection; catches sophisticated and emerging threats |

The grading standard requires level 2 (moderate) or higher for all machine learning detection and prevention settings. Level 0 (disabled) or level 1 (cautious) on any ML setting causes the scan to fail.

## Scan Inclusions and File Coverage

The grading standard expects scheduled scans to cover the entire filesystem using the `**` path pattern, which matches all files in all directories recursively. This ensures no part of the filesystem is excluded from scrutiny. A scan configured with narrow inclusion paths, such as only `C:\Users`, misses large portions of the disk where threats could hide.

At present the tool validates the ML levels, quarantine, schedule, and status. Verifying the specific inclusion paths is not part of the current grading checks, but reviewing the scan configuration in the CrowdStrike console to confirm `**` is included is recommended.

Exclusions are not checked by the tool, but a scan with broad exclusions that omit common hiding places for threats (e.g., `C:\Windows\Temp`) would be a risk even if it meets the other grading requirements. Regular review of both inclusions and exclusions in the Falcon console is important to maintain strong coverage.

## Scan Focus: PE Files

ODS scheduled scans are designed primarily to examine Portable Executable (PE) files — the `.exe`, `.dll`, `.sys`, and related binary formats that contain executable code on Windows. These are the file types most frequently weaponized by threat actors. Macros in documents and scripts are handled by real-time protection settings. Scheduled scans with the `**` inclusion pattern catch PE-format threats wherever they reside on disk.

## Host Coverage Model

Unlike other policy types where a policy is directly assigned to each device, ODS scheduled scans target host groups. A single scan can cover many devices by targeting the host groups those devices belong to. The tool expands each scan's host groups to build a coverage index, then determines each Windows device's status:

- **PASSED** — the device is covered by at least one scan that passes all grading checks
- **FAILED** — the device is covered only by scans that fail one or more checks, or is not covered by any scan at all
- **NOT GRADED** — no ODS graded data is available yet (fetch has not been run)
- **N/A** — the device is not a Windows host

## Understanding the Results

When reviewing ODS scan results, a common pattern is one scan passing and another failing. This often reflects:

**A production scan with strong settings and a legacy or test scan with weak settings**: If a device belongs to the host group for both scans, it is covered by the passing scan and receives a PASSED status. However, the failing scan still appears in the policy-level report and should be remediated or removed.

**Quarantine disabled on an older scan**: Scans originally created in detection mode before quarantine was enabled are a common source of failures. Enabling quarantine requires editing the scan in the CrowdStrike Falcon console.

**ML levels left at cautious or disabled**: Scans configured conservatively during initial rollout and never updated to meet current standards will fail the ML level checks. These require updating the scan settings.

**Windows devices not in any host group assigned to a passing scan**: A device might exist in the environment but not belong to any group targeted by a scheduled scan. These devices receive a FAILED host status even if all existing scans are passing, because coverage does not reach them.

## Practical Application

When you find ODS scan failures, remediation typically involves one of:

**Updating ML detection and prevention levels**: In the CrowdStrike Falcon console, locate the scheduled scan and increase the cloud and sensor ML levels to moderate (2) or higher for both detection and prevention. Also ensure the PUP/Adware prevention level meets the same minimum.

**Enabling quarantine**: Edit the scan and switch quarantine on. This is a single toggle change and ensures that detected threats are isolated, not just logged.

**Adjusting the schedule interval**: If the scan is set to run less frequently than weekly, reduce the interval to seven days or fewer. Daily scans provide the strongest assurance.

**Expanding host group coverage**: If Windows devices are not covered by any scan, either add them to an existing host group that a passing scan targets, or create a new host group and assign it to a scan.

**Replacing or removing failing scans**: If a legacy scan exists only for historical reasons with weak settings, consider replacing it with a properly configured scan or removing it if it is no longer needed.

As with prevention policies, test changes in a representative pilot group before applying them broadly. Increasing ML prevention levels during a scan means detected files will be quarantined, which could affect legitimate files in edge cases. Confirming the impact on a small set of devices before fleet-wide rollout reduces operational risk.
