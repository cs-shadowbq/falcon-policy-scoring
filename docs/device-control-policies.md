# Understanding Device Control Policy Grading

## What Device Control Policies Do

Device control policies determine what external devices can connect to your computers. USB drives, printers, cameras, and mobile devices all fall under device control. When these policies are properly configured, they prevent unauthorized devices from introducing malware or stealing data. When they are weak or disabled, they create security risks.

## Why Device Control Matters

Many security breaches start with physical access. An attacker inserts a USB drive containing malware. An employee connects an unauthorized external hard drive and copies sensitive files. A visitor plugs in their phone and bypasses network security. Device control policies prevent these scenarios by blocking or restricting external device connections.

Without proper device control, your organization's data can walk out the door on a USB stick. Even well-meaning employees can create risk by connecting infected personal devices. The tool checks whether your device control policies enforce the restrictions needed to prevent these threats.

## How the Tool Grades Device Control

The tool examines each device control policy and verifies it meets security standards. Each policy receives checks in three areas.

**The policy must be enabled.** A disabled policy provides no protection. The tool fails any policy that is not enabled regardless of how well the settings are configured.

**The enforcement mode must be appropriate.** Device control policies can run in different modes. The tool checks that your policies use the enforcement mode specified in your grading configuration. The default standard requires monitor and enforce mode, which logs activity and actively blocks unauthorized devices. Policies in monitoring-only mode log activity but allow all devices, providing visibility without protection.

**Each device class must have appropriate restrictions.** Devices are organized into classes: mass storage, imaging, audio and video, mobile, printer, and wireless. The tool checks whether each class is set to block all devices or allow full access based on your security requirements.

The default grading standard requires all device classes except the generic catchall class to block all devices. This represents a strict security posture. The catchall class can be set to either block all or allow full access because it serves as a default for device types that do not fit other categories.

Organizations can customize these standards. You might allow printers to have full access while blocking all other device types. The grading configuration supports these variations. The tool checks your actual settings against whatever standard you define.

## What Does Not Affect Grading

Device control policies let you define exceptions within each device class. You might block all USB drives but create an exception for specific approved vendor IDs. These exceptions do not cause grading failures. The tool checks the overall action for each device class, not the individual exception rules. This design recognizes that controlled exceptions are a legitimate security practice.

The tool also does not grade enhanced file metadata settings or other advanced features. The focus stays on the fundamental security controls that matter most.

## Understanding the Results

When you review device control policy results, you see each policy's status. A passing policy has all required settings correct. A failing policy has one or more settings that do not meet the standard.

The most common failure is a disabled policy. An organization might create a device control policy with excellent settings but forget to enable it. The policy provides no protection until enabled.

Another common failure is an enforcement mode mismatch. A policy might be in monitoring-only mode when your standard requires full enforcement. This gives visibility but no actual blocking.

Device class configuration failures indicate that a class is set to allow devices when your standard requires blocking them, or vice versa. If your standard requires mass storage to be blocked but the policy allows it, this creates a failure. Each misconfigured class counts as a separate failed check.

The grading summary shows how many checks each policy passed and failed. A policy with nine checks and one failure might have eight properly configured device classes plus enforcement mode correct, but the policy itself is disabled. A policy with nine checks and eight failures might be enabled but have nearly every device class misconfigured.

## Practical Application

When you find device control policy failures, the remediation usually involves enabling the policy, changing the enforcement mode, or adjusting device class settings. These are straightforward configuration changes in the CrowdStrike console.

Consider the impact before making changes. Blocking device classes that users currently access will disrupt their workflow. Coordinate with your organization before enforcing strict device control. Users need advance notice and approved alternatives for legitimate business needs.

The tool provides the data to show whether your device control policies match your intended security posture. Your security team must decide whether failures represent real risks or acceptable exceptions for your environment. The tool measures configuration against standards, but your team makes the risk decisions.
