# Understanding Response Policy Grading

## What Response Policies Do

Response policies in CrowdStrike Falcon control whether and how administrators can take real-time action on your devices. This includes connecting to a live session on a host, running commands, transferring files, and executing scripts directly through the CrowdStrike console. These capabilities are collectively called Real-Time Response, or RTR.

When response policies are properly configured, your security and IT teams can investigate incidents quickly, contain compromised machines without physical access, and perform remediation tasks at scale. When they are absent or misconfigured, your team loses its ability to respond to threats efficiently—and the features that depend on response policies, including IT automation, stop working entirely.

## Why Response Policy Configuration Matters

Real-Time Response gives administrators powerful capabilities over endpoints. The ability to run commands, transfer files, and execute scripts remotely is exactly what an attacker wants to do once they have gained access to your environment. If response policies are not deliberately configured, you either block your own team from responding to threats, or you leave capabilities in an undefined state that creates ambiguity about who can do what.

There is a second, equally important reason to get response policies right. IT automation policies—which allow CrowdStrike to run automated remediation tasks, osquery execution, and other management workflows—require a response policy to be in place as a prerequisite. Without a response policy, IT automation features will not function for those host groups, regardless of how the IT automation policy itself is configured. Response policy is the permission layer that makes downstream automation possible.

## How the Tool Grades Response Policies

The tool checks each response policy against a set of minimum required settings. All settings are toggles that must be explicitly enabled. A policy that exists but has all capabilities turned off provides no operational value and fails grading.

**The policy itself must be enabled.** A disabled response policy means no response or automation capabilities are available for hosts assigned to that policy group. This is the most fundamental check.

**Real-Time Functionality must be enabled.** This is the core toggle that activates RTR for the policy. Without it, administrators cannot open live response sessions to investigate or remediate hosts. This also blocks the response layer that IT automation depends on.

**Custom Scripts must be enabled.** This setting allows administrators to deploy and run scripts written for your specific environment. Most organizations need custom scripts for their unique remediation and management tasks. Leaving this disabled limits your team to only the built-in RTR commands.

**Get Command must be enabled.** This allows files to be downloaded from a host during an investigation or remediation session. Retrieving suspicious files, logs, and configuration data is a fundamental part of both incident response and routine management.

**Put Command must be enabled.** This allows files to be uploaded to a host. Delivering remediation tools, configuration files, or replacement binaries to a compromised or misconfigured machine requires this capability.

**Run Command must be enabled.** This allows commands to be executed on the host. Together with Put, the ability to upload a tool and then run it forms the core workflow for most remediation tasks.

**Put and Run Command must be enabled (Windows only).** This combined command allows uploading a file and immediately executing it in a single operation. On Windows devices, this is how most automated remediation workflows operate. The tool requires this to be enabled on Windows response policies.

## Platform Differences

Windows, Linux, and Mac devices each have their own response policy. The grading criteria are the same across Linux and Mac, covering the six settings listed above. Windows adds the Put and Run Command requirement because that platform has the richest set of RTR capabilities and IT automation workflows depend most heavily on it.

If a setting does not exist in a platform's policy—for example, Put and Run Command on Linux—the tool skips that check rather than failing it. Each platform is graded only against the settings it actually supports.

## The IT Automation Dependency

This is the most operationally significant aspect of response policy grading. IT automation features in CrowdStrike Falcon for IT—including automated remediation workflows, osquery execution, and scripted management tasks—require a response policy to be active for the target host group. CrowdStrike will not permit automation tasks to run on hosts that do not have a response policy granting those permissions.

In practice, this means:

- If your response policy is disabled, your IT automation policy becomes inoperative regardless of its own configuration.
- If Real-Time Functionality is disabled in the response policy, automation tasks that depend on live session capabilities will not execute.
- If your hosts have an IT automation policy but no response policy, the automation features will not work for those hosts.

When you see a response policy grading failure, check whether IT automation is also affected for the same host group. The two policies work together as a pair. Fixing the response policy may be a prerequisite for restoring IT automation functionality.

## Understanding the Results

When you review response policy results, you see which policies and which platforms are passing or failing each check.

**Policy disabled** is the most severe failure. Hosts assigned to a disabled response policy have no RTR capability and cannot use IT automation. This also means your security team cannot open live response sessions to investigate incidents on those hosts.

**Real-Time Functionality disabled** is similarly severe. Even with the policy enabled, if this toggle is off, response capabilities are not available. This is the gating toggle for everything else.

**Individual command settings disabled** are more targeted failures. A policy with Real-Time Functionality enabled but specific commands disabled can still be used for some purposes, but your team's ability to perform certain tasks will be restricted. For example, with Put Command disabled, your team cannot upload remediation tools to affected hosts.

**Put and Run Command disabled on Windows** is often the failure that most directly blocks IT automation workflows. If you see Windows response policies failing only on this check, enabling Put and Run Command may be what your IT automation team is waiting for.

## What to Do About Failures

Remediation is straightforward. In the CrowdStrike console, navigate to the response policy for the failing platform. Enable the policy if it is disabled. Then review each setting that the tool flagged and enable the required toggles.

Before making changes, confirm that the right people are aware. Enabling response capabilities expands what administrators can do on endpoints. Your change management process should include notifying the teams who will have new capabilities, verifying that access controls are configured correctly so only appropriate administrators can use RTR, and confirming that audit logging is active so all response sessions and commands are recorded.

Enabling these settings does not grant every user in the CrowdStrike console unlimited access to endpoints. Actual RTR permissions are controlled through CrowdStrike roles. Enabling the policy setting makes the feature available; role assignments determine who can use it. Review your role assignments after enabling response capabilities to ensure permissions are scoped appropriately.

## Access Controls and Audit Logging

The tool evaluates response policy settings, not the access controls or audit configuration that governs their use. Passing all response policy checks means the capabilities are turned on—it does not mean they are properly restricted to the right people.

Your security team should separately verify that RTR permissions are assigned to a limited set of trusted administrators, that all response sessions are logged and reviewed, and that your organization has a process for authorizing and auditing remote command execution. CrowdStrike provides full audit trails for RTR sessions, including every command executed, every file transferred, and who initiated the session. Make sure those logs are being collected and reviewed.

## Practical Application

If your hosts are grouped by criticality or business function, ensure response policies are assigned appropriately across all groups. A common gap is a response policy that covers most hosts but misses a subset of servers or specialized workstations. Hosts without any response policy appear in the tool as not graded, which is itself a signal worth investigating.

If you are introducing IT automation and encounter failures, check response policy compliance first. Organizations that deploy IT automation on top of an unchecked response policy configuration often find that the automation does not work as expected until the response prerequisites are met. The tool makes this relationship visible so you can address the dependency before troubleshooting the automation configuration itself.

Document your response policy configuration decisions. Record which capabilities are enabled, why they are enabled, and who has permission to use them. Future administrators and auditors benefit from understanding whether the current configuration was the result of deliberate choices or accumulated defaults.
