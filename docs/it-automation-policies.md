# Understanding IT Automation Policy Grading

## What IT Automation Policies Do

IT automation policies control whether administrators can remotely execute scripts and commands on your devices through CrowdStrike. This capability is powerful and useful for system management, but it also creates security risk if misconfigured. When IT automation policies are properly configured, they enable administrators to perform remote management tasks efficiently. When they are too restrictive or improperly set, they either prevent legitimate management or create security vulnerabilities.

## Why IT Automation Configuration Matters

Remote script execution is a double-edged capability. On one hand, it lets your IT team perform administrative tasks across many devices without needing physical access to each one. This efficiency is essential in modern IT operations. On the other hand, the ability to remotely execute arbitrary code is exactly what attackers seek to gain. If IT automation is configured too permissively, it becomes an attack vector.

The security concern is not about the feature existing—it is about ensuring it is enabled deliberately and understanding the implications. Organizations need remote management capabilities, but those capabilities should be configured consciously rather than left in default states without consideration of the security impact.

## How the Tool Grades IT Automation Policies

The tool examines each IT automation policy and verifies that script execution is explicitly enabled. This might seem counterintuitive—why does the tool require a capability that creates security risk?

**The policy must be enabled.** A disabled IT automation policy means the entire IT automation system is turned off. While this eliminates the security risk of remote script execution, it also eliminates legitimate administrative capabilities your IT team likely needs.

**Script execution must be explicitly enabled.** This setting controls whether the remote script execution feature is available. The tool checks that this setting is deliberately enabled rather than in an undefined state. This ensures organizations have made a conscious decision about remote execution capabilities.

The grading approach recognizes that IT automation is a necessary feature in most environments. Rather than requiring it to be disabled, the tool verifies it is configured explicitly. An undefined or default configuration suggests the organization has not considered the security implications. An explicit enable setting indicates the organization has made a deliberate choice to allow remote script execution.

## Understanding the Security Trade-off

IT automation policies represent a security trade-off between operational capability and attack surface. Completely disabling IT automation eliminates the security risk but also eliminates useful management capabilities. Enabling IT automation provides operational benefits but creates potential attack vectors.

The right answer for most organizations is to enable IT automation but implement controls around its use. CrowdStrike provides audit logging of all remote script executions, role-based access controls that limit who can execute scripts, and approval workflows for sensitive operations. These controls let you benefit from remote management while mitigating the risks.

What the tool measures is whether you have made a deliberate configuration choice. An IT automation policy that exists but has never been configured suggests the organization is unaware of the feature or has not considered its implications. An explicitly configured policy, whether permissive or restrictive, suggests the organization has made conscious decisions about remote execution capabilities.

## What Gets Checked

The tool evaluates IT automation policies for each platform separately. Windows devices have their own policy. Linux devices have their own policy. Mac devices have their own policy. Each platform must have an enabled policy with script execution explicitly configured.

For each platform policy, the tool checks two things. First, the policy itself must be enabled. A disabled policy means IT automation is completely unavailable for that platform. Second, script execution must be explicitly enabled within the policy settings. This confirms the organization has deliberately chosen to allow remote script execution for that platform.

The grading standard requires both the policy to be enabled and script execution to be enabled. This reflects the reality that most organizations need remote script execution capabilities. An organization that genuinely wants to disable remote execution should do so deliberately and understand the operational limitations that creates.

## Understanding the Results

When you review IT automation policy results, you see which platform policies are explicitly configured and which are not. Each platform is evaluated independently.

The most common failure is having IT automation policies that exist but have never been properly configured. The policy might be in a default state where script execution is neither explicitly enabled nor explicitly disabled. This undefined configuration suggests the organization has not reviewed the policy and made deliberate choices about remote execution capabilities.

Another pattern is having IT automation policies disabled entirely. While this eliminates security risk, it also eliminates operational capability. Organizations that disable IT automation need alternative methods for remote management, which often means more complicated and less secure approaches like using other remote access tools.

Less commonly, policies might have script execution explicitly disabled while the policy itself is enabled. This configuration provides audit logging and other IT automation features while preventing actual script execution. This might be appropriate for certain environments, but it limits administrative capabilities.

## The Role of Access Controls

The grading standard focuses on whether IT automation is deliberately configured rather than whether it is restricted. This is because the actual security controls for IT automation happen through access controls rather than policy configuration.

CrowdStrike's role-based access control system determines which administrators can execute scripts remotely. Even with IT automation policies fully enabled and script execution allowed, individual administrators only have access if they are granted appropriate roles. This is where the real security enforcement happens.

Organizations should grant remote script execution permissions only to administrators who need them. Not every user with access to the CrowdStrike console needs the ability to execute arbitrary scripts on devices. By restricting these permissions to a small number of trusted administrators and logging all their actions, you gain operational capability while managing risk.

The grading system does not evaluate your access controls because those are not defined in policies—they are defined in user roles and permissions. The tool can only evaluate what is configured in policies themselves. Your security team must separately ensure appropriate access controls are in place for IT automation capabilities.

## Practical Application

When you find IT automation policy failures, remediation usually involves explicitly enabling script execution in the policy configuration. This change is made in the CrowdStrike console by editing the IT automation policy for each platform.

Before enabling script execution, ensure your access controls are appropriate. Review which administrators have remote script execution permissions. Verify that audit logging is enabled so all script executions are recorded. Consider implementing approval workflows for sensitive script operations.

Enabling script execution does not mean every administrator immediately gains unlimited remote execution capability. It means the feature is available to be used by administrators with appropriate permissions. You control who has those permissions through role assignments.

Document your decision about IT automation configuration. Whether you enable or disable script execution, that decision should be recorded along with the reasoning. Future administrators need to understand why the configuration exists and what considerations drove the choice.

The tool provides data about whether your IT automation policies are explicitly configured. Your security team must make the actual decisions about what configuration is appropriate, implement proper access controls around the capability, and ensure logging and monitoring are in place to detect misuse.
