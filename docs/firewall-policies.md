# Understanding Firewall Policy Grading

## What Firewall Policies Do

Firewall policies control which network connections are allowed to and from your devices. These policies define rules about what traffic can reach your computers and what traffic your computers can send. When firewall policies are properly configured, they prevent unauthorized network access and block communication with malicious servers. When they are weak or misconfigured, they expose devices to network-based attacks.

## Why Firewall Configuration Matters

Network-based attacks are a primary threat vector. Attackers scan for vulnerable services, attempt to connect to devices directly, and try to trick devices into connecting to malicious servers. A properly configured firewall blocks these attempts by restricting network communication to only what is necessary and authorized.

Without strong firewall policies, devices accept connections from any source. An attacker on the network can probe services, exploit vulnerabilities, and move laterally between compromised devices. Strong firewall policies create barriers that force attackers to overcome additional defenses.

The default posture of your firewall is particularly important. When traffic does not match any specific rule, the default action determines whether it is allowed or blocked. A permissive default allows everything except what is explicitly blocked. A restrictive default blocks everything except what is explicitly allowed. The restrictive approach is much more secure.

## How the Tool Grades Firewall Policies

The tool examines each firewall policy and verifies that it enforces appropriate network restrictions. Firewall policies have several key settings that determine their security posture.

**The policy must be enabled.** A disabled firewall policy provides no protection. All network traffic flows freely regardless of what rules the policy contains. The tool fails any disabled policy because it cannot protect devices no matter how well configured the rules might be.

**The default inbound action must be deny.** This setting controls what happens to inbound connection attempts that do not match any specific firewall rule. Setting this to deny means blocking all inbound connections except those explicitly allowed. Setting it to allow means accepting all inbound connections except those explicitly blocked. The tool requires deny to ensure the firewall has a secure default posture.

**The policy must be in enforce mode.** Firewall policies can run in enforce mode or monitor mode. Enforce mode actively blocks traffic that violates rules. Monitor mode logs violations but allows the traffic. The tool requires enforce mode because monitoring provides visibility but not protection.

**Test mode must be disabled.** Test mode is a special state for validating firewall rules before fully deploying them. When test mode is enabled, the firewall behavior might differ from what the rules specify. The tool requires test mode to be disabled to ensure the firewall operates according to its configured rules.

## Understanding Firewall Modes

The distinction between enforce mode and monitor mode is similar to the distinction between detection and prevention in other policy types. Monitor mode tells you what the firewall would block if it were enforcing rules. Enforce mode actually blocks that traffic.

Organizations sometimes run in monitor mode initially when deploying firewall policies. They want to see what would be blocked before actually blocking it. This helps identify legitimate traffic that would be disrupted by the new rules. Monitor mode provides a learning period without operational risk.

Running permanently in monitor mode defeats the purpose of having a firewall. You gain visibility into network traffic patterns and see what would be blocked, but you receive no actual protection. Network attacks succeed even though the firewall logs them. This is marginally better than having no firewall at all, but much worse than actually enforcing restrictions.

Test mode serves a similar purpose but is intended for more limited use during rule development. When creating new firewall rules, test mode lets you validate they work as intended before making them active. Test mode should be temporary and limited to development environments. Production devices should never have test mode enabled.

## Understanding Default Inbound Action

The default inbound action represents your firewall's fundamental security posture. This single setting has major security implications.

**Default deny (blocking inbound)** means the firewall blocks all inbound connection attempts unless a rule explicitly allows them. This is the secure approach. Attackers cannot connect to services on your devices unless you have specifically created rules allowing those connections. You must think deliberately about what inbound access is necessary and create rules for only that traffic.

**Default allow (permitting inbound)** means the firewall allows all inbound connection attempts unless a rule explicitly blocks them. This is the permissive approach. Attackers can connect to any service running on your devices unless you have specifically created rules blocking those connections. You must identify every potential risk and create rules to block it, which is much harder than identifying and allowing only necessary traffic.

The security community universally recommends default deny for inbound traffic. This approach aligns with the principle of least privilege—nothing is allowed unless specifically authorized. The tool enforces this by requiring policies to have their default inbound action set to deny.

## What Gets Checked

The tool evaluates the fundamental firewall policy settings that establish security posture. These checks focus on whether the firewall is active and configured with secure defaults rather than evaluating individual firewall rules.

Individual firewall rules are not graded. A firewall policy might contain dozens or hundreds of rules allowing specific traffic for business applications. The tool does not attempt to evaluate whether each rule is appropriate. That determination requires understanding your organization's specific network architecture and application requirements.

Instead, the tool checks the framework within which those rules operate. Is the policy enabled so rules actually apply? Is the default deny so the rules define exceptions to a secure baseline rather than exceptions to a permissive baseline? Is enforce mode active so rules actually block traffic rather than just logging it? These fundamental settings determine whether your firewall provides security.

## Understanding the Results

When you review firewall policy results, you see which policies have secure fundamental configuration and which have one or more settings that weaken protection.

The most common failure is having the default inbound action set to allow. Organizations sometimes configure firewalls this way to avoid breaking applications during initial deployment. They plan to eventually switch to default deny after identifying all necessary traffic, but that switch never happens. The firewall remains permanently in a permissive posture that provides minimal protection.

Another common failure is running in monitor mode instead of enforce mode. Like default allow, this often starts as a temporary state during deployment and becomes permanent. The organization learns what the firewall would block but never switches to actually blocking it. Users do not experience any disruption, but the firewall provides no security benefit.

Having test mode enabled in production is less common but does happen. Organizations might enable test mode while troubleshooting a connectivity problem, then forget to disable it. Or a policy might be accidentally promoted from a test environment to production with test mode still active. Either way, test mode in production means the firewall is not operating according to its configured rules.

Disabled policies are the worst failure. The policy exists with potentially excellent rules and settings, but because it is disabled, none of that matters. The firewall provides zero protection. This usually happens when the firewall is disabled during troubleshooting and never re-enabled.

## Practical Application

When you find firewall policy failures, remediation usually involves enabling the policy, switching from monitor to enforce mode, changing default inbound to deny, or disabling test mode.

Each of these changes can cause operational disruption. Enabling a firewall, switching to enforce mode, or changing to default deny will start blocking traffic that was previously allowed. Applications that depend on that traffic will stop working. This is why organizations often run in permissive modes initially—they want to identify problems before actually enforcing restrictions.

The proper approach is to run in monitor mode with default deny temporarily while learning about traffic patterns. Review the monitor logs to identify legitimate traffic that would be blocked. Create firewall rules to allow that necessary traffic. Once you have rules for all legitimate use cases, switch to enforce mode and keep default deny. This process takes time and effort but results in a firewall that provides security without breaking applications.

Do not leave firewalls in permissive modes permanently. The learning period should be measured in days or weeks, not months or years. If you have been running in monitor mode for six months, you have enough information to create appropriate rules. Switch to enforce mode and address issues as they arise rather than indefinitely delaying the switch.

The tool provides data about your firewall configuration fundamentals. Your security and operations teams must implement the changes needed to achieve secure configuration while managing the operational impact. Most organizations find that proper planning and a phased rollout make the transition manageable.
