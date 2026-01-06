# Understanding the Falcon Policy Audit Tool

## What This Tool Does

The Falcon Policy Audit Tool monitors your CrowdStrike security settings and tells you when something is not configured according to best practices. Think of it as a continuous health checker for your security policies. Instead of manually reviewing hundreds or thousands of security settings across your organization, this tool does the work for you and produces reports that show what needs attention.

## Why You Need This

Your organization relies on CrowdStrike to protect computers from threats. CrowdStrike uses policies to control how this protection works. These policies determine which threats get blocked, how aggressively the system responds, and how devices are secured. Over time, these policies can drift from recommended settings. Someone might weaken a setting to solve a temporary problem and forget to change it back. Or recommended practices might change while your policies stay the same.

Without this tool, you would need to manually check every policy across every device type to ensure compliance. In a large organization, this means reviewing hundreds of individual settings. This tool automates that review and gives you clear reports showing what passes and what fails.

## What Gets Measured

For detailed information about how the overall grading system works, see the [Policy Grading System](policy-grading-system.md) documentation, which explains the grading architecture, how policies are evaluated, and how results are stored.

The tool examines six types of security policies:

**Prevention policies** control how aggressively CrowdStrike blocks threats. The tool checks whether critical protections are enabled at appropriate levels. Weak prevention settings mean threats could slip through. [Learn more about prevention policy grading](prevention-policies.md).

**Sensor update policies** determine which version of the CrowdStrike agent runs on your devices. The tool verifies you are running current versions. Outdated sensors miss new protections. [Learn more about sensor update policy grading](sensor-update-policies.md).

**Content update policies** control how quickly devices receive new threat intelligence. The tool checks that devices get updates frequently enough. Delays in content updates mean devices cannot recognize the latest threats. [Learn more about content update policy grading](content-update-policies.md).

**Firewall policies** define which network connections are allowed or blocked. The tool validates that your firewall rules follow security standards. Poor firewall policies expose devices to network-based attacks. [Learn more about firewall policy grading](firewall-policies.md).

**Device control policies** manage what USB drives and peripherals can connect to computers. The tool ensures unauthorized devices cannot introduce malware or steal data. Weak device control policies create insider threat risks. [Learn more about device control policy grading](device-control-policies.md).

**IT automation policies** govern remote access and scripting capabilities. The tool confirms these powerful features are properly restricted. Misconfigured automation policies let attackers gain elevated access. [Learn more about IT automation policy grading](it-automation-policies.md).

## Additonal Data

To provide context for policy grading, the tool also collects:

- **Host information**: Details about each computer, including operating system, assigned policies, and zero trust assessment scores.

- **Policy assignments**: Which policies apply to which devices, helping identify scope of impact for any failures.

- **Zero Trust Assessment data**: Scores indicating how well each device adheres to zero trust principles, providing additional security context.

## How Grading Works

Each policy receives a grade based on whether it meets specific security criteria. The tool compares your actual settings against a reference configuration that represents security best practices. When a setting matches the recommendation, that check passes. When it differs, that check fails.

A policy might have dozens of individual checks. Some checks are more important than others. The tool assigns point values to each check based on its security impact. The total points earned divided by total possible points gives a percentage score. A policy with all checks passing scores one hundred percent. A policy with half its checks passing scores roughly fifty percent.

The tool aggregates these individual policy scores into category scores and an overall score. This lets you see both the big picture and drill down into specific problem areas.

## Understanding the Three Report Files

The tool produces three JSON files each time it runs. These files serve different purposes and different audiences.

**The policy audit report** answers the question "Are my policies configured correctly?" It lists every policy, shows whether it passed or failed grading, and provides a summary score. Security teams use this report to identify which policies need remediation. It shows the overall health of your security configuration without overwhelming you with details about every device.

**The host summary report** answers the question "Which devices have policy problems?" It lists every computer and shows which policies are failing on that device. Operations teams use this report to understand the scope of policy failures. If a policy is failing on five devices, that is a focused problem. If it is failing on five hundred devices, that requires urgent attention.

**The host details report** answers the question "What exactly is wrong with this device?" It contains complete information about every device, including all policy assignments, detailed configuration settings, and zero trust assessment scores. Engineers use this report for troubleshooting and detailed analysis. When you need to understand why a specific device is failing checks, this report has the full picture.

Together, these three reports let different teams work at different levels of detail. Management reviews the policy audit report to see overall trends. Operations reviews the host summary to prioritize remediation efforts. Engineers review the host details to fix specific problems.

## Scheduling and Timing

The tool runs continuously and produces reports on a schedule you define. Choosing the right schedule balances timeliness against noise.

**Every four hours** works well for most organizations. This frequency catches policy changes quickly without generating excessive reports. If someone modifies a policy at ten in the morning, you see the impact by two in the afternoon. Four-hour intervals produce six reports per day, which is manageable to review.

**Every eight hours** (three times daily) suits stable environments where policies change infrequently. This is enough to catch overnight changes by morning and end-of-day changes by the next morning. Eight-hour intervals produce only three reports per day, making review lightweight.

**Once daily** is the minimum useful frequency. Running less often means problems can persist for a full day before detection. Daily reports work for organizations with very stable policies and relaxed security requirements, but most organizations need tighter monitoring.

Avoid running more frequently than every two hours. Enterprise policies do not change that fast except during initial deployment, and device data does not change that fast. Running every fifteen minutes creates noise without adding value. That frequency is useful only when testing the tool itself.

## How Caching and TTL Work

The tool stores data locally in a database to avoid repeatedly requesting the same information from CrowdStrike. This makes the tool faster and reduces load on the CrowdStrike API. Each piece of data has a time-to-live (TTL) value that determines how long it remains valid before requiring a refresh.

The TTL settings relate directly to your reporting schedule. If you report every four hours, you want data fresh enough to reflect that timeframe but not so fresh that you waste resources fetching unchanged data.

**Host lists** have a five-minute TTL because the list of devices changes relatively frequently as machines come online and offline. When the tool runs, it checks if the host list is more than five minutes old. If so, it fetches a fresh list. If not, it uses the cached list. This keeps device data current without excessive API calls.

**Policy data** has a ten-minute TTL because policies change less frequently than device lists. Most policies stay stable for days or weeks. A ten-minute cache means the tool can run twice in quick succession without re-fetching unchanged policies.

**Policy containers and rule groups** have a one-hour TTL because these structural elements change very infrequently. Organizations might add a new firewall rule group once a month. Caching this data for an hour reduces API load without sacrificing accuracy.

The relationship between reporting frequency and TTL is complementary. If you report every four hours, nearly all cached data expires between runs. The tool fetches fresh data each reporting cycle. If you report every two hours, some data might still be cached from the previous run, making the second run faster. Either way, your reports reflect current state because TTL values are shorter than reporting intervals.

You can use the CLI mode rather than daemon mode for faster one-time checks. As reporting frequency is in the hours, the CLI mode allows you to track immediate changes without waiting for the next scheduled run, but still benefits from caching during that single execution.

## Reading the Output

Each report file includes a timestamp showing when it was generated. Files are named with date and time stamps so you can track trends over time. The metadata section shows which customer environment the report covers, how many policies exist, and how many passed or failed.

When reviewing reports, start with the summary section. This tells you the overall health score and how many items need attention. If the overall score is high and few items are failing, your environment is in good shape. If the score is low or many items are failing, you have work to do.

Next, look at category-level results. Which policy types are performing well and which are struggling? If prevention policies score well but firewall policies score poorly, you know where to focus your effort.

Finally, drill into specific failed items. The detailed reports show exactly which settings are misconfigured and what the expected values should be. This gives your team the information needed to make corrections.

## Day-to-Day Usage

In normal operation, you configure the tool once and let it run continuously. It fetches data from CrowdStrike, grades the policies, writes the three report files, and waits until the next scheduled run. The files accumulate in the output directory, giving you a historical record of your security posture over time.

The tool automatically manages this accumulation by running a cleanup process once daily (by default at two in the morning). This cleanup removes report files older than thirty days and limits the number of files kept for each report type to one hundred. These settings prevent your output directory from growing indefinitely while preserving enough history for trend analysis. You can adjust the cleanup schedule, retention period, and file limits in the configuration file if your needs differ.

You should review reports regularly. 

You should use another tool or script to push the reports to a central location or notify stakeholders when new reports are available. This could be as simple as an email notification, SOAP XML push, or as complex as integrating with a SIEM / dashboarding system.

Manually you could set a calendar reminder to check results at least once per day. Look for changes from the previous report. Is your overall score improving or declining? Are new failures appearing? Are old failures getting fixed?

## Best Practices for Remediation

When you find failures, prioritize them by impact. A failed prevention policy affects more devices and creates more risk than a failed device control policy. Address high-impact failures first. Use the host summary report to understand how widespread each failure is, then use the host details report to diagnose root causes.

The tool is not a replacement for your security team's judgment. It tells you what differs from recommended settings, but your team must decide whether those differences matter in your specific environment. Some failures might be acceptable based on your organization's risk tolerance. Others require immediate action. The tool provides data to inform those decisions.

## Audit Service Health Monitoring

The tool can expose health check endpoints that monitoring systems can query. These endpoints report whether the tool is running, whether recent checks succeeded, and how long the tool has been operating. You can integrate these endpoints with your existing monitoring infrastructure to receive alerts if the tool stops working.

The health check runs on port 8088 by default. Visiting that port in a web browser or querying it with monitoring tools returns status information. If you are running the tool in Kubernetes, these health checks integrate with Kubernetes liveness and readiness probes to ensure the tool restarts automatically if it encounters problems.

## Where to Learn More

This document explains what the tool does and why it matters. For information about installing and configuring the tool, see the main README file in the repository root. For details about running the tool in daemon mode, see the daemon mode documentation. For technical API references and troubleshooting, see the other documentation files in the docs directory.

The configuration file (config.yaml) contains inline comments explaining each setting. Reviewing that file will help you understand the available options and their effects.

If you need to understand the underlying API calls or database structure, the design documents in the design-docs directory provide technical depth. The grading configuration files in config/grading show exactly which checks are performed for each policy type.

For detailed information about how the overall grading system works, see the [Policy Grading System](policy-grading-system.md) documentation, which explains the grading architecture, how policies are evaluated, and how results are stored.

## Getting Started

To begin using this tool, you need CrowdStrike API credentials with permission to read policy and device information. Your CrowdStrike administrator can generate these credentials. Once you have credentials, you edit the configuration file to include them (or use more secure methods such as environment variables or secret management systems), set your preferred reporting schedule, and start the tool. Within one reporting interval, you will have your first set of reports showing your current security posture.

From there, establish a routine for reviewing reports and addressing failures. The tool will continue monitoring in the background and producing updated reports according to your schedule. Over time, you will build a history of your security posture and be able to demonstrate improvement to stakeholders.
