# Understanding Policy Grading

## How Grading Works

The tool evaluates your CrowdStrike policies by comparing their actual configuration against predefined security standards. This comparison produces a pass or fail result for each policy. The grading process happens in three stages: defining standards, evaluating policies, and assessing hosts.

## Defining Security Standards

Security standards are defined in configuration files stored in the `config/grading/` directory. Each policy type has its own grading configuration file that specifies what settings matter and what values they should have.

These configuration files are written in JSON format and contain the minimum acceptable values for each security setting. Think of them as answer keys that define what good security looks like. When you want to change what the tool considers passing or failing, you edit these configuration files rather than changing code.

Each grading configuration file is specific to one policy type. The file names follow a pattern that makes them easy to identify. All grading configuration files end with `_grading.json` and begin with the policy type name. You can review these files to understand exactly what checks the tool performs and what values it expects.

## Evaluating Policies

When the tool runs, it fetches all policies from your CrowdStrike environment and compares each policy's settings against the appropriate grading configuration. This evaluation happens at the customer level, examining every policy you have defined regardless of which devices use it.

For each setting in a policy, the tool performs a comparison. The type of comparison depends on what kind of setting it is. Some settings are numeric levels that can be compared using greater than or less than logic. Others are simple on or off toggles. Still others are text values that must match exactly.

**Numeric level settings** use a ranking system. Protection levels like disabled, cautious, moderate, aggressive, and extra aggressive have numeric values behind them. The tool can determine whether your setting meets or exceeds the minimum required level.

**Toggle settings** are straightforward true or false comparisons. If the standard requires a protection to be enabled, the tool checks whether it is enabled in your policy.

**String settings** must match the expected value exactly or fall within a list of acceptable values. Enforcement modes and other categorical settings use this comparison method.

When any setting in a policy fails its check, the entire policy fails. This strict approach ensures that a single misconfigured setting does not go unnoticed because other settings passed. A policy must pass all checks to receive a passing grade.

## Assessing Hosts

After grading all policies, the tool examines your hosts. Each computer in your environment has policies assigned to it that control its security behavior. The tool determines each host's compliance status by checking whether its assigned policies passed grading.

A host fails if any of its assigned policies failed. This means a single weak policy affects every device that uses it. If a prevention policy fails grading and five hundred hosts use that policy, all five hundred hosts fail assessment. This ripple effect makes it easy to identify the scope of impact for any policy problem.

The tool does not re-evaluate policies for each host. Policy grading happens once per policy, then that result applies to every host using the policy. This design is efficient and reflects the reality that policies are defined once and reused across many devices.

## Understanding Failures

Failures flow upward through your security configuration. A single misconfigured setting causes the entire policy to fail. A single failed policy causes all hosts using it to fail. This cascading effect means you can trace any host failure back to specific policy failures and ultimately to specific setting failures.

The tool provides detailed information about failures at each level. You can see which settings failed in each policy. You can see which policies failed overall. You can see which hosts are affected by failed policies. This layered visibility helps you understand both the specific problem and its broader impact.

When you fix a failed setting in a policy, the next grading run will show that policy passing. All hosts using that policy will then show as passing as well, assuming their other assigned policies also pass. One fix can resolve failures across many hosts if those hosts share the same policy.

## Scores and Percentages

The tool calculates a percentage score for each policy based on how many checks passed versus how many total checks were performed. A policy that passes all checks scores one hundred percent. A policy that passes half its checks scores approximately fifty percent.

Not all checks carry equal weight. Some security settings are more critical than others. The tool assigns point values to individual checks based on their security impact. High-impact settings like whether threat protection is enabled count for more points than lower-impact settings like notification preferences.

The percentage score helps you prioritize remediation. A policy scoring thirty percent needs more urgent attention than a policy scoring ninety percent. However, both are failures if they do not pass all required checks. The score indicates severity, but the pass or fail status indicates compliance.

These percentage scores aggregate upward. The tool can show you the overall score for a policy type by averaging the scores of all policies in that category. It can show you an environment-wide score by aggregating across all policy types. These summary scores give you a quick view of overall security posture.

## How Data Is Stored

The tool stores both raw policy data and grading results in a local database. This database serves as a cache to avoid repeatedly requesting the same information from CrowdStrike.

Raw policy data comes directly from the CrowdStrike API. The tool fetches the actual policy configurations as they exist in your environment and stores them with a timestamp. This raw data shows what settings are currently configured.

Grading results are stored separately from raw policy data. After comparing policies against grading standards, the tool saves the pass or fail results along with details about which specific checks failed. These grading results link back to the raw policy data through unique identifiers.

Host information is stored with references to the policies assigned to each host. When you look up a host, you can see which policies apply to it. When you look at grading results, you can see which hosts are affected by each policy. The database maintains these relationships so the tool can quickly answer questions about policy impact.

The database uses timestamps to manage cache freshness. Each piece of stored data includes the time it was fetched. The tool checks these timestamps against configured time-to-live values to determine when data needs refreshing. This approach balances performance against data accuracy.

## Customizing Standards

You can modify what the tool considers passing or failing by editing the grading configuration files. These files define the security standards, so changing them changes the evaluation criteria.

When you edit a grading configuration file, you are changing your organization's definition of acceptable security. You might make standards stricter by requiring higher protection levels or additional checks. You might make standards more lenient by lowering minimum acceptable values. These decisions depend on your organization's risk tolerance and operational requirements.

After changing grading configuration files, you need to re-run the grading process for your policies. The tool does not automatically detect configuration changes. Running the tool with fresh data will apply your new standards and generate updated results.

Different organizations have different security needs. The grading configuration approach lets you define standards appropriate for your environment without changing code. You can maintain organization-specific configuration files and apply them consistently across repeated grading runs.

## Reports and Visibility

The tool produces three types of reports that provide different views of your security posture. Each report serves a different audience and answers different questions.

The policy audit report shows the status of every policy in your environment. It tells you which policies passed grading and which failed. This report is useful for security teams who need to know what needs fixing at the policy level.

The host summary report shows which devices have policy problems. It lists hosts and indicates whether they have any failing policies assigned. This report helps operations teams understand the scope of policy failures and prioritize remediation based on affected device count.

The host details report provides complete information about individual devices, including all assigned policies and their detailed configurations. This report supports troubleshooting and detailed analysis when you need to understand why a specific device failed assessment.

Together these reports let you work at different levels of detail. You can review high-level summaries to identify problem areas, then drill down into specifics when you need to fix individual issues.

## Adding Support for New Policy Types

The tool is designed to support multiple policy types through a consistent architecture. Adding support for a new policy type involves several steps but does not require fundamental changes to how the tool works.

You create a grading configuration file that defines the standards for the new policy type. This file follows the same JSON structure used by existing policy type configurations and specifies what settings should be checked and what values they should have.

You implement the logic to fetch the new policy type from CrowdStrike and compare it against the grading standards. The tool provides comparison functions for common setting types, so you can often reuse existing comparison logic rather than writing new code.

You extend the database to store both raw policy data and grading results for the new policy type. The database adapter provides methods for storing and retrieving this information using a consistent pattern across all policy types.

You update the reporting components to display results for the new policy type. The tool uses a modular approach where each policy type plugs into the same reporting infrastructure, so adding display support is typically straightforward.

This extensible design means the tool can grow to cover additional policy types as CrowdStrike adds new security controls or as your organization identifies additional policies worth monitoring.

## Technical Implementation Details

The grading process follows a consistent workflow regardless of policy type. The tool first loads the appropriate grading configuration file for the policy type being evaluated. This configuration specifies what checks to perform and what values are acceptable.

Next, the tool fetches policies from the CrowdStrike API. It retrieves the actual configuration data that defines how each policy is set up in your environment. Some policy types require fetching additional details beyond the basic policy information. Device control policies, for example, require fetching separate settings data that contains the enforcement mode and device class configurations.

The comparison engine evaluates each setting in each policy against the requirements from the grading configuration. The engine uses different comparison methods depending on setting type. Numeric settings use mathematical comparisons. Boolean settings check for exact matches. String settings verify the value matches one of the acceptable options.

The engine records the result of each comparison. When all checks complete, it aggregates these individual results into an overall pass or fail status for the policy. It also calculates how many checks passed versus how many total checks were performed, generating the percentage score.

Finally, the tool stores both the raw policy data and the grading results in the database. Raw data goes into one set of tables, grading results into another. Cross-references link policies to their grading results and to the hosts that use them.

When generating reports, the tool queries this stored data rather than repeating the grading process. This separation between grading and reporting means you can generate multiple report views from the same grading run.

## Relationship Between Policies and Hosts

Understanding how policies relate to hosts is crucial for interpreting results. Policies are configuration templates defined once and applied to many devices. A single prevention policy might apply to hundreds or thousands of hosts depending on how your organization has structured device grouping.

When the tool grades a policy, it evaluates that policy definition one time. The result applies to every host using that policy. This means grading scales efficiently even in large environments with many devices. The tool grades each unique policy once, not once per device using the policy.

Host assessment happens after policy grading completes. The tool looks at each host, determines which policies are assigned to it, and checks the grading results for those policies. If all assigned policies passed grading, the host passes. If any assigned policy failed, the host fails.

This relationship means fixing a single policy can improve many host results simultaneously. If a failed policy applies to two hundred hosts, fixing that one policy causes all two hundred hosts to show as passing on the next assessment. Conversely, a newly introduced bad policy can cause many previously passing hosts to fail.

The tool maintains these relationships in the database so you can query them efficiently. You can ask which hosts use a specific policy. You can ask which policies a specific host uses. You can see the full chain from setting to policy to host to environment-wide status.

Host in CrowdStrike are assigned to Host Groups. Host Groups have policies assigned to them. A host inherits all policies assigned to any Host Group it belongs to. The tool accounts for this inheritance when determining which policies apply to each host during assessment. Host Group membership enumeration is able to be bypassed as the Host Details API call returns all policies assigned to a host including those inherited from Host Groups.