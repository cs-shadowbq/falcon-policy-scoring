# Understanding Prevention Policy Grading

## What Prevention Policies Do

Prevention policies control how aggressively CrowdStrike blocks threats on your devices. These policies determine which suspicious files and behaviors get stopped before they can cause harm. When prevention policies are properly configured, they provide strong protection against malware, ransomware, and other threats. When they are weak or misconfigured, threats can slip through your defenses.

## Why Prevention Settings Matter

Prevention policies represent your first line of defense against threats. CrowdStrike uses machine learning to identify suspicious files and behaviors. Prevention policies control how the system responds when it detects something suspicious. A strong prevention policy stops threats immediately. A weak policy might only log the detection and let the threat execute.

The difference between detection and prevention is critical. Detection means the system recognizes a threat and records it. Prevention means the system stops the threat from running. Your organization needs both, but prevention is what actually protects your computers from being compromised.

## How the Tool Grades Prevention Policies

The tool examines each prevention policy and evaluates its protection levels. Prevention policies contain many individual settings organized into categories. The two most important categories are cloud machine learning and sensor machine learning.

**Cloud machine learning** analyzes files by checking them against threat intelligence in the cloud. When a file matches known bad patterns, the system can detect or prevent it based on your policy settings. The tool checks both detection and prevention levels for cloud machine learning.

**Sensor machine learning** analyzes file behavior directly on the device without requiring cloud connectivity. This provides protection even when devices are offline or have limited connectivity. The tool checks both detection and prevention levels for sensor machine learning.

Each machine learning setting has separate controls for detection level and prevention level. Detection levels determine how aggressively the system identifies suspicious files. Prevention levels determine how aggressively the system blocks those files.

## Protection Levels Explained

CrowdStrike uses named levels to indicate protection aggressiveness. From weakest to strongest, these levels are: disabled, cautious, moderate, aggressive, and extra aggressive.

**Disabled** means the protection is turned off completely. No detection or prevention occurs for that setting. This represents the weakest possible configuration.

**Cautious** provides minimal protection, only catching the most obvious threats. This level minimizes false positives but also misses many real threats.

**Moderate** provides balanced protection, catching most common threats while keeping false positives relatively low. This represents a middle ground between security and operational disruption.

**Aggressive** provides strong protection, catching more threats but with increased risk of false positives. This level prioritizes security over convenience.

**Extra aggressive** provides maximum protection, catching even marginal threats but with the highest false positive rate. This level is appropriate when security is the absolute top priority.

The default grading standard requires aggressive detection levels for all machine learning settings. This ensures your systems can identify a wide range of threats. The standard also requires moderate prevention levels for all machine learning settings, providing a baseline level of active protection while balancing operational concerns.

## What Gets Checked

The tool evaluates multiple settings within each prevention policy, with specific requirements varying by platform.

**For Linux systems**, the tool checks:

- Cloud Anti-Malware: detection must be AGGRESSIVE, prevention must be MODERATE
- Sensor Machine Learning: detection must be AGGRESSIVE, prevention must be MODERATE

**For Mac systems**, the tool checks:

- Cloud Anti-Malware: detection must be AGGRESSIVE, prevention must be MODERATE
- Adware and PUP: detection must be AGGRESSIVE, prevention must be MODERATE
- Sensor Machine Learning: detection must be AGGRESSIVE, prevention must be MODERATE

**For Windows systems**, the tool checks:

- Sensor Tampering Protection: must be configured and enabled
- Cloud Anti-Malware: detection must be AGGRESSIVE, prevention must be MODERATE
- Adware and PUP: detection must be AGGRESSIVE, prevention must be MODERATE
- Sensor Machine Learning: detection must be AGGRESSIVE, prevention must be MODERATE
- ML Large File Handling: must be enabled
- Detect On Write: must be enabled
- Quarantine On Write: must be enabled
- NextGen AV Quarantine: must be enabled

The tool compares your configured values against these minimum required levels in the grading standard. Settings with detection and prevention levels must meet or exceed both thresholds. Toggle settings must match the expected enabled/disabled state.

## Understanding the Results

When you review prevention policy results, you see which policies passed all checks and which failed one or more checks. A single setting configured below the minimum requirement causes the entire policy to fail.

The most common failure patterns include:

**Detection set to moderate instead of aggressive**: Organizations often start with moderate detection to minimize disruption, but this leaves gaps in threat coverage. Moving from moderate to aggressive detection typically requires testing to understand the impact on your environment.

**Prevention set to cautious or disabled instead of moderate**: Some organizations run in detection-only mode or with minimal prevention. The grading standard requires moderate prevention for all machine learning settings, establishing a baseline level of active threat blocking.

**Machine learning completely disabled**: This sometimes happens when troubleshooting other issues. Someone disables machine learning temporarily to isolate a problem, then forgets to re-enable it. A disabled machine learning setting provides no protection at all.

**Windows-specific settings misconfigured**: Sensor tampering protection left disabled, NextGen AV quarantine not enabled, ML Large File Handling left disabled, or Quarantine On Write left disabled can all cause policy failures.

The grading summary shows how many settings passed and how many failed in each policy. A prevention policy might have eight or more individual checks depending on the platform. If seven settings are correct but one is too weak, the policy still fails. This strict approach ensures no weak settings go unnoticed.

## Prevention Versus Detection

The grading standard requires both strong detection and active prevention. The default configuration requires aggressive detection and moderate prevention for all machine learning settings.

**Aggressive detection** ensures your systems can identify a wide range of threats, including sophisticated and emerging malware. This setting prioritizes comprehensive threat visibility.

**Moderate prevention** establishes a baseline level of active threat blocking. This level provides meaningful protection against identified threats while balancing the risk of false positives and operational disruption. Moderate prevention is more permissive than aggressive prevention, but significantly stronger than detection-only mode.

Organizations that prefer detection-only mode (prevention disabled) will fail the grading checks. While running in detection-only mode may be appropriate during initial deployment or testing phases, it is not considered a secure long-term configuration. Detection-only mode provides visibility but not protection—the system logs threats but lets them execute.

If your organization requires different prevention levels based on your risk tolerance, you can modify the grading configuration file. You might increase prevention to aggressive for higher security, or you might temporarily reduce requirements during a pilot phase. However, the default standard reflects a balanced approach that provides meaningful protection without requiring the most aggressive settings.

## Practical Application

When you find prevention policy failures, remediation typically involves increasing protection levels for specific settings. These changes are made in the CrowdStrike console by editing the policy configuration.

Before strengthening prevention settings, understand the impact:

**Moving from moderate to aggressive detection** will identify more threats, which means more alerts for your security team to review. This increased visibility is valuable but requires resources to investigate the additional detections.

**Increasing prevention levels** will start blocking files that were previously allowed. Moving from disabled to moderate prevention, or from cautious to moderate prevention, means the system will actively stop threats instead of just logging them. This provides better security but could disrupt legitimate applications if those files are false positives.

**Enabling Windows-specific protections** like sensor tampering protection, NextGen AV quarantine, ML Large File Handling, and Quarantine On Write provides important defensive capabilities. These settings protect the security solution itself, extend coverage to large files, and provide clean-up capabilities for detected threats. ML Large File Handling ensures that machine learning analysis applies to large executables that might otherwise be skipped. Quarantine On Write automatically isolates suspicious files when they are written to disk, providing proactive protection.

The best practice is to test changes in a pilot group before applying them broadly. Assign the strengthened policy to a small set of representative devices. Monitor for false positives and user complaints. Once you confirm the changes are acceptable, roll them out to your broader environment.

The tool provides data about your current prevention posture. Your security team must decide the appropriate balance between security and operational impact. Some organizations need maximum protection regardless of false positive risk. Others must minimize disruption even if it means accepting slightly weaker protection. The tool measures configuration against standards, but your team makes the risk decisions.
