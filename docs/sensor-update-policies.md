# Understanding Sensor Update Policy Grading

## What Sensor Update Policies Do

Sensor update policies control which version of the CrowdStrike agent runs on your devices. The CrowdStrike agent, called the sensor, is the software that actually provides protection on each computer. CrowdStrike regularly releases new sensor versions with improved protections, bug fixes, and new features. Sensor update policies determine how quickly your devices receive these updates.

## Why Sensor Versions Matter

New sensor versions contain protections that older versions lack. As threats evolve, CrowdStrike adds detection capabilities for new attack techniques. Running outdated sensors means missing these new protections. Your devices remain vulnerable to threats that newer sensors would catch.

Beyond new protections, sensor updates include stability improvements and bug fixes. An outdated sensor might have known issues that affect performance or reliability. Keeping sensors current ensures your devices benefit from all improvements CrowdStrike has made.

The risk of running old sensors increases over time. A sensor that is one version behind has minimal risk. A sensor that is five versions behind has substantial risk. The tool checks whether your sensor update policies keep devices reasonably current.

## How the Tool Grades Sensor Update Policies

The tool examines each sensor update policy and verifies that devices will receive sufficiently current sensor versions. Sensor versions are released on a regular schedule, with each release identified by a build number.

**The policy must be enabled.** A disabled sensor update policy means devices will never receive updates. They remain stuck on whatever version they currently run. This creates increasing risk as time passes and the installed sensor falls further behind current protections.

**The build selection must be recent enough.** Sensor update policies specify which build devices should receive. CrowdStrike releases new builds regularly and maintains multiple build streams. The tool checks whether your policy targets a build that is reasonably current.

Build selection uses notation like "n-1" or "n-2" where "n" represents the absolute latest build. The notation "n-1" means one build behind the latest, while "n-2" means two builds behind. This relative notation lets policies automatically advance as CrowdStrike releases new builds without requiring manual policy updates.

## Understanding Build Selection

The build selection represents a balance between having the latest protections and managing rollout risk. Running the absolute latest build means getting new protections immediately but also getting any bugs or issues that might exist in a brand new release. Running several builds behind means better stability but delayed access to new protections.

**Selecting "n" (the latest build)** means your devices always run the newest sensor version. You get new protections as soon as they are available. You also get any issues that might exist in new releases before they have been tested by other customers.

**Selecting "n-1" (one build behind)** means your devices run the previous sensor version. New releases have been available to other customers for the typical release cycle, providing some real-world validation. You still get new protections relatively quickly while reducing the risk of encountering new bugs.

**Selecting "n-2" (two builds behind)** provides additional stability at the cost of slower access to new protections. By the time you receive a build, it has been running in many customer environments long enough for issues to surface and be addressed. This is the default minimum in the grading standard.

**Selecting specific build numbers** means locking devices to an exact sensor version. This is called version pinning and prevents devices from receiving any updates beyond that specific build. While this might seem safer from a stability perspective, it creates serious security risk as new protections and bug fixes become available. The tool fails any policy that pins to a specific build number rather than using the relative notation.

## What Gets Checked

The tool evaluates sensor update policies for each platform separately. Windows devices have their own sensor update policy. Linux devices have their own policy. Mac devices have their own policy. Each platform must have an enabled policy with an appropriate build selection.

For each platform policy, the tool checks that the policy is enabled and that the build selection is at least "n-2" or newer. Policies selecting "n", "n-1", or "n-2" all pass. Policies using specific build numbers or any other configuration fail because they prevent automatic updates.

The grading standard focuses on these fundamental requirements because they have the most security impact. Other sensor update settings like schedule and maintenance windows do not affect grading. Those settings control when updates apply, but what matters most for security is that updates apply at some point and continue to advance with new releases.

## Understanding the Results

When you review sensor update policy results, you see which platform policies passed and which failed. Each platform is evaluated independently.

The most common failure is having no sensor update policy enabled for a platform. Organizations sometimes deploy CrowdStrike but forget to configure sensor updates, or they disable updates during initial deployment and never re-enable them. Without enabled update policies, sensors remain at their initial installation version indefinitely.

Another common failure is pinning to specific build numbers instead of using relative notation. Organizations sometimes pin to a specific build during troubleshooting, then forget to change back to relative notation. Or they pin thinking it provides stability, not realizing it prevents receiving critical security updates and bug fixes. Version pinning creates the same risk as having no update policy at all.

Less commonly, organizations create sensor update policies but leave them disabled. The policy exists with correct build selection, but because it is disabled, no updates actually apply. This usually happens when updates are disabled temporarily for troubleshooting and never re-enabled.

## The Update Process

Understanding how sensor updates work helps interpret grading results. When CrowdStrike releases a new sensor build, your devices do not update immediately. The update process follows the schedule and build selection defined in your sensor update policies.

Devices check for updates periodically based on the policy schedule. When a device checks for updates, it compares its current sensor version against the build specified in its assigned policy. If the device is running an older build than the policy specifies, it downloads and installs the newer sensor.

The build notation like "n-2" is evaluated at the time each device checks for updates. As CrowdStrike releases new builds, what "n-2" means advances automatically. Your policy configuration does not change, but the actual build devices receive does change as new releases become available.

This automatic advancement is why selecting relative build positions like "n-2" is better than selecting specific build numbers. If you select a specific build number, devices will install that exact build and stop updating. Using relative notation ensures devices continue receiving newer builds as they become available.

## Practical Application

When you find sensor update policy failures, remediation usually involves enabling disabled policies or adjusting build selections to be more current.

Enabling a disabled sensor update policy is straightforward but requires planning. When you enable updates after a long period of being disabled, many devices might be far behind the current build. All those devices will attempt to update relatively quickly, which creates network load and potential disruption as sensors restart during updates.

Changing from a pinned build number to relative notation like "n-2" has similar considerations. Devices stuck on old pinned builds will need to update multiple versions to catch up to current builds. Plan for this by transitioning gradually across device groups rather than changing all policies simultaneously. Remove the pin, allow devices to update, and verify the updates complete successfully before moving to the next group.

Consider the operational impact of sensor updates. When a sensor updates, it typically requires a reboot or at minimum a service restart. Users experience brief interruption during this process. Schedule updates during maintenance windows when possible, or at least communicate expected disruptions to users.

The tool provides data about your sensor update policy configuration. Your security and operations teams must decide the appropriate balance between having current protections and managing update disruption. Most organizations find that "n-2" provides a good balance, which is why it serves as the default grading standard.
