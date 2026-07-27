# Readiness Map

`readiness_map` is a small, self-contained helper that transforms a Policy Audit
**hosts report** (JSON) into a flat `readiness_map.json` — one record per host in
a fixed "readiness" shape suitable for feeding downstream inventory/compliance
systems.

> [!NOTE]
> `readiness_map` is a **starting-point template**, not a fixed product. It is
> plain stdlib Python and is meant to be **edited** to match your target schema.
> A few fields are intentionally left blank (e.g. `bios_uuid`, `marketing_version`)
> because they are not present in the source data.

## Where it lives

- **From source / git checkout:** `bin/readiness_map`
- **Airgap install:** `install.sh` places it next to the `policy-audit` CLI
  (e.g. `/usr/local/bin/readiness_map` for a SYSTEM install, or
  `~/.local/bin/readiness_map`), records it in the state manifest, and
  `uninstall.sh` removes it. It is **not** a pip console script.

## Workflow

`readiness_map` consumes the JSON output of the **`hosts`** report, so the flow is
fetch → export hosts JSON → transform:

```bash
# 1. Fetch host + policy data from CrowdStrike into the local datastore
policy-audit fetch

# 2. Export the hosts report as JSON to a file
policy-audit hosts --output-format json --output-file data/hosts.json

# 3. Transform it into readiness-map format
readiness_map data/hosts.json -o data/readiness_map.json
```

> [!IMPORTANT]
> The input **must be a `hosts` report** (top-level `{ "metadata": {...},
> "hosts": [...] }`, where each host has `host_record` and `policy_status`).
> A single-`host` report or a `policies` report does not have the right shape.

### Options

```text
readiness_map <input_file> [-o/--output-file OUTPUT]

  input_file            Input JSON from `policy-audit hosts --output-format json`
  -o, --output-file     Output path (default: ./data/readiness_map.json)
```

## Output shape

```json
{
  "metadata": { "...": "carried over from the hosts report",
                "report_type": "readiness_map",
                "database_type": "json" },
  "readiness": [
    {
      "hostname": "...",
      "device_sn": "...",
      "crowdstrike_agent_guid": "...",
      "ipv4": "...",
      "agent_vendor_name": "CrowdStrike",
      "agent_product_name": "falcon",
      "agent_version": "...",
      "agent_status": "PASSED | FAILED | <reduced_functionality_mode>",
      "firewall_status": "...",
      "usb_device_control": "...",
      "behavioral_ips_detections": "...",
      "antimalware_lastquickscan": "...",
      "...": "see bin/readiness_map for the full field list"
    }
  ]
}
```

### Field mapping notes

- `agent_status` is derived from `host_record.reduced_functionality_mode`:
  `no` → `PASSED`, `yes` → `FAILED`, anything else passes through unchanged.
- `firewall_status`, `usb_device_control`, `behavioral_ips_*`, `antimalware_*`
  are pulled from each host's `policy_status.<type>.status`.
- `bios_uuid` and `marketing_version` are emitted empty (not available in the
  source) — populate them in your own edit if you have another source.

## Customizing

Because target readiness schemas vary, copy or edit `readiness_map` directly:
adjust `transform_host_to_readiness()` to add/rename fields or change the
`PASSED`/`FAILED` mapping. It has no third-party dependencies, so it runs anywhere
Python 3 is available.
