# JSON Output and Schemas

The `policy-audit` tool supports structured JSON output for programmatic consumption and integration with other tools. All JSON output conforms to strict schemas based on JSON Schema Draft-07.

## Usage

### Generate JSON Output

```bash
# Output to stdout
./bin/policy-audit policies --output-format json

# Output to file
./bin/policy-audit policies --output-format json --output-file results.json

# With filtering options
./bin/policy-audit policies --output-format json --output-file results.json \
  -t prevention \
  -p Windows \
  -s failed

# Multiple policy types
./bin/policy-audit policies --output-format json --output-file results.json \
  -t prevention,firewall,device-control

# Host summary output
./bin/policy-audit hosts --output-format json --output-file hosts.json

# Specific host output
./bin/policy-audit host WIN-SERVER-01 --output-format json
```

### Generate JSON Schema

```bash
# Generate all schemas to output/schemas/
./bin/policy-audit generate-schema

# Generate a specific schema
./bin/policy-audit generate-schema host-details
./bin/policy-audit generate-schema policy-audit
./bin/policy-audit generate-schema host-summary
./bin/policy-audit generate-schema metrics

# Save to a custom location
./bin/policy-audit generate-schema host-details --schema-output /path/to/custom.schema.json
```

## JSON Schemas

The JSON output follows strict schemas based on **JSON Schema Draft-07** (`https://json-schema.org/draft-07/schema#`).

### Available Schemas

Four schema files are generated for the various report types:

- **host-details.schema.json** - Schema for comprehensive host details reports with full policy grading and host information (CLI and daemon)
- **policy-audit.schema.json** - Schema for simplified policy audit summary reports (daemon only)
- **host-summary.schema.json** - Schema for host compliance summary reports (daemon only)
- **metrics.schema.json** - Schema for daemon runtime metrics and statistics (daemon only)

### Schema Location

Schemas are generated to `./output/schemas/` by default:

```
output/schemas/host-details.schema.json
output/schemas/policy-audit.schema.json
output/schemas/host-summary.schema.json
output/schemas/metrics.schema.json
```

The default output directory is placed under `./output/schemas` to simplify container volume mounting. You only need to mount the `./output/` directory to access both reports and schemas.

### Schema Usage

These schemas can be used with:

- JSON validators to verify report structure
- IDE schema validation for JSON files
- Documentation generation tools
- API documentation systems
- Container/Kubernetes ConfigMaps for validation

## Output Structure

### Root Object

```json
{
  "metadata": { },
  "summary": { },
  "policies": { },
  "hosts": [ ]
}
```

### Metadata Section

Contains information about the audit run:

```json
{
  "metadata": {
    "version": "1.0.0",
    "timestamp": "2025-12-01T10:30:45Z",
    "cid": "ABC123...",
    "database_type": "sqlite",
    "filters": {
      "policy_types": ["prevention", "sensor_update", "content_update", "firewall"],
      "platform": "Windows",
      "status": null,
      "product_types": ["Workstation", "Domain Controller", "Server"]
    }
  }
}
```

**Note:** The `policy_types` array reflects the filtered policy types. When using `-t all`, all policy types are included. When using comma-separated types like `-t prevention,firewall`, only those types appear in the array.

### Summary Section

Aggregated statistics across all policies:

```json
{
  "summary": {
    "total_policies": 12,
    "passed_policies": 10,
    "failed_policies": 2,
    "overall_score": 83.33,
    "total_hosts": 412,
    "hosts_all_passed": 380,
    "hosts_any_failed": 32
  }
}
```

### Policies Section

Detailed results for each policy type:

```json
{
  "policies": {
    "prevention": {
      "cache_age_seconds": 120,
      "cache_ttl_seconds": 600,
      "cache_expired": false,
      "total_policies": 3,
      "passed_policies": 2,
      "failed_policies": 1,
      "score_percentage": 66.67,
      "graded_policies": [
        {
          "policy_id": "abc123",
          "policy_name": "Production - Windows Prevention",
          "platform_name": "Windows",
          "passed": false,
          "checks_count": 15,
          "failures_count": 3,
          "score_percentage": 80.0,
          "setting_results": [
            {
              "setting_id": "RealTimeScan",
              "setting_name": "Real-time Scanning",
              "passed": true
            },
            {
              "setting_id": "CloudMLLevel",
              "setting_name": "Cloud ML Detection Level",
              "passed": false,
              "failures": [
                {
                  "field": "detection_level",
                  "actual": "moderate",
                  "minimum": "aggressive",
                  "comparison": "less_than"
                }
              ]
            }
          ]
        }
      ]
    }
  }
}
```

### Hosts Section (Optional)

Only included when `--show-hosts` flag is used:

```json
{
  "hosts": [
    {
      "device_id": "abc123def456",
      "hostname": "WIN-SERVER-01",
      "platform": "Windows",
      "policy_status": {
        "prevention": {
          "status": "PASSED",
          "policy_id": "xyz789",
          "policy_name": "Production - Windows Prevention"
        },
        "sensor_update": {
          "status": "PASSED",
          "policy_id": "xyz790",
          "policy_name": "Production - Sensor Update"
        },
        "content_update": {
          "status": "FAILED",
          "policy_id": "xyz791",
          "policy_name": "Production - Content Update"
        },
        "firewall": {
          "status": "NOT_GRADED",
          "policy_id": "xyz792",
          "policy_name": "Production - Firewall"
        }
      },
      "all_policies_passed": false,
      "any_policy_failed": true,
      "host_record": {
        "device_id": "abc123def456",
        "cid": "ABC123...",
        "hostname": "WIN-SERVER-01",
        "platform_name": "Windows",
        "os_version": "Windows Server 2019",
        "agent_version": "7.31.18410.0",
        "first_seen": "2025-11-26T12:05:17Z",
        "last_seen": "2025-12-03T17:16:53Z",
        "local_ip": "10.0.0.40",
        "external_ip": "1.2.3.4",
        "mac_address": "02-de-65-e1-43-03",
        "groups": ["group-id-1", "group-id-2"],
        "tags": ["tag1", "tag2"],
        "device_policies": { "...": "..." },
        "...": "... (includes all fields from CrowdStrike GetDeviceDetailsV2 API)"
      }
    }
  ]
}
```

**Note:** The `host_record` field contains the complete device details from the CrowdStrike API (`GetDeviceDetailsV2`). This includes extensive information such as:

- Device identification (device_id, cid, hostname)
- Operating system details (platform_name, os_version, kernel_version)
- Agent information (agent_version, config_id_base, etc.)
- Network details (local_ip, external_ip, mac_address, connection_ip)
- Cloud provider info (service_provider, instance_id, zone_group)
- Groups and tags
- All assigned policies with detailed metadata
- System hardware information
- And many more fields (~57+ fields total)

This provides comprehensive host context for integration with other systems and detailed analysis.

## Policy Status Values

Host policy status can be one of:

- `PASSED` - Policy is assigned and passed grading
- `FAILED` - Policy is assigned but failed grading
- `NOT_GRADED` - Policy is assigned but not graded yet
- `NO_POLICY_ASSIGNED` - No policy assigned to this host

## Comparison Types

Setting failures include a comparison type:

- `less_than` - Actual value is less than required minimum
- `greater_than` - Actual value exceeds maximum (e.g., ring_points)
- `not_equal` - Value doesn't match expected
- `missing` - Required field is missing

## Output Files

### File Naming Convention

`<report-type>_YYYY-MM-DD_HH-MM-SS_TZ.json[.gz]`

**Examples:**

- `policy-audit_2025-12-01_10-30-45_EST.json`
- `host-summary_2025-12-01_10-30-45_EST.json.gz`
- `metrics_2025-12-01_10-30-45_EST.json.gz`
- `host-details_2025-12-01_10-30-45_EST.json`

### Report Types

Daemon mode generates four types of reports:

#### 1. Policy Audit Report

```json
{
  "timestamp": "2025-12-07T14:30:00",
  "report_type": "policy-audit",
  "metadata": {
    "cid": "ABC123...",
    "total_policies": 50,
    "passed_policies": 45,
    "failed_policies": 5
  },
  "data": {
    "cid": "ABC123...",
    "summary": {...},
    "policies": {...}
  }
}
```

#### 2. Host Summary Report

```json
{
  "timestamp": "2025-12-07T14:30:00",
  "report_type": "host-summary",
  "metadata": {
    "cid": "ABC123...",
    "total_hosts": 1000,
    "compliant_hosts": 950,
    "non_compliant_hosts": 50
  },
  "data": {
    "cid": "ABC123...",
    "summary": {...},
    "hosts": [...]
  }
}
```

#### 3. Metrics Report

```json
{
  "timestamp": "2025-12-07T14:30:00",
  "report_type": "metrics",
  "data": {
    "uptime_seconds": 3600,
    "total_runs": 24,
    "successful_runs": 24,
    "total_hosts_processed": 24000,
    "total_policies_graded": 1200,
    "rate_limiter": {...}
  }
}
```

#### 4. Host Details Report

```json
{
  "timestamp": "2025-12-07T14:30:00",
  "report_type": "host-details",
  "metadata": {
    "cid": "ABC123...",
    "total_hosts": 1000,
    "hosts_with_failures": 50
  },
  "data": {
    "cid": "ABC123...",
    "hosts": [...]
  }
}
```

## Examples

### Basic JSON Output

```bash
./bin/policy-audit policies --output-format json > audit_results.json
```

### Filter and Export Failed Policies Only

```bash
./bin/policy-audit policies \
  --output-format json \
  -s failed \
  --output-file failed_policies.json
```

### Full Audit with Host Details

```bash
# First fetch data
./bin/policy-audit fetch

# Then export hosts
./bin/policy-audit hosts \
  --output-format json \
  --output-file full_audit.json
```

### Platform-Specific JSON Report

```bash
./bin/policy-audit policies \
  --output-format json \
  -p Windows \
  -t prevention \
  --output-file windows_prevention.json
```

## Schema Validation

To validate JSON output against the schema:

```bash
# Install ajv-cli
npm install -g ajv-cli

# Generate schema
./bin/policy-audit generate-schema --schema-output schema.json

# Generate output
./bin/policy-audit policies --output-format json --output-file output.json

# Validate
ajv validate -s schema.json -d output.json
```

## Notes

- JSON output suppresses all Rich formatting and progress bars
- Use `--verbose` (global option) with JSON output to see diagnostic messages on stderr
- The `--output-file` option is recommended for large outputs
- Schema validation is optional but recommended for integration testing
- All timestamps are in ISO 8601 format (UTC)
- Use the `hosts` subcommand to include host data in JSON output
- The `host` subcommand can output detailed single-host data in JSON format
