# Policy Audit Tool - Interactive Mode

A professional command-line tool for auditing CrowdStrike Falcon security policies. This tool fetches, grades, and displays policy compliance information with beautiful table formatting and flexible filtering options.

## Features

- 🔍 **Policy Grading**: Automatically grade prevention, sensor update, content update, firewall, device control, and IT automation policies against best practices
- 🖥️ **Host Analysis**: View policy status across all managed hosts
- 🎨 **Rich Formatting**: Beautiful colored tables with status indicators
- 🔎 **Advanced Filtering**: Filter by policy type, platform, and grading status
- 📊 **Detailed Reports**: View summary statistics and detailed failure information
- 🔀 **Flexible Sorting**: Sort policies and hosts by multiple criteria
- 💾 **Caching**: Uses local database to avoid unnecessary API calls

## Installation

Ensure the package is installed in editable mode:

```bash
pip install -e .
```

## Quick Start

### Fetch fresh data and grade all policies

```bash
./bin/policy-audit fetch
```

### View policy grades (from cache)

```bash
./bin/policy-audit policies
```

### Show detailed failure information for policies

```bash
./bin/policy-audit policies --details
```

### View host-level policy status summary

```bash
./bin/policy-audit hosts
```

### View detailed status for a specific host

```bash
./bin/policy-audit host HOSTNAME --details
```

## Usage Examples

### Fetching Data

**Fetch all policies and hosts:**

```bash
./bin/policy-audit fetch
```

**Fetch specific policy type:**

```bash
./bin/policy-audit fetch -t prevention
```

**Fetch with custom product types:**

```bash
./bin/policy-audit fetch --product-types "Workstation,Server"
```

**Fetch only hosts seen in the last day:**

```bash
./bin/policy-audit fetch --last-seen day
```

**Fetch hosts from specific group seen in last 12 hours:**

```bash
./bin/policy-audit fetch --host-groups "Production Servers" --last-seen "12 hours"
```

### Viewing Policies

**Show all policies:**

```bash
./bin/policy-audit policies
```

**Show only prevention policies:**

```bash
./bin/policy-audit policies -t prevention
```

**Show multiple policy types:**

```bash
./bin/policy-audit policies -t prevention,firewall
```

**Show only failed policies:**

```bash
./bin/policy-audit policies -s failed
```

**Show Windows policies that failed:**

```bash
./bin/policy-audit policies -p Windows -s failed
```

**Show failed policies with details:**

```bash
./bin/policy-audit policies -s failed --details
```

### Sorting Policies

**Sort policies by score (worst first):**

```bash
./bin/policy-audit policies --sort score
```

**Sort policies by name:**

```bash
./bin/policy-audit policies -t firewall --sort name
```

**Sort by platform:**

```bash
./bin/policy-audit policies --sort platform
```

### Host Analysis

**Show all hosts:**

```bash
./bin/policy-audit hosts
```

**Show only hosts where all policies passed:**

```bash
./bin/policy-audit hosts -s all-passed
```

**Show only hosts with any failed policy:**

```bash
./bin/policy-audit hosts -s any-failed
```

**Show Windows hosts with policy failures:**

```bash
./bin/policy-audit hosts -p Windows -s any-failed
```

**Sort hosts by hostname:**

```bash
./bin/policy-audit hosts --sort hostname
```

**Sort hosts by status (failed first):**

```bash
./bin/policy-audit hosts --sort status
```

### Single Host Details

**View specific host status:**

```bash
./bin/policy-audit host WIN-SERVER-01
```

**View host with detailed failure information:**

```bash
./bin/policy-audit host WIN-SERVER-01 --details
```

**View specific policy type for a host:**

```bash
./bin/policy-audit host WIN-SERVER-01 -t prevention --details
```

**View multiple policy types for a host:**

```bash
./bin/policy-audit host WIN-SERVER-01 -t prevention,firewall,device-control --details
```

### Using Different Configurations

**Use a different config file:**

```bash
./bin/policy-audit -c config/production.yaml --fetch
```

**Override API credentials:**

```bash
./bin/policy-audit --client-id YOUR_CLIENT_ID --client-secret YOUR_SECRET --fetch
```

**Specify different base URL:**

```bash
./bin/policy-audit --base-url EU1 --fetch
```

## Command Reference

### Global Options

These options are available for all subcommands:

| Option | Description |
|--------|-------------|
| `-c, --config` | Path to configuration YAML file (default: `config/config.yaml`) |
| `--client-id` | CrowdStrike API Client ID (overrides config file) |
| `--client-secret` | CrowdStrike API Client Secret (overrides config file) |
| `--base-url` | CrowdStrike API Base URL: US1, US2, EU1, etc. (overrides config file) |
| `--output-format` | Output format: `text` (default) or `json` |
| `--output-file` | Write output to file instead of stdout |
| `-v, --verbose` | Enable verbose output |

### Subcommands

#### `fetch` - Fetch and grade data from API

Fetches fresh policy and host data from CrowdStrike API.

```bash
policy-audit fetch [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-t, --type` | Policy type(s): `all` or comma-separated list (e.g., `prevention,firewall`) - choices: `prevention`, `sensor-update`, `content-update`, `firewall`, `device-control`, `it-automation` (default: `all`) |
| `--product-types` | Comma-separated product types (default: `Workstation,Domain Controller,Server`) |
| `--host-groups` | Comma-separated list of host group names to filter hosts (e.g., `"Production Servers,Development"`) |
| `--last-seen` | Filter hosts by last seen time: `hour`, `12 hours`, `day`, or `week` |

#### `policies` - Display policy grading tables

Shows graded policy tables with filtering and sorting.

```bash
policy-audit policies [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-t, --type` | Policy type(s) to display: `all` or comma-separated list (e.g., `prevention,firewall`) (default: `all`) |
| `-p, --platform` | Filter by platform: `Windows`, `Mac`, `Linux` |
| `-s, --status` | Filter by status: `passed`, `failed` |
| `--details` | Show detailed failure information |
| `--sort` | Sort by: `platform` (default), `name`, or `score` |

#### `hosts` - Display host-level status summary

Shows policy status for all hosts.

```bash
policy-audit hosts [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-t, --type` | Policy type(s) to include: `all` or comma-separated list (e.g., `prevention,firewall`) (default: `all`) |
| `-p, --platform` | Filter by platform: `Windows`, `Mac`, `Linux` |
| `-s, --status` | Filter by status: `all-passed`, `any-failed` |
| `--sort` | Sort by: `platform` (default), `hostname`, or `status` |

#### `host` - Display detailed status for specific host

Shows detailed policy information for a single host.

```bash
policy-audit host HOSTNAME [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `hostname` | Hostname to display (required, positional) |

| Option | Description |
|--------|-------------|
| `-t, --type` | Policy type(s) to include: `all` or comma-separated list (e.g., `prevention,firewall`) (default: `all`) |
| `--details` | Show detailed failure information |

#### `regrade` - Re-grade existing policies

Re-grades policies already in the database using current grading criteria without fetching new data from the API.

```bash
policy-audit regrade [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-t, --type` | Policy type(s) to re-grade: `all` or comma-separated list (e.g., `prevention,firewall`) (default: `all`) |

#### `generate-schema` - Generate JSON schema

Generates JSON schema for policy-audit output.

```bash
policy-audit generate-schema [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--schema-output` | Path to write schema file (default: stdout) |

## Output Format

### Policy Table

The policy table shows:

- ✓/✗ Status indicator with color
- Policy name
- Platform (Windows, Mac, Linux)
- Failed checks (e.g., "2/15 failed")
- Overall score percentage with color coding:
  - Green: 100%
  - Yellow: 80-99%
  - Red: <80%

### Host Summary Table

The host summary shows:

- Hostname
- Platform
- Prevention policy status
- Sensor update policy status
- Content update policy status
- Firewall policy status
- Device Control policy status
- IT Automation policy status

Status values:

- ✓ PASSED (green)
- ✗ FAILED (red)
- NOT GRADED (yellow)
- NO POLICY (dim)

### Detailed Failure Information

When using `--details`, failed policies show:

- Policy name and platform
- Total checks and failures
- List of failed settings with specific values that don't meet requirements

## Configuration

Create a `config/config.yaml` file with your CrowdStrike API credentials:

```yaml
falcon_api:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  base_url: "US2"

tiny_db:
  path: "data/db.json"

ttl:
  hosts: 3600
  policies: 3600

logging:
  level: "INFO"
  file: "logs/policy-audit.log"
```

## Tips

1. **First run**: Use `fetch` subcommand to populate the database
2. **Regular updates**: Run `fetch` periodically to get fresh data
3. **Quick checks**: Use `policies` or `hosts` subcommands to view cached data instantly
4. **Focus on failures**: Use `policies -s failed --details` to quickly identify issues
5. **Monitor hosts**: Use `hosts -s any-failed` to find problematic hosts
6. **Single host details**: Use `host HOSTNAME --details` for deep dive on specific systems
7. **Multiple policy types**: Use comma-separated lists with `-t` (e.g., `-t prevention,firewall`) to view specific policy combinations
8. **Filter by recency**: Use `--last-seen` to focus on recently active hosts (e.g., `--last-seen day` for hosts seen in last 24 hours)
9. **Update grading criteria**: Use `regrade` to re-evaluate policies when grading rules are updated, without re-fetching data
10. **Verbose mode**: Add `-v` (global option) when troubleshooting

## Example Workflow

```bash
# Initial fetch of all data
./bin/policy-audit fetch

# View all policies
./bin/policy-audit policies

# Daily check for failures (worst first)
./bin/policy-audit policies -s failed --sort score

# Check specific policy type with details
./bin/policy-audit policies -t prevention --details

# Check multiple policy types
./bin/policy-audit policies -t prevention,sensor-update,firewall

# View all hosts
./bin/policy-audit hosts

# Audit Windows hosts (failed first)
./bin/policy-audit hosts -p Windows --sort status

# Check device control policies
./bin/policy-audit policies -t device-control --details

# Check IT automation policies
./bin/policy-audit policies -t it-automation --details

# View specific host details
./bin/policy-audit host WIN-SERVER-01 --details

# Fetch only prevention policies
./bin/policy-audit fetch -t prevention

# Fetch only hosts seen in the last day
./bin/policy-audit fetch --last-seen day

# Fetch specific host group seen in last 12 hours
./bin/policy-audit fetch --host-groups "Production" --last-seen "12 hours"

# Re-grade all policies with updated criteria
./bin/policy-audit regrade

# Re-grade only specific policy types
./bin/policy-audit regrade -t prevention,firewall
```

## Key Features

- **Subcommand architecture**: Intuitive command structure with dedicated subcommands for different operations
- **Professional CLI interface**: Built with argparse and Rich for beautiful output
- **Rich table formatting**: Color-coded status indicators and formatted tables
- **Flexible filtering**: Filter by platform, status, policy type
- **Multiple sorting options**: Sort by platform, name, score, hostname, or status
- **Caching support**: View cached data instantly without API calls
- **Host analysis**: Both summary view (hosts) and detailed view (host)
- **JSON output**: Machine-readable output for automation and integration
- **Comprehensive help**: Built-in help for all subcommands

## Troubleshooting

**Error: No client_id provided**

- Ensure `config/config.yaml` exists and contains API credentials, or use `--client-id` and `--client-secret` global options

**No data displayed**

- Run `policy-audit fetch` first to populate the database
- Check that your API credentials are correct

**Empty tables**

- Run `policy-audit fetch` to ensure data is cached
- Verify filters aren't too restrictive
- Use `--verbose` (global option) to see what's happening
- Check that policies exist in your environment

**Import errors**

- Ensure package is installed: `pip install -e .`
- Verify you're in the correct directory
