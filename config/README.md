# Configuration Directory

This directory contains user-editable configuration files for the application. You'll find the main YAML configuration for API credentials, database adapters, TTL settings, and logging, as well as JSON files that define the grading criteria used to evaluate CrowdStrike Falcon policy compliance. All files here are designed to be customized to match your environment and security standards.

## Structure

- `config.yaml` - Main application configuration (API credentials, settings, TTLs, logging, database adapter, etc.)
  - **Note**: This file is not checked in (it is intended to be local and contains secrets). Copy from `example.config.yaml` to get started and then edit values.
- `example.config.yaml` - Up-to-date example configuration template you can copy and adapt
- `grading/` - Policy grading configuration files used by the grading engine
  - `prevention_policies_grading.json` - Minimum standards for prevention policies
  - `sensor_update_policies_grading.json` - Minimum standards for sensor update policies
  - `content_update_policies_grading.json` - Minimum standards for content update policies
  - `firewall_policies_grading.json` - Minimum standards for firewall policies
  - `device_control_policies_grading.json` - Minimum standards for device control policies
  - `it_automation_policies_grading.json` - Minimum standards for IT automation policies

## What to expect in `config.yaml`

The project uses an opinionated set of keys in `config.yaml`. Here are the common fields and their meaning:

- `db.type`: select the database adapter in use. Common values: `sqlite`, `tiny_db`.
- `tiny_db.path`: path to TinyDB file (used when `db.type: tiny_db`). Default: `data/db.json`.
- `sqlite.path`: path to SQLite DB file (used when `db.type: sqlite`). Default: `data/db.sqlite`.
- `ttl`: TTL (time-to-live) configuration for cached records. Typical subkeys: `default`, `hosts`, `host_records`, and `policies` (per-policy TTLs such as `firewall_rules`, `firewall_rule_groups`, etc.).
- `falcon_credentials`: API credentials for the Falcon API. Contains `client_id`, `client_secret`, and `base_url`.
- `host_fetching`: parameters used when fetching hosts from the API, e.g. `batch_size` and `progress_threshold`.
- `schedule`: scheduled jobs (name, cron expression, and ttl_hours) used by background tasks.
- `logging`: file paths and `level` for logs (e.g. `logs/app.log`, `logs/api.log`).
- `test`: convenience fields used in local development for sampling a test host, e.g. `aid` and `username`.

Reasonable defaults for many of these fields are set in the runtime helper `src/falcon_policy_scoring/utils/config.py`. If you do not provide a `config/config.yaml`, the loader will populate sensible defaults for `db.type`, TTLs, logging and paths.

## Getting started

1. Copy the example config to create a local `config.yaml`:

  ```bash
  cp config/example.config.yaml config/config.yaml
  ```

2. Edit `config/config.yaml` and set your `falcon_credentials.client_id`, `client_secret`, and `base_url` for your environment, or set them via environment variables as described in the example config comments.

3. If you use the `sqlite` adapter, ensure the `sqlite.path` directory exists (e.g. the `data/` directory).

4. Optionally adjust TTLs and `grading/*.json` to change policy scoring thresholds.

## Grading configuration files

The JSON files in `config/grading/` define grading requirements used by the grading engine. They are read at runtime and applied when evaluating policies. Each file's structure is specific to the policy type but commonly includes:

- `platform_name` or `platform_requirements` — which platforms the rules apply to (e.g. `Windows`, `Linux`, or `all`).
- Flags and required fields for that policy (for example, in `firewall_policies_grading.json` a rule may require `default_inbound: "DENY"`, `enforce: true`, etc.).

Learn More: 
[Understanding The Tool](../docs/understanding-the-tool.md) and
[Policy Grading System Documentation](../docs/policy-grading-system.md) for details on how these files are used.

## Developer notes

- `src/falcon_policy_scoring/utils/config.py` merges defaults into your loaded YAML so the application remains tolerant of missing fields. If you change default keys here, keep `README.md` in sync.
- `example.config.yaml` is intentionally a template — keep secrets out of version control and use the example as a starting point.
