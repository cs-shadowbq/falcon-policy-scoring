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
  - `ods_scheduled_scan_policies_grading.json` - Minimum standards for ODS scheduled scan policies
  - `response_policies_grading.json` - Minimum standards for response (RTR) policies
  - `sca_policies_grading.json` - Minimum standards for SCA (security config assessment) policies

## What to expect in `config.yaml`

The project uses an opinionated set of keys in `config.yaml`. Here are the common fields and their meaning:

- `db.type`: select the database adapter in use. Supported values: `sqlite` (default), `tiny_db`, `dynalite`, `dynamodb`, `foundry_collections`. For disconnected / hardened deployments use `sqlite` — it is the only adapter that is both fully offline and crash-safe.
- `tiny_db.path`: path to TinyDB file (used when `db.type: tiny_db`). Default: `data/db.json`.
- `sqlite.path`: path to SQLite DB file (used when `db.type: sqlite`). Default: `data/db.sqlite` (relative to the working directory). See the note below about absolute paths under systemd.
- `dynalite` / `dynamodb` / `foundry_collections`: adapter-specific settings (local DynamoDB endpoint, AWS region/credentials, or Foundry `app_id`). These require network or platform access and are not suitable for air-gapped hosts.
- `ttl`: TTL (time-to-live) configuration for cached records. Subkeys: `default`, `hosts`, `host_records`, and a `policies` map with per-policy-type TTLs (e.g. `prevention_policy`, `firewall_rules`, `firewall_rule_groups`, `ods_scheduled_scan_policies`, etc.).
- `falcon_credentials`: Falcon API credential handling. Credentials are **not** stored here by default — the recommended approach is environment variables. Keys: `prefix` (ENV var prefix, e.g. `FALCON_` to read `FALCON_CLIENT_ID`/`FALCON_CLIENT_SECRET`/`FALCON_BASE_URL`; empty means `CLIENT_ID`/`CLIENT_SECRET`/`BASE_URL`) and an optional `metadata` block (`include_client_source`, `include_client_hash`, `include_client_id`) controlling what identifying data is embedded in JSON output. `client_id`/`client_secret`/`base_url` may be set here but are commented out in the example and discouraged for security.
- `host_fetching`: parameters used when fetching hosts from the API — `batch_size` (max 100), `progress_threshold`, and `include_zta`.
- `logging`: log file paths and level — `file` (e.g. `logs/app.log`), `api` (e.g. `logs/api.log`), and `level` (e.g. `INFO`).
- `daemon`: daemon-mode settings (ignored for one-off CLI runs). Includes `schedules` (a map of task name → cron expression, e.g. `fetch_and_grade`, `cleanup`, `metrics`), `check_interval`, `policy_types`, `rate_limit`, `output`, and `health_check` (`enabled`, `port`, `bind_address`).

Reasonable defaults for many of these fields are set in the runtime helper `src/falcon_policy_scoring/utils/config.py`. If you do not provide a `config/config.yaml`, the loader will populate sensible defaults for `db.type` (`sqlite`), TTLs, logging, and paths.

> **Note on `sqlite.path` under systemd:** the default `data/db.sqlite` is relative to the process working directory. When installed as a hardened systemd service via the airgap `install.sh`, the seeded config is rewritten to an **absolute** path in the writable data dir (e.g. `/var/lib/falcon-policy-audit/db.sqlite`) so it resolves inside the sandbox's `ReadWritePaths`. See [../INSTALL.md](../INSTALL.md).

## Getting started

1. Copy the example config to create a local `config.yaml`:

  ```bash
  cp config/example.config.yaml config/config.yaml
  ```

2. Edit `config/config.yaml` and set your `falcon_credentials.client_id`, `client_secret`, and `base_url` for your environment, or set them via environment variables as described in the example config comments.

3. If you use the `sqlite` adapter (the default), ensure the directory holding `sqlite.path` exists (e.g. the `data/` directory for the default relative path, or the absolute data dir when running as a service — see the note above).

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
