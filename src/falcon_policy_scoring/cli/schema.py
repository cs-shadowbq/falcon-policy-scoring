"""JSON schema generation for policy-audit output."""
import json
import sys
from pathlib import Path


def generate_host_details_schema() -> dict:
    """Generate JSON schema for host-details output.

    Returns:
        JSON schema dict
    """
    return {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "$id": "https://github.com/crowdstrike/policy-audit/schemas/host-details.schema.json",
        "title": "CrowdStrike Falcon Policy Audit - Host Details Output",
        "description": "Schema for host-details report containing policy grading results and comprehensive host information",
        "type": "object",
        "required": ["metadata", "summary", "policies"],
        "properties": {
            "metadata": {
                "type": "object",
                "required": ["version", "timestamp", "report_type", "cid", "database_type", "filters"],
                "properties": {
                    "version": {
                        "type": "string",
                        "description": "Version of the policy-audit tool"
                    },
                    "timestamp": {
                        "type": "string",
                        "format": "date-time",
                        "description": "ISO 8601 timestamp when the audit was run"
                    },
                    "report_type": {
                        "type": "string",
                        "description": "Type of report (e.g., 'policy-audit', 'host-details', 'host-summary', 'metrics')"
                    },
                    "cid": {
                        "type": "string",
                        "description": "CrowdStrike Customer ID"
                    },
                    "database_type": {
                        "type": "string",
                        "description": "Type of database used for caching"
                    },
                    "filters": {
                        "type": "object",
                        "properties": {
                            "policy_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Policy types included in the audit"
                            },
                            "platform": {
                                "type": ["string", "null"],
                                "enum": ["Windows", "Mac", "Linux", None],
                                "description": "Platform filter applied"
                            },
                            "status": {
                                "type": ["string", "null"],
                                "enum": ["passed", "failed", None],
                                "description": "Status filter applied"
                            },
                            "product_types": {
                                "type": ["array", "null"],
                                "items": {"type": "string"},
                                "description": "Product types included when fetching hosts"
                            }
                        }
                    }
                }
            },
            "summary": {
                "type": "object",
                "required": ["total_policies", "passed_policies", "failed_policies", "overall_score"],
                "properties": {
                    "total_policies": {
                        "type": "integer",
                        "description": "Total number of policies audited"
                    },
                    "passed_policies": {
                        "type": "integer",
                        "description": "Number of policies that passed grading"
                    },
                    "failed_policies": {
                        "type": "integer",
                        "description": "Number of policies that failed grading (excludes ungradable)"
                    },
                    "ungradable_policies": {
                        "type": "integer",
                        "description": "Number of policies that could not be graded"
                    },
                    "overall_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 100,
                        "description": "Overall score percentage across all policies"
                    },
                    "total_hosts": {
                        "type": "integer",
                        "description": "Total number of hosts (present when --show-hosts is used)"
                    },
                    "hosts_all_passed": {
                        "type": "integer",
                        "description": "Number of hosts where all policies passed"
                    },
                    "hosts_any_failed": {
                        "type": "integer",
                        "description": "Number of hosts where at least one policy failed"
                    }
                }
            },
            "policies": {
                "type": "object",
                "description": "Policy results by policy type",
                "patternProperties": {
                    "^(prevention|sensor_update|content_update|firewall|device_control|it_automation)$": {
                        "type": "object",
                        "required": ["cache_age_seconds", "cache_ttl_seconds", "cache_expired", "total_policies", "passed_policies", "failed_policies", "score_percentage", "graded_policies"],
                        "properties": {
                            "cache_age_seconds": {
                                "type": "integer",
                                "description": "Age of cached data in seconds"
                            },
                            "cache_ttl_seconds": {
                                "type": "integer",
                                "description": "Time-to-live for cached data in seconds"
                            },
                            "cache_expired": {
                                "type": "boolean",
                                "description": "Whether cached data has expired"
                            },
                            "total_policies": {
                                "type": "integer",
                                "description": "Total policies of this type"
                            },
                            "passed_policies": {
                                "type": "integer",
                                "description": "Policies that passed grading"
                            },
                            "failed_policies": {
                                "type": "integer",
                                "description": "Policies that failed grading (excludes ungradable)"
                            },
                            "ungradable_policies": {
                                "type": "integer",
                                "description": "Policies that could not be graded"
                            },
                            "score_percentage": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 100,
                                "description": "Score percentage for this policy type"
                            },
                            "graded_policies": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["policy_id", "policy_name", "platform_name", "passed", "checks_count", "failures_count", "score_percentage", "setting_results"],
                                    "properties": {
                                        "policy_id": {
                                            "type": "string",
                                            "description": "Unique policy identifier"
                                        },
                                        "policy_name": {
                                            "type": "string",
                                            "description": "Human-readable policy name"
                                        },
                                        "platform_name": {
                                            "type": "string",
                                            "description": "Platform the policy applies to"
                                        },
                                        "passed": {
                                            "type": ["boolean", "null"],
                                            "description": "Whether the policy passed grading (null if ungradable)"
                                        },
                                        "grading_status": {
                                            "type": "string",
                                            "enum": ["graded", "ungradable"],
                                            "description": "Indicates if policy was graded or ungradable"
                                        },
                                        "ungradable_reason": {
                                            "type": "string",
                                            "description": "Reason policy could not be graded (e.g., 'no_platform_config')"
                                        },
                                        "checks_count": {
                                            "type": "integer",
                                            "description": "Total number of checks performed"
                                        },
                                        "failures_count": {
                                            "type": "integer",
                                            "description": "Number of checks that failed"
                                        },
                                        "score_percentage": {
                                            "type": "number",
                                            "minimum": 0,
                                            "maximum": 100,
                                            "description": "Policy score percentage"
                                        },
                                        "setting_results": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "setting_name": {"type": "string"},
                                                    "expected_value": {},
                                                    "actual_value": {},
                                                    "passed": {"type": "boolean"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "hosts": {
                "type": "array",
                "description": "Host-level policy status (present when --show-hosts is used)",
                "items": {
                    "type": "object",
                    "required": ["device_id", "hostname", "platform", "policy_status", "all_policies_passed", "any_policy_failed"],
                    "properties": {
                        "device_id": {
                            "type": "string",
                            "description": "CrowdStrike device ID"
                        },
                        "hostname": {
                            "type": "string",
                            "description": "Hostname of the device"
                        },
                        "platform": {
                            "type": "string",
                            "description": "Operating system platform"
                        },
                        "policy_status": {
                            "type": "object",
                            "description": "Status of each policy type for this host",
                            "properties": {
                                "prevention": {"$ref": "#/definitions/hostPolicyStatus"},
                                "sensor_update": {"$ref": "#/definitions/hostPolicyStatus"},
                                "content_update": {"$ref": "#/definitions/hostPolicyStatus"},
                                "firewall": {"$ref": "#/definitions/hostPolicyStatus"},
                                "device_control": {"$ref": "#/definitions/hostPolicyStatus"},
                                "it_automation": {"$ref": "#/definitions/hostPolicyStatus"}
                            }
                        },
                        "all_policies_passed": {
                            "type": "boolean",
                            "description": "True if all policies passed for this host"
                        },
                        "any_policy_failed": {
                            "type": "boolean",
                            "description": "True if any policy failed for this host"
                        },
                        "host_record": {
                            "type": "object",
                            "description": "Complete host details from CrowdStrike API (GetDeviceDetailsV2). Includes device information, policies, configuration, network details, and more."
                        },
                        "zero_trust": {
                            "type": "object",
                            "description": "Zero Trust Assessment data for this host from CrowdStrike ZTA API",
                            "properties": {
                                "aid": {
                                    "type": "string",
                                    "description": "Agent ID (same as device_id)"
                                },
                                "cid": {
                                    "type": "string",
                                    "description": "Customer ID"
                                },
                                "assessment": {
                                    "type": "object",
                                    "description": "ZTA scores",
                                    "properties": {
                                        "sensor_config": {
                                            "type": "integer",
                                            "description": "Sensor configuration score (0-100)"
                                        },
                                        "os": {
                                            "type": "integer",
                                            "description": "Operating system score (0-100)"
                                        },
                                        "overall": {
                                            "type": "integer",
                                            "description": "Overall ZTA score (0-100)"
                                        },
                                        "version": {
                                            "type": "string",
                                            "description": "ZTA assessment version"
                                        }
                                    }
                                },
                                "assessment_items": {
                                    "type": "object",
                                    "description": "Detailed assessment criteria and results",
                                    "properties": {
                                        "os_signals": {
                                            "type": "array",
                                            "description": "OS-level security signals",
                                            "items": {"type": "object"}
                                        },
                                        "sensor_signals": {
                                            "type": "array",
                                            "description": "Sensor-level security signals",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "signal_id": {"type": "string"},
                                                    "signal_name": {"type": "string"},
                                                    "group_name": {"type": "string"},
                                                    "criteria": {"type": "string"},
                                                    "meets_criteria": {"type": "string", "enum": ["yes", "no"]}
                                                }
                                            }
                                        }
                                    }
                                },
                                "modified_time": {
                                    "type": "string",
                                    "description": "Last modification timestamp (ISO 8601)"
                                },
                                "sensor_file_status": {
                                    "type": "string",
                                    "description": "Sensor deployment status"
                                },
                                "system_serial_number": {
                                    "type": "string",
                                    "description": "System serial number"
                                },
                                "event_platform": {
                                    "type": "string",
                                    "description": "Platform type"
                                },
                                "product_type_desc": {
                                    "type": "string",
                                    "description": "Product type description"
                                }
                            }
                        }
                    }
                }
            }
        },
        "definitions": {
            "hostPolicyStatus": {
                "type": "object",
                "required": ["status"],
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["passed", "failed", "not-assigned", "not-graded"],
                        "description": "Policy status for the host"
                    },
                    "policy_id": {
                        "type": ["string", "null"],
                        "description": "ID of the policy assigned to the host"
                    },
                    "policy_name": {
                        "type": ["string", "null"],
                        "description": "Name of the policy assigned to the host"
                    }
                }
            }
        }
    }


def generate_policy_audit_schema() -> dict:
    """Generate JSON schema for policy-audit output (simplified daemon report).

    Returns:
        JSON schema dict
    """
    return {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "$id": "https://github.com/crowdstrike/policy-audit/schemas/policy-audit.schema.json",
        "title": "CrowdStrike Falcon Policy Audit - Policy Audit Output",
        "description": "Schema for policy-audit daemon report containing simplified policy grading summary",
        "type": "object",
        "required": ["metadata", "summary", "policies"],
        "properties": {
            "metadata": {
                "type": "object",
                "required": ["version", "timestamp", "report_type", "command", "cid", "database_type"],
                "properties": {
                    "version": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "report_type": {"type": "string", "const": "policy-audit"},
                    "command": {"type": "string"},
                    "cid": {"type": "string"},
                    "database_type": {"type": "string"},
                    "client_source": {"type": "string", "description": "SHA256 hash of username:hostname"},
                    "client_hash": {"type": "string", "description": "SHA256 hash of client_id:client_secret"},
                    "client_id": {"type": "string", "description": "CrowdStrike API client ID"}
                }
            },
            "summary": {
                "type": "object",
                "required": ["total_policies", "passed_policies", "failed_policies", "pass_rate"],
                "properties": {
                    "total_policies": {"type": "integer", "minimum": 0},
                    "passed_policies": {"type": "integer", "minimum": 0},
                    "failed_policies": {"type": "integer", "minimum": 0},
                    "pass_rate": {"type": "number", "minimum": 0, "maximum": 1}
                }
            },
            "policies": {
                "type": "object",
                "patternProperties": {
                    "^(prevention|sensor-update|content-update|firewall|device-control|it-automation)$": {
                        "type": "object",
                        "required": ["fetch_success", "grade_success", "policies_count", "passed_policies", "failed_policies"],
                        "properties": {
                            "fetch_success": {"type": "boolean"},
                            "grade_success": {"type": "boolean"},
                            "policies_count": {"type": "integer", "minimum": 0},
                            "containers_count": {"type": "integer", "minimum": 0},
                            "settings_count": {"type": "integer", "minimum": 0},
                            "passed_policies": {"type": "integer", "minimum": 0},
                            "failed_policies": {"type": "integer", "minimum": 0}
                        }
                    }
                }
            }
        }
    }


def generate_host_summary_schema() -> dict:
    """Generate JSON schema for host-summary output.

    Returns:
        JSON schema dict
    """
    return {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "$id": "https://github.com/crowdstrike/policy-audit/schemas/host-summary.schema.json",
        "title": "CrowdStrike Falcon Policy Audit - Host Summary Output",
        "description": "Schema for host-summary report containing host compliance statistics",
        "type": "object",
        "required": ["metadata", "summary", "hosts"],
        "properties": {
            "metadata": {
                "type": "object",
                "required": ["version", "timestamp", "report_type", "command", "cid", "database_type"],
                "properties": {
                    "version": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "report_type": {"type": "string", "const": "host-summary"},
                    "command": {"type": "string"},
                    "cid": {"type": "string"},
                    "database_type": {"type": "string"},
                    "client_source": {"type": "string", "description": "SHA256 hash of username:hostname"},
                    "client_hash": {"type": "string", "description": "SHA256 hash of client_id:client_secret"},
                    "client_id": {"type": "string", "description": "CrowdStrike API client ID"}
                }
            },
            "summary": {
                "type": "object",
                "required": ["total_hosts", "hosts_all_passed", "hosts_any_failed"],
                "properties": {
                    "total_hosts": {"type": "integer", "minimum": 0},
                    "hosts_all_passed": {"type": "integer", "minimum": 0},
                    "hosts_any_failed": {"type": "integer", "minimum": 0}
                }
            },
            "hosts": {
                "type": "array",
                "items": {"type": "string", "description": "Device ID"},
                "description": "List of device IDs included in the summary"
            }
        }
    }


def generate_metrics_schema() -> dict:
    """Generate JSON schema for metrics output.

    Returns:
        JSON schema dict
    """
    return {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "$id": "https://github.com/crowdstrike/policy-audit/schemas/metrics.schema.json",
        "title": "CrowdStrike Falcon Policy Audit - Metrics Output",
        "description": "Schema for daemon metrics report containing runtime statistics",
        "type": "object",
        "required": ["metadata", "uptime_seconds", "total_runs", "successful_runs", "failed_runs"],
        "properties": {
            "metadata": {
                "type": "object",
                "required": ["version", "timestamp", "report_type", "command", "cid", "database_type"],
                "properties": {
                    "version": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "report_type": {"type": "string", "const": "metrics"},
                    "command": {"type": "string"},
                    "cid": {"type": "string"},
                    "database_type": {"type": "string"},
                    "client_source": {"type": "string", "description": "SHA256 hash of username:hostname"},
                    "client_hash": {"type": "string", "description": "SHA256 hash of client_id:client_secret"},
                    "client_id": {"type": "string", "description": "CrowdStrike API client ID"}
                }
            },
            "uptime_seconds": {"type": "number", "minimum": 0},
            "uptime_hours": {"type": "number", "minimum": 0},
            "total_runs": {"type": "integer", "minimum": 0},
            "successful_runs": {"type": "integer", "minimum": 0},
            "failed_runs": {"type": "integer", "minimum": 0},
            "success_rate": {"type": "number", "minimum": 0, "maximum": 1},
            "total_hosts_processed": {"type": "integer", "minimum": 0},
            "total_policies_graded": {"type": "integer", "minimum": 0},
            "total_policies_passed": {"type": "integer", "minimum": 0},
            "total_policies_failed": {"type": "integer", "minimum": 0},
            "policy_pass_rate": {"type": "number", "minimum": 0, "maximum": 1},
            "total_api_calls": {"type": "integer", "minimum": 0},
            "total_api_errors": {"type": "integer", "minimum": 0},
            "api_error_rate": {"type": "number", "minimum": 0, "maximum": 1},
            "total_duration_seconds": {"type": "number", "minimum": 0},
            "avg_run_duration_seconds": {"type": "number", "minimum": 0},
            "last_run": {
                "type": "object",
                "properties": {
                    "start_time": {"type": "string"},
                    "end_time": {"type": "string"},
                    "duration_seconds": {"type": "number"},
                    "hosts_processed": {"type": "integer"},
                    "policies_graded": {"type": "integer"},
                    "policies_passed": {"type": "integer"},
                    "policies_failed": {"type": "integer"},
                    "api_calls": {"type": "integer"},
                    "api_errors": {"type": "integer"},
                    "success": {"type": "boolean"},
                    "error_message": {"type": ["string", "null"]}
                }
            },
            "rate_limiter": {
                "type": "object",
                "properties": {
                    "total_requests": {"type": "integer"},
                    "throttled_requests": {"type": "integer"},
                    "failed_requests": {"type": "integer"},
                    "total_wait_time": {"type": "number"},
                    "current_rpm": {"type": "integer"},
                    "current_tokens": {"type": "number"},
                    "consecutive_429s": {"type": "integer"},
                    "in_backoff": {"type": "boolean"},
                    "backoff_remaining": {"type": "number"}
                }
            }
        }
    }


SCHEMA_GENERATORS = {
    "host-details": generate_host_details_schema,
    "policy-audit": generate_policy_audit_schema,
    "host-summary": generate_host_summary_schema,
    "metrics": generate_metrics_schema
}


def handle_schema_generation(args):
    """Handle generate-schema subcommand.

    Args:
        args: Command line arguments with report_type and schema_output
    """
    output_dir = Path(args.schema_output) if args.schema_output else Path("./output/schemas")

    # If report_type is specified, generate only that schema
    if hasattr(args, 'report_type') and args.report_type:
        report_type = args.report_type
        if report_type not in SCHEMA_GENERATORS:
            print(f"Error: Unknown report type '{report_type}'", file=sys.stderr)
            print(f"Available types: {', '.join(SCHEMA_GENERATORS.keys())}", file=sys.stderr)
            sys.exit(1)

        schema = SCHEMA_GENERATORS[report_type]()
        schema_json = json.dumps(schema, indent=2)

        # If output is a directory, write to file; otherwise treat as single file path
        if output_dir.is_dir() or (not output_dir.exists() and output_dir.suffix == ''):
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = output_dir / f"{report_type}.schema.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(schema_json)
            print(f"Schema written to {output_file}")
        else:
            # Single file output
            output_dir.parent.mkdir(parents=True, exist_ok=True)
            with open(output_dir, 'w', encoding='utf-8') as f:
                f.write(schema_json)
            print(f"Schema written to {output_dir}")
    else:
        # Generate all schemas
        output_dir.mkdir(parents=True, exist_ok=True)

        for report_type, generator in SCHEMA_GENERATORS.items():
            schema = generator()
            schema_json = json.dumps(schema, indent=2)
            output_file = output_dir / f"{report_type}.schema.json"

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(schema_json)
            print(f"Schema written to {output_file}")

        print(f"\nGenerated {len(SCHEMA_GENERATORS)} schemas in {output_dir}")
