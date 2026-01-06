import yaml


def _load_config_defaults(config):
    # Ensure we have a dict to work with
    if not isinstance(config, dict):
        config = {}

    # Database adapter defaults
    config.setdefault('db', {})
    config['db']['type'] = config['db'].get('type', 'sqlite')

    # TinyDB defaults
    config.setdefault('tiny_db', {})
    config['tiny_db']['path'] = config['tiny_db'].get('path', 'data/db.json')

    # SQLite defaults
    config.setdefault('sqlite', {})
    config['sqlite']['path'] = config['sqlite'].get('path', 'data/db.sqlite')

    # Falcon credentials placeholder defaults (keeps keys present)
    config.setdefault('falcon_credentials', {})
    fc = config['falcon_credentials']
    fc['client_id'] = fc.get('client_id', '')
    fc['client_secret'] = fc.get('client_secret', '')
    fc['base_url'] = fc.get('base_url', '')

    # Host fetching defaults
    config.setdefault('host_fetching', {})
    hf = config['host_fetching']
    hf['batch_size'] = hf.get('batch_size', 100)
    hf['progress_threshold'] = hf.get('progress_threshold', 500)

    # Logging defaults
    config.setdefault('logging', {})
    log = config['logging']
    log['file'] = log.get('file', 'logs/app.log')
    log['api'] = log.get('api', 'logs/api.log')
    log['level'] = log.get('level', 'INFO')

    # Set default TTL values
    if 'ttl' not in config:
        config['ttl'] = {}

    config['ttl']['hosts'] = config['ttl'].get('hosts', 300)  # Host records TTL in seconds
    config['ttl']['host_records'] = config['ttl'].get('host_records', 600)  # Host detailed records TTL in seconds
    config['ttl']['default'] = config['ttl'].get('default', 600)  # Default TTL for records in seconds

    if 'policies' not in config['ttl']:
        config['ttl']['policies'] = {}
    elif isinstance(config['ttl']['policies'], list):
        # Handle case where policies is a list (incorrect format)
        policies_dict = {}
        for item in config['ttl']['policies']:
            if isinstance(item, dict):
                policies_dict.update(item)
        config['ttl']['policies'] = policies_dict

    policy_ttl_defaults = {
        'prevention_policy': 600,
        'devicecontrol_policy': 600,
        'firewall_policy': 600,
        'sensor_update_policy': 600,
        'content_policy': 600,
        'rtr_policy': 600
    }
    for policy, default_ttl in policy_ttl_defaults.items():
        config['ttl']['policies'][policy] = config['ttl']['policies'].get(policy, default_ttl)

    return config


def read_config_from_yaml(config_file="config/config.yaml"):
    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file) or {}
    except Exception as e:
        print(f"Error reading App configuration from {config_file}: {e}")
        config = {}
    config = _load_config_defaults(config)
    return config
