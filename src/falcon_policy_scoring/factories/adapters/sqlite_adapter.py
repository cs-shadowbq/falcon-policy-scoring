import sqlite3
import json
import logging
from falcon_policy_scoring.factories.adapters.database_adapter import DatabaseAdapter
from falcon_policy_scoring.utils.core import epoch_now


class SQLiteAdapter(DatabaseAdapter):
    """SQLite adapter implementation."""

    def __init__(self):
        self.db = None
        self.conn = None
        self.cursor = None

    def connect(self, config):
        """Connect to SQLite database and create tables if they don't exist."""
        self.conn = sqlite3.connect(config['path'], check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._create_tables()
        logging.info(f"Connected to SQLite database at {config['path']}")

    def _create_tables(self):
        """Create all necessary tables if they don't exist."""

        # Hosts table - stores list of device IDs for a CID
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cid TEXT NOT NULL UNIQUE,
                base_url TEXT,
                epoch INTEGER NOT NULL,
                hosts TEXT NOT NULL,
                total INTEGER NOT NULL
            )
        ''')

        # Host records table - stores detailed device information
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cid TEXT NOT NULL,
                aid TEXT NOT NULL,
                record_type INTEGER NOT NULL,
                epoch INTEGER NOT NULL,
                data TEXT NOT NULL,
                UNIQUE(aid, record_type)
            )
        ''')

        # Generic policies table - stores all policy types
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_type TEXT NOT NULL,
                cid TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                policies TEXT NOT NULL,
                total INTEGER NOT NULL,
                error INTEGER,
                UNIQUE(policy_type, cid)
            )
        ''')

        # Graded policies table - stores graded policy results
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS graded_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_type TEXT NOT NULL,
                cid TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                graded_policies TEXT NOT NULL,
                total_policies INTEGER NOT NULL,
                passed_policies INTEGER NOT NULL,
                failed_policies INTEGER NOT NULL,
                UNIQUE(policy_type, cid)
            )
        ''')

        # Firewall policy containers table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_policy_containers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                cid TEXT NOT NULL,
                policy_containers TEXT NOT NULL,
                count INTEGER NOT NULL,
                epoch INTEGER NOT NULL
            )
        ''')

        # Device control policy settings table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_control_policy_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                cid TEXT NOT NULL,
                policy_settings TEXT NOT NULL,
                count INTEGER NOT NULL,
                epoch INTEGER NOT NULL
            )
        ''')

        # Zero Trust Assessment table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_zta (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL UNIQUE,
                epoch INTEGER NOT NULL,
                data TEXT NOT NULL
            )
        ''')

        # Create indexes for better performance
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_cid ON hosts(cid)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_records_aid ON host_records(aid, record_type)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_policies_type_cid ON policies(policy_type, cid)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_graded_policies_type_cid ON graded_policies(policy_type, cid)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_firewall_containers_key ON firewall_policy_containers(key)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_control_settings_key ON device_control_policy_settings(key)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_zta_device_id ON host_zta(device_id)')

        self.conn.commit()
        logging.info("SQLite tables and indexes created/verified")

    def get_hosts_collection(self):
        """Not applicable for SQLite - returns None."""
        return None

    def get_host_records_collection(self):
        """Not applicable for SQLite - returns None."""
        return None

    def create_record(self, collection, newvalue_set):
        """Not used in SQLite adapter - specific methods handle inserts."""
        pass

    def update_record(self, collection, resource, newvalue_set):
        """Not used in SQLite adapter - specific methods handle updates."""
        pass

    def update_or_create_record(self, collection, resource, data):
        """Not used in SQLite adapter - specific methods handle upserts."""
        pass

    # 'hosts' Table

    def put_hosts(self, list_of_devices):
        """
        Store the list of devices for a CID.

        Args:
            list_of_devices: Dict with structure:
                {
                    'cid': string,
                    'base_url': string,
                    'epoch': int,
                    'hosts': [string, ...],
                    'total': int
                }

        Returns:
            int: Row ID of the inserted/updated record
        """
        cid = list_of_devices['cid']
        base_url = list_of_devices.get('base_url', '')
        epoch = list_of_devices.get('epoch', epoch_now())
        hosts = json.dumps(list_of_devices['hosts'])
        total = list_of_devices['total']

        # Delete existing record for this CID
        self.cursor.execute('DELETE FROM hosts WHERE cid = ?', (cid,))

        # Insert new record
        self.cursor.execute('''
            INSERT INTO hosts (cid, base_url, epoch, hosts, total)
            VALUES (?, ?, ?, ?, ?)
        ''', (cid, base_url, epoch, hosts, total))

        self.conn.commit()
        row_id = self.cursor.lastrowid
        logging.info(f"SQLite hosts record created for CID {cid} with row_id {row_id}")
        return row_id

    def get_hosts(self, cid):
        """
        Retrieve the hosts record for a given CID.

        Args:
            cid: Customer ID

        Returns:
            dict: Hosts record with structure matching TinyDB format, or None if not found
        """
        self.cursor.execute('''
            SELECT cid, base_url, epoch, hosts, total
            FROM hosts
            WHERE cid = ?
        ''', (cid,))

        row = self.cursor.fetchone()
        if row:
            result = {
                'cid': row['cid'],
                'base_url': row['base_url'],
                'epoch': row['epoch'],
                'hosts': json.loads(row['hosts']),
                'total': row['total']
            }
            return result
        else:
            logging.info(f"Hosts record for CID {cid} NOT Found.")
            return None

    def put_host(self, device_details, record_type=4):
        """
        Store detailed device information.

        Args:
            device_details: Dict containing device information
            record_type: Type of record (default: 4)
        """
        cid = device_details.get('cid', 'unknown_cid')
        aid = device_details.get('device_id', 'unknown_aid')
        epoch = epoch_now()
        data = json.dumps(device_details)

        # Check for existing record
        self.cursor.execute('''
            SELECT id FROM host_records
            WHERE aid = ? AND record_type = ?
        ''', (aid, record_type))

        existing = self.cursor.fetchone()

        if existing:
            # Update existing record
            self.cursor.execute('''
                UPDATE host_records
                SET cid = ?, epoch = ?, data = ?
                WHERE aid = ? AND record_type = ?
            ''', (cid, epoch, data, aid, record_type))
            logging.info(f"SQLite host record updated for device_id {aid}, record_type {record_type}")
        else:
            # Insert new record
            self.cursor.execute('''
                INSERT INTO host_records (cid, aid, record_type, epoch, data)
                VALUES (?, ?, ?, ?, ?)
            ''', (cid, aid, record_type, epoch, data))
            logging.info(f"SQLite host record created for device_id {aid}, record_type {record_type}")

        self.conn.commit()

    def get_host(self, device_id, record_type=4):
        """
        Retrieve detailed device information.

        Args:
            device_id: Device ID (aid)
            record_type: Type of record (default: 4)

        Returns:
            dict: Host record with structure matching TinyDB format, or None if not found
        """
        self.cursor.execute('''
            SELECT id, cid, aid, record_type, epoch, data
            FROM host_records
            WHERE aid = ? AND record_type = ?
        ''', (device_id, record_type))

        row = self.cursor.fetchone()
        if row:
            result = {
                '_id': row['id'],
                'cid': row['cid'],
                'aid': row['aid'],
                'record_type': row['record_type'],
                'epoch': row['epoch'],
                'data': json.loads(row['data'])
            }
            return result
        else:
            logging.info(f"Host record type {record_type} for device_id {device_id} NOT Found.")
            return None

    # 'host_zta' Table (Zero Trust Assessments)

    def put_host_zta(self, device_id, zta_data):
        """Store Zero Trust Assessment data for a host."""
        epoch = epoch_now()
        data_json = json.dumps(zta_data)

        self.cursor.execute('''
            INSERT OR REPLACE INTO host_zta (device_id, epoch, data)
            VALUES (?, ?, ?)
        ''', (device_id, epoch, data_json))

        self.conn.commit()
        logging.info(f"Stored ZTA data for device {device_id}")

    def get_host_zta(self, device_id):
        """Get Zero Trust Assessment data for a host."""
        self.cursor.execute('''
            SELECT data FROM host_zta WHERE device_id = ?
        ''', (device_id,))

        row = self.cursor.fetchone()
        if row:
            return json.loads(row['data'])
        else:
            logging.debug(f"ZTA data for device_id {device_id} NOT Found.")
            return None

    # 'policies' Tables (generic for all policy types)

    def put_policies(self, policy_type, cid, policies_data):
        """
        Store policies for a given type and CID.

        Args:
            policy_type: Type of policy (e.g., 'prevention_policies', 'firewall_policies')
            cid: Customer ID
            policies_data: The policy data from the API response

        Returns:
            int: Row ID of the inserted/updated record
        """
        epoch = epoch_now()

        # Check if this is an error response (e.g., 403)
        if 'error' in policies_data:
            policies = json.dumps([])
            total = -1
            error = policies_data['error']
        else:
            resources = policies_data.get('body', {}).get('resources', [])
            policies = json.dumps(resources)
            total = len(resources)
            error = None

        # Delete existing record for this policy_type and CID
        self.cursor.execute('''
            DELETE FROM policies
            WHERE policy_type = ? AND cid = ?
        ''', (policy_type, cid))

        # Insert new record
        self.cursor.execute('''
            INSERT INTO policies (policy_type, cid, epoch, policies, total, error)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (policy_type, cid, epoch, policies, total, error))

        self.conn.commit()
        row_id = self.cursor.lastrowid

        if error:
            logging.info(f"SQLite {policy_type} error record (error {error}) created for CID {cid} with row_id {row_id}")
        else:
            logging.info(f"SQLite {policy_type} record created for CID {cid} with row_id {row_id}")

        return row_id

    def get_policies(self, policy_type, cid):
        """
        Get policies for a given type and CID.

        Args:
            policy_type: Type of policy (e.g., 'prevention_policies', 'firewall_policies')
            cid: Customer ID

        Returns:
            dict: The policy record matching TinyDB format, or None if not found
        """
        self.cursor.execute('''
            SELECT id, cid, epoch, policies, total, error
            FROM policies
            WHERE policy_type = ? AND cid = ?
        ''', (policy_type, cid))

        row = self.cursor.fetchone()
        if row:
            result = {
                'cid': row['cid'],
                'epoch': row['epoch'],
                'policies': json.loads(row['policies']),
                'total': row['total']
            }
            if row['error']:
                result['error'] = row['error']
            return result
        else:
            logging.info(f"{policy_type} record for CID {cid} NOT Found.")
            return None

    # 'graded_policies' Tables (generic for all policy types)

    def put_graded_policies(self, policy_type, cid, graded_results):
        """
        Store graded policy results for a given type and CID.

        Args:
            policy_type: Type of policy (e.g., 'prevention_policies', 'firewall_policies')
            cid: Customer ID
            graded_results: List of graded policy result dicts

        Returns:
            int: Row ID of the inserted/updated record
        """
        if graded_results is None:
            logging.error("Cannot store graded policies: graded_results is None")
            return None

        epoch = epoch_now()

        # Calculate summary statistics
        total_policies = len(graded_results)
        passed_policies = sum(1 for r in graded_results if r.get('passed', False))
        failed_policies = total_policies - passed_policies

        graded_policies_json = json.dumps(graded_results)

        # Delete existing record for this policy_type and CID
        self.cursor.execute('''
            DELETE FROM graded_policies
            WHERE policy_type = ? AND cid = ?
        ''', (policy_type, cid))

        # Insert new record
        self.cursor.execute('''
            INSERT INTO graded_policies (policy_type, cid, epoch, graded_policies,
                                        total_policies, passed_policies, failed_policies)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (policy_type, cid, epoch, graded_policies_json,
              total_policies, passed_policies, failed_policies))

        self.conn.commit()
        row_id = self.cursor.lastrowid

        logging.info(
            f"SQLite graded_{policy_type} record created for CID {cid} with row_id {row_id} "
            f"({passed_policies}/{total_policies} policies passed)"
        )

        return row_id

    def get_graded_policies(self, policy_type, cid):
        """
        Get graded policy results for a given type and CID.

        Args:
            policy_type: Type of policy (e.g., 'prevention_policies', 'firewall_policies')
            cid: Customer ID

        Returns:
            dict: The graded policy record matching TinyDB format, or None if not found
        """
        self.cursor.execute('''
            SELECT cid, epoch, graded_policies, total_policies, passed_policies, failed_policies
            FROM graded_policies
            WHERE policy_type = ? AND cid = ?
        ''', (policy_type, cid))

        row = self.cursor.fetchone()
        if row:
            result = {
                'cid': row['cid'],
                'epoch': row['epoch'],
                'graded_policies': json.loads(row['graded_policies']),
                'total_policies': row['total_policies'],
                'passed_policies': row['passed_policies'],
                'failed_policies': row['failed_policies']
            }
            return result
        else:
            logging.info(f"graded_{policy_type} record for CID {cid} NOT Found.")
            return None

    # Firewall policy containers storage

    def put_firewall_policy_containers(self, cid, containers_map):
        """
        Store firewall policy containers for a CID.

        Args:
            cid: Customer ID
            containers_map: Dict mapping policy_id -> container object

        Returns:
            int: Row ID in database
        """
        key = f"firewall_policy_containers_{cid}"
        epoch = epoch_now()
        policy_containers = json.dumps(containers_map)
        count = len(containers_map)

        # Check if record already exists
        self.cursor.execute('''
            SELECT id FROM firewall_policy_containers
            WHERE key = ?
        ''', (key,))

        existing = self.cursor.fetchone()

        if existing:
            # Update existing record
            row_id = existing['id']
            self.cursor.execute('''
                UPDATE firewall_policy_containers
                SET cid = ?, policy_containers = ?, count = ?, epoch = ?
                WHERE key = ?
            ''', (cid, policy_containers, count, epoch, key))
            logging.info(f"SQLite firewall_policy_containers record updated for CID {cid} with {count} containers")
        else:
            # Insert new record
            self.cursor.execute('''
                INSERT INTO firewall_policy_containers (key, cid, policy_containers, count, epoch)
                VALUES (?, ?, ?, ?, ?)
            ''', (key, cid, policy_containers, count, epoch))
            row_id = self.cursor.lastrowid
            logging.info(f"SQLite firewall_policy_containers record created for CID {cid} with {count} containers, row_id {row_id}")

        self.conn.commit()
        return row_id

    def get_firewall_policy_containers(self, cid):
        """
        Get firewall policy containers for a CID.

        Args:
            cid: Customer ID

        Returns:
            dict: The containers record with 'policy_containers' map, or None if not found
        """
        key = f"firewall_policy_containers_{cid}"

        self.cursor.execute('''
            SELECT key, cid, policy_containers, count, epoch
            FROM firewall_policy_containers
            WHERE key = ?
        ''', (key,))

        row = self.cursor.fetchone()
        if row:
            result = {
                'key': row['key'],
                'cid': row['cid'],
                'policy_containers': json.loads(row['policy_containers']),
                'count': row['count'],
                'epoch': row['epoch']
            }
            logging.info(f"firewall_policy_containers record for CID {cid} found with {result['count']} containers.")
            return result
        else:
            logging.info(f"firewall_policy_containers record for CID {cid} NOT Found.")
            return None

    # Device control policy settings storage

    def put_device_control_policy_settings(self, cid, settings_map):
        """
        Store device control policy settings for a CID.

        Args:
            cid: Customer ID
            settings_map: Dict mapping policy_id -> settings object

        Returns:
            int: Row ID in database
        """
        key = f"device_control_policy_settings_{cid}"
        epoch = epoch_now()
        policy_settings = json.dumps(settings_map)
        count = len(settings_map)

        # Check if record already exists
        self.cursor.execute('''
            SELECT id FROM device_control_policy_settings
            WHERE key = ?
        ''', (key,))

        existing = self.cursor.fetchone()

        if existing:
            # Update existing record
            row_id = existing['id']
            self.cursor.execute('''
                UPDATE device_control_policy_settings
                SET cid = ?, policy_settings = ?, count = ?, epoch = ?
                WHERE key = ?
            ''', (cid, policy_settings, count, epoch, key))
            logging.info(f"SQLite device_control_policy_settings record updated for CID {cid} with {count} settings")
        else:
            # Insert new record
            self.cursor.execute('''
                INSERT INTO device_control_policy_settings (key, cid, policy_settings, count, epoch)
                VALUES (?, ?, ?, ?, ?)
            ''', (key, cid, policy_settings, count, epoch))
            row_id = self.cursor.lastrowid
            logging.info(f"SQLite device_control_policy_settings record created for CID {cid} with {count} settings, row_id {row_id}")

        self.conn.commit()
        return row_id

    def get_device_control_policy_settings(self, cid):
        """
        Get device control policy settings for a CID.

        Args:
            cid: Customer ID

        Returns:
            dict: The settings record with 'policy_settings' map, or None if not found
        """
        key = f"device_control_policy_settings_{cid}"

        self.cursor.execute('''
            SELECT key, cid, policy_settings, count, epoch
            FROM device_control_policy_settings
            WHERE key = ?
        ''', (key,))

        row = self.cursor.fetchone()
        if row:
            result = {
                'key': row['key'],
                'cid': row['cid'],
                'policy_settings': json.loads(row['policy_settings']),
                'count': row['count'],
                'epoch': row['epoch']
            }
            logging.info(f"device_control_policy_settings record for CID {cid} found with {result['count']} settings.")
            return result
        else:
            logging.info(f"device_control_policy_settings record for CID {cid} NOT Found.")
            return None

    # CID Caching

    def put_cid(self, cid, base_url):
        """Store CID for a given base_url to avoid unnecessary API calls."""
        epoch = epoch_now()

        # Create table if it doesn't exist
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS cid_cache (
                base_url TEXT PRIMARY KEY,
                cid TEXT NOT NULL,
                epoch INTEGER NOT NULL
            )
        ''')

        # Upsert the CID cache
        self.conn.execute('''
            INSERT OR REPLACE INTO cid_cache (base_url, cid, epoch)
            VALUES (?, ?, ?)
        ''', (base_url, cid, epoch))

        self.conn.commit()
        logging.info(f"CID {cid} cached for base_url {base_url}")

    def get_cid(self, base_url):
        """Get cached CID for a given base_url. Returns None if not cached."""
        # Ensure table exists
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS cid_cache (
                base_url TEXT PRIMARY KEY,
                cid TEXT NOT NULL,
                epoch INTEGER NOT NULL
            )
        ''')

        cursor = self.conn.execute('''
            SELECT cid FROM cid_cache WHERE base_url = ?
        ''', (base_url,))

        result = cursor.fetchone()
        if result:
            cid = result[0]
            logging.info(f"CID {cid} retrieved from cache for base_url {base_url}")
            return cid

        logging.info(f"No cached CID found for base_url {base_url}")
        return None

    def get_cached_cid_info(self):
        """Get the most recent cached CID info. Returns dict with 'cid' and 'base_url' or None."""
        # Ensure table exists
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS cid_cache (
                base_url TEXT PRIMARY KEY,
                cid TEXT NOT NULL,
                epoch INTEGER NOT NULL
            )
        ''')

        cursor = self.conn.execute('''
            SELECT cid, base_url FROM cid_cache ORDER BY epoch DESC LIMIT 1
        ''')

        result = cursor.fetchone()
        if result:
            cid, base_url = result
            logging.info(f"Most recent cached CID {cid} for base_url {base_url}")
            return {'cid': cid, 'base_url': base_url}

        logging.info("No cached CID found")
        return None

    def close(self):
        """Close the SQLite database connection."""
        if self.conn:
            self.conn.commit()
            self.conn.close()
            logging.info("SQLite database connection closed")
