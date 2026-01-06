from tinydb import TinyDB, Query
from tinydb import table as Table
from falcon_policy_scoring.factories.adapters.database_adapter import DatabaseAdapter
import logging
from falcon_policy_scoring.utils.core import epoch_now


class TinyDBAdapter(DatabaseAdapter):
    """TinyDB adapter implementation."""

    def __init__(self):
        self.db = None

    def connect(self, config):

        self.db = TinyDB(
            config['path'],
            create_dirs=True,
            ensure_ascii=False,
            encoding='utf-8'
        )

    # Setup collections

    # List of the Hosts
    def get_hosts_collection(self):
        return self.db.table('hosts', cache_size=0)

    # Records keyed to individual hosts
    def get_host_records_collection(self):
        return self.db.table('host_records', cache_size=0)

    # Record management

    # Generic methods for all records

    def create_record(self, collection, newvalue_set):
        """Create a new database record."""
        id = collection.insert(newvalue_set)
        logging.info(f"Record created: {id}")
        return id

    def update_record(self, collection, resource, newvalue_set):
        """Update an existing database record."""
        id = collection.upsert(Table.Document(newvalue_set, doc_id=resource['_id']))
        logging.info(f"TinyDB record updated: {id}")
        return id

    def update_or_create_record(self, collection, resource, data):
        """Override parent to check for existing records before creating duplicates."""
        # Check if record already exists (if _id not already provided)
        if '_id' not in resource:
            q = Query()
            existing_records = collection.search(
                (q.aid == resource['aid']) &
                (q.record_type == resource['record_type'])
            )

            if existing_records:
                if len(existing_records) > 1:
                    # Clean up duplicates - keep the most recent one
                    logging.warning(
                        f"Found {len(existing_records)} duplicate records for aid {resource['aid']}, "
                        f"record_type {resource['record_type']}, cleaning up..."
                    )
                    # Sort by epoch (most recent first) and keep the first one
                    existing_records.sort(key=lambda x: x.get('epoch', 0), reverse=True)
                    resource['_id'] = existing_records[0].doc_id
                    # Remove the duplicates
                    for dup in existing_records[1:]:
                        collection.remove(doc_ids=[dup.doc_id])
                        logging.info(f"Removed duplicate record with doc_id {dup.doc_id}")
                else:
                    resource['_id'] = existing_records[0].doc_id

        # Now call parent implementation
        return super().update_or_create_record(collection, resource, data)

    # 'hosts' Table

    """
        'hosts' Table
        Schema Structure:
        [
            {'base_url': string,
            'cid': string,
            'epoch': int,
            'hosts':
                [string, string, ...],
            'total': int
            }, ...
        ]
    """

    def put_hosts(self, list_of_devices):
        # given the structured list_of_devices as a dict, store it in TinyDB
        # delete any existing record for this cid
        cid = list_of_devices['cid']
        q = Query()
        db_hosts = self.db.table('hosts', cache_size=0)
        db_hosts.remove(q.cid == cid)
        # insert the new record
        doc_id = db_hosts.insert(list_of_devices)
        logging.info(f"TinyDB hosts record created for CID {cid} with doc_id {doc_id}")
        return doc_id

    def get_hosts(self, cid):
        # given a cid, retrieve the latest hosts record from TinyDB
        # cid should always be required in this function
        q = Query()
        db_hosts = self.db.table('hosts', cache_size=0)
        result = db_hosts.search(q.cid == cid)
        if len(result) > 0:
            if len(result) > 1:
                logging.warning(f"Multiple hosts list records found for CID {cid}.")
                raise Exception(f"Multiple hosts list records found for CID {cid}.")
            result = result[-1]
            return result
        else:
            logging.info(f"Hosts record for CID {cid} NOT Found.")
            return None

    def put_host(self, device_details, record_type=4):
        # given the structured device_details as a dict, store it in TinyDB host_records table
        cid = device_details.get('cid', 'unknown_cid')
        aid = device_details.get('device_id', 'unknown_aid')

        resource = {
            'cid': cid,
            'aid': aid,
            'record_type': record_type
        }

        db_host_records = self.db.table('host_records', cache_size=0)
        self.update_or_create_record(db_host_records, resource, [device_details])

    def get_host(self, device_id, record_type=4):
        # given a device_id, retrieve the latest host record from TinyDB
        q = Query()
        db_host_records = self.db.table('host_records', cache_size=0)
        result = db_host_records.search((q.aid == device_id) & (q.record_type == record_type))
        if len(result) > 0:
            if len(result) > 1:
                logging.warning(f"Multiple host records found for device_id {device_id}.")
                raise Exception(f"Multiple host records found for device_id {device_id}.")
            result = result[-1]
            return result
        else:
            logging.info(f"Host record type {record_type} for device_id {device_id} NOT Found.")
            return None

    # 'host_zta' Table (Zero Trust Assessments)

    """
        'host_zta' Table
        Schema Structure:
        [
            {
                'device_id': string,
                'epoch': int,
                'data': {
                    'aid': string,
                    'cid': string,
                    'assessment': {
                        'sensor_config': int,
                        'os': int,
                        'overall': int,
                        'version': string
                    },
                    'assessment_items': {...},
                    'modified_time': string,
                    ...
                }
            }, ...
        ]
    """

    def put_host_zta(self, device_id, zta_data):
        """Store Zero Trust Assessment data for a host."""
        epoch = epoch_now()
        q = Query()
        db_host_zta = self.db.table('host_zta', cache_size=0)

        # Remove existing record for this device
        db_host_zta.remove(q.device_id == device_id)

        # Insert new record
        record = {
            'device_id': device_id,
            'epoch': epoch,
            'data': zta_data
        }
        db_host_zta.insert(record)
        logging.info(f"Stored ZTA data for device {device_id}")

    def get_host_zta(self, device_id):
        """Get Zero Trust Assessment data for a host."""
        q = Query()
        db_host_zta = self.db.table('host_zta', cache_size=0)
        result = db_host_zta.search(q.device_id == device_id)

        if result:
            if len(result) > 1:
                logging.warning(f"Multiple ZTA records found for device_id {device_id}, returning most recent.")
                # Return the most recent one
                result.sort(key=lambda x: x.get('epoch', 0), reverse=True)
            return result[0].get('data')
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
            int: Document ID of the inserted record
        """
        epoch = epoch_now()

        # Check if this is an error response (e.g., 403)
        if 'error' in policies_data:
            record = {
                'cid': cid,
                'epoch': epoch,
                'error': policies_data['error'],
                'policies': [],
                'total': -1
            }
        else:
            # Create the record to store
            record = {
                'cid': cid,
                'epoch': epoch,
                'policies': policies_data.get('body', {}).get('resources', []),
                'total': len(policies_data.get('body', {}).get('resources', []))
            }

        # Get or create the table for this policy type
        q = Query()
        db_policies = self.db.table(policy_type, cache_size=0)

        # Remove any existing record for this CID
        db_policies.remove(q.cid == cid)

        # Insert the new record
        doc_id = db_policies.insert(record)
        if 'error' in record:
            logging.info(f"TinyDB {policy_type} error record (error {record['error']}) created for CID {cid} with doc_id {doc_id}")
        else:
            logging.info(f"TinyDB {policy_type} record created for CID {cid} with doc_id {doc_id}")
        return doc_id

    def get_policies(self, policy_type, cid):
        """
        Get policies for a given type and CID.

        Args:
            policy_type: Type of policy (e.g., 'prevention_policies', 'firewall_policies')
            cid: Customer ID

        Returns:
            dict: The policy record, or None if not found
        """
        q = Query()
        db_policies = self.db.table(policy_type, cache_size=0)
        result = db_policies.search(q.cid == cid)

        if len(result) > 0:
            if len(result) > 1:
                logging.warning(f"Multiple {policy_type} records found for CID {cid}.")
                raise Exception(f"Multiple {policy_type} records found for CID {cid}.")
            result = result[-1]
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
            int: Document ID of the inserted record
        """
        if graded_results is None:
            logging.error("Cannot store graded policies: graded_results is None")
            return None

        epoch = epoch_now()

        # Calculate summary statistics
        total_policies = len(graded_results)
        passed_policies = sum(1 for r in graded_results if r.get('passed', False))
        failed_policies = total_policies - passed_policies

        # Create the record to store
        record = {
            'cid': cid,
            'epoch': epoch,
            'graded_policies': graded_results,
            'total_policies': total_policies,
            'passed_policies': passed_policies,
            'failed_policies': failed_policies
        }

        # Get or create the table for this graded policy type
        table_name = f'graded_{policy_type}'
        q = Query()
        db_graded = self.db.table(table_name, cache_size=0)

        # Remove any existing record for this CID
        db_graded.remove(q.cid == cid)

        # Insert the new record
        doc_id = db_graded.insert(record)
        logging.info(
            f"TinyDB {table_name} record created for CID {cid} with doc_id {doc_id} "
            f"({passed_policies}/{total_policies} policies passed)"
        )
        return doc_id

    def get_graded_policies(self, policy_type, cid):
        """
        Get graded policy results for a given type and CID.

        Args:
            policy_type: Type of policy (e.g., 'prevention_policies', 'firewall_policies')
            cid: Customer ID

        Returns:
            dict: The graded policy record, or None if not found
        """
        table_name = f'graded_{policy_type}'
        q = Query()
        db_graded = self.db.table(table_name, cache_size=0)
        result = db_graded.search(q.cid == cid)

        if len(result) > 0:
            if len(result) > 1:
                logging.warning(f"Multiple {table_name} records found for CID {cid}.")
                raise Exception(f"Multiple {table_name} records found for CID {cid}.")
            result = result[-1]
            return result
        else:
            logging.info(f"{table_name} record for CID {cid} NOT Found.")
            return None

    # Firewall policy containers storage

    def put_firewall_policy_containers(self, cid, containers_map):
        """
        Store firewall policy containers for a CID.

        Args:
            cid: Customer ID
            containers_map: Dict mapping policy_id -> container object

        Returns:
            int: Document ID in database
        """
        table_name = 'firewall_policy_containers'
        q = Query()
        db_containers = self.db.table(table_name, cache_size=0)

        # Create key: firewall_policy_containers_{cid}
        key = f"firewall_policy_containers_{cid}"

        # Check if record already exists
        existing = db_containers.search(q.key == key)

        record = {
            'key': key,
            'cid': cid,
            'policy_containers': containers_map,
            'count': len(containers_map),
            'epoch': epoch_now()
        }

        if existing:
            doc_id = existing[0].doc_id
            db_containers.update(record, doc_ids=[doc_id])
            logging.info(f"TinyDB {table_name} record updated for CID {cid} with {len(containers_map)} containers")
            return doc_id
        else:
            doc_id = db_containers.insert(record)
            logging.info(f"TinyDB {table_name} record created for CID {cid} with {len(containers_map)} containers, doc_id {doc_id}")
            return doc_id

    def get_firewall_policy_containers(self, cid):
        """
        Get firewall policy containers for a CID.

        Args:
            cid: Customer ID

        Returns:
            dict: The containers record with 'policy_containers' map, or None if not found
        """
        table_name = 'firewall_policy_containers'
        q = Query()
        db_containers = self.db.table(table_name, cache_size=0)

        key = f"firewall_policy_containers_{cid}"
        result = db_containers.search(q.key == key)

        if result:
            if len(result) > 1:
                logging.warning(f"Multiple {table_name} records found for CID {cid}.")
                result = sorted(result, key=lambda x: x.get('epoch', 0))[-1]
            else:
                result = result[0]

            logging.info(f"{table_name} record for CID {cid} found with {result.get('count', 0)} containers.")
            return result
        else:
            logging.info(f"{table_name} record for CID {cid} NOT Found.")
            return None

    # Device control policy settings storage

    def put_device_control_policy_settings(self, cid, settings_map):
        """
        Store device control policy settings for a CID.

        Args:
            cid: Customer ID
            settings_map: Dict mapping policy_id -> settings object

        Returns:
            int: Document ID in database
        """
        table_name = 'device_control_policy_settings'
        q = Query()
        db_settings = self.db.table(table_name, cache_size=0)

        # Create key: device_control_policy_settings_{cid}
        key = f"device_control_policy_settings_{cid}"

        # Check if record already exists
        existing = db_settings.search(q.key == key)

        record = {
            'key': key,
            'cid': cid,
            'policy_settings': settings_map,
            'count': len(settings_map),
            'epoch': epoch_now()
        }

        if existing:
            doc_id = existing[0].doc_id
            db_settings.update(record, doc_ids=[doc_id])
            logging.info(f"TinyDB {table_name} record updated for CID {cid} with {len(settings_map)} settings")
            return doc_id
        else:
            doc_id = db_settings.insert(record)
            logging.info(f"TinyDB {table_name} record created for CID {cid} with {len(settings_map)} settings, doc_id {doc_id}")
            return doc_id

    def get_device_control_policy_settings(self, cid):
        """
        Get device control policy settings for a CID.

        Args:
            cid: Customer ID

        Returns:
            dict: The settings record with 'policy_settings' map, or None if not found
        """
        table_name = 'device_control_policy_settings'
        q = Query()
        db_settings = self.db.table(table_name, cache_size=0)

        key = f"device_control_policy_settings_{cid}"
        result = db_settings.search(q.key == key)

        if result:
            if len(result) > 1:
                logging.warning(f"Multiple {table_name} records found for CID {cid}.")
                result = sorted(result, key=lambda x: x.get('epoch', 0))[-1]
            else:
                result = result[0]

            logging.info(f"{table_name} record for CID {cid} found with {result.get('count', 0)} settings.")
            return result
        else:
            logging.info(f"{table_name} record for CID {cid} NOT Found.")
            return None

    # CID Caching

    def put_cid(self, cid, base_url):
        """Store CID for a given base_url to avoid unnecessary API calls."""
        epoch = epoch_now()
        q = Query()
        db_cid_cache = self.db.table('cid_cache', cache_size=0)

        # Remove any existing cache for this base_url
        db_cid_cache.remove(q.base_url == base_url)

        # Insert new cache entry
        db_cid_cache.insert({
            'base_url': base_url,
            'cid': cid,
            'epoch': epoch
        })
        logging.info(f"CID {cid} cached for base_url {base_url}")

    def get_cid(self, base_url):
        """Get cached CID for a given base_url. Returns None if not cached."""
        q = Query()
        db_cid_cache = self.db.table('cid_cache', cache_size=0)
        result = db_cid_cache.search(q.base_url == base_url)

        if result:
            cid = result[0].get('cid')
            logging.info(f"CID {cid} retrieved from cache for base_url {base_url}")
            return cid
        logging.info(f"No cached CID found for base_url {base_url}")
        return None

    def get_cached_cid_info(self):
        """Get the most recent cached CID info. Returns dict with 'cid' and 'base_url' or None."""
        db_cid_cache = self.db.table('cid_cache', cache_size=0)
        all_entries = db_cid_cache.all()

        if all_entries:
            # Sort by epoch (most recent first) and get the first entry
            most_recent = sorted(all_entries, key=lambda x: x.get('epoch', 0), reverse=True)[0]
            cid = most_recent.get('cid')
            base_url = most_recent.get('base_url')
            logging.info(f"Most recent cached CID {cid} for base_url {base_url}")
            return {'cid': cid, 'base_url': base_url}

        logging.info("No cached CID found")
        return None

    def close(self):
        self.db.close()
        # Close the TinyDB database
