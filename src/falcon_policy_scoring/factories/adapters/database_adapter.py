from abc import ABC, abstractmethod
from falcon_policy_scoring.utils.core import epoch_now
import logging

# TODO: Ensure this Abastract Class is used in the DB Adapters.
class DatabaseAdapter(ABC):
    """Abstract base class for database adapters."""

    @abstractmethod
    def connect(self, config):
        """Connect to the database."""
        pass

    @abstractmethod
    def get_hosts_collection(self):
        """Get the hosts collection."""
        pass

    @abstractmethod
    def get_host_records_collection(self):
        """Get the host records collection."""
        pass

    # Record management

    # Generic methods for all records

    @abstractmethod
    def create_record(self, collection, newvalue_set):
        """Create a new database record."""
        pass

    @abstractmethod
    def update_record(self, collection, resource, newvalue_set):
        """Update an existing database record."""
        pass

    def update_or_create_record(self, collection, resource, data=None):
        """
        Update an existing record or create a new one.
        Concrete implementation that subclasses can override or call via super().
        """
        epoch = epoch_now()

        if data == [] or data is None:
            logging.warning("No data provided for record. Creating empty record.")
            data = [{}]

        data_record = data[0] if len(data) == 1 else data

        newvalue_set = {
            "data": data_record,
            "epoch": epoch,
            "aid": resource['aid'],
            "cid": resource['cid'],
            "record_type": resource['record_type']
        }

        try:
            if resource.get('_id'):
                self.update_record(collection, resource, newvalue_set)
            else:
                self.create_record(collection, newvalue_set)
        except KeyError:
            self.create_record(collection, newvalue_set)

    # 'hosts' Table

    @abstractmethod
    def put_hosts(self, list_of_devices):
        """Put the latest host record for a given CID."""
        pass

    @abstractmethod
    def get_hosts(self, cid):
        """Get the latest host record for a given CID."""
        pass

    # 'host_records' Table

    @abstractmethod
    def put_host(self, device_details):
        """Put a host record."""
        pass

    def get_host(self, device_id):
        """Get a host record."""
        pass

    # 'host_zta' Table (Zero Trust Assessments)

    @abstractmethod
    def put_host_zta(self, device_id, zta_data):
        """Store Zero Trust Assessment data for a host.

        Args:
            device_id: Device ID (AID)
            zta_data: ZTA assessment data from API
        """
        pass

    @abstractmethod
    def get_host_zta(self, device_id):
        """Get Zero Trust Assessment data for a host.

        Args:
            device_id: Device ID (AID)

        Returns:
            ZTA assessment data or None if not found
        """
        pass

    # 'policies' Tables (generic for all policy types)

    @abstractmethod
    def put_policies(self, policy_type, cid, policies_data):
        """Store policies for a given type and CID."""
        pass

    @abstractmethod
    def get_policies(self, policy_type, cid):
        """Get policies for a given type and CID."""
        pass

    # 'graded_policies' Tables (generic for all policy types)

    @abstractmethod
    def put_graded_policies(self, policy_type, cid, graded_results):
        """Store graded policy results for a given type and CID."""
        pass

    @abstractmethod
    def get_graded_policies(self, policy_type, cid):
        """Get graded policy results for a given type and CID."""
        pass

    # 'firewall_rule_groups' Table (global cache of all rule groups)

    @abstractmethod
    def put_firewall_policy_containers(self, cid, containers_map):
        """Store firewall policy containers for a CID."""
        pass

    @abstractmethod
    def get_firewall_policy_containers(self, cid):
        """Get firewall policy containers for a CID."""
        pass

    # 'device_control_policy_settings' Table (cache of device control policy settings)

    @abstractmethod
    def put_device_control_policy_settings(self, cid, settings_map):
        """Store device control policy settings for a CID."""
        pass

    @abstractmethod
    def get_device_control_policy_settings(self, cid):
        """Get device control policy settings for a CID."""
        pass

    # CID Caching

    @abstractmethod
    def put_cid(self, cid, base_url):
        """Store CID for a given base_url to avoid unnecessary API calls."""
        pass

    @abstractmethod
    def get_cid(self, base_url):
        """Get cached CID for a given base_url. Returns None if not cached or expired."""
        pass

    @abstractmethod
    def get_cached_cid_info(self):
        """Get the most recent cached CID info. Returns dict with 'cid' and 'base_url' or None."""
        pass

    @abstractmethod
    def close(self):
        """Close the connection to the database."""
        pass
