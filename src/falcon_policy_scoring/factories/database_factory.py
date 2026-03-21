from falcon_policy_scoring.factories.adapters.tinydb_adapter import TinyDBAdapter
from falcon_policy_scoring.factories.adapters.sqlite_adapter import SQLiteAdapter


class DatabaseFactory:
    """Factory to create database adapters."""

    @staticmethod
    def get_config_key(db_type):
        """Map db.type value to the YAML config section key.

        All db types use their own name as the config section key.
        """
        return db_type

    @staticmethod
    def create_adapter(db_type):
        if db_type == 'tiny_db':
            return TinyDBAdapter()
        elif db_type == 'sqlite':
            return SQLiteAdapter()
        elif db_type in ('dynalite', 'dynamodb'):
            from falcon_policy_scoring.factories.adapters.dynamodb_adapter import DynamoDBAdapter  # noqa: PLC0415
            return DynamoDBAdapter()
        elif db_type == 'foundry_collections':
            from falcon_policy_scoring.factories.adapters.foundry_collections_adapter import FoundryCollectionsAdapter  # noqa: PLC0415
            return FoundryCollectionsAdapter()
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
