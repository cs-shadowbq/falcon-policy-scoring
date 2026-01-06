from falcon_policy_scoring.factories.adapters.tinydb_adapter import TinyDBAdapter
from falcon_policy_scoring.factories.adapters.sqlite_adapter import SQLiteAdapter


class DatabaseFactory:
    """Factory to create database adapters."""

    @staticmethod
    def create_adapter(db_type):
        if db_type == 'tiny_db':
            return TinyDBAdapter()
        elif db_type == 'sqlite':
            return SQLiteAdapter()
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
