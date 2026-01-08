"""
SQLite adapter-specific tests.

Tests SQLite-specific behavior:
- Schema creation and migration
- Connection management
- Transaction handling
- Index performance
- Concurrent access patterns
- Database file integrity
"""

import pytest
import sqlite3
import threading
import time
from pathlib import Path
from falcon_policy_scoring.factories.adapters.sqlite_adapter import SQLiteAdapter


@pytest.fixture
def sqlite_adapter(tmp_path):
    """Create SQLite adapter for testing."""
    adapter = SQLiteAdapter()
    db_path = tmp_path / "test.db"
    adapter.connect({'path': str(db_path)})
    yield adapter
    adapter.close()


@pytest.mark.unit
class TestSQLiteSchema:
    """Test SQLite schema creation and structure."""

    def test_creates_all_tables(self, tmp_path):
        """Test that all required tables are created."""
        adapter = SQLiteAdapter()
        db_path = tmp_path / "schema_test.db"
        adapter.connect({'path': str(db_path)})

        # Check that all tables exist
        cursor = adapter.cursor
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        expected_tables = [
            'hosts',
            'host_records',
            'policies',
            'graded_policies',
            'firewall_policy_containers',
            'device_control_policy_settings'
            # Note: cid_cache and host_zta are created lazily on first use
        ]

        for table in expected_tables:
            assert table in tables, f"Table '{table}' not created"

        adapter.close()

    def test_table_schemas(self, sqlite_adapter):
        """Test that table schemas have required columns."""
        cursor = sqlite_adapter.cursor

        # Check hosts table structure
        cursor.execute("PRAGMA table_info(hosts)")
        hosts_columns = {row[1] for row in cursor.fetchall()}
        assert 'cid' in hosts_columns
        assert 'hosts' in hosts_columns
        assert 'epoch' in hosts_columns
        assert 'total' in hosts_columns

        # Check policies table structure
        cursor.execute("PRAGMA table_info(policies)")
        policies_columns = {row[1] for row in cursor.fetchall()}
        assert 'policy_type' in policies_columns
        assert 'cid' in policies_columns
        assert 'policies' in policies_columns
        assert 'epoch' in policies_columns

        # Check graded_policies table structure
        cursor.execute("PRAGMA table_info(graded_policies)")
        graded_columns = {row[1] for row in cursor.fetchall()}
        assert 'policy_type' in graded_columns
        assert 'graded_policies' in graded_columns
        assert 'total_policies' in graded_columns
        assert 'passed_policies' in graded_columns
        assert 'failed_policies' in graded_columns

    def test_unique_constraints(self, sqlite_adapter):
        """Test that unique constraints are enforced."""
        # Test hosts table unique constraint on cid
        hosts_data = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'epoch': 1234567890,
            'hosts': ['host-1', 'host-2'],
            'total': 2
        }

        sqlite_adapter.put_hosts(hosts_data)

        # Try to insert duplicate - should replace, not error
        hosts_data_updated = hosts_data.copy()
        hosts_data_updated['hosts'] = ['host-3']
        hosts_data_updated['total'] = 1
        sqlite_adapter.put_hosts(hosts_data_updated)

        # Verify only one record exists
        cursor = sqlite_adapter.cursor
        cursor.execute("SELECT COUNT(*) FROM hosts WHERE cid = ?", ('test-cid',))
        count = cursor.fetchone()[0]
        assert count == 1


@pytest.mark.unit
class TestSQLiteConnections:
    """Test SQLite connection management."""

    def test_connection_string_formats(self, tmp_path):
        """Test various connection string formats."""
        # Test with file path
        adapter1 = SQLiteAdapter()
        db_path1 = tmp_path / "test1.db"
        adapter1.connect({'path': str(db_path1)})
        assert adapter1.conn is not None
        adapter1.close()

        # Test with relative path
        adapter2 = SQLiteAdapter()
        adapter2.connect({'path': 'test2.db'})
        assert adapter2.conn is not None
        adapter2.close()

        # Cleanup
        Path('test2.db').unlink(missing_ok=True)

    def test_connection_persists(self, sqlite_adapter):
        """Test that connection persists across operations."""
        # Store data
        hosts_data = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'epoch': 1234567890,
            'hosts': ['host-1'],
            'total': 1
        }
        sqlite_adapter.put_hosts(hosts_data)

        # Retrieve data - should use same connection
        retrieved = sqlite_adapter.get_hosts('test-cid')
        assert retrieved['hosts'] == ['host-1']

        # Connection should still be open
        assert sqlite_adapter.conn is not None

    def test_close_connection(self, tmp_path):
        """Test that connection is properly closed."""
        adapter = SQLiteAdapter()
        db_path = tmp_path / "close_test.db"
        adapter.connect({'path': str(db_path)})

        # Verify connection is open
        assert adapter.conn is not None

        # Close connection
        adapter.close()

        # Verify connection is closed (trying to use it should fail)
        with pytest.raises(sqlite3.ProgrammingError):
            adapter.cursor.execute("SELECT 1")


@pytest.mark.unit
class TestSQLiteTransactions:
    """Test SQLite transaction handling."""

    def test_auto_commit(self, sqlite_adapter):
        """Test that operations are auto-committed."""
        # Insert data
        hosts_data = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'epoch': 1234567890,
            'hosts': ['host-1'],
            'total': 1
        }
        sqlite_adapter.put_hosts(hosts_data)

        # Create new connection to same database
        new_adapter = SQLiteAdapter()
        new_adapter.connect({'path': sqlite_adapter.conn.execute("PRAGMA database_list").fetchone()[2]})

        # Should see data from first connection (auto-committed)
        retrieved = new_adapter.get_hosts('test-cid')
        assert retrieved['hosts'] == ['host-1']

        new_adapter.close()

    def test_data_persistence(self, tmp_path):
        """Test that data persists after closing connection."""
        db_path = tmp_path / "persist_test.db"

        # First connection - write data
        adapter1 = SQLiteAdapter()
        adapter1.connect({'path': str(db_path)})
        hosts_data = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'epoch': 1234567890,
            'hosts': ['host-1'],
            'total': 1
        }
        adapter1.put_hosts(hosts_data)
        adapter1.close()

        # Second connection - read data
        adapter2 = SQLiteAdapter()
        adapter2.connect({'path': str(db_path)})
        retrieved = adapter2.get_hosts('test-cid')
        assert retrieved['hosts'] == ['host-1']
        adapter2.close()


@pytest.mark.unit
class TestSQLiteConcurrency:
    """Test SQLite concurrent access patterns."""

    def test_multiple_readers(self, tmp_path):
        """Test that multiple connections can read simultaneously."""
        db_path = tmp_path / "multi_read.db"

        # Setup initial data
        adapter = SQLiteAdapter()
        adapter.connect({'path': str(db_path)})
        hosts_data = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'epoch': 1234567890,
            'hosts': ['host-1', 'host-2', 'host-3'],
            'total': 3
        }
        adapter.put_hosts(hosts_data)
        adapter.close()

        # Create multiple reader connections
        results = []

        def reader_thread(path, results_list):
            reader = SQLiteAdapter()
            reader.connect({'path': str(path)})
            data = reader.get_hosts('test-cid')
            results_list.append(data)
            reader.close()

        # Start multiple readers
        threads = []
        for _ in range(5):
            t = threading.Thread(target=reader_thread, args=(db_path, results))
            threads.append(t)
            t.start()

        # Wait for all readers
        for t in threads:
            t.join()

        # All should have read the same data
        assert len(results) == 5
        for result in results:
            assert result['total'] == 3
            assert len(result['hosts']) == 3

    def test_write_after_read(self, tmp_path):
        """Test that writes work after reads."""
        db_path = tmp_path / "write_after_read.db"

        adapter = SQLiteAdapter()
        adapter.connect({'path': str(db_path)})

        # Initial write
        hosts_data1 = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'epoch': 1234567890,
            'hosts': ['host-1'],
            'total': 1
        }
        adapter.put_hosts(hosts_data1)

        # Read
        retrieved1 = adapter.get_hosts('test-cid')
        assert retrieved1['total'] == 1

        # Write again
        hosts_data2 = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'epoch': 1234567891,
            'hosts': ['host-1', 'host-2'],
            'total': 2
        }
        adapter.put_hosts(hosts_data2)

        # Read again
        retrieved2 = adapter.get_hosts('test-cid')
        assert retrieved2['total'] == 2

        adapter.close()


@pytest.mark.unit
class TestSQLitePerformance:
    """Test SQLite performance characteristics."""

    def test_bulk_insert_performance(self, sqlite_adapter):
        """Test performance of bulk inserts."""
        import time

        # Insert 100 host records
        start_time = time.time()
        for i in range(100):
            host_data = {
                'cid': f'cid-{i % 10}',  # 10 different CIDs
                'aid': f'host-{i}',
                'hostname': f'hostname-{i}',
                'os_version': '10.0',
                'first_seen': 1234567890 + i
            }
            sqlite_adapter.put_host(host_data)
        elapsed = time.time() - start_time

        # Should complete reasonably quickly (< 5 seconds)
        assert elapsed < 5.0, f"Bulk insert took {elapsed} seconds"

    def test_query_performance(self, sqlite_adapter):
        """Test query performance with moderate data volume."""
        import time

        # Insert test data for 10 CIDs
        for cid_num in range(10):
            hosts_data = {
                'cid': f'cid-{cid_num}',
                'base_url': f'https://cid-{cid_num}.com',
                'epoch': 1234567890,
                'hosts': [f'host-{i}' for i in range(50)],
                'total': 50
            }
            sqlite_adapter.put_hosts(hosts_data)

        # Query all CIDs
        start_time = time.time()
        for cid_num in range(10):
            sqlite_adapter.get_hosts(f'cid-{cid_num}')
        elapsed = time.time() - start_time

        # Should complete quickly (< 1 second)
        assert elapsed < 1.0, f"Queries took {elapsed} seconds"


@pytest.mark.unit
class TestSQLiteFileOperations:
    """Test SQLite file-related operations."""

    def test_database_file_created(self, tmp_path):
        """Test that database file is created."""
        db_path = tmp_path / "new_db.db"
        assert not db_path.exists()

        adapter = SQLiteAdapter()
        adapter.connect({'path': str(db_path)})

        # File should now exist
        assert db_path.exists()
        assert db_path.is_file()

        adapter.close()

    def test_database_file_permissions(self, tmp_path):
        """Test database file has correct permissions."""
        db_path = tmp_path / "perms_test.db"

        adapter = SQLiteAdapter()
        adapter.connect({'path': str(db_path)})
        adapter.close()

        # File should be readable and writable by owner
        assert db_path.stat().st_mode & 0o600

    def test_database_size_growth(self, tmp_path):
        """Test that database file grows with data."""
        db_path = tmp_path / "size_test.db"

        adapter = SQLiteAdapter()
        adapter.connect({'path': str(db_path)})

        # Initial size
        initial_size = db_path.stat().st_size

        # Add significant data
        for i in range(100):
            hosts_data = {
                'cid': f'cid-{i}',
                'base_url': f'https://cid-{i}.com',
                'epoch': 1234567890,
                'hosts': [f'host-{j}' for j in range(100)],
                'total': 100
            }
            adapter.put_hosts(hosts_data)

        adapter.close()

        # File should have grown
        final_size = db_path.stat().st_size
        assert final_size > initial_size


@pytest.mark.unit
class TestSQLiteJSON:
    """Test SQLite JSON serialization."""

    def test_json_storage_and_retrieval(self, sqlite_adapter):
        """Test that complex data structures are properly serialized."""
        complex_data = {
            'cid': 'test-cid',
            'device_id': 'test-host',  # adapter looks for device_id not aid
            'nested': {
                'level1': {
                    'level2': {
                        'value': 'deep'
                    }
                }
            },
            'array': [1, 2, 3, 4, 5],
            'mixed': [
                {'id': 1, 'name': 'first'},
                {'id': 2, 'name': 'second'}
            ]
        }

        sqlite_adapter.put_host(complex_data, record_type=4)
        retrieved = sqlite_adapter.get_host('test-host', record_type=4)

        # Should match original structure (data is nested under 'data' key)
        assert retrieved is not None
        data = retrieved['data']
        assert data['nested']['level1']['level2']['value'] == 'deep'
        assert data['array'] == [1, 2, 3, 4, 5]
        assert len(data['mixed']) == 2
        assert data['mixed'][0]['name'] == 'first'

    def test_special_characters_in_json(self, sqlite_adapter):
        """Test handling of special characters in JSON data."""
        special_data = {
            'cid': 'test-cid',
            'device_id': 'test-host',  # adapter looks for device_id not aid
            'quotes': 'He said "hello"',
            'backslash': 'C:\\Windows\\System32',
            'newline': 'Line1\nLine2',
            'unicode': '你好世界 🌍'
        }

        sqlite_adapter.put_host(special_data, record_type=4)
        retrieved = sqlite_adapter.get_host('test-host', record_type=4)

        assert retrieved is not None
        data = retrieved['data']
        assert data['quotes'] == 'He said "hello"'
        assert data['backslash'] == 'C:\\Windows\\System32'
        assert data['newline'] == 'Line1\nLine2'
        assert data['unicode'] == '你好世界 🌍'
