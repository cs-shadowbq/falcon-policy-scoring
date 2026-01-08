"""
FalconAPI module tests.

IMPORTANT: These tests must include comprehensive pagination testing.
Pagination bugs have caused production issues in the past.

Test coverage needed:
- Single page responses
- Multiple page responses (2-10 pages)
- Large datasets (100+ pages)
- Empty result sets
- Pagination token handling
- Rate limiting during pagination
- Errors mid-pagination (network failures, API errors)
- Offset-based vs token-based pagination
- Batch size configuration
- API response structure validation

See tests/test_cli_operations.py for progress bar tests (>500 hosts).
"""
