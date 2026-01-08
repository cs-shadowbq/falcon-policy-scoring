#!/bin/bash
# Helper script to run E2E tests with credentials from .env file

# Usage: ./run_e2e_tests.sh [env_file] [test_name] [vcr_mode]
# Example: ./run_e2e_tests.sh cao.env test_fetch_workstation_device_ids once

ENV_FILE=${1:-".env"}
TEST_NAME=${2:-""}
VCR_MODE=${3:-"once"}

echo "================================================"
echo "Running E2E Tests with VCR"
echo "================================================"
echo "Environment file: $ENV_FILE"
echo "VCR mode: $VCR_MODE"
echo "================================================"
echo ""

# Load credentials from .env file
if [ -f "$ENV_FILE" ]; then
    echo "✓ Loading credentials from $ENV_FILE"
    export $(cat "$ENV_FILE" | grep -v '^#' | xargs)
    echo "  CLIENT_ID: ${CLIENT_ID:0:10}..."
    echo "  BASE_URL: $BASE_URL"
    echo ""
else
    echo "✗ Error: $ENV_FILE not found"
    exit 1
fi

# Build pytest command
PYTEST_CMD="python -m pytest tests/test_e2e_smoke.py"

if [ -n "$TEST_NAME" ]; then
    PYTEST_CMD="$PYTEST_CMD::$TEST_NAME"
fi

PYTEST_CMD="$PYTEST_CMD -m e2e -v --vcr-record=$VCR_MODE -s"

echo "Running: $PYTEST_CMD"
echo "================================================"
echo ""

# Run the tests
$PYTEST_CMD

echo ""
echo "================================================"
echo "Cassettes stored in: tests/fixtures/vcr_cassettes_e2e/"
ls -lh tests/fixtures/vcr_cassettes_e2e/ 2>/dev/null || echo "No cassettes yet"
echo "================================================"
