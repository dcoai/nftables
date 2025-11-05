#!/bin/bash
# Emergency cleanup script for nftables test tables
# This script removes all test tables that start with "nftex_test_"

set -e

echo "🔍 Searching for test tables..."

# List all test tables
TEST_TABLES=$(sudo nft list ruleset 2>/dev/null | grep "table inet nftex_test" | awk '{print $3}' | sort -u)

if [ -z "$TEST_TABLES" ]; then
    echo "✅ No test tables found. System is clean."
    exit 0
fi

echo "📋 Found the following test tables:"
echo "$TEST_TABLES"
echo ""

# Count tables
TABLE_COUNT=$(echo "$TEST_TABLES" | wc -l)
echo "⚠️  About to delete $TABLE_COUNT test table(s)"
echo ""

# Ask for confirmation unless --force flag is used
if [ "$1" != "--force" ]; then
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Aborted"
        exit 1
    fi
fi

# Delete each test table
echo ""
echo "🗑️  Deleting test tables..."
DELETED=0
FAILED=0

while IFS= read -r table; do
    if sudo nft delete table inet "$table" 2>/dev/null; then
        echo "  ✓ Deleted: $table"
        ((DELETED++))
    else
        echo "  ✗ Failed to delete: $table"
        ((FAILED++))
    fi
done <<< "$TEST_TABLES"

echo ""
echo "📊 Summary:"
echo "  ✓ Deleted: $DELETED"
if [ $FAILED -gt 0 ]; then
    echo "  ✗ Failed: $FAILED"
    exit 1
fi

echo ""
echo "✅ All test tables cleaned up successfully!"
echo ""
echo "💡 To prevent test tables from accumulating:"
echo "   1. Always use 'test_mode: true' when calling Policy.setup_basic_firewall"
echo "   2. Ensure on_exit callbacks run in your tests"
echo "   3. Avoid Ctrl+C during test runs"
