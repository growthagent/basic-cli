#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Shared skip rules (also used by ci/all_tests.sh)
source ci/test_skip_rules.sh

indent() {
    sed 's/^/    /'
}

for test_file in tests/*.roc; do
    # Skip helper files (not actual tests)
    if is_helper_test "$test_file"; then
        continue
    fi

    echo "Running $test_file..."

    DB_PATH=./tests/test.db roc dev --linker legacy "$test_file" 2>&1 | indent

    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
        echo "FAILED: $test_file"
        exit 1
    fi
done

echo "All tests passed."
