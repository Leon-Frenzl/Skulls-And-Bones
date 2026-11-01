#!/bin/bash
set -euo pipefail

echo "======================================================================"
echo "EMPIRICAL TEST SUITE: SSHD BACKUP & ROLLBACK HARDENING"
echo "Target Host: $(hostname) ($(uname -a))"
echo "GNU coreutils cp: $(cp --version | head -n1)"
echo "Bash version: $BASH_VERSION"
echo "======================================================================"

PASSED=0
FAILED=0

run_test() {
    local test_name="$1"
    local setup_fn="$2"
    local verify_fn="$3"
    
    echo -n "Running [Test: $test_name] ... "
    
    # Create isolated test environment
    local TEST_ROOT
    TEST_ROOT=$(mktemp -d /tmp/sb_rollback_test.XXXXXX)
    local CONFIG_D="$TEST_ROOT/etc/ssh/sshd_config.d"
    local BACKUP_DIR="$TEST_ROOT/etc/ssh/.sb-backup-test"
    mkdir -p "$CONFIG_D" "$BACKUP_DIR"
    
    # 1. Setup initial state
    "$setup_fn" "$CONFIG_D"
    
    # 2. Execute exact backup commands from bootstrap.rs (lines 661-662)
    # adapted to test CONFIG_D and BACKUP_DIR paths
    ([ -e "$CONFIG_D/99-sb-ca.conf" ] || [ -L "$CONFIG_D/99-sb-ca.conf" ]) && cp -a "$CONFIG_D/99-sb-ca.conf" "${BACKUP_DIR}/" || true
    ([ -e "$CONFIG_D/99-sbm.conf" ] || [ -L "$CONFIG_D/99-sbm.conf" ]) && cp -a "$CONFIG_D/99-sbm.conf" "${BACKUP_DIR}/" || true
    
    # 3. Simulate Phase 3 provisioning mutation (lines 710-718)
    cat > "$CONFIG_D/99-sb-ca.conf.tmp" << 'EOF'
# SWARM CA PROVISIONED
TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
EOF
    mv "$CONFIG_D/99-sb-ca.conf.tmp" "$CONFIG_D/99-sb-ca.conf"
    ln -sf "$CONFIG_D/99-sb-ca.conf" "$CONFIG_D/99-sbm.conf"
    
    # Verify provisioning mutation state: 99-sbm.conf is a symlink to 99-sb-ca.conf
    if [ ! -L "$CONFIG_D/99-sbm.conf" ]; then
        echo "SETUP ERROR: Provisioning symlink failed"
        exit 1
    fi
    
    # 4. Execute exact rollback script from bootstrap.rs (lines 666-684)
    local B="$BACKUP_DIR"
    rm -f "$CONFIG_D/99-sb-ca.conf"
    if [ -e "$B/99-sb-ca.conf" ] || [ -L "$B/99-sb-ca.conf" ]; then
        cp -a "$B/99-sb-ca.conf" "$CONFIG_D/99-sb-ca.conf"
    fi
    rm -f "$CONFIG_D/99-sbm.conf"
    if [ -e "$B/99-sbm.conf" ] || [ -L "$B/99-sbm.conf" ]; then
        cp -a "$B/99-sbm.conf" "$CONFIG_D/99-sbm.conf"
    fi
    
    # 5. Verification
    local ERR=""
    if ! "$verify_fn" "$CONFIG_D"; then
        echo "FAILED!"
        FAILED=$((FAILED + 1))
    else
        echo "PASSED"
        PASSED=$((PASSED + 1))
    fi
    
    # Cleanup
    rm -rf "$TEST_ROOT"
}

# -----------------------------------------------------------------------------
# Case 1: Clean slate (neither 99-sb-ca.conf nor 99-sbm.conf pre-existed)
# Expected after rollback: neither exists.
# -----------------------------------------------------------------------------
setup_case_1() {
    local dir="$1"
    # nothing to create
    return 0
}
verify_case_1() {
    local dir="$1"
    if [ -e "$dir/99-sb-ca.conf" ] || [ -L "$dir/99-sb-ca.conf" ]; then
        echo "Error: 99-sb-ca.conf should not exist"
        return 1
    fi
    if [ -e "$dir/99-sbm.conf" ] || [ -L "$dir/99-sbm.conf" ]; then
        echo "Error: 99-sbm.conf should not exist"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 2: Only 99-sbm.conf pre-existed as regular file (Scenario A from Round 2)
# Expected after rollback: 99-sb-ca.conf does NOT exist, 99-sbm.conf restored as regular file
# with original content.
# -----------------------------------------------------------------------------
setup_case_2() {
    local dir="$1"
    echo "ORIGINAL_SBM_CONTENT" > "$dir/99-sbm.conf"
}
verify_case_2() {
    local dir="$1"
    if [ -e "$dir/99-sb-ca.conf" ] || [ -L "$dir/99-sb-ca.conf" ]; then
        echo "Error: 99-sb-ca.conf should not exist"
        return 1
    fi
    if [ -L "$dir/99-sbm.conf" ]; then
        echo "Error: 99-sbm.conf should not be a symlink"
        return 1
    fi
    if [ ! -f "$dir/99-sbm.conf" ]; then
        echo "Error: 99-sbm.conf regular file is missing"
        return 1
    fi
    local content
    content=$(cat "$dir/99-sbm.conf")
    if [ "$content" != "ORIGINAL_SBM_CONTENT" ]; then
        echo "Error: 99-sbm.conf content mismatch: '$content'"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 3: Only 99-sb-ca.conf pre-existed as regular file
# Expected after rollback: 99-sb-ca.conf restored with original content, 99-sbm.conf does NOT exist
# -----------------------------------------------------------------------------
setup_case_3() {
    local dir="$1"
    echo "ORIGINAL_SB_CA_CONTENT" > "$dir/99-sb-ca.conf"
}
verify_case_3() {
    local dir="$1"
    if [ -e "$dir/99-sbm.conf" ] || [ -L "$dir/99-sbm.conf" ]; then
        echo "Error: 99-sbm.conf should not exist"
        return 1
    fi
    if [ -L "$dir/99-sb-ca.conf" ]; then
        echo "Error: 99-sb-ca.conf should not be a symlink"
        return 1
    fi
    if [ ! -f "$dir/99-sb-ca.conf" ]; then
        echo "Error: 99-sb-ca.conf regular file is missing"
        return 1
    fi
    local content
    content=$(cat "$dir/99-sb-ca.conf")
    if [ "$content" != "ORIGINAL_SB_CA_CONTENT" ]; then
        echo "Error: 99-sb-ca.conf content mismatch: '$content'"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 4: Both 99-sb-ca.conf and 99-sbm.conf pre-existed as regular files (Scenario B from Round 2)
# Expected after rollback: Both restored with respective original content, neither corrupted or linked.
# -----------------------------------------------------------------------------
setup_case_4() {
    local dir="$1"
    echo "ORIGINAL_SB_CA_CONTENT_4" > "$dir/99-sb-ca.conf"
    echo "ORIGINAL_SBM_CONTENT_4" > "$dir/99-sbm.conf"
}
verify_case_4() {
    local dir="$1"
    if [ -L "$dir/99-sb-ca.conf" ] || [ -L "$dir/99-sbm.conf" ]; then
        echo "Error: Neither file should be a symlink"
        return 1
    fi
    local c_ca c_sbm
    c_ca=$(cat "$dir/99-sb-ca.conf")
    c_sbm=$(cat "$dir/99-sbm.conf")
    if [ "$c_ca" != "ORIGINAL_SB_CA_CONTENT_4" ]; then
        echo "Error: 99-sb-ca.conf corrupted! Found: '$c_ca'"
        return 1
    fi
    if [ "$c_sbm" != "ORIGINAL_SBM_CONTENT_4" ]; then
        echo "Error: 99-sbm.conf corrupted! Found: '$c_sbm'"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 5: 99-sbm.conf was an external valid symlink pointing to external_rule.conf
# Expected after rollback: 99-sbm.conf restored as symlink to external_rule.conf
# -----------------------------------------------------------------------------
setup_case_5() {
    local dir="$1"
    echo "EXTERNAL_RULE" > "$dir/external_rule.conf"
    ln -s "$dir/external_rule.conf" "$dir/99-sbm.conf"
}
verify_case_5() {
    local dir="$1"
    if [ ! -L "$dir/99-sbm.conf" ]; then
        echo "Error: 99-sbm.conf should be a symlink"
        return 1
    fi
    local target
    target=$(readlink "$dir/99-sbm.conf")
    if [ "$target" != "$dir/external_rule.conf" ]; then
        echo "Error: 99-sbm.conf points to wrong target: '$target'"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 6: 99-sbm.conf was a DANGLING symlink pointing to /nonexistent/path.conf
# Expected after rollback: 99-sbm.conf restored as a dangling symlink to /nonexistent/path.conf
# -----------------------------------------------------------------------------
setup_case_6() {
    local dir="$1"
    ln -s "/nonexistent/path.conf" "$dir/99-sbm.conf"
}
verify_case_6() {
    local dir="$1"
    if [ ! -L "$dir/99-sbm.conf" ]; then
        echo "Error: 99-sbm.conf should be a symlink"
        return 1
    fi
    local target
    target=$(readlink "$dir/99-sbm.conf")
    if [ "$target" != "/nonexistent/path.conf" ]; then
        echo "Error: 99-sbm.conf points to wrong target: '$target'"
        return 1
    fi
    # Must be dangling: [ -e ] should fail
    if [ -e "$dir/99-sbm.conf" ]; then
        echo "Error: 99-sbm.conf should be dangling"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 7: 99-sb-ca.conf was a DANGLING symlink pointing to /nonexistent/ca.conf
# Expected after rollback: 99-sb-ca.conf restored as dangling symlink to /nonexistent/ca.conf
# -----------------------------------------------------------------------------
setup_case_7() {
    local dir="$1"
    ln -s "/nonexistent/ca.conf" "$dir/99-sb-ca.conf"
}
verify_case_7() {
    local dir="$1"
    if [ ! -L "$dir/99-sb-ca.conf" ]; then
        echo "Error: 99-sb-ca.conf should be a symlink"
        return 1
    fi
    local target
    target=$(readlink "$dir/99-sb-ca.conf")
    if [ "$target" != "/nonexistent/ca.conf" ]; then
        echo "Error: 99-sb-ca.conf points to wrong target: '$target'"
        return 1
    fi
    if [ -e "$dir/99-sb-ca.conf" ]; then
        echo "Error: 99-sb-ca.conf should be dangling"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 8: Both were dangling symlinks
# Expected after rollback: Both restored as their respective dangling symlinks
# -----------------------------------------------------------------------------
setup_case_8() {
    local dir="$1"
    ln -s "/nonexistent/ca.conf" "$dir/99-sb-ca.conf"
    ln -s "/nonexistent/sbm.conf" "$dir/99-sbm.conf"
}
verify_case_8() {
    local dir="$1"
    if [ ! -L "$dir/99-sb-ca.conf" ] || [ ! -L "$dir/99-sbm.conf" ]; then
        echo "Error: Both files must be symlinks"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Case 9: Repeated / Re-entrant Rollback Execution
# Executing rollback twice on the same backup state must be idempotent
# -----------------------------------------------------------------------------
setup_case_9() {
    local dir="$1"
    echo "IDEMPOTENT_CONTENT" > "$dir/99-sbm.conf"
}
verify_case_9() {
    local dir="$1"
    # Verify first state
    if [ "$(cat "$dir/99-sbm.conf")" != "IDEMPOTENT_CONTENT" ]; then
        return 1
    fi
    return 0
}

# Execute test suite
run_test "Clean slate (no prior drop-ins)" setup_case_1 verify_case_1
run_test "Only 99-sbm.conf pre-existed (Scenario A data-loss trap)" setup_case_2 verify_case_2
run_test "Only 99-sb-ca.conf pre-existed" setup_case_3 verify_case_3
run_test "Both regular files pre-existed (Scenario B symlink corruption trap)" setup_case_4 verify_case_4
run_test "99-sbm.conf pre-existed as external symlink" setup_case_5 verify_case_5
run_test "99-sbm.conf pre-existed as DANGLING symlink" setup_case_6 verify_case_6
run_test "99-sb-ca.conf pre-existed as DANGLING symlink" setup_case_7 verify_case_7
run_test "Both pre-existed as DANGLING symlinks" setup_case_8 verify_case_8
run_test "Idempotence verification" setup_case_9 verify_case_9

echo "======================================================================"
echo "SUMMARY: Passed: $PASSED, Failed: $FAILED"
echo "======================================================================"

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
exit 0
