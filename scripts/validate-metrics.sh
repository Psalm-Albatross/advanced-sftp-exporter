#!/bin/bash
# ==============================================================================
# Advanced SFTP Exporter - Metric Validation Script
# ==============================================================================
# Purpose: Systematically validate all metrics for duplicates, conflicts,
#          naming consistency, and proper registration.
#
# Usage: ./scripts/validate-metrics.sh
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Temporary files for tracking
METRIC_DEFS_FILE="/tmp/metric_defs.txt"
DUP_CHECK_FILE="/tmp/dup_check.txt"
NAMING_ERR_FILE="/tmp/naming_err.txt"

# Clean up temp files
rm -f "$METRIC_DEFS_FILE" "$DUP_CHECK_FILE" "$NAMING_ERR_FILE"

# Counters
ERRORS=0
WARNINGS=0
METRICS_DEFINED=0
METRICS_REGISTERED=0

# Files to validate
METRICS_FILES="main.go metrics_core.go metrics_monitoring.go metrics_advanced.go metrics_enterprise.go"

echo "================================================================================"
echo "Advanced SFTP Exporter - Metric Validation"
echo "================================================================================"
echo "Date: $(date)"
echo "Project: $PROJECT_ROOT"
echo ""

# ==============================================================================
# Step 1: Extract all metric definitions
# ==============================================================================
echo "Step 1: Extracting metric definitions..."
for file in $METRICS_FILES; do
	filepath="$PROJECT_ROOT/$file"
	
	if [ ! -f "$filepath" ]; then
		echo "  ERROR: File not found - $file"
		ERRORS=$((ERRORS + 1))
		continue
	fi
	
	echo -n "  Scanning $file... "
	
	# Extract metric names using proper grep and sed
	count=$(grep 'Name:' "$filepath" 2>/dev/null | \
		grep -oE '"sftp_[^"]+' 2>/dev/null | \
		sed 's/"//g' | wc -l)
	
	# Collect all metrics to temp file
	grep 'Name:' "$filepath" 2>/dev/null | \
		grep -oE '"sftp_[^"]+' 2>/dev/null | \
		sed 's/"//g' >> "$METRIC_DEFS_FILE" 2>/dev/null || true
	
	METRICS_DEFINED=$((METRICS_DEFINED + count))
	echo "$count metrics found"
done

echo "Total metrics defined: $METRICS_DEFINED"
echo ""

# ==============================================================================
# Step 2: Check for duplicate metric names
# ==============================================================================
echo "Step 2: Checking for duplicate metric names..."

if [ -f "$METRIC_DEFS_FILE" ]; then
	sort "$METRIC_DEFS_FILE" | uniq -d > "$DUP_CHECK_FILE" 2>/dev/null || true
	
	DUP_COUNT=$(wc -l < "$DUP_CHECK_FILE" 2>/dev/null || echo 0)
	DUP_COUNT=$((DUP_COUNT))
	
	if [ "$DUP_COUNT" -gt 0 ]; then
		echo "  ❌ DUPLICATE METRICS FOUND:"
		while IFS= read -r dup; do
			if [ -n "$dup" ]; then
				echo "    • $dup"
				ERRORS=$((ERRORS + 1))
			fi
		done < "$DUP_CHECK_FILE"
	else
		echo "  ✅ PASS: No duplicate metric names detected"
	fi
else
	echo "  ERROR: No metrics file found"
	ERRORS=$((ERRORS + 1))
fi
echo ""

# ==============================================================================
# Step 3: Verify naming conventions
# ==============================================================================
echo "Step 3: Validating naming conventions (sftp_* format)..."

if [ -f "$METRIC_DEFS_FILE" ]; then
	while IFS= read -r metric; do
		if [ -n "$metric" ]; then
			if ! echo "$metric" | grep -qE '^sftp_[a-z0-9_]+$'; then
				echo "    • $metric (must be lowercase: sftp_*)"
				ERRORS=$((ERRORS + 1))
				echo "$metric" >> "$NAMING_ERR_FILE"
			fi
		fi
	done < "$METRIC_DEFS_FILE"
	
	NAMING_ERR_COUNT=$(wc -l < "$NAMING_ERR_FILE" 2>/dev/null || echo 0)
	if [ "$NAMING_ERR_COUNT" -gt 0 ]; then
		echo "  ❌ NAMING CONVENTION VIOLATIONS: $NAMING_ERR_COUNT"
	else
		echo "  ✅ PASS: All metric names follow convention (sftp_*)"
	fi
else
	echo "  ERROR: No metrics file found"
	ERRORS=$((ERRORS + 1))
fi
echo ""

# ==============================================================================
# Step 4: Verify metric registration
# ==============================================================================
echo "Step 4: Checking metric registrations..."

for file in $METRICS_FILES; do
	filepath="$PROJECT_ROOT/$file"
	
	if [ ! -f "$filepath" ]; then
		continue
	fi
	
	echo -n "  Checking $file... "
	count=$(grep -oE 'prometheus\.MustRegister\([^)]*[a-zA-Z_][a-zA-Z0-9_]*' "$filepath" 2>/dev/null | \
		wc -l)
	
	METRICS_REGISTERED=$((METRICS_REGISTERED + count))
	echo "$count registrations found"
done

echo "Total metric registrations: $METRICS_REGISTERED"
echo ""

# ==============================================================================
# Step 5: Cross-file distribution check
# ==============================================================================
echo "Step 5: Verifying file organization..."

CORE_COUNT=$(grep 'Name:' "$PROJECT_ROOT/metrics_core.go" 2>/dev/null | \
	grep -oE '"sftp_[^"]+' 2>/dev/null | wc -l)
MONITORING_COUNT=$(grep 'Name:' "$PROJECT_ROOT/metrics_monitoring.go" 2>/dev/null | \
	grep -oE '"sftp_[^"]+' 2>/dev/null | wc -l)
ADVANCED_COUNT=$(grep 'Name:' "$PROJECT_ROOT/metrics_advanced.go" 2>/dev/null | \
	grep -oE '"sftp_[^"]+' 2>/dev/null | wc -l)
ENTERPRISE_COUNT=$(grep 'Name:' "$PROJECT_ROOT/metrics_enterprise.go" 2>/dev/null | \
	grep -oE '"sftp_[^"]+' 2>/dev/null | wc -l)

echo "  metrics_core.go: $CORE_COUNT metrics (foundational + Phase 2)"
echo "  metrics_monitoring.go: $MONITORING_COUNT metrics (Phase 3 visibility)"
echo "  metrics_advanced.go: $ADVANCED_COUNT metrics (Phase 4 features)"
echo "  metrics_enterprise.go: $ENTERPRISE_COUNT metrics (Phase 5 business)"

if [ "$CORE_COUNT" -gt 25 ] && [ "$MONITORING_COUNT" -gt 10 ] && [ "$ENTERPRISE_COUNT" -gt 40 ]; then
	echo "  ✅ PASS: Metrics properly distributed across files"
else
	echo "  ⚠️  Warning: Check metric distribution"
	WARNINGS=$((WARNINGS + 1))
fi
echo ""

# ==============================================================================
# Final Summary
# ==============================================================================
echo "================================================================================"
echo "VALIDATION SUMMARY"
echo "================================================================================"
echo "Total Metrics Defined:     $METRICS_DEFINED"
echo "Total Registrations:       $METRICS_REGISTERED"
echo "Errors:                    $ERRORS"
echo "Warnings:                  $WARNINGS"
echo ""

# Clean up
rm -f "$METRIC_DEFS_FILE" "$DUP_CHECK_FILE" "$NAMING_ERR_FILE"

if [ "$ERRORS" -eq 0 ]; then
	echo "✅ VALIDATION PASSED"
	echo "All metrics are properly defined, named, and organized."
	exit 0
else
	echo "❌ VALIDATION FAILED"
	echo "Please fix $ERRORS errors and $WARNINGS warnings before committing."
	exit 1
fi
