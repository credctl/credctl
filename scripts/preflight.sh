#!/usr/bin/env bash
set -euo pipefail

# credctl pre-launch verification script
# Runs all checks needed before a public release.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { ((PASS++)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { ((FAIL++)); echo -e "  ${RED}FAIL${NC} $1"; }
warn() { ((WARN++)); echo -e "  ${YELLOW}WARN${NC} $1"; }
section() { echo -e "\n${BOLD}$1${NC}"; }

cd "$(git rev-parse --show-toplevel)"

# -------------------------------------------------------------------
section "1. Build"
# -------------------------------------------------------------------

if go build ./... 2>&1; then
  pass "go build ./..."
else
  fail "go build ./..."
fi

if go vet ./... 2>&1; then
  pass "go vet ./..."
else
  fail "go vet ./..."
fi

# -------------------------------------------------------------------
section "2. Unit tests"
# -------------------------------------------------------------------

if go test -race -count=1 ./... 2>&1; then
  pass "go test -race ./..."
else
  fail "go test -race ./..."
fi

# -------------------------------------------------------------------
section "3. Test coverage"
# -------------------------------------------------------------------

go test -coverprofile=coverage.out -covermode=atomic ./... > /dev/null 2>&1
COVERAGE=$(go tool cover -func=coverage.out | tail -1 | awk '{print $3}' | tr -d '%')
rm -f coverage.out

if (( $(echo "$COVERAGE >= 80" | bc -l) )); then
  pass "Coverage: ${COVERAGE}%"
else
  warn "Coverage: ${COVERAGE}% (target: 80%)"
fi

# -------------------------------------------------------------------
section "4. Security scanners"
# -------------------------------------------------------------------

if command -v govulncheck &> /dev/null; then
  if govulncheck ./... 2>&1; then
    pass "govulncheck clean"
  else
    fail "govulncheck found vulnerabilities"
  fi
else
  warn "govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"
fi

if command -v gosec &> /dev/null; then
  if gosec -exclude=G104,G115,G117,G204,G304,G703 -quiet ./... 2>&1; then
    pass "gosec clean"
  else
    fail "gosec found issues"
  fi
else
  warn "gosec not installed (go install github.com/securego/gosec/v2/cmd/gosec@latest)"
fi

if command -v staticcheck &> /dev/null; then
  if staticcheck ./... 2>&1; then
    pass "staticcheck clean"
  else
    fail "staticcheck found issues"
  fi
else
  warn "staticcheck not installed (go install honnef.co/go/tools/cmd/staticcheck@latest)"
fi

# -------------------------------------------------------------------
section "5. App bundle build"
# -------------------------------------------------------------------

SIGNING_DIR="${SIGNING_DIR:-}"

if [ -n "$SIGNING_DIR" ] && [ -f "$SIGNING_DIR/Info.plist" ]; then
  make clean > /dev/null 2>&1
  if make build SIGNING_DIR="$SIGNING_DIR" 2>&1; then
    pass "App bundle build + codesign"

    BINARY="build/credctl.app/Contents/MacOS/credctl"

    if codesign --verify --deep --strict "$BINARY" 2>&1; then
      pass "Code signature valid"
    else
      fail "Code signature invalid"
    fi
  else
    fail "App bundle build"
  fi
else
  warn "Skipping app bundle build (set SIGNING_DIR to apple-signing repo path)"
fi

# -------------------------------------------------------------------
section "6. CLI smoke tests"
# -------------------------------------------------------------------

CREDCTL=""
if [ -f "build/credctl.app/Contents/MacOS/credctl" ]; then
  CREDCTL="./build/credctl.app/Contents/MacOS/credctl"
elif command -v credctl &> /dev/null; then
  CREDCTL="credctl"
fi

if [ -n "$CREDCTL" ]; then
  # version
  if $CREDCTL version > /dev/null 2>&1; then
    pass "credctl version"
  else
    fail "credctl version"
  fi

  # status (may show uninitialised — that's ok)
  if $CREDCTL status > /dev/null 2>&1; then
    pass "credctl status"
  else
    # status exits non-zero if not initialised, check stderr
    if $CREDCTL status 2>&1 | grep -qi "not initialised\|fingerprint\|status"; then
      pass "credctl status (uninitialised but responsive)"
    else
      fail "credctl status"
    fi
  fi

  # help flags
  if $CREDCTL --help > /dev/null 2>&1; then
    pass "credctl --help"
  else
    fail "credctl --help"
  fi

  if $CREDCTL auth --help > /dev/null 2>&1; then
    pass "credctl auth --help"
  else
    fail "credctl auth --help"
  fi

  if $CREDCTL setup aws --help > /dev/null 2>&1; then
    pass "credctl setup aws --help"
  else
    fail "credctl setup aws --help"
  fi

  if $CREDCTL oidc generate --help > /dev/null 2>&1; then
    pass "credctl oidc generate --help"
  else
    fail "credctl oidc generate --help"
  fi

  if $CREDCTL oidc publish --help > /dev/null 2>&1; then
    pass "credctl oidc publish --help"
  else
    fail "credctl oidc publish --help"
  fi

  # Error messages: bad input should produce clear errors, not panics
  if OUTPUT=$($CREDCTL auth 2>&1); then
    warn "credctl auth without config should fail"
  else
    if echo "$OUTPUT" | grep -qi "error\|not configured\|not initialised\|missing"; then
      pass "credctl auth error message is clear"
    else
      warn "credctl auth error message may need review: $OUTPUT"
    fi
  fi
else
  warn "Skipping CLI smoke tests (no binary found — build first or install via brew)"
fi

# -------------------------------------------------------------------
section "7. Repo hygiene"
# -------------------------------------------------------------------

if [ -f LICENSE ]; then
  pass "LICENSE file exists"
else
  fail "LICENSE file missing"
fi

if [ -f SECURITY.md ]; then
  pass "SECURITY.md exists"
else
  fail "SECURITY.md missing"
fi

if [ -f CONTRIBUTING.md ]; then
  pass "CONTRIBUTING.md exists"
else
  fail "CONTRIBUTING.md missing"
fi

if [ -f README.md ]; then
  pass "README.md exists"
else
  fail "README.md missing"
fi

if [ -d .github/ISSUE_TEMPLATE ]; then
  pass "Issue templates exist"
else
  fail "Issue templates missing"
fi

# Check no secrets accidentally committed
if git log --all --diff-filter=A --name-only --pretty=format: | grep -qiE '\.env$|credentials|\.p12$|\.pem$|secret'; then
  warn "Possible sensitive files in git history — review before making public"
else
  pass "No obvious secrets in git history"
fi

# Check signing artifacts removed
if [ -f entitlements.plist ] || [ -f embedded.provisionprofile ] || [ -d xcode/ ]; then
  fail "Signing artifacts still in repo (should be in credctl/apple-signing)"
else
  pass "No signing artifacts in repo"
fi

# -------------------------------------------------------------------
section "8. Integration tests (optional)"
# -------------------------------------------------------------------

if [ "${RUN_INTEGRATION:-}" = "1" ]; then
  if go test -race -count=1 -tags=integration ./... 2>&1; then
    pass "Integration tests"
  else
    fail "Integration tests"
  fi
else
  warn "Skipping integration tests (set RUN_INTEGRATION=1 to run)"
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------

echo ""
echo -e "${BOLD}Summary${NC}"
echo -e "  ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${WARN} warnings${NC}"

if [ "$FAIL" -gt 0 ]; then
  echo -e "\n${RED}${BOLD}Pre-flight check failed.${NC}"
  exit 1
else
  echo -e "\n${GREEN}${BOLD}Pre-flight check passed.${NC}"
  exit 0
fi
