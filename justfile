# Help commands
default:
    @just --list

# Run all checks
check: lint prepare test

# Run linter
lint:
    npm run lint

# Build TypeScript to build/ directory
build:
    npm run build

# Bundle for distribution (build + ncc bundle to dist/)
prepare:
    npm run prepare

# Run tests
test:
    npm test

# Run a single test file
test-file file:
    npx jest {{file}}

# Run tests matching a pattern
test-pattern pattern:
    npx jest --testNamePattern="{{pattern}}"

# Fix vulnerabilities
audit-fix:
    npm audit fix

# Check for vulnerabilities
audit:
    npm audit

# Install dependencies
install:
    npm install

# Update dependencies
update: update-cli-scanner
    nix flake update
    nix develop --command npm update
    nix develop --command npm audit fix
    nix develop --command pinact run -u
    nix develop --command pre-commit autoupdate

# Update sysdig-cli-scanner to latest available version
update-cli-scanner:
    #!/usr/bin/env bash
    set -euo pipefail
    file="src/infrastructure/sysdig/SysdigCliScannerConstants.ts"
    current=$(grep -oP 'cliScannerVersion = "\K[^"]+' "$file")
    latest=$(curl -sL https://download.sysdig.com/scanning/sysdig-cli-scanner/latest_version.txt)
    if [ "$latest" != "$current" ]; then
        for f in "$file" README.md action.yml; do
            sed -i "s/$current/$latest/g" "$f"
        done
        echo "Updated sysdig-cli-scanner: $current -> $latest"
    else
        echo "sysdig-cli-scanner already at latest: $current"
    fi
