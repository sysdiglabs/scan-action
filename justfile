# Help commands
[private]
default:
    @just --list

# Run all checks
[group('build')]
check: lint prepare test

# Run linter
[group('build')]
lint:
    npm run lint

# Build TypeScript to build/ directory
[group('build')]
build:
    npm run build

# Bundle for distribution (build + ncc bundle to dist/)
[group('build')]
prepare:
    npm run prepare

# Run tests
[group('test')]
test:
    npm test

# Run a single test file
[group('test')]
test-file file:
    npx jest {{file}}

# Run tests matching a pattern
[group('test')]
test-pattern pattern:
    npx jest --testNamePattern="{{pattern}}"

# Fix vulnerabilities
[group('deps')]
audit-fix:
    npm audit fix

# Check for vulnerabilities
[group('deps')]
audit:
    npm audit

# Install dependencies
[group('deps')]
install:
    npm install

# Update dependencies
[group('deps')]
update: update-cli-scanner update-oldest-cli-scanner
    nix flake update
    nix develop --command just _update-deps

# (internal) Refresh deps/hooks inside the nix devshell
[private]
[group('deps')]
_update-deps: && prepare
    npm update
    npm audit fix
    pinact run -u
    prek autoupdate

# (internal) Print the latest published sysdig-cli-scanner version
[private]
[group('scanner')]
_latest-version:
    @curl -sL https://download.sysdig.com/scanning/sysdig-cli-scanner/latest_version.txt | tr -d '[:space:]'

# Find the oldest sysdig-cli-scanner version still within the support window (default 365 days)
[group('scanner')]
oldest-cli-scanner window_days="365":
    #!/usr/bin/env bash
    set -euo pipefail
    base="https://download.sysdig.com/scanning/bin/sysdig-cli-scanner"
    os="linux"; arch="amd64"
    cutoff=$(( $(date -u +%s) - {{window_days}} * 86400 ))
    latest=$(just _latest-version)
    major=${latest%%.*}
    minor=$(echo "$latest" | cut -d. -f2)
    oldest_ver=""; oldest_epoch=""
    for m in $(seq "$minor" -1 0); do
        minor_hit=0; misses=0
        for p in $(seq 0 30); do
            v="$major.$m.$p"
            lm=$(curl -sfI "$base/$v/$os/$arch/sysdig-cli-scanner" \
                | grep -i '^last-modified:' | sed 's/^[Ll]ast-[Mm]odified: //' | tr -d '\r' || true)
            if [ -z "$lm" ]; then
                misses=$((misses + 1)); [ "$misses" -ge 2 ] && break; continue
            fi
            misses=0
            epoch=$(date -u -d "$lm" +%s)
            if [ "$epoch" -ge "$cutoff" ]; then
                minor_hit=1
                if [ -z "$oldest_epoch" ] || [ "$epoch" -lt "$oldest_epoch" ]; then
                    oldest_epoch=$epoch; oldest_ver=$v
                fi
            fi
        done
        # Versions are chronological: once a whole minor is out of window, stop.
        [ "$minor_hit" -eq 0 ] && [ -n "$oldest_ver" ] && break
    done
    if [ -z "$oldest_ver" ]; then
        echo "No version found within the last {{window_days}} days" >&2
        exit 1
    fi
    echo >&2 "Oldest supported: $oldest_ver (released $(date -u -d "@$oldest_epoch" '+%Y-%m-%d'))"
    echo "$oldest_ver"

# (internal) Replace the version tagged with <marker>-version-marker wherever it
# appears. Markers are HTML-comment spans in Markdown and trailing `#`/`//`
# comments in YAML/TS. Target files are discovered, not hardcoded, so a new
# marker anywhere is picked up automatically. DO NOT delete those markers.
[private]
[group('scanner')]
_set-version marker version:
    #!/usr/bin/env bash
    set -euo pipefail
    # Discover files carrying this marker. Skip generated output (dist/build),
    # deps, and the tooling/docs that only name the marker in prose.
    mapfile -t files < <(grep -rl \
        --exclude-dir=.git --exclude-dir=node_modules \
        --exclude-dir=build --exclude-dir=dist \
        --exclude=justfile --exclude=AGENTS.md \
        "{{marker}}-version-marker" . | sort)
    if [ "${#files[@]}" -eq 0 ]; then
        echo "No files found carrying {{marker}}-version-marker" >&2
        exit 1
    fi
    for f in "${files[@]}"; do
        echo "Updating $f" >&2
        # Markdown: <!-- {{marker}}-version-marker ... -->X<!-- /{{marker}}-version-marker -->
        sed -i -E "s#(<!-- {{marker}}-version-marker[^>]*-->)[0-9][0-9.]*(<!-- /{{marker}}-version-marker -->)#\1{{version}}\2#g" "$f"
        # YAML/TS: line carrying a `#`/`//` {{marker}}-version-marker comment
        sed -i -E "/(#|\/\/)[[:space:]]*{{marker}}-version-marker/ s/[0-9]+\.[0-9]+\.[0-9]+/{{version}}/" "$f"
    done

# Substitute the oldest supported version wherever the oldest-version-marker is placed
[group('scanner')]
update-oldest-cli-scanner window_days="365":
    #!/usr/bin/env bash
    set -euo pipefail
    oldest=$(just oldest-cli-scanner {{window_days}})
    just _set-version oldest "$oldest"
    echo "Oldest supported version set to $oldest (via oldest-version-marker)"

# Update sysdig-cli-scanner default to the latest available version
[group('scanner')]
update-cli-scanner:
    #!/usr/bin/env bash
    set -euo pipefail
    latest=$(just _latest-version)
    just _set-version newest "$latest"
    echo "Newest (default) version set to $latest (via newest-version-marker). Run 'just prepare' to rebuild dist/."
