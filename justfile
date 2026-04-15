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
update:
    nix flake update
    nix develop --command npm update
    nix develop --command npm audit fix
    nix develop --command pinact run -u
    nix develop --command pre-commit autoupdate
