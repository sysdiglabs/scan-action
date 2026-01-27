# AGENTS.md

This file provides guidance to LLM-based coding agents when working with code in this repository.

> **IMPORTANT: Keep this document accurate.** If you detect that any information in this file is outdated or incorrect while working on the codebase, update it immediately—even if documentation changes are not part of your current task. This document must never contain lies or stale information. Treat accuracy here as a continuous responsibility, not a one-time effort.

## Project Overview

This is a GitHub Action for Sysdig vulnerability scanning. It performs container image and IaC (Infrastructure as Code) analysis using the Sysdig CLI Scanner and generates SARIF reports for GitHub Security integration.

## Common Commands

```bash
# Build TypeScript to build/ directory
npm run build

# Bundle for distribution (build + ncc bundle to dist/)
npm run prepare

# Run linter
npm run lint

# Run all tests
npm test

# Run a single test file
npx jest tests/domain/services/filtering.test.ts

# Run tests matching a pattern
npx jest --testNamePattern="should filter"

# Full CI check (lint + prepare + test)
npm run all
```

## Architecture

The codebase follows Clean Architecture with three layers:

### Domain Layer (`src/domain/`)
Pure business logic with no external dependencies:
- **scanresult/**: Core entities - `ScanResult` (root aggregate), `Package`, `Vulnerability`, `Policy`, `AcceptedRisk`, `Layer`
- **services/**: `filtering.ts` (composable filter functions), `sorting.ts` (sort by severity)

**Key patterns:**
- `ScanResult` uses Maps for deduplication (vulnerabilities keyed by CVE, policies/risks by ID)
- Bidirectional relationships: `Package` ↔ `Vulnerability` ↔ `AcceptedRisk` (both sides maintain references, use `has()` checks to prevent infinite loops)
- Value objects are immutable type-safe enums with factory methods (`Severity.fromString()`, `PackageType.fromString()`)

**Severity scale (inverted - lower value = more severe):**
```
Critical (0) > High (1) > Medium (2) > Low (3) > Negligible (4) > Unknown (5)
```
Use `isMoreSevereThan()` for comparisons (compares numeric values inversely).

**Package.suggestedFixVersion()**: Scores fix versions by count of vulnerabilities fixed at each severity level, prioritizing versions that fix the most critical issues.

### Application Layer (`src/application/`)
- **use-cases/RunScanUseCase.ts**: Main orchestrator
- **ports/**: Interfaces (`IScanner`, `IReportPresenter`, `IInputProvider`, `ScanConfig`)
- **errors/**: `ChecksumVerificationError` (always fails), `ReportParsingError`, `ScanExecutionError`

**Error handling strategy:**
- `ChecksumVerificationError`: Always calls `core.setFailed()` regardless of config
- Other errors: Respects `stopOnProcessingError` flag (if true, fails; if false, logs only)
- Exit codes: 0=pass, 1=policy failure

### Infrastructure Layer (`src/infrastructure/`)
- **github/**: `GitHubActionsInputProvider`, `ActionInputs` (parsing/validation), `SarifReportPresenter`, `SummaryReportPresenter`
- **sysdig/**: `SysdigCliScanner` (CLI flag composition), `SysdigCliScannerDownloader` (SHA256 verification), `JsonScanResultV1ToScanResultAdapter` (6-phase hydration)

### Entry Point
`index.ts` wires everything together: creates input provider, downloader, scanner, and presenters, then invokes `RunScanUseCase`.

## Key Concepts

### Scan Modes
| Aspect | VM Mode (default) | IaC Mode |
|--------|-------------------|----------|
| Target | Container images (`imageTag`) | File paths (`iacScanPath`) |
| Reports | SARIF + GitHub Summary generated | No reports (scanner output only) |
| Filters | `severityAtLeast`, `packageTypes`, `excludeAccepted` | `minimumSeverity` (passed to scanner) |
| CLI flag | `--output=json-file=result.json` | `--iac` |

### SARIF Report Generation
Two modes controlled by `groupByPackage` option:
- **Group by vulnerability** (default): Each SARIF rule = one CVE, multiple results per affected package
- **Group by package**: Each SARIF rule = one vulnerable package, security-severity = max CVSS of all its vulnerabilities

**Severity to SARIF level mapping:**
- Critical, High → "error"
- Medium → "warning"
- Low, Negligible → "note"

### Filtering (VM mode only)
Filters are composable higher-order functions in `src/domain/services/filtering.ts`:
```typescript
type PackageFilterOption = (pkgs: Package[]) => Package[];
```
Applied sequentially: `packageTypes` → `notPackageTypes` → `minSeverity` → `excludeAccepted`

### Input Validation (ActionInputs.validateInputs)
1. `sysdigSecureToken` required unless `standalone: true`
2. `imageTag` required for VM mode
3. `iacScanPath` cannot be empty for IaC mode
4. `severityAtLeast` must be valid enum value or "any"

### Data Flow
```
Sysdig CLI JSON → JsonScanResultV1ToScanResultAdapter (6-phase hydration) → ScanResult
                                                                               ↓
                                                                        filterPackages()
                                                                               ↓
                                                          SarifReportPresenter / SummaryReportPresenter
```

**Adapter hydration phases:**
1. Create ScanResult with metadata
2. Add Layers
3. Add AcceptedRisks
4. Add Vulnerabilities (link to risks)
5. Add Packages (link to layers, vulnerabilities, risks)
6. Add Policies (with bundles and rules)

## Testing

Tests mirror the src/ structure in `tests/`.

**Fixtures** (`tests/fixtures/vm/`):
- `postgres_13.json`: Real scan (40 vulns, 145 packages, 25 layers)
- `report-test-v1.json`: Large fixture for integration tests
- `dummy-vuln-app_latest_accepted_risk_in_image.json`: Accepted risk scenarios

**Key test files:**
- `tests/domain/scanresult/Version.test.ts` - Semantic versioning, pre-release handling
- `tests/domain/scanresult/Package.test.ts` - Fix version scoring algorithm
- `tests/infrastructure/sysdig/JsonScanResultV1ToScanResultAdapter.test.ts` - Risk association (vuln-level vs package-level)
- `tests/infrastructure/github/SummaryReportPresenter.test.ts` - Filtering, sorting, HTML output (744 lines)

**Testing patterns:**
- Jest with `ts-jest`, mocking via `jest.Mocked<Interface>`
- `beforeEach` with `jest.resetAllMocks()` for isolation
- Factory helpers for test data creation

## Important Implementation Details

### Version Comparison (`src/domain/scanresult/Version.ts`)
- Supports semantic versioning with pre-release (`1.0.0-alpha < 1.0.0`)
- Strips `v` prefix for comparison (`v1.0.0` equals `1.0.0`)
- Build metadata ignored (`1.0.0+build1` equals `1.0.0+build2`)

### Policy Evaluation
- `Policy.getEvaluationResult()`: Failed if ANY bundle fails (short-circuit)
- `PolicyBundle.getEvaluationResult()`: Failed if ANY rule fails
- Two rule types: `PolicyBundleRulePkgVuln` (package vulnerabilities), `PolicyBundleRuleImageConfig` (image config)

### Checksum Verification (`SysdigCliScannerDownloader`)
- If `sha256sum` provided: Uses that value
- If not provided: Auto-fetches from `{url}.sha256`
- Verification uses Node.js `crypto.createHash('sha256')`

## CI/CD

### Workflows (`.github/workflows/`)

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yaml` | PR to master | Pre-commit checks (lint, build, test) |
| `ci-scan.yaml` | All PRs | **Dogfooding** - tests the action itself with 7 parallel jobs |
| `scan.yaml` | Manual (`workflow_dispatch`) | On-demand testing |
| `release.yml` | Push to master (package.json change) | Automated release |
| `stale.yml` | Daily cron + manual | Cleanup stale issues/PRs |

### Dogfooding Tests (`ci-scan.yaml`)

The action tests itself on every PR with these scenarios:
1. **scan-from-registry**: Basic scan with severity filter (expects failure - vuln image)
2. **filtered-scan-from-registry**: Group-by-package mode
3. **scan-with-old-scanner-version**: Backward compatibility (v1.18.0)
4. **standalone-scan-from-registry**: Offline mode with cached DB (donor scan pattern)
5. **scan-with-multiple-policies**: IaC mode with multiple policies
6. **scan-with-correct-checksum**: Checksum validation success
7. **scan-with-incorrect-checksum**: Checksum validation failure (expects failure)

Pattern: `continue-on-error: true` → validate outcome in follow-up step

### Release Process

1. Bump version in `package.json` and merge to master
2. `release.yml` detects version change via `jq` comparison
3. Creates git tag (e.g., `v6.3.3`)
4. Generates changelog with `git-chglog`
5. Creates GitHub release with changelog body
6. **Force-updates major tag** (e.g., `v6`) for `uses: sysdiglabs/scan-action@v6`

### Pre-commit Hooks (`.pre-commit-config.yaml`)

```bash
# Install pre-commit hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

Hooks run in order:
1. `trailing-whitespace`, `end-of-file-fixer`, `check-yaml` (exclude dist/)
2. `actionlint` - Validates GitHub Actions workflow syntax
3. `npm audit fix` - Fix vulnerabilities
4. `npm run lint` - ESLint
5. `npm run prepare` - Build dist/
6. `npm run test` - Jest tests

### Secrets Required

- `KUBELAB_SECURE_API_TOKEN`: Sysdig Secure API token for CI scans

## Technical Debt

### undici override (package.json)

There's an `overrides` section forcing `undici@^7.0.0` to fix CVE GHSA-g9mf-h72j-4rw9. This is a workaround because `@actions/http-client` (dependency of `@actions/github`) pins a vulnerable version of `undici`.

**Action required:** Remove the override once `@actions/http-client` releases a version with `undici >= 6.23.0`. Check periodically with:
```bash
npm ls undici
npm audit
```
