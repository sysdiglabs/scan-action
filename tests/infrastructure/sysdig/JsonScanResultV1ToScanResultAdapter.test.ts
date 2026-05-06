import * as fs from 'fs';
import * as path from 'path';
import { JsonScanResultV1 } from '../../../src/infrastructure/sysdig/JsonScanResultV1';
import { Severity } from '../../../src/domain/scanresult';
import { JsonScanResultV1ToScanResultAdapter } from '../../../src/infrastructure/sysdig/JsonScanResultV1ToScanResultAdapter';

describe('JsonScanResultV1ToScanResultAdapter', () => {
  let report: JsonScanResultV1;

  beforeAll(() => {
    const filePath = path.join(__dirname, '../../fixtures/vm/postgres_13.json');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    report = JSON.parse(fileContent) as JsonScanResultV1;
  });

  it('should correctly convert a Report to a ScanResult', () => {
    const adapter = new JsonScanResultV1ToScanResultAdapter();
    const scanResult = adapter.toScanResult(report);

    // Assertions based on the reference Rust test implementation
    expect(scanResult.getVulnerabilities()).toHaveLength(40);
    expect(scanResult.getPackages()).toHaveLength(145);
    expect(scanResult.getLayers()).toHaveLength(25);

    // Check severity counts from the Rust test
    const severities = scanResult.getVulnerabilities().map((v) => v.severity);
    const criticalCount = severities.filter((s) => s === Severity.Critical).length;
    const highCount = severities.filter((s) => s === Severity.High).length;
    const mediumCount = severities.filter((s) => s === Severity.Medium).length;
    const lowCount = severities.filter((s) => s === Severity.Low).length;
    const negligibleCount = severities.filter((s) => s === Severity.Negligible).length;

    expect(criticalCount).toBe(2);
    expect(highCount).toBe(3);
    expect(mediumCount).toBe(1);
    expect(lowCount).toBe(2);
    expect(negligibleCount).toBe(32);

    // Spot check a specific vulnerability that is known to exist
    const cve = 'CVE-2024-2236';
    const vulnerability = scanResult.findVulnerabilityByCve(cve);
    expect(vulnerability).toBeDefined();
    expect(vulnerability?.severity).toBe(Severity.Negligible);
    expect(vulnerability?.exploitable).toBe(false);
    expect(vulnerability?.fixVersion).toBeNull();

    // Find a package that is affected by this vulnerability to test the link
    const affectingPackage = scanResult
      .getPackages()
      .find((p) => p.getVulnerabilities().some((v) => v.cve === cve));
    expect(affectingPackage).toBeDefined();
  });

  it('should return a passed evaluation for a globally accepted risk', () => {
    const filePath = path.join(__dirname, '../../fixtures/vm/dummy-vuln-app_latest_accepted_risk_in_image.json');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    const reportWithAcceptedRisk = JSON.parse(fileContent) as JsonScanResultV1;

    const adapter = new JsonScanResultV1ToScanResultAdapter();
    const scanResult = adapter.toScanResult(reportWithAcceptedRisk);

    expect(scanResult.getEvaluationResult().isPassed()).toBe(true);
    const policyWithFailure = scanResult.getPolicies().find(p => p.getEvaluationResult().isFailed());
    expect(policyWithFailure).toBeDefined();
  });

  it('should NOT associate accepted risk to package when risk is only on vulnerability', () => {
    const riskId = "risk-123";
    const cveId = "CVE-2023-0001";
    const pkgName = "my-package";
    const layerDigest = "sha256:layer1";

    const minimalReport: any = {
      result: {
        metadata: {
          pullString: "image:tag",
          imageId: "sha256:image",
          digest: "sha256:digest",
          os: "linux",
          baseOs: "debian",
          size: 100,
          architecture: "amd64",
          createdAt: new Date().toISOString()
        },
        policies: {
          evaluations: [],
          globalEvaluation: "passed"
        },
        layers: {
          [layerDigest]: {
            digest: layerDigest,
            index: 0,
            command: "RUN something"
          }
        },
        riskAccepts: {
          [riskId]: {
            id: riskId,
            reason: "RiskOwned",
            description: "Accepting risk",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            status: "Active"
          }
        },
        vulnerabilities: {
          [cveId]: {
            name: cveId,
            severity: "High",
            cvssScore: { score: 7.5 },
            disclosureDate: new Date().toISOString(),
            riskAcceptRefs: [riskId], // Risk attached to vulnerability
            exploitable: false
          }
        },
        packages: {
          "pkg-uuid": {
            name: pkgName,
            type: "os",
            version: "1.0.0",
            path: "/bin/pkg",
            layerRef: layerDigest,
            vulnerabilitiesRefs: [cveId],
            riskAcceptRefs: null // No risk directly on package
          }
        }
      }
    };

    const adapter = new JsonScanResultV1ToScanResultAdapter();
    const result = adapter.toScanResult(minimalReport as JsonScanResultV1);

    const pkg = result.getPackages().find(p => p.name === pkgName);
    expect(pkg).toBeDefined();

    const vuln = result.getVulnerabilities().find(v => v.cve === cveId);
    expect(vuln).toBeDefined();

    // Vulnerability should have the risk
    expect(vuln!.getAcceptedRisks()).toHaveLength(1);
    expect(vuln!.getAcceptedRisks()[0].id).toBe(riskId);

    // Package should NOT have the risk
    expect(pkg!.getAcceptedRisks()).toHaveLength(0);
  });

  it('should associate accepted risk to package when risk is on package', () => {
    const riskId = "risk-pkg";
    const pkgName = "accepted-pkg";
    const layerDigest = "sha256:layer1";

    const minimalReport: any = {
      result: {
        metadata: {
          pullString: "image:tag",
          imageId: "sha256:image",
          digest: "sha256:digest",
          os: "linux",
          baseOs: "debian",
          size: 100,
          architecture: "amd64",
          createdAt: new Date().toISOString()
        },
        policies: {
          evaluations: [],
          globalEvaluation: "passed"
        },
        layers: {
          [layerDigest]: {
            digest: layerDigest,
            index: 0,
            command: "RUN something"
          }
        },
        riskAccepts: {
          [riskId]: {
            id: riskId,
            reason: "RiskOwned",
            description: "Accepting risk on package",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            status: "Active"
          }
        },
        vulnerabilities: {},
        packages: {
          "pkg-uuid": {
            name: pkgName,
            type: "os",
            version: "1.0.0",
            path: "/bin/pkg",
            layerRef: layerDigest,
            vulnerabilitiesRefs: [],
            riskAcceptRefs: [riskId] // Risk attached to package directly
          }
        }
      }
    };

    const adapter = new JsonScanResultV1ToScanResultAdapter();
    const result = adapter.toScanResult(minimalReport as JsonScanResultV1);

    const pkg = result.getPackages().find(p => p.name === pkgName);
    expect(pkg).toBeDefined();

    // Package SHOULD have the risk
    expect(pkg!.getAcceptedRisks()).toHaveLength(1);
    expect(pkg!.getAcceptedRisks()[0].id).toBe(riskId);
  });

  it('should skip unresolvable policy failures when a package is missing from the JSON (issue #108)', async () => {
    const layerDigest = "sha256:layer1";
    const existingPkgUuid = "pkg-exists";
    const missingPkgUuid = "pkg-was-truncated";
    const vulnUuid1 = "vuln-1";
    const vulnUuid2 = "vuln-2";

    const report: any = {
      result: {
        metadata: {
          pullString: "image:tag",
          imageId: "sha256:image",
          digest: "sha256:digest",
          os: "linux",
          baseOs: "debian",
          size: 100,
          architecture: "amd64",
          createdAt: new Date().toISOString()
        },
        policies: {
          globalEvaluation: "passed",
          evaluations: [{
            name: "Sysdig Runtime Threat Detection",
            identifier: "default-policy",
            description: "Default",
            evaluation: "failed",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            bundles: [{
              name: "Severe vulnerabilities with a Fix",
              identifier: "severe-vulns",
              type: "default",
              rules: [{
                ruleId: 271201,
                ruleType: "vulnSeverityAndThreats",
                failureType: "pkgVulnFailure",
                description: "Critical severity with fix",
                evaluationResult: "failed",
                predicates: [],
                failures: [
                  {
                    description: "",
                    packageRef: missingPkgUuid,
                    vulnerabilityRef: vulnUuid1
                  },
                  {
                    description: "",
                    packageRef: existingPkgUuid,
                    vulnerabilityRef: vulnUuid2
                  }
                ]
              }]
            }]
          }]
        },
        layers: {
          [layerDigest]: { digest: layerDigest, index: 0, command: "RUN apt-get install" }
        },
        riskAccepts: {},
        vulnerabilities: {
          [vulnUuid1]: {
            name: "CVE-2026-0001",
            severity: "Critical",
            cvssScore: { score: 9.8, version: "3.1", vector: "" },
            disclosureDate: new Date().toISOString(),
            exploitable: true,
            fixVersion: "2.0.0",
            mainProvider: "nvd",
            packageRef: missingPkgUuid,
            providersMetadata: {}
          },
          [vulnUuid2]: {
            name: "CVE-2026-0002",
            severity: "High",
            cvssScore: { score: 8.1, version: "3.1", vector: "" },
            disclosureDate: new Date().toISOString(),
            exploitable: false,
            fixVersion: "1.5.0",
            mainProvider: "nvd",
            packageRef: existingPkgUuid,
            providersMetadata: {}
          }
        },
        packages: {
          [existingPkgUuid]: {
            name: "libcurl",
            type: "os",
            version: "7.74.0",
            path: "/usr/lib/libcurl",
            layerRef: layerDigest,
            isRemoved: false,
            isRunning: true,
            vulnerabilitiesRefs: [vulnUuid2]
          }
        }
      }
    };

    const { SummaryReportPresenter } = await import('../../../src/infrastructure/github/SummaryReportPresenter');
    const core = await import('@actions/core');

    const adapter = new JsonScanResultV1ToScanResultAdapter();
    const scanResult = adapter.toScanResult(report as JsonScanResultV1);

    core.summary.emptyBuffer().clear();
    const presenter = new SummaryReportPresenter(core.summary);

    await presenter.generateReport(scanResult, false, { minSeverity: Severity.Unknown });

    const policies = scanResult.getPolicies();
    const rule = policies[0].getBundles()[0].getRules()[0];
    const failures = (rule as any).getFailures();
    expect(failures).toHaveLength(1);
    expect(failures[0].pkg.name).toBe("libcurl");
  });
});
