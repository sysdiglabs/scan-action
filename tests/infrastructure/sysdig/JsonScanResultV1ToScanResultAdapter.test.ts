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
});
