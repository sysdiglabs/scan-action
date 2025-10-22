import * as fs from 'fs';
import * as path from 'path';
import { Report } from '../../../src/infrastructure/entities/JsonScanResultV1';
import { Severity } from '../../../src/domain/scanresult';
import { ReportToScanResultAdapter } from '../../../src/infrastructure/adapters/ReportToScanResultAdapter';

describe('ReportToScanResultAdapter', () => {
  let report: Report;

  beforeAll(() => {
    const filePath = path.join(__dirname, '../../fixtures/postgres_13.json');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    report = JSON.parse(fileContent) as Report;
  });

  it('should correctly convert a Report to a ScanResult', () => {
    const adapter = new ReportToScanResultAdapter();
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
});
