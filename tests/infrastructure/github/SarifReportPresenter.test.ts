import { SarifReportPresenter } from '../../../src/infrastructure/github/SarifReportPresenter';
import { JsonScanResultV1ToScanResultAdapter } from '../../../src/infrastructure/sysdig/JsonScanResultV1ToScanResultAdapter';
import { JsonScanResultV1 } from '../../../src/infrastructure/sysdig/JsonScanResultV1';
import { ScanResult, Package, Vulnerability, OperatingSystem, Architecture, PackageType, Severity, Family, EvaluationResult, ScanType, Version, Layer } from '../../../src/domain/scanresult';
import * as fs from 'fs';
import * as path from 'path';

describe('SarifReportPresenter', () => {
  const sarifOutputPath = './sarif.json';

  afterEach(() => {
    // Clean up the generated file
    if (fs.existsSync(sarifOutputPath)) {
      fs.unlinkSync(sarifOutputPath);
    }
  });

  it('should produce a valid SARIF JSON file for a given scan result', () => {
    // Arrange: Create a realistic ScanResult from a fixture
    const fixturePath = path.join(__dirname, '../../fixtures/vm/report-test-v1.json');
    const rawReport: JsonScanResultV1 = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
    const adapter = new JsonScanResultV1ToScanResultAdapter();
    const scanResult = adapter.toScanResult(rawReport);
    const presenter = new SarifReportPresenter();

    // Act: Generate the report, don't group by package
    presenter.generateReport(scanResult, false);

    // Assert: The output should be a valid, parseable JSON file
    expect(fs.existsSync(sarifOutputPath)).toBe(true);
    const generatedSarifContent = fs.readFileSync(sarifOutputPath, 'utf-8');

    let parsedSarif: any;
    expect(() => {
      parsedSarif = JSON.parse(generatedSarifContent);
    }).not.toThrow('The generated SARIF file should be valid JSON');

    // A high-level check to ensure it's a SARIF-like structure
    expect(parsedSarif).toHaveProperty('runs');
    expect(Array.isArray(parsedSarif.runs)).toBe(true);
  });

  it('should not produce duplicate ruleIds when group-by-package is enabled and packages have the same name', () => {
    // Arrange: Manually create a ScanResult with duplicate package names
    const os = new OperatingSystem(Family.fromString('Alpine'), '3.18');
    const scanResult = new ScanResult(
      ScanType.Docker,
      'test-image:latest',
      'image-id-123',
      'digest-456',
      os,
      BigInt(1000),
      Architecture.Amd64,
      {},
      new Date(),
      EvaluationResult.Passed
    );

    const layer = scanResult.addLayer('layer-digest-1', 0, BigInt(100), 'cmd');

    const vuln1 = scanResult.addVulnerability('CVE-2023-1000', Severity.High, 7.5, new Date(), null, false, '1.0.1');
    const vuln2 = scanResult.addVulnerability('CVE-2023-1001', Severity.Medium, 5.0, new Date(), null, false, '2.0.1');

    const pkg1 = scanResult.addPackage('pkg-uuid-1', PackageType.fromString('Apk'), 'duplicate-package', '1.0.0', '/path/to/pkg1', layer);
    pkg1.addVulnerability(vuln1);

    const pkg2 = scanResult.addPackage('pkg-uuid-2', PackageType.fromString('Apk'), 'duplicate-package', '1.0.1', '/path/to/pkg2', layer);
    pkg2.addVulnerability(vuln2);

    const presenter = new SarifReportPresenter();

    // Act: Generate the report with group-by-package enabled
    presenter.generateReport(scanResult, true);

    // Assert: The output should be a valid, parseable JSON file, and now with no duplicate ruleIds
    expect(fs.existsSync(sarifOutputPath)).toBe(true);
    const generatedSarifContent = fs.readFileSync(sarifOutputPath, 'utf-8');
    const parsedSarif = JSON.parse(generatedSarifContent);

    const ruleIds = new Set<string>();
    let hasDuplicateRuleId = false;

    parsedSarif.runs.forEach((run: any) => {
      run.tool.driver.rules.forEach((rule: any) => {
        if (ruleIds.has(rule.id)) {
          hasDuplicateRuleId = true;
        }
        ruleIds.add(rule.id);
      });
    });

    expect(hasDuplicateRuleId).toBe(false); // Expecting false now
  });
});
