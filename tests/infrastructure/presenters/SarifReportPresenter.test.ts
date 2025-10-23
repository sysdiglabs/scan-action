import { SarifReportPresenter } from '../../../src/infrastructure/presenters/SarifReportPresenter';
import { ReportToScanResultAdapter } from '../../../src/infrastructure/adapters/ReportToScanResultAdapter';
import { JsonScanResultV1 } from '../../../src/infrastructure/entities/JsonScanResultV1';
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
    const fixturePath = path.join(__dirname, '../../fixtures/report-test-v1.json');
    const rawReport: JsonScanResultV1 = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
    const adapter = new ReportToScanResultAdapter();
    const scanResult = adapter.toScanResult(rawReport);
    const presenter = new SarifReportPresenter();

    // Act: Generate the report
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
});
