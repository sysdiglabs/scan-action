import { JsonScanResultV1ToScanResultAdapter } from '../../../src/infrastructure/sysdig/JsonScanResultV1ToScanResultAdapter';
import { RunScanUseCase } from '../../../src/application/use-cases/RunScanUseCase';
import { IInputProvider } from '../../../src/application/ports/IInputProvider';
import { IScanner } from '../../../src/application/ports/IScanner';
import { IReportPresenter } from '../../../src/application/ports/IReportPresenter';
import { ScanMode } from '../../../src/application/ports/ScannerDTOs';
import * as core from '@actions/core';
import * as report_test from "../../fixtures/vm/report-test-v1.json";
import { ScanConfig } from '../../../src/application/ports/ScanConfig';
import { JsonScanResultV1 } from '../../../src/infrastructure/sysdig/JsonScanResultV1';

jest.mock('@actions/core');

const mockCore = jest.mocked(core);

const exampleReport: JsonScanResultV1 = report_test as JsonScanResultV1;
const adapter = new JsonScanResultV1ToScanResultAdapter();
const exampleScanResult = adapter.toScanResult(exampleReport);

describe('RunScanUseCase', () => {
  let inputProvider: jest.Mocked<IInputProvider>;
  let scanner: jest.Mocked<IScanner>;
  let reportPresenter: jest.Mocked<IReportPresenter>;
  let useCase: RunScanUseCase;
  let scanConfig: ScanConfig;

  beforeEach(() => {
    // Reset mocks before each test
    jest.resetAllMocks();

    // Mock dependencies
    inputProvider = {
      getInputs: jest.fn(),
    };
    scanner = {
      executeScan: jest.fn(),
    };
    reportPresenter = {
      generateReport: jest.fn(),
    };

    mockCore.getInput.mockImplementation((name: string) => {
      switch (name) {
        case 'mode':
          return 'vm';
        case 'stop-on-processing-error':
          return 'true';
        default:
          return '';
      }
    });

    // Mock ScanConfig
    scanConfig = {
      imageTag: 'test-image:latest',
      sysdigSecureToken: 'test-token',
      stopOnFailedPolicyEval: true,
      stopOnProcessingError: true,
      mode: ScanMode.vm,
      cliScannerURL: '',
      cliScannerVersion: '',
      standalone: false,
      skipSummary: false,
      groupByPackage: false,
      overridePullString: '',
      registryUser: '',
      registryPassword: '',
      dbPath: '',
      skipUpload: false,
      usePolicies: '',
      sysdigSecureURL: '',
      sysdigSkipTLS: false,
      extraParameters: '',
      recursive: false,
      minimumSeverity: '',
      iacScanPath: '',
    };

    inputProvider.getInputs.mockReturnValue(scanConfig);
  });

  const executeUseCase = () => {
    useCase = new RunScanUseCase(scanner, [reportPresenter], inputProvider);
    return useCase.execute();
  };

  it('should end successfully if scan passes', async () => {
    const passedReport = JSON.parse(JSON.stringify(exampleReport));
    passedReport.result.policies.globalEvaluation = 'passed';
    passedReport.result.policies.evaluations.forEach((ev: { bundles: any[]; }) => {
      ev.bundles.forEach((b: { rules: any[]; }) => {
        b.rules.forEach((r: { evaluationResult: string; }) => {
          r.evaluationResult = 'passed';
        });
      });
    });

    const passedScanResult = adapter.toScanResult(passedReport);
    scanner.executeScan.mockResolvedValue(passedScanResult);

    await executeUseCase();

    expect(scanner.executeScan).toHaveBeenCalled();
    expect(reportPresenter.generateReport).toHaveBeenCalled();
    expect(mockCore.setFailed).not.toHaveBeenCalled();
  });

  it('should fail if policy evaluation fails and stopOnFailedPolicyEval is true', async () => {
    const failedReport = { ...exampleReport, result: { ...exampleReport.result, policies: { ...exampleReport.result.policies, globalEvaluation: 'failed' } } };
    const failedScanResult = adapter.toScanResult(failedReport);
    scanner.executeScan.mockResolvedValue(failedScanResult);

    await executeUseCase();

    expect(mockCore.setFailed).toHaveBeenCalledWith('Stopping because Policy Evaluation was FAILED.');
  });

  it('should not fail if policy evaluation fails and stopOnFailedPolicyEval is false', async () => {
    scanConfig.stopOnFailedPolicyEval = false;
    inputProvider.getInputs.mockReturnValue(scanConfig);
    const failedReport = { ...exampleReport, result: { ...exampleReport.result, policies: { ...exampleReport.result.policies, globalEvaluation: 'failed' } } };
    const failedScanResult = adapter.toScanResult(failedReport);
    scanner.executeScan.mockResolvedValue(failedScanResult);

    await executeUseCase();

    expect(mockCore.setFailed).not.toHaveBeenCalled();
  });

  it('should handle errors during execution', async () => {
    const error = new Error('Test error');
    scanner.executeScan.mockRejectedValue(error);

    await executeUseCase();

    expect(mockCore.setFailed).toHaveBeenCalledWith(`Unexpected error: ${error.stack}`);
  });

  it('should not generate reports if scan is not for VM mode', async () => {
    scanConfig.mode = ScanMode.iac;
    inputProvider.getInputs.mockReturnValue(scanConfig);
    scanner.executeScan.mockResolvedValue(exampleScanResult);

    await executeUseCase();

    expect(reportPresenter.generateReport).not.toHaveBeenCalled();
  });

  describe('scanResultUrl output', () => {
    const expectedUrl = 'https://secure.sysdig.com/#/vulnerabilities/results/187b947ecf6977f82a88b9e8b2c331a0/overview';

    it('should set scanResultUrl output when the scan passes', async () => {
      const passedReport = { ...exampleReport, result: { ...exampleReport.result, policies: { ...exampleReport.result.policies, globalEvaluation: 'passed' } } };
      scanner.executeScan.mockResolvedValue(adapter.toScanResult(passedReport));

      await executeUseCase();

      expect(mockCore.setOutput).toHaveBeenCalledWith('scanResultUrl', expectedUrl);
      expect(mockCore.setFailed).not.toHaveBeenCalled();
    });

    it('should set scanResultUrl output before failing on policy evaluation', async () => {
      const failedReport = { ...exampleReport, result: { ...exampleReport.result, policies: { ...exampleReport.result.policies, globalEvaluation: 'failed' } } };
      scanner.executeScan.mockResolvedValue(adapter.toScanResult(failedReport));

      await executeUseCase();

      expect(mockCore.setOutput).toHaveBeenCalledWith('scanResultUrl', expectedUrl);
      expect(mockCore.setFailed).toHaveBeenCalledWith('Stopping because Policy Evaluation was FAILED.');
      expect(mockCore.setOutput.mock.invocationCallOrder[0])
        .toBeLessThan(mockCore.setFailed.mock.invocationCallOrder[0]);
    });

    it('should set scanResultUrl output even if a report presenter fails', async () => {
      scanConfig.stopOnProcessingError = false;
      inputProvider.getInputs.mockReturnValue(scanConfig);
      scanner.executeScan.mockResolvedValue(exampleScanResult);
      reportPresenter.generateReport.mockImplementation(() => { throw new Error('presenter error'); });

      await executeUseCase();

      expect(mockCore.setOutput).toHaveBeenCalledWith('scanResultUrl', expectedUrl);
      expect(mockCore.error).toHaveBeenCalled();
      expect(mockCore.setFailed).not.toHaveBeenCalled();
    });

    it('should not set scanResultUrl output when the URL is empty', async () => {
      const reportWithoutUrl = { ...exampleReport, info: { ...exampleReport.info!, resultUrl: '' } };
      scanner.executeScan.mockResolvedValue(adapter.toScanResult(reportWithoutUrl));

      await executeUseCase();

      expect(mockCore.setOutput).not.toHaveBeenCalledWith('scanResultUrl', expect.anything());
    });

    it('should not set scanResultUrl output in IaC mode', async () => {
      scanConfig.mode = ScanMode.iac;
      inputProvider.getInputs.mockReturnValue(scanConfig);
      scanner.executeScan.mockResolvedValue(exampleScanResult);

      await executeUseCase();

      expect(mockCore.setOutput).not.toHaveBeenCalledWith('scanResultUrl', expect.anything());
    });
  });
});
