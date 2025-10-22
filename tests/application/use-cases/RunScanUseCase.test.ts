import { RunScanUseCase } from '../../../src/application/use-cases/RunScanUseCase';
import { IInputProvider } from '../../../src/application/ports/IInputProvider';
import { IScanner } from '../../../src/application/ports/IScanner';
import { IReportPresenter } from '../../../src/application/ports/IReportPresenter';
import { IReportRepository } from '../../../src/application/ports/IReportRepository';
import { ScanMode } from '../../../src/application/ports/ScannerDTOs';
import * as core from '@actions/core';
import * as report_test from "../../fixtures/report-test-v1.json";
import { ScanConfig } from '../../../src/application/ports/ScanConfig';
import { Report } from '../../../src/domain/entities/report';

jest.mock('@actions/core');

const mockCore = jest.mocked(core);

const exampleReport: Report = report_test as Report;

describe('RunScanUseCase', () => {
  let inputProvider: jest.Mocked<IInputProvider>;
  let scanner: jest.Mocked<IScanner>;
  let reportPresenter: jest.Mocked<IReportPresenter>;
  let reportRepository: jest.Mocked<IReportRepository>;
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
    reportRepository = {
      writeReport: jest.fn(),
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
    useCase = new RunScanUseCase(inputProvider, scanner, [reportPresenter], reportRepository);
    return useCase.execute();
  };

  it('should end successfully if scan passes', async () => {
    const exampleReportPassed = { ...exampleReport, result: { ...exampleReport.result, policies: { ...exampleReport.result.policies, globalEvaluation: 'passed' } } };
    scanner.executeScan.mockResolvedValue(exampleReportPassed);

    await executeUseCase();

    expect(scanner.executeScan).toHaveBeenCalled();
    expect(reportRepository.writeReport).toHaveBeenCalledWith(exampleReportPassed);
    expect(reportPresenter.generateReport).toHaveBeenCalled();
    expect(mockCore.setFailed).not.toHaveBeenCalled();
  });

  it('should fail if policy evaluation fails and stopOnFailedPolicyEval is true', async () => {
    const failedReport = { ...exampleReport, result: { ...exampleReport.result, policies: { ...exampleReport.result.policies, globalEvaluation: 'failed' } } };
    scanner.executeScan.mockResolvedValue(failedReport);

    await executeUseCase();

    expect(mockCore.setFailed).toHaveBeenCalledWith('Stopping because Policy Evaluation was FAILED.');
  });

  it('should not fail if policy evaluation fails and stopOnFailedPolicyEval is false', async () => {
    scanConfig.stopOnFailedPolicyEval = false;
    inputProvider.getInputs.mockReturnValue(scanConfig);
    const failedReport = { ...exampleReport, result: { ...exampleReport.result, policies: { ...exampleReport.result.policies, globalEvaluation: 'failed' } } };
    scanner.executeScan.mockResolvedValue(failedReport);

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
    scanner.executeScan.mockResolvedValue(exampleReport);

    await executeUseCase();

    expect(reportRepository.writeReport).not.toHaveBeenCalled();
    expect(reportPresenter.generateReport).not.toHaveBeenCalled();
  });
});
