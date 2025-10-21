import { RunScanUseCase } from '../../src/application/use-cases/RunScanUseCase';
import { IInputProvider } from '../../src/application/ports/IInputProvider';
import { IScanner } from '../../src/application/ports/IScanner';
import { IReportPresenter } from '../../src/application/ports/IReportPresenter';
import { IReportRepository } from '../../src/application/ports/IReportRepository';
import { ActionInputs } from '../../src/infrastructure/ActionInputs';
import { ScanExecutionResult, ScanMode } from '../../src/scanner';
import * as core from '@actions/core';
import * as report_test from "../fixtures/report-test-v1.json";

jest.mock('@actions/core');

const mockCore = jest.mocked(core);

const exampleReport = JSON.stringify(report_test);

describe('RunScanUseCase', () => {
  let inputProvider: jest.Mocked<IInputProvider>;
  let scanner: jest.Mocked<IScanner>;
  let reportPresenter: jest.Mocked<IReportPresenter>;
  let reportRepository: jest.Mocked<IReportRepository>;
  let useCase: RunScanUseCase;
  let actionInputs: ActionInputs;

  beforeEach(() => {
    // Reset mocks before each test
    jest.resetAllMocks();

    // Mock dependencies
    inputProvider = {
      getInputs: jest.fn(),
    };
    scanner = {
      pullScanner: jest.fn(),
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

    // Mock ActionInputs and its methods
    actionInputs = ActionInputs.overridingParsedActionInputs({
      imageTag: 'test-image:latest',
      sysdigSecureToken: 'test-token',
      stopOnFailedPolicyEval: true,
      stopOnProcessingError: true,
    });
    jest.spyOn(actionInputs, 'printOptions').mockImplementation();
    jest.spyOn(actionInputs, 'composeFlags').mockReturnValue({ envvars: {}, flags: [] });

    inputProvider.getInputs.mockReturnValue(actionInputs);
    scanner.pullScanner.mockResolvedValue(0);
  });

  const executeUseCase = () => {
    useCase = new RunScanUseCase(inputProvider, scanner, [reportPresenter], reportRepository);
    return useCase.execute();
  };

  it('should end successfully if scan passes', async () => {
    const scanResult: ScanExecutionResult = {
      ReturnCode: 0,
      Output: exampleReport,
      Error: '',
    };
    scanner.executeScan.mockResolvedValue(scanResult);

    await executeUseCase();

    expect(scanner.pullScanner).toHaveBeenCalled();
    expect(scanner.executeScan).toHaveBeenCalled();
    expect(reportRepository.writeReport).toHaveBeenCalledWith(exampleReport);
    expect(reportPresenter.generateReport).toHaveBeenCalled();
    expect(mockCore.setFailed).not.toHaveBeenCalled();
  });

  it('should fail if policy evaluation fails and stopOnFailedPolicyEval is true', async () => {
    const scanResult: ScanExecutionResult = {
      ReturnCode: 1,
      Output: exampleReport,
      Error: '',
    };
    scanner.executeScan.mockResolvedValue(scanResult);

    await executeUseCase();

    expect(mockCore.setFailed).toHaveBeenCalledWith('Stopping because Policy Evaluation was FAILED.');
  });

  it('should not fail if policy evaluation fails and stopOnFailedPolicyEval is false', async () => {
    actionInputs = ActionInputs.overridingParsedActionInputs({
        ...actionInputs.params,
        stopOnFailedPolicyEval: false,
    });
    inputProvider.getInputs.mockReturnValue(actionInputs);

    const scanResult: ScanExecutionResult = {
      ReturnCode: 1,
      Output: exampleReport,
      Error: '',
    };
    scanner.executeScan.mockResolvedValue(scanResult);

    await executeUseCase();

    expect(mockCore.setFailed).not.toHaveBeenCalled();
  });


  it('should fail if scanner returns an error code and stopOnProcessingError is true', async () => {
    const scanResult: ScanExecutionResult = {
      ReturnCode: 2,
      Output: '',
      Error: 'scanner error',
    };
    scanner.executeScan.mockResolvedValue(scanResult);

    await executeUseCase();

    expect(mockCore.setFailed).toHaveBeenCalledWith('Stopping because the scanner terminated with an error.');
  });

  it('should not fail if scanner returns an error code and stopOnProcessingError is false', async () => {
    actionInputs = ActionInputs.overridingParsedActionInputs({
        ...actionInputs.params,
        stopOnProcessingError: false,
    });
    inputProvider.getInputs.mockReturnValue(actionInputs);
    const scanResult: ScanExecutionResult = {
      ReturnCode: 2,
      Output: '',
      Error: 'scanner error',
    };
    scanner.executeScan.mockResolvedValue(scanResult);

    await executeUseCase();

    expect(mockCore.setFailed).not.toHaveBeenCalled();
  });


  it('should fail if scanner pull fails', async () => {
    scanner.pullScanner.mockResolvedValue(1);

    await executeUseCase();

    expect(core.error).toHaveBeenCalledWith("Terminating scan. Scanner couldn't be pulled.");
  });

  it('should handle errors during execution', async () => {
    const error = new Error('Test error');
    scanner.executeScan.mockRejectedValue(error);

    await executeUseCase();

    expect(mockCore.setFailed).toHaveBeenCalledWith(`Unexpected error: ${error.stack}`);
  });

  it('should not generate reports if scan is not for VM mode', async () => {
    actionInputs = ActionInputs.overridingParsedActionInputs({
        ...actionInputs.params,
        mode: ScanMode.iac,
    });
    inputProvider.getInputs.mockReturnValue(actionInputs);
    const scanResult: ScanExecutionResult = {
      ReturnCode: 0,
      Output: '',
      Error: '',
    };
    scanner.executeScan.mockResolvedValue(scanResult);

    await executeUseCase();

    expect(reportRepository.writeReport).not.toHaveBeenCalled();
    expect(reportPresenter.generateReport).not.toHaveBeenCalled();
  });
});
