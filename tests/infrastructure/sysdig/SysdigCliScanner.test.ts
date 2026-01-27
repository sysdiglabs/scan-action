import * as exec from '@actions/exec';
import { SysdigCliScanner } from '../../../src/infrastructure/sysdig/SysdigCliScanner';
import { SysdigCliScannerDownloader } from '../../../src/infrastructure/sysdig/SysdigCliScannerDownloader';
import { ScanConfig } from '../../../src/application/ports/ScanConfig';
import { ScanMode } from '../../../src/application/ports/ScannerDTOs';
import { EvaluationResult } from '../../../src/domain/scanresult';

jest.mock('@actions/exec');
jest.mock('@actions/core');

const mockExec = jest.mocked(exec);

describe('SysdigCliScanner', () => {
  let scanner: SysdigCliScanner;
  let mockDownloader: jest.Mocked<SysdigCliScannerDownloader>;
  let iacConfig: ScanConfig;

  beforeEach(() => {
    jest.resetAllMocks();

    mockDownloader = {
      download: jest.fn().mockResolvedValue('/path/to/scanner'),
    } as unknown as jest.Mocked<SysdigCliScannerDownloader>;

    scanner = new SysdigCliScanner(mockDownloader);

    iacConfig = {
      mode: ScanMode.iac,
      iacScanPath: './terraform',
      sysdigSecureToken: 'test-token',
      sysdigSecureURL: 'https://app.sysdig.com',
      cliScannerURL: '',
      stopOnFailedPolicyEval: true,
      stopOnProcessingError: true,
      standalone: false,
      skipSummary: false,
      groupByPackage: false,
      imageTag: '',
      overridePullString: '',
      registryUser: '',
      registryPassword: '',
      dbPath: '',
      skipUpload: false,
      usePolicies: '',
      sysdigSkipTLS: false,
      extraParameters: '',
      recursive: false,
      minimumSeverity: '',
    };
  });

  describe('IaC mode', () => {
    it('should return ScanResult with Passed evaluation when exit code is 0', async () => {
      mockExec.exec.mockResolvedValue(0);

      const result = await scanner.executeScan(iacConfig);

      expect(result).toBeDefined();
      expect(result.getEvaluationResult()).toBe(EvaluationResult.Passed);
    });

    it('should return ScanResult with Failed evaluation when exit code is 1', async () => {
      mockExec.exec.mockResolvedValue(1);

      const result = await scanner.executeScan(iacConfig);

      expect(result).toBeDefined();
      expect(result.getEvaluationResult()).toBe(EvaluationResult.Failed);
    });

    it('should NOT try to read scan-result.json in IaC mode', async () => {
      mockExec.exec.mockResolvedValue(0);

      await scanner.executeScan(iacConfig);

      const catCalls = mockExec.exec.mock.calls.filter(
        call => typeof call[0] === 'string' && call[0].includes('cat')
      );
      expect(catCalls).toHaveLength(0);
    });
  });
});
