import { ScanMode } from './ScannerDTOs';
import { Severity } from '../../domain/scanresult';

export interface ScanConfig {
  cliScannerURL: string;
  cliScannerVersion?: string;
  cliScannerSha256sum?: string;
  stopOnFailedPolicyEval: boolean;
  stopOnProcessingError: boolean;
  standalone: boolean;
  skipSummary: boolean;
  severityAtLeast?: string;
  packageTypes?: string;
  notPackageTypes?: string;
  excludeAccepted?: boolean;
  groupByPackage: boolean;
  mode: ScanMode;
  imageTag: string;
  overridePullString: string;
  registryUser: string;
  registryPassword: string;
  dbPath: string;
  skipUpload: boolean;
  usePolicies: string;
  sysdigSecureToken: string;
  sysdigSecureURL: string;
  sysdigSkipTLS: boolean;
  extraParameters: string;
  recursive: boolean;
  minimumSeverity: string;
  iacScanPath: string;
}
