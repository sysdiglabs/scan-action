import { ScanExecutionResult } from "./ScannerDTOs";
import { ScanConfig } from './ScanConfig';

export interface IScanner {
  pullScanner(url: string, version: string): Promise<number>;
  executeScan(config: ScanConfig): Promise<ScanExecutionResult>;
}
