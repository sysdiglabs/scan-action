import { Report } from '../../infrastructure/entities/JsonScanResultV1';
import { ScanConfig } from './ScanConfig';

export interface IScanner {
  executeScan(config: ScanConfig): Promise<Report>;
}
