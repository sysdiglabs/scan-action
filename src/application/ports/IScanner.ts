import { JsonScanResultV1 } from '../../infrastructure/entities/JsonScanResultV1';
import { ScanConfig } from './ScanConfig';

export interface IScanner {
  executeScan(config: ScanConfig): Promise<JsonScanResultV1>;
}
