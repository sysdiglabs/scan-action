import { ScanResult } from '../../domain/scanresult';
import { ScanConfig } from './ScanConfig';

export interface IScanner {
  executeScan(config: ScanConfig): Promise<ScanResult>;
}
