import { Report } from '../../domain/entities/report';
import { ScanConfig } from './ScanConfig';

export interface IScanner {
  executeScan(config: ScanConfig): Promise<Report>;
}
