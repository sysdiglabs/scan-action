import { FilterOptions } from "../../domain/services/filtering";
import { ScanResult } from "../../domain/scanresult";

export interface IReportPresenter {
  generateReport(data: ScanResult, groupByPackage: boolean, filters?: FilterOptions): void;
}
