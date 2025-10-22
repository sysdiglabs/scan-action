import { Report } from "../../infrastructure/entities/JsonScanResultV1";
import { FilterOptions } from "../../domain/services/filtering";

export interface IReportPresenter {
  generateReport(data: Report, groupByPackage: boolean, filters?: FilterOptions): void;
}
