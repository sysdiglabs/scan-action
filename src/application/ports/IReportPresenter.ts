import { JsonScanResultV1 } from "../../infrastructure/entities/JsonScanResultV1";
import { FilterOptions } from "../../domain/services/filtering";

export interface IReportPresenter {
  generateReport(data: JsonScanResultV1, groupByPackage: boolean, filters?: FilterOptions): void;
}
