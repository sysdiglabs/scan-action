import { Report } from "../../domain/entities/report";
import { FilterOptions } from "../../domain/services/filtering";

export interface IReportPresenter {
  generateReport(data: Report, groupByPackage: boolean, filters?: FilterOptions): void;
}
