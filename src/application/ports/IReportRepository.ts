import { Report } from "../../domain/entities/report";

export interface IReportRepository {
  writeReport(report: Report): void;
}
