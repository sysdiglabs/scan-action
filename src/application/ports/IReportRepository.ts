import { Report } from "../../infrastructure/entities/JsonScanResultV1";

export interface IReportRepository {
  writeReport(report: Report): void;
}
