import { JsonScanResultV1 } from "../../infrastructure/entities/JsonScanResultV1";

export interface IReportRepository {
  writeReport(report: JsonScanResultV1): void;
}
