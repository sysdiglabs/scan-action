import * as core from '@actions/core';
import fs from 'fs';
import { JsonScanResultV1 } from '../entities/JsonScanResultV1';
import { IReportRepository } from '../../application/ports/IReportRepository';

export class FileSystemReportRepository implements IReportRepository {
  writeReport(report: JsonScanResultV1): void {
    const reportData = JSON.stringify(report, null, 2);
    fs.writeFileSync("./report.json", reportData);
    core.setOutput("scanReport", "./report.json");
  }
}
